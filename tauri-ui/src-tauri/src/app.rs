use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    webview::NewWindowResponse,
    AppHandle, Emitter, Manager, WindowEvent,
};

use crate::{
    commands,
    gui_single_instance::{GuiInstance, GuiSingleInstance},
    local_gateway::ProductionGateway,
};

const BLOCK_PAGE_SURFACES: &str = "for (const event of ['contextmenu', 'dragenter', 'dragover', 'drop']) { window.addEventListener(event, (value) => value.preventDefault(), { capture: true }); }";
const WEBVIEW_BROWSER_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-breakpad --disable-crash-reporter";

#[cfg(windows)]
struct ImpersonationGuard;

#[cfg(windows)]
impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if unsafe { windows::Win32::Security::RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

pub fn run() -> tauri::Result<()> {
    #[cfg(windows)]
    commands::verify_active_gui().map_err(|error| {
        tauri::Error::Io(std::io::Error::other(format!(
            "{}: {}",
            error.code, error.message
        )))
    })?;
    let instance = match GuiSingleInstance::acquire()? {
        GuiInstance::Primary(instance) => instance,
        GuiInstance::Existing => {
            crate::gui_single_instance::activate_existing();
            return Ok(());
        }
    };
    #[cfg(windows)]
    verify_webview_environment()?;
    #[cfg(windows)]
    let (runtime, runtime_task) = fairypam_agent::runtime::start_embedded(
        fairypam_agent::runtime::RuntimeConfig::from_production().map_err(runtime_error)?,
    )
    .map_err(runtime_error)?;
    let mut context = tauri::generate_context!();
    for window in &mut context.config_mut().app.windows {
        if window.label == "main" {
            window.create = false;
            window.drag_drop_enabled = false;
        }
    }

    tauri::Builder::default()
        .manage(instance)
        .manage({
            #[cfg(windows)]
            {
                ProductionGateway::new(runtime)
            }
            #[cfg(not(windows))]
            {
                ProductionGateway::new()
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_overview,
            commands::get_connection_status,
            commands::run_environment_check,
            commands::get_log_tail,
            commands::scan_installed_games,
            commands::launch_game,
            commands::close_game,
            commands::capture_preview,
            commands::input_probe,
            commands::register_hub,
            commands::ensure_local_agent,
        ])
        .setup(move |app| {
            let main_config = &app.config().app.windows[0];
            let main_window = tauri::WebviewWindowBuilder::from_config(app.handle(), main_config)?;
            #[cfg(windows)]
            let main_window = {
                let webview_data_root = app.path().app_local_data_dir()?.join("webview");
                let webview_impersonation = begin_webview_impersonation()?;
                (
                    main_window
                        .data_directory(webview_data_root)
                        .incognito(true)
                        .devtools(cfg!(debug_assertions))
                        .additional_browser_args(WEBVIEW_BROWSER_ARGS),
                    webview_impersonation,
                )
            };
            #[cfg(windows)]
            let (main_window, webview_impersonation) = main_window;
            let main_window = main_window
                .on_navigation(allows_application_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .initialization_script(BLOCK_PAGE_SURFACES)
                .build()?;
            #[cfg(windows)]
            drop(webview_impersonation);
            disable_default_context_menu(&main_window);
            #[cfg(windows)]
            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if runtime_task.await.is_err() {
                        show_main_window(&app_handle);
                        let _ = app_handle.emit("embedded-runtime-failed", ());
                    }
                });
            }

            let activation_app = app.handle().clone();
            app.state::<GuiSingleInstance>().watch_activation(move || {
                let app = activation_app.clone();
                tauri::async_runtime::spawn(async move {
                    #[cfg(windows)]
                    if commands::verify_active_gui().is_err() {
                        exit_after_safe_shutdown(&app).await;
                        return;
                    }
                    show_main_window(&app);
                    let _ = app.emit("local-agent-activation", ());
                });
            })?;

            let show_main = MenuItemBuilder::with_id("show-main", "显示主窗口").build(app)?;
            let exit_ui = MenuItemBuilder::with_id("exit-ui", "退出界面").build(app)?;
            let menu = MenuBuilder::new(app)
                .items(&[&show_main, &exit_ui])
                .build()?;
            TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show-main" => show_main_window(app),
                    "exit-ui" => {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            exit_after_safe_shutdown(&app).await;
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(context)
}

async fn exit_after_safe_shutdown(app: &AppHandle) {
    let state = app.state::<ProductionGateway>();
    if commands::shutdown_local_agent_for_exit(&state)
        .await
        .is_err()
    {
        show_main_window(app);
        let _ = app.emit("embedded-runtime-failed", ());
        return;
    }
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    if window.clear_all_browsing_data().is_err() || window.destroy().is_err() {
        show_main_window(app);
        let _ = app.emit("embedded-runtime-failed", ());
        return;
    }
    app.exit(0);
}

#[cfg(windows)]
fn runtime_error(error: fairypam_agent_core::AgentError) -> tauri::Error {
    tauri::Error::Io(std::io::Error::other(format!(
        "{}: {}",
        error.code(),
        error
    )))
}

#[cfg(windows)]
fn verify_webview_environment() -> tauri::Result<()> {
    for variable in [
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
        "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
        "WEBVIEW2_USER_DATA_FOLDER",
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(tauri::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "WebView2 environment overrides are not allowed",
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn begin_webview_impersonation() -> tauri::Result<ImpersonationGuard> {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{
            GetTokenInformation, ImpersonateLoggedOnUser, TokenLinkedToken, TOKEN_LINKED_TOKEN,
            TOKEN_QUERY,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    let mut process_token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process_token) }
        .map_err(webview_token_error)?;
    let _process_token = OwnedHandle(process_token);
    let mut linked_token = TOKEN_LINKED_TOKEN::default();
    let mut returned_length = 0;
    unsafe {
        GetTokenInformation(
            process_token,
            TokenLinkedToken,
            Some(std::ptr::from_mut(&mut linked_token).cast()),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut returned_length,
        )
    }
    .map_err(webview_token_error)?;
    let linked_token = OwnedHandle(linked_token.LinkedToken);
    unsafe { ImpersonateLoggedOnUser(linked_token.0) }.map_err(webview_token_error)?;
    Ok(ImpersonationGuard)
}

#[cfg(windows)]
fn webview_token_error(error: windows::core::Error) -> tauri::Error {
    tauri::Error::Io(std::io::Error::other(format!(
        "unable to prepare the WebView2 data directory as the standard user: {error}"
    )))
}

fn allows_application_navigation(url: &tauri::Url) -> bool {
    url.scheme() == "tauri"
        || (matches!(url.scheme(), "http" | "https")
            && url.host_str() == Some("tauri.localhost")
            && url.port().is_none())
        || (cfg!(debug_assertions) && url.scheme() == "http" && url.host_str() == Some("127.0.0.1"))
}

fn disable_default_context_menu(window: &tauri::WebviewWindow) {
    let _ = window.with_webview(|webview| {
        #[cfg(windows)]
        unsafe {
            if let Ok(core) = webview.controller().CoreWebView2() {
                if let Ok(settings) = core.Settings() {
                    let _ = settings.SetAreDefaultContextMenusEnabled(false);
                }
            }
        }
    });
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::allows_application_navigation;

    #[test]
    fn allows_the_bundled_windows_tauri_frontend_but_not_external_navigation() {
        assert!(allows_application_navigation(
            &tauri::Url::parse("http://tauri.localhost/").unwrap()
        ));
        assert!(!allows_application_navigation(
            &tauri::Url::parse("https://example.com/").unwrap()
        ));
        assert!(!allows_application_navigation(
            &tauri::Url::parse("http://tauri.localhost:8080/").unwrap()
        ));
    }
}
