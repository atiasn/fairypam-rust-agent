use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    webview::NewWindowResponse,
    Emitter, Manager, WindowEvent,
};

use crate::{
    commands,
    gui_single_instance::{GuiInstance, GuiSingleInstance},
    local_gateway::ProductionGateway,
};

const BLOCK_PAGE_SURFACES: &str = "for (const event of ['contextmenu', 'dragenter', 'dragover', 'drop']) { window.addEventListener(event, (value) => value.preventDefault(), { capture: true }); }";

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
    let mut context = tauri::generate_context!();
    for window in &mut context.config_mut().app.windows {
        if window.label == "main" {
            window.create = false;
            window.drag_drop_enabled = false;
        }
    }

    tauri::Builder::default()
        .manage(instance)
        .manage(ProductionGateway::new())
        .invoke_handler(tauri::generate_handler![
            commands::get_overview,
            commands::get_connection_status,
            commands::run_environment_check,
            commands::get_log_tail,
            commands::scan_installed_games,
            commands::register_hub,
            commands::ensure_local_agent,
            commands::restart_local_agent,
            commands::repair_agent_tasks,
        ])
        .setup(|app| {
            let main_config = &app.config().app.windows[0];
            let main_window = tauri::WebviewWindowBuilder::from_config(app.handle(), main_config)?
                .on_navigation(allows_application_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .initialization_script(BLOCK_PAGE_SURFACES)
                .build()?;
            disable_default_context_menu(&main_window);

            let activation_app = app.handle().clone();
            app.state::<GuiSingleInstance>().watch_activation(move || {
                let app = activation_app.clone();
                tauri::async_runtime::spawn(async move {
                    #[cfg(windows)]
                    if commands::verify_active_gui().is_err() {
                        let state = app.state::<ProductionGateway>();
                        let _ = commands::shutdown_local_agent_for_exit(&state).await;
                        app.exit(0);
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
                            let state = app.state::<ProductionGateway>();
                            if commands::shutdown_local_agent_for_exit(&state)
                                .await
                                .is_ok()
                            {
                                app.exit(0);
                            } else {
                                show_main_window(&app);
                            }
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
