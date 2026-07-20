use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, WindowEvent,
};

use crate::{commands, local_gateway::ProductionGateway};

pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .manage(ProductionGateway::new())
        .invoke_handler(tauri::generate_handler![
            commands::get_overview,
            commands::get_connection_status,
            commands::run_environment_check,
            commands::get_log_tail,
            commands::scan_installed_games,
            commands::register_hub,
            commands::ensure_local_agent,
        ])
        .setup(|app| {
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
                    "exit-ui" => app.exit(0),
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
        .run(tauri::generate_context!())
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}
