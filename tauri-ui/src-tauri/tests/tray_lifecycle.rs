const APP: &str = include_str!("../src/app.rs");

#[test]
fn tray_lifecycle_hides_on_close_and_requests_bound_agent_shutdown_on_exit() {
    let lifecycle = APP
        .split(".on_window_event")
        .nth(1)
        .and_then(|section| section.split(".run(").next())
        .expect("app must define the close-to-tray lifecycle handler");

    assert!(lifecycle.contains("api.prevent_close()"));
    assert!(lifecycle.contains("window.hide()"));
    assert!(!lifecycle.contains("release_all"));
    assert!(APP.contains("\"exit-ui\" => shutdown_bound_agent_then_exit(app)"));
    assert!(APP.contains("gateway.shutdown_bound_agent().await"));
    assert!(APP.contains("tokio::time::sleep(SHUTDOWN_GRACE).await"));
    assert!(APP.contains("\"show-main\" => show_main_window(app)"));
    assert!(!APP.contains("stop-agent"));
    assert!(APP.contains("show_menu_on_left_click(false)"));
    assert!(APP.contains("TrayIconEvent::Click"));
    assert!(APP.contains("button: MouseButton::Left"));
    assert!(APP.contains("button_state: MouseButtonState::Up"));
    assert!(APP.contains("show_main_window(tray.app_handle())"));
}
