const APP: &str = include_str!("../src/app.rs");

#[test]
fn tray_lifecycle_never_stops_the_agent_while_closing_or_exiting_the_ui() {
    let lifecycle = APP
        .split(".on_window_event")
        .nth(1)
        .and_then(|section| section.split(".run(").next())
        .expect("app must define the close-to-tray lifecycle handler");

    assert!(lifecycle.contains("api.prevent_close()"));
    assert!(lifecycle.contains("window.hide()"));
    assert!(!lifecycle.contains("release_all"));
    assert!(APP.contains("\"exit-ui\" => app.exit(0)"));
    assert!(APP.contains("\"show-main\" | \"stop-agent\" => show_main_window(app)"));
    assert!(APP.contains("TrayIconEvent::DoubleClick"));
    assert!(APP.contains("button: MouseButton::Left"));
    assert!(APP.contains("show_main_window(tray.app_handle())"));
}
