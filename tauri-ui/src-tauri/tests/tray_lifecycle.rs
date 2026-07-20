const APP: &str = include_str!("../src/app.rs");

#[test]
fn tray_lifecycle_never_stops_the_agent_while_closing_or_exiting_the_ui() {
    let standard = APP
        .split("fn run_standard")
        .nth(1)
        .expect("app must define the standard window");
    let lifecycle = standard
        .split(".on_window_event")
        .nth(1)
        .and_then(|section| section.split(".run(").next())
        .expect("app must define the close-to-tray lifecycle handler");

    assert!(lifecycle.contains("api.prevent_close()"));
    assert!(lifecycle.contains("window.hide()"));
    assert!(!lifecycle.contains("release_all"));
    assert!(standard.contains("\"exit-ui\" => app.exit(0)"));
    assert!(standard.contains("\"show-main\" => show_main_window(app)"));
    assert!(!standard.contains("stop-agent"));
    assert!(standard.contains("show_menu_on_left_click(false)"));
    assert!(standard.contains("TrayIconEvent::Click"));
    assert!(standard.contains("button: MouseButton::Left"));
    assert!(standard.contains("button_state: MouseButtonState::Up"));
    assert!(standard.contains("show_main_window(tray.app_handle())"));
}
