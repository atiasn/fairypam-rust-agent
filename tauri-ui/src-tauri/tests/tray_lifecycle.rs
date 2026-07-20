const APP: &str = include_str!("../src/app.rs");

#[test]
fn tray_lifecycle_never_stops_the_agent_while_closing_or_exiting_the_ui() {
    assert!(APP.contains("api.prevent_close()"));
    assert!(APP.contains("window.hide()"));
    assert!(APP.contains("\"exit-ui\" => app.exit(0)"));
    assert!(APP.contains("\"show-main\" | \"stop-agent\" => show_main_window(app)"));
    assert!(!APP.contains("release_all"));
}
