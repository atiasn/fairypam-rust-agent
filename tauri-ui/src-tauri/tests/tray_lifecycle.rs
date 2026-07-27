const APP: &str = include_str!("../src/app.rs");
const AGENT_LIFECYCLE: &str = include_str!("../../../bins/fairypam-agent/src/gui_lifecycle.rs");
const WINDOWS_IDENTITY: &str =
    include_str!("../../../crates/fairypam-agent-windows/src/local_pipe.rs");

#[test]
fn window_close_keeps_the_process_alive_and_process_exit_stops_the_bound_agent() {
    let lifecycle = APP
        .split(".on_window_event")
        .nth(1)
        .and_then(|section| section.split(".run(").next())
        .expect("app must define the close-to-tray lifecycle handler");

    assert!(lifecycle.contains("api.prevent_close()"));
    assert!(lifecycle.contains("window.hide()"));
    assert!(!lifecycle.contains("release_all"));
    let shutdown = APP
        .find("shutdown_local_agent_for_exit")
        .expect("tray exit must request Agent cleanup");
    let exit = APP
        .find("app.exit(0)")
        .expect("tray exit must close the GUI");
    assert!(shutdown < exit);
    assert!(WINDOWS_IDENTITY.contains("PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE"));
    assert!(AGENT_LIFECYCLE.contains("watch_verified_process"));
    assert!(AGENT_LIFECYCLE.contains("shutdown.cancel()"));
    assert!(APP.contains("show_main_window(&app)"));
    assert!(APP.contains("\"show-main\" => show_main_window(app)"));
    assert!(!APP.contains("stop-agent"));
    assert!(APP.contains("show_menu_on_left_click(false)"));
    assert!(APP.contains("TrayIconEvent::Click"));
    assert!(APP.contains("button: MouseButton::Left"));
    assert!(APP.contains("button_state: MouseButtonState::Up"));
    assert!(APP.contains("show_main_window(tray.app_handle())"));
}
