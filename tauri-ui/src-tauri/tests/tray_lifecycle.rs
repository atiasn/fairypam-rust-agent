const APP: &str = include_str!("../src/app.rs");
const AGENT_RUNTIME: &str = include_str!("../../../bins/fairypam-agent/src/runtime.rs");

#[test]
fn close_to_tray_keeps_runtime_alive_and_explicit_exit_cleans_up() {
    let lifecycle = APP
        .split(".on_window_event")
        .nth(1)
        .and_then(|section| section.split(".run(").next())
        .expect("app must define close-to-tray behavior");
    assert!(lifecycle.contains("api.prevent_close()"));
    assert!(lifecycle.contains("window.hide()"));

    let shutdown = APP.find("shutdown_local_agent_for_exit").unwrap();
    let exit = APP.find("app.exit(0)").unwrap();
    assert!(shutdown < exit);
    assert!(AGENT_RUNTIME.contains("shutdown_embedded"));
    assert!(AGENT_RUNTIME.contains("supervisor.handle_control_failure()?"));
}
