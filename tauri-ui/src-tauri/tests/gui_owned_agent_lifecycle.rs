const APP: &str = include_str!("../src/app.rs");
const COMMANDS: &str = include_str!("../src/commands.rs");
const GATEWAY: &str = include_str!("../src/local_gateway.rs");
const SINGLE_INSTANCE: &str = include_str!("../src/gui_single_instance.rs");

#[test]
fn primary_gui_binds_the_agent_and_tray_exit_only_shuts_down_that_binding() {
    assert!(COMMANDS.contains("bind_ui_lifetime"));
    assert!(GATEWAY.contains("LocalCommand::BindUiLifetime"));
    assert!(GATEWAY.contains("LocalCommand::ShutdownAgent"));
    assert!(GATEWAY.contains("ui_lifetime_bound"));
    assert!(APP.contains("shutdown_bound_agent_then_exit"));
    assert!(APP.contains("SHUTDOWN_GRACE"));
    assert!(!APP.contains("\"exit-ui\" => app.exit(0)"));
}

#[test]
fn restart_after_exact_pipe_not_found_clears_the_cached_binding_before_uac() {
    let pipe_not_found = COMMANDS
        .find("Err(error) if error.code == \"local.transport.pipe_not_found\" => {")
        .expect("startup must keep the exact pipe-not-found branch");
    let clear_binding = COMMANDS
        .find("state.clear_ui_lifetime_binding()")
        .expect("a restarted Agent must invalidate the prior GUI binding");
    let launch = COMMANDS
        .find("launch_fixed_agent()?")
        .expect("the fixed UAC launch must remain present");

    assert!(pipe_not_found < clear_binding && clear_binding < launch);
    assert!(GATEWAY.contains("fn clear_ui_lifetime_binding(&self)"));
}

#[test]
fn second_gui_instance_only_activates_the_primary_window() {
    assert!(APP.contains("GuiSingleInstance::acquire"));
    assert!(APP.contains("activate_existing"));
    assert!(SINGLE_INSTANCE.contains("CreateMutexW"));
    assert!(SINGLE_INSTANCE.contains("ERROR_ALREADY_EXISTS"));
    assert!(SINGLE_INSTANCE.contains("FindWindowW"));
    assert!(SINGLE_INSTANCE.contains("SetForegroundWindow"));
}

#[test]
fn production_webview_rejects_extra_navigation_and_page_surfaces() {
    for required in [
        "config_mut",
        "window.create = false",
        "window.drag_drop_enabled = false",
        "WebviewWindowBuilder::from_config",
        "on_navigation",
        "NewWindowResponse::Deny",
        "SetAreDefaultContextMenusEnabled(false)",
    ] {
        assert!(APP.contains(required), "missing WebView hardening: {required}");
    }
}
