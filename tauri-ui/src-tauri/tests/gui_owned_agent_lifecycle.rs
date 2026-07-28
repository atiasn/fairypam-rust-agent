const APP: &str = include_str!("../src/app.rs");
const COMMANDS: &str = include_str!("../src/commands.rs");
const GATEWAY: &str = include_str!("../src/local_gateway.rs");
const SINGLE_INSTANCE: &str = include_str!("../src/gui_single_instance.rs");
const AGENT_RUNTIME: &str = include_str!("../../../bins/fairypam-agent/src/runtime.rs");
const TAURI_CONFIG: &str = include_str!("../tauri.conf.json");

#[test]
fn gui_owns_one_in_process_runtime_without_a_sibling_or_broker() {
    assert!(APP.contains("runtime::start_embedded"));
    assert!(APP.contains("ProductionGateway::new(runtime)"));
    assert!(APP.contains("runtime_task.await"));
    assert!(GATEWAY.contains("EmbeddedRuntimeHandle"));
    assert!(GATEWAY.contains("runtime.execute(&command)"));
    assert!(AGENT_RUNTIME.contains("pub fn start_embedded"));
    assert!(AGENT_RUNTIME.contains("run_embedded_driver(driver).await"));
    for forbidden in [
        "ShellExecuteExW",
        "--ui-owner-pid",
        "foreground_broker",
        "WindowsNamedPipeClientTransport",
    ] {
        assert!(!COMMANDS.contains(forbidden));
        assert!(!GATEWAY.contains(forbidden));
    }
    assert!(!TAURI_CONFIG.contains("fairypam-agent.exe"));
}

#[test]
fn embedded_runtime_is_acquired_before_the_session_driver_runs() {
    let embedded = AGENT_RUNTIME
        .split("pub fn start_embedded")
        .nth(1)
        .expect("embedded runtime entrypoint must exist");
    let acquire = embedded
        .find("let instance = AgentInstance::acquire()")
        .expect("embedded runtime must acquire the unique instance");
    let driver = embedded
        .find("let driver = GrpcSessionDriver::new(config)")
        .expect("embedded runtime must create the shared driver");
    assert!(acquire < driver);
    assert!(AGENT_RUNTIME.contains("struct AgentInstance(usize);"));
    assert!(!AGENT_RUNTIME.contains("unsafe impl Send for AgentInstance"));
    assert!(AGENT_RUNTIME.contains("RuntimeOwner::EmbeddedGui"));
    assert!(AGENT_RUNTIME.contains("local.embedded_command_not_allowed"));
}

#[test]
fn second_gui_instance_only_activates_the_current_primary() {
    assert!(APP.contains("GuiSingleInstance::acquire"));
    assert!(APP.contains("activate_existing"));
    assert!(SINGLE_INSTANCE.contains("CreateMutexW"));
    assert!(SINGLE_INSTANCE.contains("ERROR_ALREADY_EXISTS"));
    assert!(APP.contains("watch_activation"));
    assert!(APP.contains("commands::verify_active_gui()"));
}

#[test]
fn production_webview_rejects_extra_navigation_and_page_surfaces() {
    for required in [
        "window.drag_drop_enabled = false",
        "on_navigation",
        "NewWindowResponse::Deny",
        "SetAreDefaultContextMenusEnabled(false)",
        ".incognito(true)",
        ".additional_browser_args(WEBVIEW_BROWSER_ARGS)",
        "clear_all_browsing_data()",
        "window.destroy()",
    ] {
        assert!(
            APP.contains(required),
            "missing WebView hardening: {required}"
        );
    }
}
