const APP: &str = include_str!("../src/app.rs");
const COMMANDS: &str = include_str!("../src/commands.rs");
const GATEWAY: &str = include_str!("../src/local_gateway.rs");
const SINGLE_INSTANCE: &str = include_str!("../src/gui_single_instance.rs");
const AGENT_RUNTIME: &str = include_str!("../../../bins/fairypam-agent/src/runtime.rs");

#[test]
fn resident_agent_is_not_bound_to_or_stopped_with_the_gui() {
    assert!(!COMMANDS.contains("bind_ui_lifetime"));
    assert!(!GATEWAY.contains("LocalCommand::BindUiLifetime"));
    assert!(!GATEWAY.contains("LocalCommand::ShutdownAgent"));
    assert!(!GATEWAY.contains("ui_lifetime_bound"));
    assert!(!APP.contains("shutdown_bound_agent_then_exit"));
    assert!(!APP.contains("SHUTDOWN_GRACE"));
    assert!(APP.contains("\"exit-ui\" => app.exit(0)"));
}

#[test]
fn missing_pipe_runs_only_the_fixed_task_without_agent_uac() {
    let pipe_not_found = COMMANDS
        .find("Err(error) if error.code == \"local.transport.pipe_not_found\" => {")
        .expect("startup must keep the exact pipe-not-found branch");
    let launch = COMMANDS
        .find("run_fixed_helper(\"--run-agent-task\")?")
        .expect("startup must invoke the fixed Agent task");

    assert!(pipe_not_found < launch);
    assert!(COMMANDS.contains("fairypam-agent-installer.exe"));
    assert!(COMMANDS.contains("std::process::Command::new"));
    assert!(!COMMANDS.contains("fixed_agent_path"));
}

#[test]
fn restart_is_task_owned_and_only_repair_elevates_the_fixed_helper() {
    assert!(COMMANDS.contains("run_fixed_helper(\"--restart-agent-task\")"));
    assert!(COMMANDS.contains("run_repair_helper"));
    assert!(COMMANDS.contains("\"--repair-tasks\""));
    assert!(COMMANDS.contains("ShellExecuteExW"));
    assert!(COMMANDS.contains("SEE_MASK_NOCLOSEPROCESS"));
    assert!(COMMANDS.contains("HSTRING::from(\"runas\")"));
    assert!(COMMANDS.contains("\"startup.agent_repair_required\""));
    assert!(!COMMANDS.contains("fairypam-agent.exe"));
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
fn agent_single_instance_is_device_wide_and_acquired_before_runtime_side_effects() {
    assert!(AGENT_RUNTIME.contains(r#"r"Global\FairyPam.Agent.v1""#));
    let acquire = AGENT_RUNTIME
        .find("let _instance = AgentInstance::acquire()")
        .expect("Agent must acquire its instance lock");
    let driver = AGENT_RUNTIME
        .find("let driver = GrpcSessionDriver::new(config)")
        .expect("Agent runtime must create its driver");
    assert!(acquire < driver);
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
        assert!(
            APP.contains(required),
            "missing WebView hardening: {required}"
        );
    }
}
