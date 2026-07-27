const APP: &str = include_str!("../src/app.rs");
const COMMANDS: &str = include_str!("../src/commands.rs");
const GATEWAY: &str = include_str!("../src/local_gateway.rs");
const SINGLE_INSTANCE: &str = include_str!("../src/gui_single_instance.rs");
const AGENT_RUNTIME: &str = include_str!("../../../bins/fairypam-agent/src/runtime.rs");
const AGENT_MAIN: &str = include_str!("../../../bins/fairypam-agent/src/main.rs");
const GUI_LIFECYCLE: &str = include_str!("../../../bins/fairypam-agent/src/gui_lifecycle.rs");
const WINDOWS_PIPE: &str = include_str!("../../../crates/fairypam-agent-windows/src/local_pipe.rs");

#[test]
fn gui_binds_the_directly_launched_unique_agent() {
    assert!(COMMANDS.contains("--ui-owner-pid {}"));
    assert!(AGENT_MAIN.contains("RuntimeOwner::Gui"));
    assert!(AGENT_RUNTIME.contains("verify_fixed_gui_owner(pid)"));
    assert!(AGENT_RUNTIME.contains("verify_fixed_installer_parent()"));
    assert!(AGENT_RUNTIME.contains("driver.gui_lifetime.bind_verified(verified_gui)?"));
    assert!(AGENT_RUNTIME.contains("self.gui_lifetime.confirm_bound(caller.pid)?"));
    assert!(AGENT_RUNTIME.contains("self.gui_lifetime.request_shutdown(caller.pid)?"));
    assert!(AGENT_RUNTIME.contains("verify_fixed_installer_caller(caller)"));
    assert!(GUI_LIFECYCLE.contains("watch_verified_process"));
    assert!(!GUI_LIFECYCLE.contains("OpenProcess"));
    assert!(WINDOWS_PIPE.contains("PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE"));
    assert!(GATEWAY.contains("LocalCommand::ShutdownAgent"));
    let shutdown = APP
        .find("shutdown_local_agent_for_exit")
        .expect("tray exit must request Agent cleanup");
    let exit = APP
        .find("app.exit(0)")
        .expect("tray exit must close the GUI");
    assert!(shutdown < exit);
}

#[test]
fn new_gui_session_replaces_residual_agent_then_launches_fixed_sibling() {
    let stop = COMMANDS
        .find("stop_existing_agent(state).await?")
        .expect("startup must stop the residual Agent");
    let launch = COMMANDS
        .find("launch_fixed_agent()?")
        .expect("startup must launch the fixed Agent sibling");

    assert!(stop < launch);
    assert!(COMMANDS.contains("fairypam-agent-installer.exe"));
    assert!(COMMANDS.contains("fixed_agent_path"));
    assert!(COMMANDS.contains("resolve_active_suite(install_root)"));
    assert!(COMMANDS.contains("startup.inactive_suite"));
    assert!(AGENT_RUNTIME.contains("verify_active_agent_suite()?"));
    assert!(AGENT_RUNTIME.contains("runtime.inactive_suite"));
    assert!(COMMANDS.contains("ShellExecuteW"));
    assert!(COMMANDS.contains("HSTRING::from(\"runas\")"));
    assert!(COMMANDS.contains("--ui-owner-pid {}"));
    assert!(COMMANDS.contains("agent_instance_running()?"));
    assert!(COMMANDS.contains("OpenMutexW"));
    assert!(!COMMANDS.contains("CreateMutexW"));
    assert!(COMMANDS.contains(r#"Global\FairyPam.Agent.v1"#));
    assert!(COMMANDS.matches("state.acquire_lifecycle()?").count() >= 3);
}

#[test]
fn restart_is_gui_owned_and_repair_stays_on_the_fixed_helper() {
    assert!(COMMANDS.contains("replace_with_interactive_agent(&state).await"));
    assert!(COMMANDS.contains("run_repair_helper"));
    assert!(COMMANDS.contains("\"--repair-tasks\""));
    assert!(COMMANDS.contains("ShellExecuteExW"));
    assert!(COMMANDS.contains("SEE_MASK_NOCLOSEPROCESS"));
    assert!(COMMANDS.contains("HSTRING::from(\"runas\")"));
    assert!(COMMANDS.contains("fairypam-agent.exe"));
    assert!(!COMMANDS.contains("--restart-agent-task"));
    let repair = COMMANDS
        .find("run_repair_helper()?")
        .expect("repair must use the fixed helper");
    let stop = COMMANDS[..repair]
        .rfind("stop_existing_agent(&state).await?")
        .expect("repair must stop the direct Agent before task maintenance");
    assert!(stop < repair);
}

#[test]
fn second_gui_instance_activates_only_the_current_suite_primary() {
    assert!(APP.contains("GuiSingleInstance::acquire"));
    assert!(APP.contains("activate_existing"));
    assert!(SINGLE_INSTANCE.contains("CreateMutexW"));
    assert!(SINGLE_INSTANCE.contains("ERROR_ALREADY_EXISTS"));
    assert!(SINGLE_INSTANCE.contains("FindWindowW"));
    assert!(SINGLE_INSTANCE.contains("SetForegroundWindow"));
    assert!(SINGLE_INSTANCE.contains("SetEvent(activation)"));
    assert!(SINGLE_INSTANCE.contains("WaitForSingleObject"));
    assert!(APP.contains("watch_activation"));
    assert!(APP.contains("commands::verify_active_gui()"));
    assert!(APP.contains("shutdown_local_agent_for_exit"));
    assert!(APP.contains("local-agent-activation"));
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
    let bind = AGENT_RUNTIME
        .find("driver.gui_lifetime.bind_verified(verified_gui)?")
        .expect("Agent must bind the verified GUI before serving local control");
    let local_control = AGENT_RUNTIME
        .find("tokio::spawn(run_local_control")
        .expect("Agent must start local control");
    assert!(bind < local_control);
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
