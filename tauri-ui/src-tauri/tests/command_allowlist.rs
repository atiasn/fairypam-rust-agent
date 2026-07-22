const APP: &str = include_str!("../src/app.rs");
const COMMANDS: &str = include_str!("../src/command_surface.rs");
const CAPABILITY: &str = include_str!("../capabilities/default.json");
const CARGO: &str = include_str!("../Cargo.toml");

#[test]
fn registered_build_and_capability_surfaces_match() {
    for command in [
        "get_overview",
        "get_connection_status",
        "run_environment_check",
        "get_log_tail",
        "scan_installed_games",
        "register_hub",
        "ensure_local_agent",
    ] {
        assert!(
            COMMANDS.contains(command),
            "missing command surface entry: {command}"
        );
        assert!(
            APP.contains(&format!("commands::{command}")),
            "missing handler: {command}"
        );
        assert!(
            CAPABILITY.contains(&format!("allow-{}", command.replace('_', "-"))),
            "missing capability: {command}"
        );
    }
}

#[test]
fn command_surface_has_no_generic_bridge_or_removed_runtime_controls() {
    let source = include_str!("../src/commands.rs");
    for forbidden in [
        "fn invoke",
        "fn exec",
        "fn spawn",
        "fn read_file",
        "serde_json::Value",
        "lock_target",
        "stop_capture",
        "release_all",
        "agentctl.exe",
        "fairypam_agentctl",
        "schtasks",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden command surface: {forbidden}"
        );
    }
}

#[test]
fn product_gui_has_only_the_fixed_agent_uac_recovery_path() {
    let source = include_str!("../src/commands.rs");
    for required in [
        "ShellExecuteW",
        "fixed_agent_path",
        "fairypam-agent.exe",
        "HSTRING::new()",
        "SW_HIDE",
        "error.code == \"local.transport.pipe_not_found\"",
        "status: \"agent_ready\".into()",
        "status: \"hub_wait_timeout\".into()",
        "status.recovery_code == \"runtime.not_registered\"",
        "HUB_OBSERVATION_LIMIT",
    ] {
        assert!(
            source.contains(required),
            "missing fixed startup guard: {required}"
        );
    }
    for forbidden in [
        "fairypam_agentctl",
        "start_fixed_agent_task",
        "run_elevated_enrollment",
        "get_enrollment_mode",
        "start_enrollment",
        "complete_enrollment",
        "schtasks",
        "SW_SHOWNORMAL",
    ] {
        assert!(
            !source.contains(forbidden),
            "product startup must not use developer enrollment path: {forbidden}"
        );
    }
    assert!(!APP.contains("run_elevated_enrollment"));
    assert!(!CARGO.contains("fairypam-agentctl"));
    assert!(!source.contains("RegistrationResult"));
}
