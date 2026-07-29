const APP: &str = include_str!("../src/app.rs");
const COMMAND_SURFACE: &str = include_str!("../src/command_surface.rs");
const COMMANDS: &str = include_str!("../src/commands.rs");
const CAPABILITY: &str = include_str!("../capabilities/default.json");
const GATEWAY: &str = include_str!("../src/local_gateway.rs");

#[test]
fn registered_build_and_capability_surfaces_match() {
    for command in [
        "get_overview",
        "get_connection_status",
        "run_environment_check",
        "get_log_tail",
        "scan_installed_games",
        "launch_game",
        "close_game",
        "capture_preview",
        "input_probe",
        "register_hub",
        "ensure_local_agent",
    ] {
        assert!(COMMAND_SURFACE.contains(command));
        assert!(APP.contains(&format!("commands::{command}")));
        assert!(CAPABILITY.contains(&format!("allow-{}", command.replace('_', "-"))));
    }
}

#[test]
fn renderer_has_only_fixed_device_control_bridge() {
    for forbidden in [
        "fn invoke",
        "fn exec",
        "fn spawn",
        "scan_code: u16",
        "button: i32",
        "fairypam_agentctl",
        "schtasks",
        "ShellExecuteExW",
    ] {
        assert!(
            !COMMANDS.contains(forbidden),
            "forbidden command surface: {forbidden}"
        );
    }
    assert!(GATEWAY.contains("EmbeddedRuntimeHandle"));
    assert!(!GATEWAY.contains("WindowsNamedPipeClientTransport"));
    assert!(COMMANDS.contains("\"move_forward\""));
    assert!(COMMANDS.contains("\"quick_use\""));
    assert!(COMMANDS.contains("\"mouse_left\""));
}
