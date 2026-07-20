const APP: &str = include_str!("../src/app.rs");
const COMMANDS: &str = include_str!("../src/command_surface.rs");
const CAPABILITY: &str = include_str!("../capabilities/default.json");

#[test]
fn registered_build_and_capability_surfaces_match() {
    for command in [
        "get_overview",
        "get_doctor",
        "list_profiles",
        "list_targets",
        "lock_target",
        "focus_target",
        "stop_capture",
        "release_all",
        "get_update_status",
        "get_startup_status",
        "get_connection_status",
        "run_environment_check",
        "get_log_tail",
        "scan_installed_games",
        "start_enrollment",
        "export_diagnostics",
        "stop_agent_after_confirmation",
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
fn command_surface_has_no_generic_bridge() {
    let source = include_str!("../src/commands.rs");
    for forbidden in [
        "fn invoke",
        "fn exec",
        "fn spawn",
        "fn read_file",
        "serde_json::Value",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden command surface: {forbidden}"
        );
    }
}
