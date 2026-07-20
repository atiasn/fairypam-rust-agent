const APP: &str = include_str!("../src/app.rs");
const COMMANDS: &str = include_str!("../src/command_surface.rs");
const CAPABILITY: &str = include_str!("../capabilities/default.json");
const ENROLLMENT: &str = include_str!("../../../bins/fairypam-agentctl/src/enrollment.rs");

#[test]
fn registered_build_and_capability_surfaces_match() {
    for command in [
        "get_overview",
        "get_connection_status",
        "run_environment_check",
        "get_log_tail",
        "scan_installed_games",
        "get_enrollment_mode",
        "start_enrollment",
        "complete_enrollment",
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
fn elevated_enrollment_window_exposes_only_enrollment_commands() {
    let elevated = APP
        .split("fn run_elevated_enrollment")
        .nth(1)
        .and_then(|section| section.split("fn run_standard").next())
        .expect("app must define the elevated enrollment window");

    for command in ["get_enrollment_mode", "complete_enrollment"] {
        assert!(
            elevated.contains(&format!("commands::{command}")),
            "elevated window missing required command: {command}"
        );
    }
    for command in [
        "get_overview",
        "get_connection_status",
        "run_environment_check",
        "get_log_tail",
        "scan_installed_games",
        "start_enrollment",
        "ensure_local_agent",
    ] {
        assert!(
            !elevated.contains(&format!("commands::{command}")),
            "elevated window must not expose regular command: {command}"
        );
    }
    for forbidden in ["ProductionGateway", "TrayIconBuilder", ".on_window_event"] {
        assert!(
            !elevated.contains(forbidden),
            "elevated window must not configure: {forbidden}"
        );
    }
    assert!(
        ENROLLMENT.contains("current_process_is_elevated().unwrap_or(false)"),
        "elevated helper selection must fail closed when token verification fails"
    );
    assert!(
        APP.contains("is_elevated_ui_invocation"),
        "app must select the helper builder through the elevated-token check"
    );
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
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden command surface: {forbidden}"
        );
    }
}

#[test]
fn elevated_helper_exposes_only_the_registration_surface() {
    let helper = APP
        .split("fn run_elevated_enrollment()")
        .nth(1)
        .and_then(|source| source.split("fn run_standard()").next())
        .expect("elevated enrollment builder must be isolated from the standard builder");

    for required in [
        "commands::get_enrollment_mode",
        "commands::complete_enrollment",
    ] {
        assert!(
            helper.contains(required),
            "missing elevated helper command: {required}"
        );
    }
    for forbidden in [
        "ProductionGateway",
        "get_overview",
        "get_connection_status",
        "run_environment_check",
        "get_log_tail",
        "scan_installed_games",
        "start_enrollment",
        "ensure_local_agent",
        "TrayIconBuilder",
        "on_window_event",
    ] {
        assert!(
            !helper.contains(forbidden),
            "elevated helper exposes ordinary UI capability: {forbidden}"
        );
    }
}
