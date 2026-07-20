use fairypam_agent_local_client::LocalClientError;
use fairypam_agent_local_protocol::LocalCommand;
use fairypam_agentctl::{
    is_fixed_elevated_ui_invocation, is_fixed_interactive_task_xml, parse_command,
    parse_enrollment_invocation, CliError, EnrollmentInvocation,
};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

#[test]
fn cli_uses_shared_domain_commands_and_rejects_process_or_input_arguments() {
    assert_eq!(
        parse_command(&arguments(&["status"])).unwrap(),
        LocalCommand::Status
    );
    assert_eq!(
        parse_command(&arguments(&["release-all"])).unwrap(),
        LocalCommand::ReleaseAll
    );
    assert_eq!(
        parse_command(&arguments(&["target", "lock", "--hwnd", "1"]))
            .unwrap_err()
            .exit_code(),
        2
    );
    assert_eq!(
        parse_command(&arguments(&["run", "cmd.exe"]))
            .unwrap_err()
            .exit_code(),
        2
    );
    assert_eq!(
        parse_command(&arguments(&[
            "enroll",
            "--hub",
            "https://hub.example",
            "--code",
            "one-time-code",
        ]))
        .unwrap_err()
        .exit_code(),
        2
    );
    #[cfg(not(feature = "dev-automation"))]
    assert_eq!(
        parse_command(&arguments(&["testbed", "pulse"]))
            .unwrap_err()
            .exit_code(),
        2
    );
    assert!(!include_str!("../Cargo.toml").contains("fairypam-agent-windows"));
}

#[test]
fn error_prefixes_have_stable_process_exit_codes() {
    assert_eq!(CliError::Usage("bad".to_owned()).exit_code(), 2);
    assert_eq!(
        CliError::Client(LocalClientError::identity("sid_mismatch")).exit_code(),
        3
    );
    assert_eq!(
        CliError::Client(LocalClientError::pipe_not_found()).exit_code(),
        4
    );
    assert_eq!(
        CliError::Client(LocalClientError::domain(
            fairypam_agent_local_protocol::LocalError {
                code: "local.domain.denied".to_owned(),
                message: "denied".to_owned(),
            }
        ))
        .exit_code(),
        5
    );
}

#[test]
fn enrollment_has_only_a_secret_free_uac_trigger() {
    assert_eq!(
        parse_enrollment_invocation(&arguments(&["enroll"])).unwrap(),
        Some(EnrollmentInvocation::LaunchElevatedHelper)
    );
    assert_eq!(
        parse_enrollment_invocation(&arguments(&["--enrollment-helper"])).unwrap(),
        Some(EnrollmentInvocation::ElevatedHelper)
    );
    assert_eq!(
        parse_enrollment_invocation(&arguments(&["enroll", "--code", "one-time-code"]))
            .unwrap_err()
            .exit_code(),
        2
    );
}

#[test]
fn elevated_gui_route_requires_the_fixed_argument_and_an_elevated_token() {
    assert!(is_fixed_elevated_ui_invocation(
        &arguments(&["--enrollment-helper"]),
        true,
    ));
    assert!(!is_fixed_elevated_ui_invocation(
        &arguments(&["--enrollment-helper"]),
        false,
    ));
    assert!(!is_fixed_elevated_ui_invocation(
        &arguments(&["--enrollment-helper", "--extra"]),
        true,
    ));
}

#[test]
fn production_task_accepts_only_the_fixed_interactive_agent_action() {
    let action = r"C:\FairyPam\fairypam-agent.exe";
    let fixed = r#"<Task><Triggers><LogonTrigger></LogonTrigger></Triggers><Principals><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principals><Actions><Exec><Command>C:\FairyPam\fairypam-agent.exe</Command></Exec></Actions></Task>"#;
    assert!(is_fixed_interactive_task_xml(fixed, action));
    assert!(!is_fixed_interactive_task_xml(
        &fixed.replace("</Exec>", "<Arguments>--bad</Arguments></Exec>"),
        action,
    ));
    assert!(!is_fixed_interactive_task_xml(
        &fixed.replace("fairypam-agent.exe", "cmd.exe"),
        action,
    ));
    assert!(!is_fixed_interactive_task_xml(
        &fixed.replace(
            "</Triggers>",
            "<BootTrigger></BootTrigger></Triggers>",
        ),
        action,
    ));
    assert!(!is_fixed_interactive_task_xml(
        &fixed.replace(
            "</Actions>",
            "<Exec><Command>C:\\Windows\\System32\\cmd.exe</Command></Exec></Actions>",
        ),
        action,
    ));
}
