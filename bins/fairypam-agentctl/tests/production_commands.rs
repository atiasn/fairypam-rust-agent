use fairypam_agent_local_client::LocalClientError;
use fairypam_agent_local_protocol::LocalCommand;
use fairypam_agentctl::{parse_command, CliError};

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
fn agentctl_has_no_product_enrollment_helper_or_agent_dependency() {
    let library = include_str!("../src/lib.rs");
    let main = include_str!("../src/main.rs");
    let manifest = include_str!("../Cargo.toml");

    for forbidden in ["parse_enrollment", "--enrollment-helper", "schtasks"] {
        assert!(!library.contains(forbidden));
        assert!(!main.contains(forbidden));
    }
    assert!(!manifest.contains("path = \"../fairypam-agent\""));
}
