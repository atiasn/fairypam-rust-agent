#![cfg(feature = "dev-automation")]

use fairypam_agent_local_protocol::LocalCommand;
use fairypam_agentctl::{dev_registration_code, parse_command};

#[test]
fn dev_cli_exposes_only_the_fixed_testbed_pulse() {
    let arguments = ["testbed", "pulse"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert_eq!(
        parse_command(&arguments).unwrap(),
        LocalCommand::TestbedPulse
    );
}

#[test]
fn dev_registration_code_accepts_one_bounded_stdin_line() {
    assert_eq!(
        dev_registration_code(b"0123456789abcdef\r\n").unwrap(),
        "0123456789abcdef"
    );
    assert!(dev_registration_code(b"first\nsecond").is_err());
    assert!(dev_registration_code(&vec![b'a'; 257]).is_err());
}

#[test]
fn dev_registration_is_isolated_from_product_command_parsing() {
    let source = include_str!("../src/main.rs");
    assert!(source.contains("operation == \"register\""));
    assert!(source.contains("read_until(b'\\n', &mut line)"));
    assert!(source.contains("execute_dev(LocalCommand::RegisterHub"));
    assert!(source.contains("LocalCommand::GetConnectionStatus"));
    assert!(!source.contains("--code"));
}
