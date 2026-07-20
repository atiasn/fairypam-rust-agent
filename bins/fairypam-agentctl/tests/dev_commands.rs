#![cfg(feature = "dev-automation")]

use fairypam_agent_local_protocol::LocalCommand;
use fairypam_agentctl::parse_command;

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
