#![cfg(feature = "dev-automation")]

use fairypam_agent_local_protocol::{
    decode_request, encode_frame, LocalCommand, RequestEnvelope, PROTOCOL_VERSION,
};

#[test]
fn dev_feature_accepts_only_the_fixed_testbed_pulse_command() {
    let request = RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: "dev-testbed-pulse".to_owned(),
        nonce: [3; 32],
        command: LocalCommand::TestbedPulse,
    };

    assert_eq!(
        decode_request(&encode_frame(&request).unwrap()).unwrap(),
        request
    );
}
