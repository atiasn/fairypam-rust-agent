use fairypam_agent_local_protocol::{
    decode_request, decode_request_or_error_response, decode_response, encode_frame,
    CaptureEncoding, LocalCommand, LocalResponse, LogLevel, NonceReplayGuard, RequestEnvelope,
    ResponseEnvelope, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use serde_json::json;

fn valid_request(command: LocalCommand) -> RequestEnvelope {
    RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: "request-1".to_owned(),
        nonce: [7; 32],
        command,
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = (payload.len() as u32).to_le_bytes().to_vec();
    framed.extend_from_slice(payload);
    framed
}

#[test]
fn round_trips_all_supported_command_shapes() {
    let commands = [
        LocalCommand::Status,
        LocalCommand::Doctor,
        LocalCommand::ListProfiles,
        LocalCommand::EnumerateTargets {
            profile_id: "profile".to_owned(),
        },
        LocalCommand::LockTarget {
            profile_id: "profile".to_owned(),
            candidate_id: "candidate".to_owned(),
        },
        LocalCommand::FocusTarget,
        LocalCommand::StartCapture {
            source_id: "source".to_owned(),
            fps: 30,
            encoding: CaptureEncoding::Jpeg { quality: 85 },
        },
        LocalCommand::StartCapture {
            source_id: "source".to_owned(),
            fps: 30,
            encoding: CaptureEncoding::Png,
        },
        LocalCommand::StopCapture {
            source_id: "source".to_owned(),
        },
        LocalCommand::ReleaseAll,
        LocalCommand::ResetEmergencyStop,
        LocalCommand::UpdateStatus,
        LocalCommand::StartupStatus,
        LocalCommand::GetConnectionStatus,
        LocalCommand::RunEnvironmentCheck,
        LocalCommand::GetLogTail {
            lines: 20,
            level: LogLevel::Info,
        },
        LocalCommand::ScanInstalledGames,
        LocalCommand::BindUiLifetime,
        LocalCommand::ShutdownAgent,
        LocalCommand::RegisterHub {
            hub_address: "https://hub.example".to_owned(),
            registration_code: "0123456789abcdef".to_owned(),
        },
    ];

    for command in commands {
        let request = valid_request(command);
        assert_eq!(
            decode_request(&encode_frame(&request).unwrap()).unwrap(),
            request
        );
    }
}

#[test]
fn observability_commands_are_bounded_and_reject_path_or_secret_fields() {
    let invalid_lines = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"get_log_tail","lines":201,"level":"info"}"#,
    );
    assert_eq!(
        decode_request(&invalid_lines).unwrap_err().code(),
        "local.protocol.invalid"
    );

    let arbitrary_path = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"get_log_tail","lines":20,"level":"info","path":"C:\\secrets\\agent.log"}"#,
    );
    assert_eq!(
        decode_request(&arbitrary_path).unwrap_err().code(),
        "local.protocol.invalid"
    );
}

#[test]
fn registration_is_strictly_bounded_and_rejects_secret_extensions() {
    let enrollment = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"enroll_hub","hub_address":"https://hub.example","code":"one-time-code"}"#,
    );
    assert_eq!(
        decode_request(&enrollment).unwrap_err().code(),
        "local.protocol.unsupported_capability"
    );

    let valid = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"register_hub","hub_address":"https://hub.example","registration_code":"0123456789abcdef"}"#,
    );
    assert!(decode_request(&valid).is_ok());

    let non_https = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"register_hub","hub_address":"http://hub.example","registration_code":"0123456789abcdef"}"#,
    );
    let error = decode_request(&non_https).unwrap_err();
    assert_eq!(error.code(), "local.protocol.invalid");
    assert!(!error.to_string().contains("http://hub.example"));
    assert!(!error.to_string().contains("0123456789abcdef"));

    for invalid in [
        LocalCommand::RegisterHub {
            hub_address: format!("https://{}.example", "a".repeat(2_048)),
            registration_code: "0123456789abcdef".to_owned(),
        },
        LocalCommand::RegisterHub {
            hub_address: "https://hub.example?redirect=https://other.example".to_owned(),
            registration_code: "0123456789abcdef".to_owned(),
        },
        LocalCommand::RegisterHub {
            hub_address: "https://hub.example".to_owned(),
            registration_code: "01234567 9abcdef".to_owned(),
        },
        LocalCommand::RegisterHub {
            hub_address: "https://hub.example:0".to_owned(),
            registration_code: "0123456789abcdef".to_owned(),
        },
        LocalCommand::RegisterHub {
            hub_address: "https://hub.example:99999".to_owned(),
            registration_code: "0123456789abcdef".to_owned(),
        },
    ] {
        assert_eq!(
            decode_request(&encode_frame(&valid_request(invalid)).unwrap())
                .unwrap_err()
                .code(),
            "local.protocol.invalid"
        );
    }

    let secret_extension = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"register_hub","hub_address":"https://hub.example","registration_code":"0123456789abcdef","client_key":"must-not-be-accepted"}"#,
    );
    assert_eq!(
        decode_request(&secret_extension).unwrap_err().code(),
        "local.protocol.invalid"
    );
}

#[test]
fn rejects_version_unknown_field_unknown_command_and_malformed_json() {
    let unsupported_version = frame(
        br#"{"protocol_version":2,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"status"}"#,
    );
    assert_eq!(
        decode_request(&unsupported_version).unwrap_err().code(),
        "local.protocol.unsupported_version"
    );

    let unknown_field = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"status","extra":true}"#,
    );
    assert_eq!(
        decode_request(&unknown_field).unwrap_err().code(),
        "local.protocol.invalid"
    );

    let duplicate_key = frame(
        br#"{"protocol_version":1,"protocol_version":2,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"status"}"#,
    );
    assert_eq!(
        decode_request(&duplicate_key).unwrap_err().code(),
        "local.protocol.invalid"
    );

    let unknown_command = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"dev_run"}"#,
    );
    assert_eq!(
        decode_request(&unknown_command).unwrap_err().code(),
        "local.protocol.unsupported_capability"
    );

    let dev_testbed_command = frame(
        br#"{"protocol_version":1,"request_id":"r","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"testbed_pulse"}"#,
    );
    assert_eq!(
        decode_request(&dev_testbed_command).unwrap_err().code(),
        "local.protocol.unsupported_capability"
    );

    assert_eq!(
        decode_request(&frame(br#"{"protocol_version":1"#))
            .unwrap_err()
            .code(),
        "local.protocol.invalid"
    );
}

#[test]
fn turns_an_unknown_dev_message_into_a_correlated_protocol_response() {
    let message = frame(
        br#"{"protocol_version":1,"request_id":"production-dev-message","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"command":"dev.create_live_game_arm"}"#,
    );

    let response = decode_request_or_error_response(&message).unwrap_err();
    assert_eq!(response.request_id, "production-dev-message");
    assert_eq!(
        response.result.unwrap_err().code,
        "local.protocol.unsupported_capability"
    );
}

#[test]
fn rejects_replayed_nonce_and_frames_outside_the_64_kib_boundary() {
    let request = valid_request(LocalCommand::Status);
    let mut replay = NonceReplayGuard::new(8);
    replay.accept(request.nonce).unwrap();
    assert_eq!(
        replay.accept(request.nonce).unwrap_err().code(),
        "local.protocol.nonce_replayed"
    );

    let exact_limit = encode_frame(&"x".repeat(MAX_FRAME_BYTES - 2)).unwrap();
    assert_eq!(exact_limit.len(), MAX_FRAME_BYTES + 4);
    assert_eq!(
        decode_request(&exact_limit).unwrap_err().code(),
        "local.protocol.invalid"
    );
    assert_eq!(
        encode_frame(&"x".repeat(MAX_FRAME_BYTES - 1))
            .unwrap_err()
            .code(),
        "local.protocol.frame_too_large"
    );
    assert_eq!(
        decode_request(&vec![0; MAX_FRAME_BYTES + 5])
            .unwrap_err()
            .code(),
        "local.protocol.frame_too_large"
    );
}

#[test]
fn response_decoder_reuses_strict_framing_and_duplicate_key_rejection() {
    let response = ResponseEnvelope {
        request_id: "request-1".to_owned(),
        result: Ok(LocalResponse {
            body: json!({"status":"ready"}),
        }),
    };
    assert_eq!(
        decode_response(&encode_frame(&response).unwrap()).unwrap(),
        response
    );

    assert_eq!(
        decode_response(&frame(
            br#"{"request_id":"request-1","request_id":"request-2","result":{"Ok":{"body":{}}}}"#,
        ))
        .unwrap_err()
        .code(),
        "local.protocol.invalid"
    );
}
