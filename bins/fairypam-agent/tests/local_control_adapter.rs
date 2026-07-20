use fairypam_agent::{
    local_control::{AuditEvent, AuditSink, LocalControlAdapter, LocalControlRuntime},
    production_authorization,
};
use fairypam_agent_core::AgentError;
use fairypam_agent_local_protocol::{LocalCommand, RequestEnvelope, PROTOCOL_VERSION};
use fairypam_agent_windows::{IntegrityLevel, PipeOwner, VerifiedPipeCaller};
use serde_json::{json, Value};

#[derive(Default)]
struct FakeRuntime {
    calls: usize,
    released: usize,
}

impl LocalControlRuntime for FakeRuntime {
    fn execute(&mut self, command: &LocalCommand) -> Result<Value, AgentError> {
        self.calls += 1;
        if matches!(command, LocalCommand::ReleaseAll) {
            self.released += 1;
        }
        Ok(json!({"authorization":"deny_all"}))
    }
}

#[derive(Default)]
struct MemoryAudit(Vec<AuditEvent>);

impl AuditSink for MemoryAudit {
    fn record(&mut self, event: AuditEvent) {
        self.0.push(event);
    }
}

fn owner() -> PipeOwner {
    PipeOwner {
        user_sid: "S-1-5-21-owner".to_owned(),
        logon_sid: "S-1-5-5-owner".to_owned(),
        session_id: 1,
        minimum_integrity: IntegrityLevel::Medium,
    }
}

fn caller() -> VerifiedPipeCaller {
    VerifiedPipeCaller {
        pid: 7,
        user_sid: "S-1-5-21-owner".to_owned(),
        logon_sid: "S-1-5-5-owner".to_owned(),
        session_id: 1,
        integrity: IntegrityLevel::Medium,
    }
}

fn request(command: LocalCommand, nonce: u8) -> RequestEnvelope {
    RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: format!("request-{nonce}"),
        nonce: [nonce; 32],
        command,
    }
}

#[test]
fn rejects_mismatched_identity_before_runtime_dispatch() {
    let mut adapter = LocalControlAdapter::new(
        owner(),
        FakeRuntime::default(),
        MemoryAudit::default(),
        "build-1",
    );
    for caller in [
        VerifiedPipeCaller {
            user_sid: "S-1-5-21-other".to_owned(),
            ..caller()
        },
        VerifiedPipeCaller {
            logon_sid: "S-1-5-5-other".to_owned(),
            ..caller()
        },
        VerifiedPipeCaller {
            session_id: 2,
            ..caller()
        },
        VerifiedPipeCaller {
            integrity: IntegrityLevel::Low,
            ..caller()
        },
    ] {
        assert!(adapter
            .handle(
                &caller,
                request(LocalCommand::Status, caller.session_id as u8)
            )
            .is_err());
    }
    let (runtime, audit) = adapter.into_parts();
    assert_eq!(runtime.calls, 0);
    assert!(audit.0.is_empty());
}

#[test]
fn release_all_records_redacted_mutation_audit() {
    let mut adapter = LocalControlAdapter::new(
        owner(),
        FakeRuntime::default(),
        MemoryAudit::default(),
        "build-1",
    );
    let response = adapter
        .handle(&caller(), request(LocalCommand::ReleaseAll, 1))
        .unwrap();
    assert!(response.result.is_ok());

    let (runtime, audit) = adapter.into_parts();
    assert_eq!(runtime.released, 1);
    assert_eq!(audit.0[0].command, "release_all");
    assert_eq!(audit.0[0].result_code, "ok");
    assert!(!audit.0[0].to_json().contains("private_key"));
    assert_ne!(audit.0[0].caller_sid_hash, "S-1-5-21-owner");
}

#[test]
fn production_authorization_remains_deny_all() {
    assert!(matches!(
        production_authorization(),
        fairypam_agent_core::platform::DenyAllAuthorization
    ));
}
