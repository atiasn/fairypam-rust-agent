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
        if matches!(command, LocalCommand::RegisterHub { .. }) {
            return Ok(json!({"status": "pending"}));
        }
        Ok(json!({"authorization":"deny_all"}))
    }
}

#[derive(Default)]
struct MemoryAudit(Vec<AuditEvent>);

impl AuditSink for MemoryAudit {
    fn record(&mut self, event: AuditEvent) -> Result<(), AgentError> {
        self.0.push(event);
        Ok(())
    }
}

struct FailingAudit;

impl AuditSink for FailingAudit {
    fn record(&mut self, _event: AuditEvent) -> Result<(), AgentError> {
        Err(AgentError::new(
            "local.audit_failed",
            "local control mutation audit could not be persisted",
        ))
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
    assert_eq!(audit.0[0].result_code, "attempt");
    assert_eq!(audit.0[1].command, "release_all");
    assert_eq!(audit.0[1].result_code, "ok");
    assert!(!audit.0[1].to_json().contains("private_key"));
    assert_ne!(audit.0[1].caller_sid_hash, "S-1-5-21-owner");
}

#[test]
#[cfg(not(windows))]
fn registration_audit_and_response_never_echo_credentials() {
    let hub = "https://hub.example/private";
    let code = "fp_enroll_secret_0123456789";
    let mut adapter = LocalControlAdapter::new(
        owner(),
        FakeRuntime::default(),
        MemoryAudit::default(),
        "build-1",
    );

    let response = adapter
        .handle(
            &caller(),
            request(
                LocalCommand::RegisterHub {
                    hub_address: hub.to_owned(),
                    registration_code: code.to_owned(),
                },
                2,
            ),
        )
        .unwrap();
    let (_, audit) = adapter.into_parts();
    let evidence = format!("{} {response:?}", audit.0[1].to_json());

    assert_eq!(audit.0[0].result_code, "attempt");
    assert_eq!(audit.0[1].command, "register_hub");
    assert_eq!(audit.0[1].result_code, "pending");
    assert!(!evidence.contains(hub));
    assert!(!evidence.contains(code));
    assert!(!evidence.contains("certificate"));
    assert!(!evidence.contains("private_key"));
}

#[test]
fn mutation_is_not_dispatched_when_the_attempt_audit_cannot_be_persisted() {
    let mut adapter =
        LocalControlAdapter::new(owner(), FakeRuntime::default(), FailingAudit, "build-1");

    let response = adapter
        .handle(&caller(), request(LocalCommand::ReleaseAll, 8))
        .unwrap();
    let (runtime, _) = adapter.into_parts();

    assert_eq!(runtime.calls, 0);
    assert_eq!(response.result.unwrap_err().code, "local.audit_failed");
}

#[test]
fn replayed_registration_nonce_is_audited_without_redispatch() {
    let mut adapter = LocalControlAdapter::new(
        owner(),
        FakeRuntime::default(),
        MemoryAudit::default(),
        "build-1",
    );
    let command = LocalCommand::ReleaseAll;

    adapter
        .handle(&caller(), request(command.clone(), 9))
        .unwrap();
    let replay = adapter.handle(&caller(), request(command, 9)).unwrap();
    let (runtime, audit) = adapter.into_parts();

    assert_eq!(runtime.calls, 1);
    assert!(replay.result.is_err());
    assert_eq!(audit.0.last().unwrap().command, "release_all");
    assert_eq!(
        audit.0.last().unwrap().result_code,
        "local.protocol.nonce_replayed"
    );
}

#[test]
fn release_agent_uses_the_windows_gui_subsystem() {
    assert!(include_str!("../src/main.rs").contains(
        "cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = \"windows\")"
    ));
}

#[test]
fn production_authorization_remains_deny_all() {
    assert!(matches!(
        production_authorization(),
        fairypam_agent_core::platform::DenyAllAuthorization
    ));
}

#[test]
fn enrollment_source_keeps_claims_bounded_and_publishes_only_validated_candidates() {
    let source = include_str!("../src/enrollment.rs");
    assert!(source.contains("WinHttpSetTimeouts"));
    assert!(source.contains("set_remaining_timeouts(request, deadline)"));
    assert!(source.contains("ensure_success_status(request)"));
    assert!(source.contains("CLAIM_DEADLINE"));
    assert!(source.contains("CLAIM_OPERATION_TIMEOUT_MS"));
    assert!(source.contains("set_remaining_timeouts(request, deadline)"));
    assert!(source.contains("ensure_success_status(request)"));
    assert!(source.contains("crate::runtime::validate_enrollment_candidate(&root, &generation)"));
    assert!(
        source.find("validate_enrollment_candidate") < source.rfind("MoveFileExW("),
        "candidate validation must precede pointer publication"
    );
    assert!(source.contains("fs::remove_dir_all(&directory)"));
    assert!(!source.contains("current.json.previous"));
}

#[test]
fn production_audit_source_uses_restricted_storage_and_real_jsonl_newlines() {
    let source = include_str!("../src/runtime.rs");
    assert!(source.contains("PRODUCTION_AUDIT_STATE_DIR"));
    assert!(source.contains("crate::enrollment::ensure_private_directory(&audit_state_dir)?"));
    assert!(source.contains("audit_state_dir: Some(audit_state_dir)"));
    assert!(source.contains("format!(\"{}\\n\", event.to_json())"));
    assert!(!source.contains("format!(\"{}\\\\n\", event.to_json())"));
    assert!(!source.contains("format!(\"{line}\\\\n\")"));
}

#[test]
fn state_roots_are_preprovisioned_and_verified_without_following_reparse_points() {
    let source = include_str!("../src/enrollment.rs");
    let verify = source
        .find("pub(crate) fn ensure_private_directory")
        .expect("state root verifier must remain explicit");
    let verifier = &source[verify..];

    assert!(!verifier.contains("fs::create_dir_all"));
    assert!(verifier.contains("verify_nonreparse_directory"));
    assert!(verifier.contains("GetFileAttributesW"));
    assert!(verifier.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
    assert!(verifier.contains("GetNamedSecurityInfoW"));
    assert!(verifier.contains("PROTECTED_DACL_SECURITY_INFORMATION"));
    assert!(verifier.contains("STATE_PARENT"));
    assert!(verifier.contains("AUDIT_ROOT"));
}

#[test]
fn production_pipe_bounds_response_writes_and_uses_single_request_connections() {
    let source = include_str!("../src/runtime.rs");
    assert!(source.contains("local control response write exceeded deadline"));
    assert!(source.contains("before_local_request_deadline(response_deadline"));
    assert!(source.contains("single_request_connections: true"));
}

#[test]
fn rejected_registration_caller_is_audited_before_the_identity_error_returns() {
    let source = include_str!("../src/local_control.rs");
    let verification = source
        .find("if let Err(error) = verify_fixed_gui_caller(caller.pid)")
        .expect("RegisterHub must verify the fixed product GUI");
    let audit = source[verification..]
        .find("self.audit.record(AuditEvent")
        .expect("a rejected RegisterHub caller must be audited");
    let rejection = source[verification..]
        .find("return Err(error)")
        .expect("the rejected caller must not reach runtime dispatch");

    assert!(audit < rejection, "audit must precede identity rejection");
    assert!(source[verification..verification + rejection]
        .contains("result_code: error.code().to_owned()"));
}

#[test]
fn invalid_persisted_enrollment_keeps_the_local_repair_path_available() {
    let source = include_str!("../src/runtime.rs");
    let warning = source
        .find("invalid enrollment state ignored; local registration remains available")
        .expect("invalid enrollment must fall back to the unregistered runtime");

    assert!(source[..warning].contains("Self::from_enrollment_state()"));
    assert!(source[warning..].contains("Ok(Self::unregistered())"));
}

#[test]
fn every_registration_requires_bounded_elevated_user_presence_before_claim() {
    let runtime = include_str!("../src/runtime.rs");
    let enrollment = include_str!("../src/enrollment.rs");
    let dispatch = runtime
        .find("runtime.finish_registration(hub_address, registration_code)")
        .expect("the Pipe must delegate confirmation work to a bounded background task");
    let pending = runtime
        .find("Ok(registration_pending())")
        .expect("the Pipe must return a pending DTO before confirmation");
    assert!(
        dispatch < pending,
        "background dispatch must precede pending response"
    );
    assert!(runtime.contains("registration_in_progress"));
    let registration = enrollment
        .split_once("pub fn register_with_confirmation(")
        .and_then(|(_, source)| source.split_once("fn register_before"))
        .map(|(source, _)| source)
        .expect("registration must remain an explicit bounded operation");
    let confirmation = registration
        .find("confirm_registration(hub_address, replaces_existing_registration, deadline)?")
        .expect("every registration must require elevated user presence");
    let claim = registration
        .find("register_before(hub_address, registration_code, deadline)")
        .expect("the registration code must be consumed only after confirmation");

    assert!(confirmation < claim, "confirmation must precede claim");
    let elevated = registration
        .find("ensure_elevated()?")
        .expect("the confirmation must be shown by an elevated Agent");
    assert!(
        elevated < confirmation,
        "elevation must precede confirmation"
    );
    assert!(enrollment.contains("MessageBoxW("));
    assert!(enrollment.contains("result == IDYES"));
    assert!(enrollment.contains("REPLACEMENT_CONFIRMATION_TIMEOUT"));
    assert!(enrollment.contains(".recv_timeout(timeout)"));
    let confirmation_source = enrollment
        .split_once("fn confirm_registration")
        .and_then(|(_, source)| source.split_once("fn claim_target"))
        .map(|(source, _)| source)
        .expect("Agent confirmation must remain isolated from the claim secret");
    assert!(!confirmation_source.contains("registration_code"));
}

#[test]
fn replacement_registration_installs_the_new_config_before_requesting_reconnect() {
    let runtime = include_str!("../src/runtime.rs");
    let register = runtime
        .split_once("fn finish_registration(")
        .and_then(|(_, source)| source.split_once("fn request_reconnect"))
        .map(|(source, _)| source)
        .expect("registration flow must remain explicit");
    let activate = register
        .find(".and_then(|config| self.activate_enrollment(config))")
        .expect("newly persisted credentials must become the in-memory config");
    let reconnect = register
        .find("self.request_reconnect()")
        .expect("an active session must still be interrupted");

    assert!(activate < reconnect);
    assert!(register[activate..reconnect].contains("if !was_waiting"));
}

#[test]
fn dev_runtime_initializes_the_registration_gate() {
    let runtime = include_str!("../src/runtime.rs");
    let dev_runtime = runtime
        .split_once("pub async fn run_dev_local()")
        .and_then(|(_, source)| source.split_once("fn dev_local_control_config()"))
        .map(|(source, _)| source)
        .expect("Dev runtime construction must remain explicit");

    assert!(dev_runtime.contains("registration_in_progress: Arc::new(AtomicBool::new(false))"));
}
