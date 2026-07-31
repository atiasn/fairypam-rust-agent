use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use fairypam_agent_core::platform::{AuthorizationState, DenyAllAuthorization, LocalAuthorization};
use fairypam_agent_core::profile::{
    profile_content_sha256, verify_profile, ActionDefinition, CaptureRegion, CaptureSource,
    Profile, ProfileContent, ProfileEnvelope, SignatureVerifier, TargetRules, VerifiedProfile,
};
use fairypam_agent_core::state::{AgentState, Effect, Event, Machine, SessionIdentity};
use fairypam_agent_core::target::{ClientRect, IntegrityLevel, TargetBinding, TargetSnapshot};

struct TestRoot;

impl SignatureVerifier for TestRoot {
    fn verify(&self, _digest: &[u8; 32], signature: &str) -> bool {
        signature == "test-signature"
    }
}

struct TestAuthorization {
    expires_at: Instant,
}

impl LocalAuthorization for TestAuthorization {
    fn current(&self, _now: Instant) -> AuthorizationState {
        AuthorizationState::Granted {
            expires_at: self.expires_at,
        }
    }
}

fn verified_profile() -> VerifiedProfile {
    let content = ProfileContent {
        schema_version: 1,
        profile: Profile {
            id: "fairypam-test-window".into(),
            version: "1.0.0".into(),
            display_name: "FairyPam Test Window".into(),
            target: TargetRules {
                process_names: vec!["fairypam-test-window.exe".into()],
                process_path_sha256: vec!["a".repeat(64)],
                window_classes: vec!["FairyPamTestWindow".into()],
                title_patterns: vec!["FairyPam Test Window".into()],
                require_elevated: false,
                minimum_client_width: 640,
                minimum_client_height: 360,
                minimum_dpi: 96,
            },
            capture_sources: vec![CaptureSource {
                id: "client".into(),
                region: CaptureRegion::FullClient,
                maximum_fps: 30,
                encodings: vec!["jpeg".into()],
            }],
            actions: BTreeMap::from([(
                "move.forward".into(),
                ActionDefinition::Hold { scan_code: 0x11 },
            )]),
        },
        files: Vec::new(),
    };
    let content_sha256 = profile_content_sha256(&content).unwrap();
    let bytes = serde_json::to_vec(&ProfileEnvelope {
        content,
        content_sha256,
        signature: "test-signature".into(),
    })
    .unwrap();
    verify_profile(&bytes, &TestRoot).unwrap()
}

fn target_binding() -> TargetBinding {
    TargetBinding {
        profile_id: "fairypam-test-window".into(),
        profile_version: "1.0.0".into(),
        process_id: 42,
        process_name: "fairypam-test-window.exe".into(),
        process_started_at_unix_ms: 1_000,
        process_path_sha256: "a".repeat(64),
        window_handle: 100,
        window_title: "FairyPam Test Window".into(),
        window_class: "FairyPamTestWindow".into(),
        client_rect: ClientRect {
            width: 1280,
            height: 720,
        },
        dpi: 96,
        integrity: IntegrityLevel::Medium,
    }
}

fn session(generation: u64) -> SessionIdentity {
    SessionIdentity {
        agent_id: "agent-test".into(),
        session_id: format!("session-{generation}"),
        generation,
    }
}

fn dry_run_machine() -> Machine {
    let profile = verified_profile();
    let binding = target_binding();
    let mut state = Machine::new();
    state.start_completed().unwrap();
    state.control_connected(session(1)).unwrap();
    state.activate_profile(&profile).unwrap();
    state.lock_target(binding.clone()).unwrap();
    state
        .preflight_passed(TargetSnapshot {
            binding,
            foreground: true,
            minimized: false,
            capturable: true,
        })
        .unwrap();
    state.enter_dry_run().unwrap();
    state
}

fn controlling_machine(now: Instant) -> Machine {
    let expires_at = now + Duration::from_secs(30);
    let mut state = dry_run_machine();
    state
        .request_arm(&TestAuthorization { expires_at }, now, expires_at)
        .unwrap();
    state.begin_control(now).unwrap();
    state
}

#[test]
fn input_capability_requires_current_controlling_target_snapshot() {
    let now = Instant::now();
    let state = controlling_machine(now);
    let binding = target_binding();

    let error = state
        .issue_input_capability(
            now,
            &TargetSnapshot {
                binding: binding.clone(),
                foreground: false,
                minimized: false,
                capturable: true,
            },
            true,
        )
        .unwrap_err();
    assert_eq!(error.code(), "input.capability_denied");

    state
        .issue_input_capability(
            now,
            &TargetSnapshot {
                binding,
                foreground: true,
                minimized: false,
                capturable: true,
            },
            true,
        )
        .unwrap();

    let error = state
        .issue_input_capability(
            now + Duration::from_secs(31),
            &TargetSnapshot {
                binding: target_binding(),
                foreground: true,
                minimized: false,
                capturable: true,
            },
            true,
        )
        .unwrap_err();
    assert_eq!(error.code(), "input.capability_denied");
}

#[test]
fn controlling_input_authorization_can_be_renewed_per_frame() {
    let now = Instant::now();
    let mut state = controlling_machine(now);
    let renewed_at = now + Duration::from_secs(31);
    let expires_at = renewed_at + Duration::from_secs(1);

    state
        .renew_control_authorization(&TestAuthorization { expires_at }, renewed_at, expires_at)
        .unwrap();
    state
        .issue_input_capability(
            renewed_at,
            &TargetSnapshot {
                binding: target_binding(),
                foreground: true,
                minimized: false,
                capturable: true,
            },
            true,
        )
        .unwrap();
}

#[test]
fn disconnected_from_controlling_releases_before_transition() {
    let mut state = controlling_machine(Instant::now());

    let effects = state.apply(Event::ControlDisconnected).unwrap();

    assert_eq!(effects, vec![Effect::CloseInputGate, Effect::ReleaseAll]);
    assert_eq!(state.current(), &AgentState::Disconnected);
}

#[test]
fn production_deny_all_authorization_cannot_arm() {
    let now = Instant::now();
    let mut state = dry_run_machine();

    let err = state
        .request_arm(&DenyAllAuthorization, now, now + Duration::from_secs(30))
        .unwrap_err();

    assert_eq!(err.code(), "authorization.denied");
    assert_eq!(state.current(), &AgentState::DryRun);
}

#[test]
fn lease_expiry_closes_gate_and_releases_all() {
    let mut state = controlling_machine(Instant::now());

    let effects = state.apply(Event::LeaseExpired).unwrap();

    assert_eq!(effects, vec![Effect::CloseInputGate, Effect::ReleaseAll]);
    assert_eq!(state.current(), &AgentState::DryRun);
}

#[test]
fn emergency_stop_requires_authorized_local_reset() {
    let now = Instant::now();
    let mut state = controlling_machine(now);
    state.apply(Event::EmergencyStop).unwrap();

    let err = state.local_reset(&DenyAllAuthorization, now).unwrap_err();

    assert_eq!(err.code(), "authorization.denied");
    assert_eq!(state.current(), &AgentState::EmergencyStopped);
}

#[test]
fn emergency_stop_survives_disconnect_until_local_reset() {
    let now = Instant::now();
    let mut state = controlling_machine(now);
    state.apply(Event::EmergencyStop).unwrap();

    let effects = state.apply(Event::ControlDisconnected).unwrap();

    assert_eq!(effects, vec![Effect::CloseInputGate, Effect::ReleaseAll]);
    assert_eq!(state.current(), &AgentState::EmergencyStopped);
    state
        .local_reset(
            &TestAuthorization {
                expires_at: now + Duration::from_secs(30),
            },
            now,
        )
        .unwrap();
    assert_eq!(state.current(), &AgentState::Disconnected);
}

#[test]
fn connected_agent_cannot_enter_dry_run_without_verified_preflight() {
    let mut state = Machine::new();
    state.start_completed().unwrap();
    state.control_connected(session(1)).unwrap();

    let err = state.enter_dry_run().unwrap_err();

    assert_eq!(err.code(), "state.invalid_transition");
    assert_eq!(state.current(), &AgentState::ConnectedIdle);
}

#[test]
fn local_reset_before_profile_returns_only_to_connected_idle() {
    let now = Instant::now();
    let mut state = Machine::new();
    state.start_completed().unwrap();
    state.control_connected(session(1)).unwrap();
    state.apply(Event::EmergencyStop).unwrap();

    state
        .local_reset(
            &TestAuthorization {
                expires_at: now + Duration::from_secs(30),
            },
            now,
        )
        .unwrap();

    assert_eq!(state.current(), &AgentState::ConnectedIdle);
    assert_eq!(
        state.enter_dry_run().unwrap_err().code(),
        "state.invalid_transition"
    );
}

#[test]
fn target_binding_must_match_the_verified_profile() {
    let profile = verified_profile();
    let mut binding = target_binding();
    binding.process_path_sha256 = "f".repeat(64);
    let mut state = Machine::new();
    state.start_completed().unwrap();
    state.control_connected(session(1)).unwrap();
    state.activate_profile(&profile).unwrap();

    let err = state.lock_target(binding).unwrap_err();

    assert_eq!(err.code(), "target.profile_mismatch");
    assert_eq!(state.current(), &AgentState::ProfileLoaded);
}

#[test]
fn focus_and_guardian_failures_release_in_order() {
    for event in [Event::FocusLost, Event::GuardianUnhealthy] {
        let mut state = controlling_machine(Instant::now());

        let effects = state.apply(event).unwrap();

        assert_eq!(effects, vec![Effect::CloseInputGate, Effect::ReleaseAll]);
        assert_eq!(state.current(), &AgentState::DryRun);
    }
}

#[test]
fn failed_safe_cannot_be_downgraded_to_a_resettable_state() {
    let now = Instant::now();
    let mut state = controlling_machine(now);
    state.apply(Event::FailSafe).unwrap();

    let effects = state.apply(Event::EmergencyStop).unwrap();

    assert_eq!(effects, vec![Effect::CloseInputGate, Effect::ReleaseAll]);
    assert_eq!(state.current(), &AgentState::FailedSafe);
    assert_eq!(
        state
            .local_reset(
                &TestAuthorization {
                    expires_at: now + Duration::from_secs(30),
                },
                now,
            )
            .unwrap_err()
            .code(),
        "state.invalid_transition"
    );
}
