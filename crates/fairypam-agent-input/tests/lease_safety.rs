use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fairypam_agent_core::platform::{AuthorizationState, LocalAuthorization};
use fairypam_agent_core::profile::{
    profile_content_sha256, verify_profile, ActionDefinition, CaptureRegion, CaptureSource,
    Profile, ProfileContent, ProfileEnvelope, SignatureVerifier, TargetRules, VerifiedProfile,
};
use fairypam_agent_core::state::Machine;
use fairypam_agent_core::target::{ClientRect, IntegrityLevel, TargetBinding, TargetSnapshot};
use fairypam_agent_input::{
    ActionId, GuardianClient, InputLease, InputPermit, InputPlatform, LeaseExecutor, ReleaseReason,
    SafetyError, SessionKey,
};

#[derive(Default)]
struct FakeInput {
    pressed: BTreeSet<u16>,
    released: Vec<u16>,
    events: Option<Arc<Mutex<Vec<&'static str>>>>,
    fail_pulse: bool,
    fail_wheel_lease: bool,
    emergency_releases: Vec<Vec<u16>>,
    wheel_events: Vec<(Option<(u32, u32)>, i32)>,
}

impl InputPlatform for FakeInput {
    fn press_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        if let Some(events) = &self.events {
            events.lock().unwrap().push("local_press");
        }
        self.pressed.insert(scan_code);
        Ok(())
    }

    fn release_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.pressed.remove(&scan_code);
        self.released.push(scan_code);
        Ok(())
    }

    fn pulse_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        if self.fail_pulse {
            return Err(SafetyError::new("input.test_failure", "pulse failed"));
        }
        self.press_scan_code(scan_code)?;
        self.release_scan_code(scan_code)
    }

    fn apply_guarded_key_transitions(
        &mut self,
        transitions: &[(u16, bool, bool)],
    ) -> Result<(), SafetyError> {
        if let Some(events) = &self.events {
            events.lock().unwrap().push("local_batch");
        }
        for &(scan_code, _extended, pressed) in transitions {
            if pressed {
                self.pressed.insert(scan_code);
            } else {
                self.pressed.remove(&scan_code);
                self.released.push(scan_code);
            }
        }
        Ok(())
    }

    fn emergency_release(&mut self, scan_codes: &[u16]) -> Result<(), SafetyError> {
        self.emergency_releases.push(scan_codes.to_vec());
        for scan_code in scan_codes {
            self.pressed.remove(scan_code);
            self.released.push(*scan_code);
        }
        Ok(())
    }

    fn wheel(&mut self, delta: i32, _expires_at: Instant) -> Result<(), SafetyError> {
        if self.fail_wheel_lease {
            return Err(SafetyError::new(
                "input.lease_expired",
                "wheel lease expired",
            ));
        }
        self.wheel_events.push((None, delta));
        Ok(())
    }

    fn wheel_at_client_point(
        &mut self,
        x_ppm: u32,
        y_ppm: u32,
        delta: i32,
        _expires_at: Instant,
    ) -> Result<(), SafetyError> {
        if self.fail_wheel_lease {
            return Err(SafetyError::new(
                "input.lease_expired",
                "wheel lease expired",
            ));
        }
        self.wheel_events.push((Some((x_ppm, y_ppm)), delta));
        Ok(())
    }
}

#[derive(Default)]
struct FakeGuardian {
    calls: Vec<&'static str>,
    releases: Vec<ReleaseReason>,
    events: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl GuardianClient for FakeGuardian {
    fn register_intent(
        &mut self,
        _sequence: u64,
        _holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError> {
        self.calls.push("register_intent");
        if let Some(events) = &self.events {
            events.lock().unwrap().push("register_intent");
        }
        Ok(())
    }

    fn commit_holds(
        &mut self,
        _sequence: u64,
        _holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError> {
        self.calls.push("commit_holds");
        if let Some(events) = &self.events {
            events.lock().unwrap().push("commit_holds");
        }
        Ok(())
    }

    fn heartbeat(&mut self, _sequence: u64) -> Result<(), SafetyError> {
        self.calls.push("heartbeat");
        if let Some(events) = &self.events {
            events.lock().unwrap().push("heartbeat");
        }
        Ok(())
    }

    fn release_all(&mut self, reason: ReleaseReason) -> Result<(), SafetyError> {
        self.calls.push("release_all");
        self.releases.push(reason);
        Ok(())
    }
}

fn session(generation: u64) -> SessionKey {
    SessionKey {
        agent_id: "agent-test".into(),
        session_id: "session-test".into(),
        generation,
    }
}

struct PermitAuthority {
    machine: Machine,
    snapshot: TargetSnapshot,
}

impl PermitAuthority {
    fn new(now: Instant) -> Self {
        let profile = verified_profile();
        let binding = target_binding();
        let snapshot = TargetSnapshot {
            binding: binding.clone(),
            foreground: true,
            minimized: false,
            capturable: true,
        };
        let mut machine = Machine::new();
        machine.start_completed().unwrap();
        machine.control_connected(session(1)).unwrap();
        machine.activate_profile(&profile).unwrap();
        machine.lock_target(binding).unwrap();
        machine.preflight_passed(snapshot.clone()).unwrap();
        machine.enter_dry_run().unwrap();
        machine
            .request_arm(&TestAuthorization, now, now + Duration::from_secs(30))
            .unwrap();
        machine.begin_control(now).unwrap();
        Self { machine, snapshot }
    }

    fn permit(&self, now: Instant) -> InputPermit<'_> {
        InputPermit::from_capability(
            self.machine
                .issue_input_capability(now, &self.snapshot, true)
                .unwrap(),
        )
    }
}

struct TestRoot;

impl SignatureVerifier for TestRoot {
    fn verify(&self, _digest: &[u8; 32], signature: &str) -> bool {
        signature == "test-signature"
    }
}

struct TestAuthorization;

impl LocalAuthorization for TestAuthorization {
    fn current(&self, now: Instant) -> AuthorizationState {
        AuthorizationState::Granted {
            expires_at: now + Duration::from_secs(30),
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
            actions: BTreeMap::from([
                (
                    "movement.forward".into(),
                    ActionDefinition::Hold { scan_code: 17 },
                ),
                (
                    "combat.attack".into(),
                    ActionDefinition::Pulse { scan_code: 30 },
                ),
                (
                    "camera.wheel".into(),
                    ActionDefinition::Wheel {
                        maximum_delta: 76_800,
                    },
                ),
            ]),
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

#[test]
fn guarded_music_frame_arms_once_then_batches_without_reauthorizing() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput {
            events: Some(Arc::clone(&events)),
            ..Default::default()
        },
        FakeGuardian {
            events: Some(Arc::clone(&events)),
            ..Default::default()
        },
    )
    .unwrap();
    let permit = authority.permit(now);
    let expires_at = now + Duration::from_secs(1);

    executor
        .arm_guarded_physical_frame(session(1), 1, expires_at, &[(17, false)], &permit, now)
        .unwrap();
    executor
        .apply_guarded_physical_frame(&session(1), &[(17, false)], &permit, now)
        .unwrap();
    executor
        .apply_guarded_physical_frame(&session(1), &[], &permit, now)
        .unwrap();
    executor
        .renew_guarded_physical_frame(&session(1), 2, expires_at, &permit, now)
        .unwrap();

    assert_eq!(
        *events.lock().unwrap(),
        [
            "register_intent",
            "commit_holds",
            "local_batch",
            "local_batch",
            "heartbeat",
        ]
    );
}

#[test]
fn expired_lease_releases_every_hold() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();
    executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_millis(500),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap();

    executor.tick(now + Duration::from_millis(501)).unwrap();

    assert!(executor.held_actions().is_empty());
    assert_eq!(
        executor.last_release_reason(),
        Some(ReleaseReason::LeaseExpired)
    );
    assert_eq!(executor.platform().released, vec![17, 30]);
}

#[test]
fn guardian_intent_precedes_local_press_and_commit() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput {
            events: Some(events.clone()),
            ..FakeInput::default()
        },
        FakeGuardian {
            events: Some(events.clone()),
            ..FakeGuardian::default()
        },
    )
    .unwrap();
    executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_millis(500),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap();

    assert_eq!(
        executor.guardian().calls,
        vec!["register_intent", "commit_holds"]
    );
    assert_eq!(executor.platform().pressed, [17].into());
    assert_eq!(
        *events.lock().unwrap(),
        vec!["register_intent", "local_press", "commit_holds"]
    );
}

#[test]
fn focus_loss_closes_gate_and_releases() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();
    executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_secs(1),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap();

    executor.release_all(ReleaseReason::FocusLost).unwrap();

    assert!(!executor.input_gate_open());
    assert!(executor.held_actions().is_empty());
    assert_eq!(executor.guardian().releases, vec![ReleaseReason::FocusLost]);
}

#[test]
fn invalid_lease_after_hold_fails_closed_locally_and_in_guardian() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();
    executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_secs(1),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap();

    let error = executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_secs(1),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.sequence_invalid");
    assert!(!executor.input_gate_open());
    assert!(executor.held_actions().is_empty());
    assert_eq!(
        executor.guardian().releases.last(),
        Some(&ReleaseReason::EmergencyStop)
    );
    assert_eq!(
        executor.platform().emergency_releases.last(),
        Some(&vec![17, 30])
    );
}

#[test]
fn expired_replacement_lease_after_hold_fails_closed() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();
    executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_secs(1),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap();

    let error = executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 2,
                expires_at: now,
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.lease_expired");
    assert!(!executor.input_gate_open());
    assert!(executor.held_actions().is_empty());
    assert_eq!(
        executor.guardian().releases.last(),
        Some(&ReleaseReason::LeaseExpired)
    );
}

#[test]
fn unknown_action_after_hold_fails_closed() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();
    executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_secs(1),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap();

    let error = executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 2,
                expires_at: now + Duration::from_secs(1),
                desired_holds: [ActionId::new("undeclared.action").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.action_not_allowed");
    assert!(!executor.input_gate_open());
    assert!(executor.held_actions().is_empty());
    assert_eq!(
        executor.guardian().releases.last(),
        Some(&ReleaseReason::EmergencyStop)
    );
}

#[test]
fn permit_cannot_be_replayed_for_another_control_generation() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    let error = executor
        .apply_lease(
            InputLease {
                session: session(2),
                sequence: 1,
                expires_at: now + Duration::from_secs(1),
                desired_holds: [ActionId::new("movement.forward").unwrap()].into(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.permit_invalid");
    assert!(!executor.input_gate_open());
    assert_eq!(
        executor.guardian().releases,
        vec![ReleaseReason::EmergencyStop]
    );
}

#[test]
fn permit_cannot_authorize_another_signed_profile_content() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let permit = authority.permit(now);

    assert!(!permit.is_valid_for_target_and_profile(
        now,
        &session(1),
        &target_binding(),
        &"ff".repeat(32),
    ));
}

#[test]
fn failed_pulse_fails_closed_and_releases_all_profile_inputs() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput {
            fail_pulse: true,
            ..FakeInput::default()
        },
        FakeGuardian::default(),
    )
    .unwrap();
    executor
        .apply_lease(
            InputLease {
                session: session(1),
                sequence: 1,
                expires_at: now + Duration::from_secs(1),
                desired_holds: BTreeSet::new(),
            },
            &authority.permit(now),
            now,
        )
        .unwrap();

    let error = executor
        .execute_pulse(
            &ActionId::new("combat.attack").unwrap(),
            &session(1),
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.test_failure");
    assert!(!executor.input_gate_open());
    assert_eq!(executor.platform().emergency_releases, vec![vec![17, 30]]);
    assert_eq!(
        executor.guardian().releases,
        vec![ReleaseReason::PlatformFailure]
    );
}

#[test]
fn physical_frame_applies_and_releases_profile_declared_key() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(1),
            &[(17, false)],
            &[],
            0,
            None,
            &authority.permit(now),
            now,
        )
        .unwrap();
    assert!(executor.platform().pressed.contains(&17));

    executor
        .apply_physical_frame(
            session(1),
            2,
            now + Duration::from_secs(1),
            &[],
            &[],
            0,
            None,
            &authority.permit(now),
            now,
        )
        .unwrap();
    assert!(!executor.platform().pressed.contains(&17));
}

#[test]
fn physical_frame_executes_profile_pulse_atomically() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(1),
            &[(30, false)],
            &[],
            0,
            None,
            &authority.permit(now),
            now,
        )
        .unwrap();

    assert!(!executor.platform().pressed.contains(&30));
    assert_eq!(executor.platform().released, vec![30]);
}

#[test]
fn physical_frame_rejects_mixed_pulse_and_hold_before_side_effects() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    let error = executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(1),
            &[(17, false), (30, false)],
            &[],
            0,
            None,
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.frame_invalid");
    assert!(executor.platform().pressed.is_empty());
    assert!(executor.platform().released.is_empty());
    assert!(executor.guardian().calls.is_empty());
}

#[test]
fn invalid_wheel_rejects_the_entire_physical_frame_before_side_effects() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    let error = executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(1),
            &[(17, false)],
            &[],
            76_920,
            None,
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.wheel_not_allowed");
    assert!(executor.platform().pressed.is_empty());
    assert!(executor.platform().emergency_releases.is_empty());
    assert!(executor.guardian().calls.is_empty());
}

#[test]
fn physical_frame_positions_the_pointer_before_wheel_without_button_holds() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(1),
            &[],
            &[],
            -120,
            Some((500_000, 500_000)),
            &authority.permit(now),
            now,
        )
        .unwrap();

    assert_eq!(
        executor.platform().wheel_events,
        vec![(Some((500_000, 500_000)), -120)]
    );
    assert!(executor.held_actions().is_empty());
}

#[test]
fn physical_frame_keeps_a_large_page_scroll_as_one_aggregate_delta() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(4),
            &[],
            &[],
            -39_600,
            Some((500_000, 500_000)),
            &authority.permit(now),
            now,
        )
        .unwrap();

    assert_eq!(
        executor.platform().wheel_events,
        vec![(Some((500_000, 500_000)), -39_600)]
    );
}

#[test]
fn physical_frame_maps_mid_wheel_expiry_to_lease_expired_release() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput {
            fail_wheel_lease: true,
            ..Default::default()
        },
        FakeGuardian::default(),
    )
    .unwrap();

    let error = executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(4),
            &[],
            &[],
            -39_600,
            None,
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.lease_expired");
    assert_eq!(
        executor.last_release_reason(),
        Some(ReleaseReason::LeaseExpired)
    );
}

#[test]
fn physical_frame_without_a_wheel_point_keeps_legacy_wheel_behavior() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(1),
            &[],
            &[],
            -120,
            None,
            &authority.permit(now),
            now,
        )
        .unwrap();

    assert_eq!(executor.platform().wheel_events, vec![(None, -120)]);
}

#[test]
fn invalid_wheel_point_rejects_the_entire_frame_before_side_effects() {
    let now = Instant::now();
    let authority = PermitAuthority::new(now);
    let mut executor = LeaseExecutor::new(
        &verified_profile(),
        FakeInput::default(),
        FakeGuardian::default(),
    )
    .unwrap();

    let error = executor
        .apply_physical_frame(
            session(1),
            1,
            now + Duration::from_secs(1),
            &[(17, false)],
            &[],
            -120,
            Some((1_000_001, 500_000)),
            &authority.permit(now),
            now,
        )
        .unwrap_err();

    assert_eq!(error.code(), "input.wheel_point_invalid");
    assert!(executor.platform().pressed.is_empty());
    assert!(executor.platform().wheel_events.is_empty());
    assert!(executor.guardian().calls.is_empty());
}
