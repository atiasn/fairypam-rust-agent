use fairypam_agent_core::profile::SignatureVerifier;
use fairypam_agent_realtime::music_engine::LaneState;
use fairypam_agent_realtime::program::{StartProgram, MUSIC_AUTOPLAY_PROGRAM_ID};
use fairypam_agent_realtime::spec::{
    ClientSize, LaneSpec, RealtimeProgramEnvelope, RealtimeProgramSpec, SafetySpec,
    VerifiedRealtimeSpec,
};
use sha2::{Digest, Sha256};
use std::time::Duration;

struct AcceptDigest([u8; 32]);

impl SignatureVerifier for AcceptDigest {
    fn verify(&self, digest: &[u8; 32], signature: &str) -> bool {
        digest == &self.0 && signature == "test-signature"
    }
}

#[test]
fn signed_spec_binds_only_the_installed_independent_engine() {
    let content = spec();
    let canonical = serde_json::to_vec(&content).unwrap();
    let digest_bytes: [u8; 32] = Sha256::digest(canonical).into();
    let digest = digest_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let installed = VerifiedRealtimeSpec::verify(
        &serde_json::to_vec(&RealtimeProgramEnvelope {
            content,
            content_sha256: digest.clone(),
            signature: "test-signature".into(),
        })
        .unwrap(),
        &AcceptDigest(digest_bytes),
    )
    .unwrap();
    assert!(StartProgram {
        program_id: MUSIC_AUTOPLAY_PROGRAM_ID.into(),
        schema_version: 1,
        digest,
        maximum_duration: Duration::from_secs(90),
        supervision_lease: Some(Duration::from_secs(2)),
    }
    .bind(&installed)
    .is_ok());
}

#[test]
fn lane_state_uses_explicit_press_and_release_transitions() {
    let mut lane = LaneState::default();
    assert_eq!(lane.observe(219, 220, 220), Some(true));
    assert_eq!(lane.observe(100, 220, 220), None);
    assert_eq!(lane.observe(220, 220, 220), Some(false));
    assert!(!lane.pressed());
}

fn spec() -> RealtimeProgramSpec {
    let actions = [
        "music.note.a",
        "music.note.s",
        "music.note.d",
        "music.note.j",
        "music.note.k",
        "music.note.l",
    ];
    let x = [217_188, 327_083, 439_583, 552_604, 665_104, 777_604];
    RealtimeProgramSpec {
        id: MUSIC_AUTOPLAY_PROGRAM_ID.into(),
        schema_version: 1,
        kind: "pixel-threshold-key-state".into(),
        engine: "independent-six-lane".into(),
        required_client_size: ClientSize {
            width: 1_920,
            height: 1_080,
        },
        sample_interval_us: 5_000,
        event_freshness_us: 80_000,
        lanes: actions
            .into_iter()
            .zip(x)
            .map(|(action_id, x_ppm)| LaneSpec {
                action_id: action_id.into(),
                x_ppm,
                y_ppm: 852_778,
                channel: "blue".into(),
                press_below: 220,
                release_at_or_above: 220,
            })
            .collect(),
        safety: SafetySpec {
            require_foreground: true,
            reject_local_input: true,
            target_revalidate_ms: 250,
            maximum_queue_depth: 32,
        },
    }
}
