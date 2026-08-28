use std::collections::BTreeMap;

use fairypam_agent_core::profile::{
    profile_content_sha256, verify_profile, ActionDefinition, CaptureRegion, CaptureSource,
    ClientPointButton, Ed25519SignatureVerifier, Profile, ProfileContent, ProfileEnvelope,
    ProfileFile, SignatureVerifier, TargetRules,
};

struct TestRoot;

impl SignatureVerifier for TestRoot {
    fn verify(&self, digest: &[u8; 32], signature: &str) -> bool {
        let expected = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        signature == format!("test:{expected}")
    }
}

fn valid_content() -> ProfileContent {
    ProfileContent {
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
                    "move.forward".into(),
                    ActionDefinition::Hold {
                        maa_virtual_key: 0x57,
                        physical_scan_code: 0x11,
                        extended: false,
                    },
                ),
                (
                    "camera.delta".into(),
                    ActionDefinition::RelativeMouse { maximum_delta: 200 },
                ),
                (
                    "inventory.scroll".into(),
                    ActionDefinition::Wheel {
                        maximum_delta: 76_800,
                    },
                ),
                (
                    "ui.confirm".into(),
                    ActionDefinition::ClientPointClick {
                        button: ClientPointButton::Left,
                    },
                ),
            ]),
        },
        files: vec![ProfileFile {
            path: "profile.json".into(),
            sha256: "b".repeat(64),
        }],
    }
}

#[test]
fn production_genshin_profile_matches_the_formal_root_and_target() {
    let verifier = Ed25519SignatureVerifier::from_public_key_hex(
        "a1fe01b263727eddd401ce276ac34ce085df8b917b4eca6d6cd7bbfb8d0fbfaa",
    )
    .unwrap();
    let profile = verify_profile(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/genshin-impact/profile.json"
        )),
        &verifier,
    )
    .unwrap();

    assert_eq!(profile.profile().id, "genshin-impact");
    assert_eq!(profile.profile().version, "2.0.1");
    assert!(matches!(
        profile.profile().actions.get("input.f"),
        Some(ActionDefinition::Pulse {
            maa_virtual_key: 0x46,
            physical_scan_code: 33,
            extended: false,
        })
    ));
    assert!(matches!(
        profile.profile().actions.get("inventory.scrollbar_drag"),
        Some(ActionDefinition::ClientPointSwipe {
            button: ClientPointButton::Left,
            maximum_distance_ppm: 100_000,
            maximum_duration_ms: 1_000,
        })
    ));
    assert!(profile
        .profile()
        .target
        .process_path_sha256
        .iter()
        .any(|hash| {
            hash == "a07b065bda33f8cc9f1b9f56eae1bab0fada986cb2699c19d793fba8a5ab4276"
        }));
}

fn envelope(content: ProfileContent, signature: Option<String>) -> Vec<u8> {
    let digest = profile_content_sha256(&content).unwrap();
    serde_json::to_vec(&ProfileEnvelope {
        content,
        content_sha256: digest.clone(),
        signature: signature.unwrap_or_else(|| format!("test:{digest}")),
    })
    .unwrap()
}

#[test]
fn unsigned_profile_is_rejected() {
    let bytes = envelope(valid_content(), Some(String::new()));

    let err = verify_profile(&bytes, &TestRoot).unwrap_err();

    assert_eq!(err.code(), "profile.signature_invalid");
}

#[test]
fn content_hash_mismatch_is_rejected_before_activation() {
    let bytes = envelope(valid_content(), None);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["content"]["profile"]["display_name"] = "Tampered".into();

    let err = verify_profile(&serde_json::to_vec(&value).unwrap(), &TestRoot).unwrap_err();

    assert_eq!(err.code(), "profile.hash_mismatch");
}

#[test]
fn executable_profile_content_is_rejected() {
    for path in [
        "hooks/bootstrap.ps1",
        "hooks/launcher.hta",
        "hooks/shortcut.lnk",
        "hooks/control.cpl",
        "hooks/archive.jar",
        "hooks/script.py",
    ] {
        let mut content = valid_content();
        content.files.push(ProfileFile {
            path: path.into(),
            sha256: "c".repeat(64),
        });

        let err = verify_profile(&envelope(content, None), &TestRoot).unwrap_err();

        assert_eq!(err.code(), "profile.executable_content", "accepted {path}");
    }
}

#[test]
fn unknown_fields_are_rejected_by_the_schema() {
    let bytes = envelope(valid_content(), None);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["network_override"] = "https://example.invalid".into();

    let err = verify_profile(&serde_json::to_vec(&value).unwrap(), &TestRoot).unwrap_err();

    assert_eq!(err.code(), "profile.schema_invalid");
}

#[test]
fn generic_window_class_without_process_identity_is_rejected() {
    let mut content = valid_content();
    content.profile.target.process_names.clear();
    content.profile.target.process_path_sha256.clear();

    let err = verify_profile(&envelope(content, None), &TestRoot).unwrap_err();

    assert_eq!(err.code(), "profile.target_rules_invalid");
}

#[test]
fn empty_target_rule_values_are_rejected() {
    let mut content = valid_content();
    content.profile.target.process_names = vec![String::new()];

    let err = verify_profile(&envelope(content, None), &TestRoot).unwrap_err();

    assert_eq!(err.code(), "profile.target_rules_invalid");
}

#[test]
fn profile_version_must_be_semver() {
    let mut content = valid_content();
    content.profile.version = "latest".into();

    let err = verify_profile(&envelope(content, None), &TestRoot).unwrap_err();

    assert_eq!(err.code(), "profile.schema_invalid");
}

#[test]
fn capture_roi_must_stay_inside_the_normalized_client_area() {
    let mut content = valid_content();
    content.profile.capture_sources[0].region = CaptureRegion::NormalizedRoi {
        x_ppm: 900_000,
        y_ppm: 0,
        width_ppm: 200_000,
        height_ppm: 1_000_000,
    };

    let err = verify_profile(&envelope(content, None), &TestRoot).unwrap_err();

    assert_eq!(err.code(), "profile.capture_invalid");
}
