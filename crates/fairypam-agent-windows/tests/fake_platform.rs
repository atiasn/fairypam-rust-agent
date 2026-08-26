use fairypam_agent_core::profile::{
    profile_content_sha256, verify_profile, ProfileContent, ProfileEnvelope, SignatureVerifier,
};
use fairypam_agent_core::target::{ClientRect, IntegrityLevel, TargetBinding};
use fairypam_agent_windows::{
    lock_unique, revalidate_identity, FakeWindows, Rect, TargetIdentity, WindowsError,
    WindowsTargetCandidate, WindowsTargetPlatform,
};

struct AcceptSignature;

impl SignatureVerifier for AcceptSignature {
    fn verify(&self, _digest: &[u8; 32], signature: &str) -> bool {
        signature == "test-signature"
    }
}

fn profile() -> fairypam_agent_core::profile::VerifiedProfile {
    let content: ProfileContent = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "profile": {
            "id": "testbed",
            "version": "1.0.0",
            "display_name": "Testbed",
            "target": {
                "process_names": ["testbed.exe"],
                "process_path_sha256": ["11".repeat(32)],
                "window_classes": ["FairyPamTestbed"],
                "title_patterns": ["FairyPam Testbed *"],
                "require_elevated": false,
                "minimum_client_width": 640,
                "minimum_client_height": 360,
                "minimum_dpi": 96
            },
            "capture_sources": [{
                "id": "main",
                "region": { "kind": "full_client" },
                "maximum_fps": 10,
                "encodings": ["png"]
            }],
            "actions": {
                "movement.forward": {
                    "kind": "hold",
                    "maa_virtual_key": 87,
                    "physical_scan_code": 17,
                    "extended": false
                }
            }
        },
        "files": []
    }))
    .unwrap();
    let envelope = ProfileEnvelope {
        content_sha256: profile_content_sha256(&content).unwrap(),
        content,
        signature: "test-signature".into(),
    };
    verify_profile(&serde_json::to_vec(&envelope).unwrap(), &AcceptSignature).unwrap()
}

fn candidate(hwnd: isize, started_at: u64) -> WindowsTargetCandidate {
    WindowsTargetCandidate {
        identity: TargetIdentity {
            hwnd,
            pid: 42,
            process_started_at: started_at,
            process_path_sha256: [0x11; 32],
            window_class: "FairyPamTestbed".into(),
            client_rect: Rect::new(0, 0, 1280, 720).unwrap(),
            dpi: 96,
        },
        process_name: "TESTBED.EXE".into(),
        window_title: format!("FairyPam Testbed {hwnd}"),
        elevated: false,
        foreground: true,
        minimized: false,
        capturable: true,
    }
}

fn binding(hwnd: u64, started_at: u64) -> TargetBinding {
    TargetBinding {
        profile_id: "testbed".into(),
        profile_version: "1.0.0".into(),
        process_id: 42,
        process_name: "testbed.exe".into(),
        process_started_at_unix_ms: started_at,
        process_path_sha256: "11".repeat(32),
        window_handle: hwnd,
        window_title: format!("FairyPam Testbed {hwnd}"),
        window_class: "FairyPamTestbed".into(),
        client_rect: ClientRect {
            width: 1280,
            height: 720,
        },
        dpi: 96,
        integrity: IntegrityLevel::Medium,
    }
}

#[test]
fn ambiguous_candidates_are_not_auto_selected() {
    let mut platform = FakeWindows::with_candidates(vec![candidate(1, 100), candidate(2, 101)]);
    let error = lock_unique(&mut platform, &profile()).unwrap_err();
    assert_eq!(error.code(), "target.ambiguous");
}

#[test]
fn stale_process_start_time_invalidates_identity() {
    let original = candidate(1, 100);
    let mut platform = FakeWindows::with_candidates(vec![candidate(1, 101)]);
    let error = revalidate_identity(&mut platform, &original.identity).unwrap_err();
    assert_eq!(error.code(), "target.stale");
}

#[test]
fn rediscovery_accepts_only_one_replacement_window_from_the_same_process() {
    let mut targets =
        WindowsTargetPlatform::new(FakeWindows::with_candidates(vec![candidate(2, 100)]));

    let refreshed = targets.rediscover(&profile(), &binding(1, 100)).unwrap();

    assert_eq!(refreshed.window_handle, 2);
    assert_eq!(refreshed.process_id, 42);
}

#[test]
fn class_only_match_is_not_bound() {
    let mut unrelated = candidate(1, 100);
    unrelated.process_name = "other.exe".into();
    let mut platform = FakeWindows::with_candidates(vec![unrelated]);
    let error = lock_unique(&mut platform, &profile()).unwrap_err();
    assert_eq!(error.code(), "target.not_found");
}

#[test]
fn invalid_rectangle_is_rejected_at_the_boundary() {
    let error = Rect::new(10, 10, 0, 720).unwrap_err();
    assert_eq!(error.code(), "target.client_rect_invalid");
    let _: WindowsError = error;
}
