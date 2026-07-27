use std::time::{Duration, Instant};

use fairypam_agent_core::profile::CaptureRegion;
use fairypam_agent_windows::{
    normalized_process_path_sha256, CaptureBackend, CaptureEncoding, CapturePipeline,
    CaptureSession, CapturedBgraFrame, LatestFrameSlot, Rect, WindowsError,
};

#[derive(Default)]
struct FakeCapture {
    frames: Vec<CapturedBgraFrame>,
    rebuilds: Vec<(Rect, u32)>,
}

impl CaptureBackend for FakeCapture {
    fn next_bgra(&mut self, _deadline: Instant) -> Result<CapturedBgraFrame, WindowsError> {
        self.frames
            .pop()
            .ok_or_else(|| WindowsError::new("capture.deadline", "no frame"))
    }

    fn rebuild(&mut self, client_rect: Rect, dpi: u32) -> Result<(), WindowsError> {
        self.rebuilds.push((client_rect, dpi));
        Ok(())
    }
}

fn solid_bgra(width: u32, height: u32, value: [u8; 4]) -> CapturedBgraFrame {
    CapturedBgraFrame {
        pixels: value.repeat((width * height) as usize),
        width,
        height,
        captured_at: Instant::now(),
    }
}

#[test]
fn signed_testbed_profile_hash_matches_the_canonical_gate_path() {
    let profile: serde_json::Value = serde_json::from_str(include_str!(
        "../../../profiles/fairypam-test-window/profile.json"
    ))
    .unwrap();
    let expected = profile["content"]["profile"]["target"]["process_path_sha256"][0]
        .as_str()
        .unwrap();
    let actual = normalized_process_path_sha256(r"C:\FairyPam\Testbed\fairypam-test-window.exe")
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(actual, expected);
}

#[test]
fn capture_rebuilds_after_client_size_change() {
    let backend = FakeCapture::default();
    let rect = Rect::new(0, 0, 1280, 720).unwrap();
    let mut capture = CapturePipeline::new(
        backend,
        rect,
        96,
        CaptureRegion::FullClient,
        CaptureEncoding::Png,
    )
    .unwrap();

    capture
        .resize(Rect::new(0, 0, 1920, 1080).unwrap(), 144)
        .unwrap();
    capture
        .resize(Rect::new(0, 0, 1920, 1080).unwrap(), 144)
        .unwrap();

    assert_eq!(capture.backend().rebuilds.len(), 1);
}

#[test]
fn capture_refreshes_client_crop_after_window_move() {
    let backend = FakeCapture::default();
    let mut capture = CapturePipeline::new(
        backend,
        Rect::new(0, 0, 1280, 720).unwrap(),
        96,
        CaptureRegion::FullClient,
        CaptureEncoding::Png,
    )
    .unwrap();

    capture
        .resize(Rect::new(300, 200, 1280, 720).unwrap(), 96)
        .unwrap();

    assert_eq!(capture.backend().rebuilds.len(), 1);
}

#[test]
fn normalized_roi_is_cropped_before_encoding() {
    let mut backend = FakeCapture::default();
    backend.frames.push(solid_bgra(4, 2, [0, 0, 255, 255]));
    let mut capture = CapturePipeline::new(
        backend,
        Rect::new(0, 0, 4, 2).unwrap(),
        96,
        CaptureRegion::NormalizedRoi {
            x_ppm: 500_000,
            y_ppm: 0,
            width_ppm: 500_000,
            height_ppm: 1_000_000,
        },
        CaptureEncoding::Png,
    )
    .unwrap();

    let frame = capture
        .next_frame(Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!((frame.width, frame.height, frame.sequence), (2, 2, 1));
    assert!(!frame.bytes.is_empty());
}

#[test]
fn latest_frame_slot_overwrites_without_queueing() {
    let slot = LatestFrameSlot::default();
    let mut backend = FakeCapture::default();
    backend.frames.push(solid_bgra(1, 1, [0, 255, 0, 255]));
    backend.frames.push(solid_bgra(1, 1, [255, 0, 0, 255]));
    let mut capture = CapturePipeline::new(
        backend,
        Rect::new(0, 0, 1, 1).unwrap(),
        96,
        CaptureRegion::FullClient,
        CaptureEncoding::Png,
    )
    .unwrap();

    slot.publish(
        capture
            .next_frame(Instant::now() + Duration::from_secs(1))
            .unwrap(),
    );
    slot.publish(
        capture
            .next_frame(Instant::now() + Duration::from_secs(1))
            .unwrap(),
    );

    assert_eq!(slot.overwritten(), 1);
    assert_eq!(slot.take().unwrap().sequence, 2);
    assert!(slot.take().is_none());
}

#[test]
fn jpeg_quality_above_one_hundred_is_rejected() {
    let error = CapturePipeline::new(
        FakeCapture::default(),
        Rect::new(0, 0, 1, 1).unwrap(),
        96,
        CaptureRegion::FullClient,
        CaptureEncoding::Jpeg { quality: 101 },
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), "capture.encoding_invalid");
}

#[test]
fn expired_deadline_is_rejected_before_capture_work() {
    let mut backend = FakeCapture::default();
    backend.frames.push(solid_bgra(1, 1, [0, 0, 0, 255]));
    let mut capture = CapturePipeline::new(
        backend,
        Rect::new(0, 0, 1, 1).unwrap(),
        96,
        CaptureRegion::FullClient,
        CaptureEncoding::Png,
    )
    .unwrap();

    let error = capture.next_frame(Instant::now()).unwrap_err();
    assert_eq!(error.code(), "capture.deadline");
}

#[cfg(windows)]
#[test]
#[ignore = "requires a running FairyPam Testbed window on cleiagent"]
fn cleiagent_testbed_wgc_soak() {
    use std::thread;

    use fairypam_agent_windows::{DxgiCaptureBackend, NativeWindows, WindowsApi};

    let expected_pid = std::env::var("FAIRYPAM_TESTBED_PID")
        .expect("FAIRYPAM_TESTBED_PID must identify the running testbed")
        .parse::<u32>()
        .expect("FAIRYPAM_TESTBED_PID must be an integer");
    let expected_started_at = std::env::var("FAIRYPAM_TESTBED_STARTED_AT_UNIX_MS")
        .expect("FAIRYPAM_TESTBED_STARTED_AT_UNIX_MS must identify the running testbed")
        .parse::<u64>()
        .expect("FAIRYPAM_TESTBED_STARTED_AT_UNIX_MS must be an integer");
    let expected_path_sha256 = std::env::var("FAIRYPAM_TESTBED_PATH_SHA256")
        .expect("FAIRYPAM_TESTBED_PATH_SHA256 must identify the canonical testbed path");
    assert_eq!(expected_path_sha256.len(), 64, "path SHA256 must be hex");
    let nonce = std::env::var("FAIRYPAM_WGC_NONCE").expect("FAIRYPAM_WGC_NONCE is required");
    assert!(
        nonce.len() == 64 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "WGC nonce must be 64 hex characters"
    );
    let duration_seconds = std::env::var("FAIRYPAM_WGC_SOAK_SECONDS")
        .unwrap_or_else(|_| "1800".into())
        .parse::<u64>()
        .expect("FAIRYPAM_WGC_SOAK_SECONDS must be an integer");
    let fps = std::env::var("FAIRYPAM_WGC_SOAK_FPS")
        .unwrap_or_else(|_| "10".into())
        .parse::<u32>()
        .expect("FAIRYPAM_WGC_SOAK_FPS must be an integer");
    let gate = match std::env::var("FAIRYPAM_WGC_GATE_MODE").as_deref() {
        Ok("formal") => {
            assert!(
                duration_seconds >= 1800,
                "formal WGC soak must run for at least 1800 seconds"
            );
            "WINDOWS-WGC-SOAK"
        }
        Ok("diagnostic") => {
            assert!(duration_seconds > 0, "diagnostic duration must be positive");
            "WINDOWS-WGC-DIAGNOSTIC"
        }
        _ => panic!("FAIRYPAM_WGC_GATE_MODE must be formal or diagnostic"),
    };
    assert!((1..=10).contains(&fps), "soak FPS must be between 1 and 10");
    let mut native = NativeWindows;
    let candidate = native
        .enumerate_candidates()
        .unwrap()
        .into_iter()
        .find(|candidate| {
            let path_sha256 = candidate
                .identity
                .process_path_sha256
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            candidate.identity.pid == expected_pid
                && candidate.identity.process_started_at == expected_started_at
                && path_sha256 == expected_path_sha256
        })
        .expect("the exact started Testbed identity was not enumerated");
    let backend = DxgiCaptureBackend::new(&candidate.identity).unwrap();
    let mut capture = CapturePipeline::new(
        backend,
        candidate.identity.client_rect,
        candidate.identity.dpi,
        CaptureRegion::FullClient,
        CaptureEncoding::Png,
    )
    .unwrap();
    assert_ne!(candidate.identity.pid, 0);
    assert_ne!(candidate.identity.process_started_at, 0);
    assert!(!candidate.identity.window_class.is_empty());

    let interval = Duration::from_secs_f64(1.0 / f64::from(fps));
    let started = Instant::now();
    let deadline = started + Duration::from_secs(duration_seconds);
    let mut next_tick = started;
    let mut frames = 0_u64;
    let mut maximum_frame_bytes = 0_usize;
    while Instant::now() < deadline {
        let frame_started = Instant::now();
        let frame = capture
            .next_frame(frame_started + Duration::from_secs(5))
            .unwrap();
        assert!(!frame.bytes.is_empty());
        assert_eq!(
            (frame.width, frame.height),
            (
                candidate.identity.client_rect.width,
                candidate.identity.client_rect.height
            )
        );
        frames += 1;
        maximum_frame_bytes = maximum_frame_bytes.max(frame.bytes.len());
        next_tick += interval;
        thread::sleep(next_tick.saturating_duration_since(Instant::now()));
    }
    let elapsed_seconds = started.elapsed().as_secs_f64();
    let actual_fps = frames as f64 / elapsed_seconds;
    let minimum_actual_fps = f64::from(fps) * 0.95;
    assert!(
        actual_fps >= minimum_actual_fps,
        "actual FPS {actual_fps:.3} is below the gate {minimum_actual_fps:.3}"
    );
    println!(
        "FAIRYPAM_WGC_SOAK_RECEIPT={}",
        serde_json::json!({
            "gate": gate,
            "nonce": nonce,
            "testbed_pid": candidate.identity.pid,
            "testbed_process_started_at_unix_ms": candidate.identity.process_started_at,
            "testbed_process_path_sha256": expected_path_sha256,
            "duration_seconds": duration_seconds,
            "elapsed_seconds": elapsed_seconds,
            "requested_fps": fps,
            "minimum_actual_fps": minimum_actual_fps,
            "actual_fps": actual_fps,
            "captured_frames": frames,
            "maximum_frame_bytes": maximum_frame_bytes,
        })
    );
}
