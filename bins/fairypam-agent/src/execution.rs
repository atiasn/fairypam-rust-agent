use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::{CaptureRegion, VerifiedProfile};
use fairypam_agent_core::target::{TargetBinding, TargetCandidate, TargetSelector, TargetSnapshot};
use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v1::{
    hub_control_command, FramePacket, HubControlCommand, SessionRef,
};
use fairypam_agent_transport::{SessionFrameSlot, VerifiedSession};
use serde_json::json;

use crate::profile_store::ProfileStore;

const MAX_CLOSE_TIMEOUT_MS: u32 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeCaptureEncoding {
    Jpeg { quality: u8 },
    Png,
}

pub struct RuntimeCapturedFrame {
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub sequence: u64,
}

pub trait RuntimeCapture: Send {
    fn next_frame(&mut self, deadline: Instant) -> Result<RuntimeCapturedFrame, AgentError>;
}

pub trait FrameSink: Send + Sync {
    fn publish(&self, frame: FramePacket) -> Result<(), AgentError>;

    fn overwritten_frames(&self) -> u64 {
        0
    }
}

impl FrameSink for SessionFrameSlot {
    fn publish(&self, frame: FramePacket) -> Result<(), AgentError> {
        SessionFrameSlot::publish(self, frame)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))
    }

    fn overwritten_frames(&self) -> u64 {
        SessionFrameSlot::overwritten_frames(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionSession {
    reference: SessionRef,
}

impl ExecutionSession {
    pub fn from_verified(session: &VerifiedSession) -> Self {
        Self {
            reference: SessionRef {
                agent_id: session.agent_id().to_owned(),
                session_id: session.session_id().to_owned(),
                generation: session.generation(),
            },
        }
    }

    #[cfg(test)]
    fn test() -> Self {
        Self {
            reference: SessionRef {
                agent_id: "11111111-1111-1111-1111-111111111111".into(),
                session_id: "session-1".into(),
                generation: 1,
            },
        }
    }
}

pub trait RuntimePlatform: Send {
    fn enumerate(&mut self, profile: &VerifiedProfile) -> Result<Vec<TargetCandidate>, AgentError>;

    fn lock(
        &mut self,
        profile: &VerifiedProfile,
        selector: TargetSelector,
    ) -> Result<TargetBinding, AgentError>;

    fn start_capture(
        &mut self,
        binding: &TargetBinding,
        region: CaptureRegion,
        encoding: RuntimeCaptureEncoding,
    ) -> Result<Box<dyn RuntimeCapture>, AgentError>;

    fn focus(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError>;

    fn close(&mut self, binding: &TargetBinding, timeout: Duration) -> Result<(), AgentError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandOutcome {
    Ack(String),
    Nack { code: String, message: String },
}

impl CommandOutcome {
    fn from_error(error: AgentError) -> Self {
        Self::Nack {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

struct CaptureWorker {
    source_id: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CaptureWorker {
    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub struct CommandExecutor {
    profiles: ProfileStore,
    platform: Box<dyn RuntimePlatform>,
    active_profile: Option<VerifiedProfile>,
    binding: Option<TargetBinding>,
    capture: Option<CaptureWorker>,
    frame_sequences: BTreeMap<String, Arc<AtomicU64>>,
}

impl CommandExecutor {
    pub fn production(profiles: ProfileStore) -> Self {
        Self::with_platform(profiles, production_platform())
    }

    pub fn with_platform(profiles: ProfileStore, platform: Box<dyn RuntimePlatform>) -> Self {
        Self {
            profiles,
            platform,
            active_profile: None,
            binding: None,
            capture: None,
            frame_sequences: BTreeMap::new(),
        }
    }

    pub fn execute(
        &mut self,
        command: &HubControlCommand,
        session: &ExecutionSession,
        frames: Arc<dyn FrameSink>,
    ) -> CommandOutcome {
        self.execute_inner(command, session, frames)
            .unwrap_or_else(CommandOutcome::from_error)
    }

    fn execute_inner(
        &mut self,
        command: &HubControlCommand,
        session: &ExecutionSession,
        frames: Arc<dyn FrameSink>,
    ) -> Result<CommandOutcome, AgentError> {
        use hub_control_command::Payload;
        match command.payload.as_ref() {
            Some(Payload::EnumerateTargets(value)) => {
                self.stop_capture(None)?;
                let profile = self.profiles.get(&value.profile_id)?.clone();
                let candidates = self.platform.enumerate(&profile)?;
                self.active_profile = Some(profile);
                self.binding = None;
                let candidates = candidates
                    .iter()
                    .map(|candidate| {
                        json!({
                            "hwnd": candidate.window_handle,
                            "pid": candidate.process_id,
                            "process_path_sha256": candidate.process_path_sha256,
                            "window_class": candidate.window_class,
                            "title": candidate.window_title,
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(CommandOutcome::Ack(
                    json!({"candidates": candidates}).to_string(),
                ))
            }
            Some(Payload::LockTarget(value)) => {
                self.stop_capture(None)?;
                let profile = self.profiles.get(&value.profile_id)?.clone();
                let candidates = self.platform.enumerate(&profile)?;
                let selector = candidates
                    .iter()
                    .find(|candidate| {
                        candidate.window_handle == value.hwnd && candidate.process_id == value.pid
                    })
                    .map(|candidate| candidate.selector.clone())
                    .ok_or_else(|| {
                        AgentError::new(
                            "target.not_found",
                            "requested target is not a current signed Profile candidate",
                        )
                    })?;
                let binding = self.platform.lock(&profile, selector)?;
                self.active_profile = Some(profile);
                self.binding = Some(binding.clone());
                Ok(CommandOutcome::Ack(
                    json!({
                        "profile_id": binding.profile_id,
                        "pid": binding.process_id,
                        "hwnd": binding.window_handle,
                        "state": "DryRun",
                    })
                    .to_string(),
                ))
            }
            Some(Payload::FocusTarget(_)) => {
                let binding = self.binding.clone().ok_or_else(|| {
                    AgentError::new("target.not_locked", "focus requires a locked target")
                })?;
                let snapshot = self.platform.focus(&binding)?;
                self.binding = Some(snapshot.binding.clone());
                Ok(CommandOutcome::Ack(
                    json!({
                        "profile_id": snapshot.binding.profile_id,
                        "pid": snapshot.binding.process_id,
                        "hwnd": snapshot.binding.window_handle,
                        "window_title": snapshot.binding.window_title,
                        "window_class": snapshot.binding.window_class,
                        "client_width": snapshot.binding.client_rect.width,
                        "client_height": snapshot.binding.client_rect.height,
                        "dpi": snapshot.binding.dpi,
                        "foreground": snapshot.foreground,
                        "minimized": snapshot.minimized,
                        "capturable": snapshot.capturable,
                        "state": "DryRun",
                    })
                    .to_string(),
                ))
            }
            Some(Payload::CloseTarget(value)) => {
                if !(1..=MAX_CLOSE_TIMEOUT_MS).contains(&value.timeout_ms) {
                    return Err(AgentError::new(
                        "target.close_timeout_invalid",
                        "close timeout must be between 1 and 5000 ms",
                    ));
                }
                let binding = self.binding.clone().ok_or_else(|| {
                    AgentError::new("target.not_locked", "close requires a locked target")
                })?;
                self.stop_capture(None)?;
                self.platform
                    .close(&binding, Duration::from_millis(u64::from(value.timeout_ms)))?;
                self.active_profile = None;
                self.binding = None;
                Ok(CommandOutcome::Ack(
                    json!({
                        "profile_id": binding.profile_id,
                        "pid": binding.process_id,
                        "hwnd": binding.window_handle,
                        "closed": true,
                        "state": "ConnectedIdle",
                    })
                    .to_string(),
                ))
            }
            Some(Payload::StartCapture(value)) => {
                let profile = self.active_profile.clone().ok_or_else(|| {
                    AgentError::new("profile.not_active", "capture requires an active Profile")
                })?;
                let binding = self.binding.clone().ok_or_else(|| {
                    AgentError::new("target.not_locked", "capture requires a locked target")
                })?;
                let source = profile
                    .profile()
                    .capture_sources
                    .iter()
                    .find(|source| source.id == value.source_id)
                    .ok_or_else(|| {
                        AgentError::new(
                            "capture.source_not_allowed",
                            "capture source is not declared by the active Profile",
                        )
                    })?;
                if value.fps == 0 || value.fps > source.maximum_fps {
                    return Err(AgentError::new(
                        "capture.fps_invalid",
                        "capture FPS exceeds the signed Profile limit",
                    ));
                }
                let encoding = parse_encoding(&value.encoding, value.quality, &source.encodings)?;
                let capture =
                    self.platform
                        .start_capture(&binding, source.region.clone(), encoding)?;
                self.stop_capture(None)?;
                let frame_sequence = Arc::clone(
                    self.frame_sequences
                        .entry(value.source_id.clone())
                        .or_insert_with(|| Arc::new(AtomicU64::new(0))),
                );
                self.capture = Some(spawn_capture_worker(
                    capture,
                    frame_sequence,
                    value.source_id.clone(),
                    value.fps,
                    encoding,
                    session,
                    frames,
                )?);
                Ok(CommandOutcome::Ack(
                    json!({"capture_source_id": value.source_id, "state": "running"}).to_string(),
                ))
            }
            Some(Payload::StopCapture(value)) => {
                self.stop_capture(Some(&value.source_id))?;
                Ok(CommandOutcome::Ack(
                    json!({"capture_source_id": value.source_id, "state": "stopped"}).to_string(),
                ))
            }
            Some(Payload::ReleaseAll(_)) => Ok(CommandOutcome::Ack(
                json!({"state": "DryRun", "holds": 0}).to_string(),
            )),
            Some(Payload::StopSession(_)) => {
                self.stop_capture(None)?;
                self.active_profile = None;
                self.binding = None;
                Ok(CommandOutcome::Ack(
                    json!({"state": "ConnectedIdle"}).to_string(),
                ))
            }
            Some(
                Payload::InputLease(_)
                | Payload::PulseAction(_)
                | Payload::MouseDeltaAction(_)
                | Payload::WindowPointClickAction(_),
            ) => Ok(CommandOutcome::Nack {
                code: "agent.dry_run_only".into(),
                message: "production Agent has no local Arm authority".into(),
            }),
            Some(Payload::Hello(_)) | None => Err(AgentError::new(
                "protocol.command_invalid",
                "HubHello is not an executable command",
            )),
        }
    }

    pub fn stop_capture(&mut self, source_id: Option<&str>) -> Result<(), AgentError> {
        if let Some(current) = self.capture.as_ref() {
            if source_id.is_some_and(|source_id| current.source_id != source_id) {
                return Err(AgentError::new(
                    "capture.source_not_active",
                    "requested capture source is not active",
                ));
            }
        }
        if let Some(worker) = self.capture.take() {
            worker.stop();
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), AgentError> {
        self.stop_capture(None)?;
        self.active_profile = None;
        self.binding = None;
        self.frame_sequences.clear();
        Ok(())
    }
}

impl Drop for CommandExecutor {
    fn drop(&mut self) {
        let _ = self.stop_capture(None);
    }
}

fn parse_encoding(
    encoding: &str,
    quality: u32,
    allowed: &[String],
) -> Result<RuntimeCaptureEncoding, AgentError> {
    if !allowed.iter().any(|allowed| allowed == encoding) {
        return Err(AgentError::new(
            "capture.encoding_not_allowed",
            "capture encoding is not declared by the active Profile",
        ));
    }
    match encoding {
        "jpeg" if (1..=100).contains(&quality) => Ok(RuntimeCaptureEncoding::Jpeg {
            quality: quality as u8,
        }),
        "png" if quality == 0 => Ok(RuntimeCaptureEncoding::Png),
        "jpeg" | "png" => Err(AgentError::new(
            "capture.quality_invalid",
            "capture quality is invalid for the requested encoding",
        )),
        _ => Err(AgentError::new(
            "capture.encoding_invalid",
            "capture encoding is unsupported",
        )),
    }
}

fn spawn_capture_worker(
    mut capture: Box<dyn RuntimeCapture>,
    frame_sequence: Arc<AtomicU64>,
    source_id: String,
    fps: u32,
    encoding: RuntimeCaptureEncoding,
    session: &ExecutionSession,
    frames: Arc<dyn FrameSink>,
) -> Result<CaptureWorker, AgentError> {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker_source = source_id.clone();
    let session = session.reference.clone();
    let thread = std::thread::Builder::new()
        .name(format!("fairypam-capture-{source_id}"))
        .spawn(move || {
            let interval = Duration::from_secs_f64(1.0 / f64::from(fps));
            let mut reported_overwrites = 0;
            while !worker_stop.load(Ordering::Acquire) {
                let started = Instant::now();
                match capture.next_frame(started + interval) {
                    Ok(frame) => {
                        let sequence = match frame_sequence.fetch_update(
                            Ordering::AcqRel,
                            Ordering::Acquire,
                            |value| value.checked_add(1),
                        ) {
                            Ok(previous) => previous + 1,
                            Err(_) => {
                                tracing::error!(
                                    capture_source_id = %worker_source,
                                    "capture frame sequence exhausted"
                                );
                                break;
                            }
                        };
                        let packet = FramePacket {
                            session: Some(session.clone()),
                            capture_source_id: worker_source.clone(),
                            frame_sequence: sequence,
                            captured_at_unix_us: now_unix_us(),
                            width: frame.width,
                            height: frame.height,
                            encoding: match encoding {
                                RuntimeCaptureEncoding::Jpeg { .. } => "jpeg".into(),
                                RuntimeCaptureEncoding::Png => "png".into(),
                            },
                            payload: frame.bytes,
                        };
                        if let Err(error) = frames.publish(packet) {
                            tracing::error!(code = error.code(), %error, "frame publish failed");
                            break;
                        }
                        let overwritten = frames.overwritten_frames();
                        if overwritten > reported_overwrites {
                            reported_overwrites = overwritten;
                            tracing::warn!(
                                capture_source_id = worker_source,
                                overwritten_frames = overwritten,
                                "latest-frame backpressure dropped stale frames"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::error!(code = error.code(), %error, "capture failed");
                        break;
                    }
                }
                std::thread::sleep(interval.saturating_sub(started.elapsed()));
            }
        })
        .map_err(|error| {
            AgentError::new(
                "capture.worker_start_failed",
                format!("capture worker thread could not start: {error}"),
            )
        })?;
    Ok(CaptureWorker {
        source_id,
        stop,
        thread: Some(thread),
    })
}

fn now_unix_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(i64::MAX as u128) as i64
}

#[cfg(windows)]
fn production_platform() -> Box<dyn RuntimePlatform> {
    Box::new(WindowsRuntimePlatform::new())
}

#[cfg(not(windows))]
fn production_platform() -> Box<dyn RuntimePlatform> {
    Box::new(UnsupportedPlatform)
}

#[cfg(not(windows))]
struct UnsupportedPlatform;

#[cfg(not(windows))]
impl RuntimePlatform for UnsupportedPlatform {
    fn enumerate(
        &mut self,
        _profile: &VerifiedProfile,
    ) -> Result<Vec<TargetCandidate>, AgentError> {
        Err(AgentError::new(
            "target.platform_unsupported",
            "target operations require Windows",
        ))
    }

    fn lock(
        &mut self,
        _profile: &VerifiedProfile,
        _selector: TargetSelector,
    ) -> Result<TargetBinding, AgentError> {
        Err(AgentError::new(
            "target.platform_unsupported",
            "target operations require Windows",
        ))
    }

    fn start_capture(
        &mut self,
        _binding: &TargetBinding,
        _region: CaptureRegion,
        _encoding: RuntimeCaptureEncoding,
    ) -> Result<Box<dyn RuntimeCapture>, AgentError> {
        Err(AgentError::new(
            "capture.platform_unsupported",
            "capture requires Windows",
        ))
    }

    fn focus(&mut self, _binding: &TargetBinding) -> Result<TargetSnapshot, AgentError> {
        Err(AgentError::new(
            "target.platform_unsupported",
            "target operations require Windows",
        ))
    }

    fn close(&mut self, _binding: &TargetBinding, _timeout: Duration) -> Result<(), AgentError> {
        Err(AgentError::new(
            "target.platform_unsupported",
            "target operations require Windows",
        ))
    }
}

#[cfg(windows)]
struct WindowsRuntimePlatform {
    targets: fairypam_agent_windows::WindowsTargetPlatform<fairypam_agent_windows::NativeWindows>,
}

#[cfg(windows)]
impl WindowsRuntimePlatform {
    fn new() -> Self {
        Self {
            targets: fairypam_agent_windows::WindowsTargetPlatform::new(
                fairypam_agent_windows::NativeWindows,
            ),
        }
    }
}

#[cfg(windows)]
impl RuntimePlatform for WindowsRuntimePlatform {
    fn enumerate(&mut self, profile: &VerifiedProfile) -> Result<Vec<TargetCandidate>, AgentError> {
        use fairypam_agent_core::platform::TargetPlatform;
        self.targets.enumerate(profile)
    }

    fn lock(
        &mut self,
        profile: &VerifiedProfile,
        selector: TargetSelector,
    ) -> Result<TargetBinding, AgentError> {
        use fairypam_agent_core::platform::TargetPlatform;
        self.targets.lock(profile, selector)
    }

    fn start_capture(
        &mut self,
        binding: &TargetBinding,
        region: CaptureRegion,
        encoding: RuntimeCaptureEncoding,
    ) -> Result<Box<dyn RuntimeCapture>, AgentError> {
        use fairypam_agent_windows::CaptureEncoding;
        let encoding = match encoding {
            RuntimeCaptureEncoding::Jpeg { quality } => CaptureEncoding::Jpeg { quality },
            RuntimeCaptureEncoding::Png => CaptureEncoding::Png,
        };
        let capture = self.targets.start_capture(binding, region, encoding)?;
        Ok(Box::new(WindowsCapture { capture }))
    }

    fn focus(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError> {
        self.targets.focus(binding)
    }

    fn close(&mut self, binding: &TargetBinding, timeout: Duration) -> Result<(), AgentError> {
        self.targets.close(binding, timeout)
    }
}

#[cfg(windows)]
struct WindowsCapture {
    capture: fairypam_agent_windows::WindowsTargetCapture,
}

#[cfg(windows)]
impl RuntimeCapture for WindowsCapture {
    fn next_frame(&mut self, deadline: Instant) -> Result<RuntimeCapturedFrame, AgentError> {
        use fairypam_agent_windows::CaptureSession;
        let frame = self
            .capture
            .next_frame(deadline)
            .map_err(AgentError::from)?;
        Ok(RuntimeCapturedFrame {
            bytes: frame.bytes,
            width: frame.width,
            height: frame.height,
            sequence: frame.sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;

    use ed25519_dalek::{Signer, SigningKey};
    use fairypam_agent_core::profile::{
        profile_content_sha256, verify_profile, ActionDefinition, CaptureSource,
        Ed25519SignatureVerifier, Profile, ProfileContent, ProfileEnvelope, TargetRules,
    };
    use fairypam_agent_core::target::{ClientRect, IntegrityLevel, TargetSnapshot};
    use fairypam_agent_protocol::v1::{
        CloseTarget, CommandRef, EnumerateTargets, FocusTarget, InputLease, LockTarget,
        StartCapture, StopCapture,
    };

    use super::*;

    fn verified_profile() -> VerifiedProfile {
        let signing = SigningKey::from_bytes(&[5_u8; 32]);
        let content = ProfileContent {
            schema_version: 1,
            profile: Profile {
                id: "testbed".into(),
                version: "1.0.0".into(),
                display_name: "Testbed".into(),
                target: TargetRules {
                    process_names: vec!["testbed.exe".into()],
                    process_path_sha256: vec!["11".repeat(32)],
                    window_classes: vec!["FairyPamTestWindow".into()],
                    title_patterns: vec!["FairyPam Test *".into()],
                    require_elevated: false,
                    minimum_client_width: 640,
                    minimum_client_height: 360,
                    minimum_dpi: 96,
                },
                capture_sources: vec![CaptureSource {
                    id: "client".into(),
                    region: CaptureRegion::FullClient,
                    maximum_fps: 10,
                    encodings: vec!["jpeg".into()],
                }],
                actions: BTreeMap::from([(
                    "move.forward".into(),
                    ActionDefinition::Hold { scan_code: 17 },
                )]),
            },
            files: Vec::new(),
        };
        let hash = profile_content_sha256(&content).unwrap();
        let mut digest = [0_u8; 32];
        for (index, chunk) in hash.as_bytes().chunks_exact(2).enumerate() {
            digest[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        let signature = signing
            .sign(&digest)
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let envelope = serde_json::to_vec(&ProfileEnvelope {
            content,
            content_sha256: hash,
            signature,
        })
        .unwrap();
        let public = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        verify_profile(
            &envelope,
            &Ed25519SignatureVerifier::from_public_key_hex(&public).unwrap(),
        )
        .unwrap()
    }

    fn candidate() -> TargetCandidate {
        TargetCandidate {
            selector: TargetSelector {
                candidate_id: "candidate-1".into(),
            },
            window_handle: 100,
            process_id: 42,
            process_name: "testbed.exe".into(),
            process_path_sha256: "11".repeat(32),
            window_title: "FairyPam Test Window".into(),
            window_class: "FairyPamTestWindow".into(),
        }
    }

    fn binding() -> TargetBinding {
        TargetBinding {
            profile_id: "testbed".into(),
            profile_version: "1.0.0".into(),
            process_id: 42,
            process_name: "testbed.exe".into(),
            process_started_at_unix_ms: 1,
            process_path_sha256: "11".repeat(32),
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

    struct FakeCapture {
        frames: VecDeque<RuntimeCapturedFrame>,
    }

    impl RuntimeCapture for FakeCapture {
        fn next_frame(&mut self, _deadline: Instant) -> Result<RuntimeCapturedFrame, AgentError> {
            self.frames
                .pop_front()
                .ok_or_else(|| AgentError::new("capture.complete", "test capture completed"))
        }
    }

    #[derive(Default)]
    struct FakePlatformState {
        focus_calls: Vec<TargetBinding>,
        close_calls: Vec<(TargetBinding, Duration)>,
        fail_close: bool,
    }

    #[derive(Default)]
    struct FakePlatform {
        state: Arc<Mutex<FakePlatformState>>,
    }

    impl RuntimePlatform for FakePlatform {
        fn enumerate(
            &mut self,
            _profile: &VerifiedProfile,
        ) -> Result<Vec<TargetCandidate>, AgentError> {
            Ok(vec![candidate()])
        }

        fn lock(
            &mut self,
            _profile: &VerifiedProfile,
            selector: TargetSelector,
        ) -> Result<TargetBinding, AgentError> {
            assert_eq!(selector.candidate_id, "candidate-1");
            Ok(binding())
        }

        fn start_capture(
            &mut self,
            _binding: &TargetBinding,
            _region: CaptureRegion,
            _encoding: RuntimeCaptureEncoding,
        ) -> Result<Box<dyn RuntimeCapture>, AgentError> {
            Ok(Box::new(FakeCapture {
                frames: VecDeque::from([RuntimeCapturedFrame {
                    bytes: vec![1, 2, 3],
                    width: 1280,
                    height: 720,
                    sequence: 1,
                }]),
            }))
        }

        fn focus(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError> {
            self.state.lock().unwrap().focus_calls.push(binding.clone());
            let mut latest = binding.clone();
            latest.window_title = "Focused Test Window".into();
            Ok(TargetSnapshot {
                binding: latest,
                foreground: true,
                minimized: false,
                capturable: true,
            })
        }

        fn close(&mut self, binding: &TargetBinding, timeout: Duration) -> Result<(), AgentError> {
            let mut state = self.state.lock().unwrap();
            state.close_calls.push((binding.clone(), timeout));
            if state.fail_close {
                Err(AgentError::new(
                    "target.close_failed",
                    "fake target did not exit",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct CollectFrames(Mutex<Vec<FramePacket>>);

    impl FrameSink for CollectFrames {
        fn publish(&self, frame: FramePacket) -> Result<(), AgentError> {
            self.0.lock().unwrap().push(frame);
            Ok(())
        }
    }

    fn executor() -> CommandExecutor {
        executor_with_state().0
    }

    fn executor_with_state() -> (CommandExecutor, Arc<Mutex<FakePlatformState>>) {
        let state = Arc::new(Mutex::new(FakePlatformState::default()));
        let executor = CommandExecutor::with_platform(
            ProfileStore::from_verified_profiles([verified_profile()]).unwrap(),
            Box::new(FakePlatform {
                state: Arc::clone(&state),
            }),
        );
        (executor, state)
    }

    fn lock_command() -> HubControlCommand {
        HubControlCommand {
            payload: Some(hub_control_command::Payload::LockTarget(LockTarget {
                hwnd: 100,
                pid: 42,
                profile_id: "testbed".into(),
                ..LockTarget::default()
            })),
        }
    }

    fn command_ref(id: &str) -> CommandRef {
        CommandRef {
            command_id: id.into(),
            ..CommandRef::default()
        }
    }

    #[test]
    fn enumerate_and_lock_return_only_profile_matched_target() {
        let mut executor = executor();
        let sink = Arc::new(CollectFrames::default());
        let enumerate = HubControlCommand {
            payload: Some(hub_control_command::Payload::EnumerateTargets(
                EnumerateTargets {
                    profile_id: "testbed".into(),
                    ..EnumerateTargets::default()
                },
            )),
        };
        let CommandOutcome::Ack(result) =
            executor.execute(&enumerate, &ExecutionSession::test(), sink.clone())
        else {
            panic!("enumeration was rejected");
        };
        assert!(result.contains("\"hwnd\":100"));

        let lock = HubControlCommand {
            payload: Some(hub_control_command::Payload::LockTarget(LockTarget {
                hwnd: 100,
                pid: 42,
                profile_id: "testbed".into(),
                ..LockTarget::default()
            })),
        };
        assert!(matches!(
            executor.execute(&lock, &ExecutionSession::test(), sink),
            CommandOutcome::Ack(_)
        ));
    }

    #[test]
    fn capture_publishes_frame_for_current_generation() {
        let mut executor = executor();
        let sink = Arc::new(CollectFrames::default());
        let lock = HubControlCommand {
            payload: Some(hub_control_command::Payload::LockTarget(LockTarget {
                hwnd: 100,
                pid: 42,
                profile_id: "testbed".into(),
                ..LockTarget::default()
            })),
        };
        assert!(matches!(
            executor.execute(&lock, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        let start = HubControlCommand {
            payload: Some(hub_control_command::Payload::StartCapture(StartCapture {
                source_id: "client".into(),
                fps: 10,
                encoding: "jpeg".into(),
                quality: 80,
                ..StartCapture::default()
            })),
        };
        assert!(matches!(
            executor.execute(&start, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        std::thread::sleep(Duration::from_millis(150));
        let stop = HubControlCommand {
            payload: Some(hub_control_command::Payload::StopCapture(StopCapture {
                source_id: "client".into(),
                ..StopCapture::default()
            })),
        };
        assert!(matches!(
            executor.execute(&stop, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        assert!(matches!(
            executor.execute(&start, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        std::thread::sleep(Duration::from_millis(150));
        assert!(matches!(
            executor.execute(&stop, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));

        let frames = sink.0.lock().unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].session.as_ref().unwrap().generation, 1);
        assert_eq!(frames[0].frame_sequence, 1);
        assert_eq!(frames[1].frame_sequence, 2);
        assert_eq!(frames[0].payload, vec![1, 2, 3]);
    }

    #[test]
    fn production_input_command_remains_dry_run_only() {
        let mut executor = executor();
        let command = HubControlCommand {
            payload: Some(hub_control_command::Payload::InputLease(InputLease {
                ttl_ms: 250,
                desired_hold_actions: vec!["move.forward".into()],
                ..InputLease::default()
            })),
        };

        assert_eq!(
            executor.execute(
                &command,
                &ExecutionSession::test(),
                Arc::new(CollectFrames::default()),
            ),
            CommandOutcome::Nack {
                code: "agent.dry_run_only".into(),
                message: "production Agent has no local Arm authority".into(),
            }
        );
    }

    #[test]
    fn focus_requires_current_locked_binding() {
        let (mut executor, state) = executor_with_state();
        let command = HubControlCommand {
            payload: Some(hub_control_command::Payload::FocusTarget(FocusTarget {
                command: Some(command_ref("focus-1")),
            })),
        };

        assert!(matches!(
            executor.execute(
                &command,
                &ExecutionSession::test(),
                Arc::new(CollectFrames::default()),
            ),
            CommandOutcome::Nack { ref code, .. } if code == "target.not_locked"
        ));
        assert!(state.lock().unwrap().focus_calls.is_empty());
    }

    #[test]
    fn focus_calls_platform_and_acks_latest_target_state_with_command_ref() {
        let (mut executor, state) = executor_with_state();
        let sink = Arc::new(CollectFrames::default());
        assert!(matches!(
            executor.execute(&lock_command(), &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        let command = HubControlCommand {
            payload: Some(hub_control_command::Payload::FocusTarget(FocusTarget {
                command: Some(command_ref("focus-2")),
            })),
        };
        let Some(hub_control_command::Payload::FocusTarget(value)) = command.payload.as_ref()
        else {
            panic!("focus command payload is missing");
        };
        assert_eq!(value.command.as_ref().unwrap().command_id, "focus-2");

        let CommandOutcome::Ack(result) =
            executor.execute(&command, &ExecutionSession::test(), sink)
        else {
            panic!("focus command was rejected");
        };
        assert!(result.contains("\"window_title\":\"Focused Test Window\""));
        assert!(result.contains("\"foreground\":true"));
        assert_eq!(state.lock().unwrap().focus_calls.len(), 1);
        assert_eq!(
            executor.binding.as_ref().unwrap().window_title,
            "Focused Test Window"
        );
    }

    #[test]
    fn close_failure_stops_capture_but_preserves_locked_state() {
        let (mut executor, state) = executor_with_state();
        state.lock().unwrap().fail_close = true;
        let sink = Arc::new(CollectFrames::default());
        assert!(matches!(
            executor.execute(&lock_command(), &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        let start = HubControlCommand {
            payload: Some(hub_control_command::Payload::StartCapture(StartCapture {
                source_id: "client".into(),
                fps: 1,
                encoding: "jpeg".into(),
                quality: 80,
                ..StartCapture::default()
            })),
        };
        assert!(matches!(
            executor.execute(&start, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        assert!(executor.capture.is_some());
        let close = HubControlCommand {
            payload: Some(hub_control_command::Payload::CloseTarget(CloseTarget {
                command: Some(command_ref("close-fail")),
                timeout_ms: 250,
            })),
        };

        assert!(matches!(
            executor.execute(&close, &ExecutionSession::test(), sink),
            CommandOutcome::Nack { ref code, .. } if code == "target.close_failed"
        ));
        assert!(executor.capture.is_none());
        assert!(executor.binding.is_some());
        assert!(executor.active_profile.is_some());
        assert_eq!(state.lock().unwrap().close_calls.len(), 1);
    }

    #[test]
    fn close_success_waits_with_bounded_timeout_then_clears_state() {
        let (mut executor, state) = executor_with_state();
        let sink = Arc::new(CollectFrames::default());
        assert!(matches!(
            executor.execute(&lock_command(), &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(_)
        ));
        let invalid = HubControlCommand {
            payload: Some(hub_control_command::Payload::CloseTarget(CloseTarget {
                command: Some(command_ref("close-invalid")),
                timeout_ms: 5_001,
            })),
        };
        assert!(matches!(
            executor.execute(&invalid, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Nack { ref code, .. } if code == "target.close_timeout_invalid"
        ));
        assert!(state.lock().unwrap().close_calls.is_empty());
        assert!(executor.binding.is_some());

        let close = HubControlCommand {
            payload: Some(hub_control_command::Payload::CloseTarget(CloseTarget {
                command: Some(command_ref("close-ok")),
                timeout_ms: 5_000,
            })),
        };
        let Some(hub_control_command::Payload::CloseTarget(value)) = close.payload.as_ref() else {
            panic!("close command payload is missing");
        };
        assert_eq!(value.command.as_ref().unwrap().command_id, "close-ok");
        assert!(matches!(
            executor.execute(&close, &ExecutionSession::test(), sink),
            CommandOutcome::Ack(_)
        ));
        assert!(executor.binding.is_none());
        assert!(executor.active_profile.is_none());
        let state = state.lock().unwrap();
        assert_eq!(state.close_calls.len(), 1);
        assert_eq!(state.close_calls[0].1, Duration::from_secs(5));
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_returns_stable_target_error_for_focus_and_close() {
        let mut platform = UnsupportedPlatform;
        assert_eq!(
            platform.focus(&binding()).unwrap_err().code(),
            "target.platform_unsupported"
        );
        assert_eq!(
            platform
                .close(&binding(), Duration::from_millis(500))
                .unwrap_err()
                .code(),
            "target.platform_unsupported"
        );
    }
}
