use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::{CaptureRegion, VerifiedProfile};
use fairypam_agent_core::target::{TargetBinding, TargetCandidate, TargetSelector, TargetSnapshot};
use fairypam_agent_core::AgentError;
use fairypam_agent_local_protocol::LocalCommand;
use fairypam_agent_protocol::v1::{
    hub_control_command, FramePacket, HubControlCommand, SessionRef, TaskAttemptReceiptV1,
    TaskCommandOutcomeV1,
};
use fairypam_agent_transport::{SessionFrameSlot, VerifiedSession};
use serde_json::json;

use crate::profile_store::ProfileStore;
use crate::task_attempt::TaskAttemptRuntime;

const MAX_CLOSE_TIMEOUT_MS: u32 = 5_000;
#[cfg(all(windows, feature = "dev-automation"))]
const DEV_TESTBED_PROFILE_ID: &str = "fairypam-test-window";
#[cfg(all(windows, feature = "dev-automation"))]
const DEV_TESTBED_ACTION_ID: &str = "move.forward";

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

    #[cfg(all(windows, feature = "dev-automation"))]
    fn testbed_pulse(
        &mut self,
        profile: &VerifiedProfile,
        expires_at: Instant,
    ) -> Result<(), AgentError>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum CommandOutcome {
    Ack(String),
    TaskAck {
        result: String,
        outcome: Option<TaskCommandOutcomeV1>,
        receipt: Box<TaskAttemptReceiptV1>,
    },
    Nack {
        code: String,
        message: String,
    },
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
    task_attempt: TaskAttemptRuntime,
}

impl CommandExecutor {
    pub fn production(profiles: ProfileStore) -> Self {
        Self::with_platform_and_attempts(
            profiles,
            production_platform(),
            TaskAttemptRuntime::production(),
        )
    }

    pub fn with_platform(profiles: ProfileStore, platform: Box<dyn RuntimePlatform>) -> Self {
        Self::with_platform_and_attempts(profiles, platform, TaskAttemptRuntime::memory())
    }

    fn with_platform_and_attempts(
        profiles: ProfileStore,
        platform: Box<dyn RuntimePlatform>,
        task_attempt: TaskAttemptRuntime,
    ) -> Self {
        Self {
            profiles,
            platform,
            active_profile: None,
            binding: None,
            capture: None,
            frame_sequences: BTreeMap::new(),
            task_attempt,
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

    pub fn execute_local(
        &mut self,
        command: &LocalCommand,
    ) -> Result<serde_json::Value, AgentError> {
        match command {
            LocalCommand::Status => Ok(json!({
                "state": if self.binding.is_some() { "TargetLocked" } else { "ConnectedIdle" },
                "capture_active": self.capture.is_some(),
                "build_id": option_env!("FAIRYPAM_BUILD_ID").unwrap_or("unknown"),
                "suite_version": env!("CARGO_PKG_VERSION"),
                "guardian_state": if self.binding.is_none() && self.capture.is_none() {
                    "idle_no_holds"
                } else {
                    "active"
                },
            })),
            LocalCommand::Doctor => {
                Ok(json!({"profiles": self.profiles.ids(), "runtime": "dry_run"}))
            }
            LocalCommand::ListProfiles => Ok(json!({"profiles": self.profiles.ids()})),
            LocalCommand::EnumerateTargets { profile_id } => {
                self.stop_capture(None)?;
                let profile = self.profiles.get(profile_id)?.clone();
                let candidates = self.platform.enumerate(&profile)?;
                self.active_profile = Some(profile);
                self.binding = None;
                Ok(
                    json!({"candidates": candidates.into_iter().map(|candidate| json!({
                    "candidate_id": candidate.selector.candidate_id,
                    "pid": candidate.process_id,
                    "process_path_sha256": candidate.process_path_sha256,
                    "window_class": candidate.window_class,
                    "title": candidate.window_title,
                })).collect::<Vec<_>>() }),
                )
            }
            LocalCommand::LockTarget {
                profile_id,
                candidate_id,
            } => {
                self.stop_capture(None)?;
                let profile = self.profiles.get(profile_id)?.clone();
                let selector = self
                    .platform
                    .enumerate(&profile)?
                    .into_iter()
                    .find(|candidate| candidate.selector.candidate_id == *candidate_id)
                    .map(|candidate| candidate.selector)
                    .ok_or_else(|| {
                        AgentError::new(
                            "target.not_found",
                            "requested candidate is no longer a signed Profile target",
                        )
                    })?;
                let binding = self.platform.lock(&profile, selector)?;
                self.active_profile = Some(profile);
                self.binding = Some(binding.clone());
                Ok(
                    json!({"profile_id": binding.profile_id, "pid": binding.process_id, "state": "DryRun"}),
                )
            }
            LocalCommand::FocusTarget => {
                let binding = self.binding.clone().ok_or_else(|| {
                    AgentError::new("target.not_locked", "focus requires a locked target")
                })?;
                let snapshot = self.platform.focus(&binding)?;
                self.binding = Some(snapshot.binding.clone());
                Ok(
                    json!({"profile_id": snapshot.binding.profile_id, "foreground": snapshot.foreground, "minimized": snapshot.minimized, "capturable": snapshot.capturable}),
                )
            }
            LocalCommand::StopCapture { source_id } => {
                self.stop_capture(Some(source_id))?;
                Ok(json!({"capture_source_id": source_id, "state": "stopped"}))
            }
            #[cfg(feature = "dev-automation")]
            LocalCommand::TestbedPulse => self.execute_dev_testbed_pulse(),
            LocalCommand::ReleaseAll => {
                self.reset()?;
                Ok(json!({"state": "ConnectedIdle", "holds": 0}))
            }
            LocalCommand::StartCapture { .. } => Err(AgentError::new(
                "capture.local_sink_unavailable",
                "local capture requires a verified Frame session; it will not discard frames",
            )),
            LocalCommand::UpdateStatus | LocalCommand::StartupStatus => {
                Ok(json!({"status": "unsupported"}))
            }
            LocalCommand::GetConnectionStatus
            | LocalCommand::RunEnvironmentCheck
            | LocalCommand::GetLogTail { .. }
            | LocalCommand::ScanInstalledGames
            | LocalCommand::BindUiLifetime
            | LocalCommand::ShutdownAgent
            | LocalCommand::RegisterHub { .. } => Err(AgentError::new(
                "local.observability_runtime_required",
                "local observability requires the Agent runtime state",
            )),
        }
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
            Some(Payload::UpdateDirective(_)) => Err(AgentError::new(
                "execution.update_wrong_layer",
                "update directives are handled by the runtime lifecycle",
            )),
            Some(Payload::BeginTaskAttempt(value)) => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
                let contract = value.contract.as_ref().ok_or_else(task_reference_invalid)?;
                let profile = self.profiles.get(&contract.profile_id)?;
                if profile.content_sha256() != contract.profile_digest {
                    return Err(AgentError::new(
                        "profile_mismatch",
                        "Agent task contract does not match the installed signed Profile",
                    ));
                }
                let build_id = option_env!("FAIRYPAM_BUILD_ID").unwrap_or("unknown");
                if contract.agent_build_id != build_id {
                    return Err(AgentError::new(
                        "agent_build_mismatch",
                        "Agent task contract does not match this Agent build",
                    ));
                }
                Ok(CommandOutcome::TaskAck {
                    result: "{}".into(),
                    outcome: None,
                    receipt: Box::new(self.task_attempt.begin(task, contract)?),
                })
            }
            Some(Payload::InspectTaskAttempt(value)) => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
                Ok(CommandOutcome::TaskAck {
                    result: "{}".into(),
                    outcome: None,
                    receipt: Box::new(self.task_attempt.inspect(task)?),
                })
            }
            Some(Payload::StartTaskTarget(_) | Payload::FinishTaskAttempt(_)) => {
                Ok(CommandOutcome::Nack {
                    code: "task.not_implemented".into(),
                    message: "M1 task target lifecycle is not implemented".into(),
                })
            }
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

    #[cfg(all(windows, feature = "dev-automation"))]
    fn execute_dev_testbed_pulse(&mut self) -> Result<serde_json::Value, AgentError> {
        let profile = self.profiles.get(DEV_TESTBED_PROFILE_ID)?.clone();
        self.platform
            .testbed_pulse(&profile, Instant::now() + Duration::from_secs(5))?;
        Ok(json!({
            "profile_id": DEV_TESTBED_PROFILE_ID,
            "action_id": DEV_TESTBED_ACTION_ID,
            "state": "released",
        }))
    }

    #[cfg(all(not(windows), feature = "dev-automation"))]
    fn execute_dev_testbed_pulse(&mut self) -> Result<serde_json::Value, AgentError> {
        Err(AgentError::new(
            "dev.testbed.platform_unsupported",
            "unattended Testbed input requires Windows",
        ))
    }
}

fn task_reference_invalid() -> AgentError {
    AgentError::new(
        "task.reference_invalid",
        "task command reference or Agent contract is missing",
    )
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
                            attempt: None,
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

    #[cfg(feature = "dev-automation")]
    fn testbed_pulse(
        &mut self,
        profile: &VerifiedProfile,
        expires_at: Instant,
    ) -> Result<(), AgentError> {
        use fairypam_agent_core::platform::TargetPlatform;
        use fairypam_agent_core::state::{Machine, SessionIdentity};
        use fairypam_agent_input::{
            ActionId, ActionMap, GuardianProcessClient, InputLease, InputPermit, ReleaseReason,
        };

        let now = Instant::now();
        let action = ActionId::new(DEV_TESTBED_ACTION_ID.to_owned())
            .map_err(|error| AgentError::new("profile.action_invalid", error.to_string()))?;
        let action_map = ActionMap::from_verified_profile(profile)
            .map_err(|error| AgentError::new("profile.action_invalid", error.to_string()))?;
        action_map
            .resolve(&action)
            .map_err(|error| AgentError::new("profile.action_invalid", error.to_string()))?;
        let candidates = self.targets.enumerate(profile)?;
        let [candidate] = candidates.as_slice() else {
            return Err(AgentError::new(
                "dev.testbed.target_ambiguous",
                "unattended Dev input requires exactly one signed fairypam-test-window target",
            ));
        };
        let binding = self.targets.lock(profile, candidate.selector.clone())?;
        let snapshot = self.targets.focus(&binding)?;

        let session = SessionIdentity {
            agent_id: "fairypam-dev-testbed".to_owned(),
            session_id: format!("{}-{}", std::process::id(), now_unix_us()),
            generation: 1,
        };
        let authorization = DevTestbedAuthorization { expires_at };
        let mut machine = Machine::new();
        machine.start_completed()?;
        machine.control_connected(session.clone())?;
        machine.activate_profile(profile)?;
        machine.lock_target(binding.clone())?;
        machine.preflight_passed(snapshot.clone())?;
        machine.enter_dry_run()?;
        machine.request_arm(&authorization, now, expires_at)?;
        machine.begin_control(now)?;

        let guardian = GuardianProcessClient::spawn(
            &dev_guardian_path()?,
            action_map.physical_holds(),
            Duration::from_millis(300),
        )
        .map_err(|error| AgentError::new("dev.testbed.guardian_unavailable", error.to_string()))?;
        let mut input = self
            .targets
            .start_input(profile, binding.clone(), guardian)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        let apply_result = {
            let permit =
                InputPermit::from_capability(machine.issue_input_capability(now, &snapshot, true)?);
            input.apply_lease(
                InputLease {
                    session,
                    sequence: 1,
                    expires_at,
                    desired_holds: std::collections::BTreeSet::from([action]),
                },
                &permit,
                now,
            )
        };
        let release_result = input.release_all(ReleaseReason::AgentExited);
        if let Err(error) = apply_result {
            return Err(AgentError::new(error.code(), error.to_string()));
        }
        release_result.map_err(|error| AgentError::new(error.code(), error.to_string()))
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
struct DevTestbedAuthorization {
    expires_at: Instant,
}

#[cfg(all(windows, feature = "dev-automation"))]
impl fairypam_agent_core::platform::LocalAuthorization for DevTestbedAuthorization {
    fn current(&self, now: Instant) -> fairypam_agent_core::platform::AuthorizationState {
        if self.expires_at > now {
            fairypam_agent_core::platform::AuthorizationState::Granted {
                expires_at: self.expires_at,
            }
        } else {
            fairypam_agent_core::platform::AuthorizationState::Denied
        }
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
fn dev_guardian_path() -> Result<std::path::PathBuf, AgentError> {
    let executable = std::env::current_exe()
        .map_err(|error| AgentError::new("dev.testbed.guardian_unavailable", error.to_string()))?;
    let guardian = executable
        .parent()
        .ok_or_else(|| {
            AgentError::new(
                "dev.testbed.guardian_unavailable",
                "Dev Agent executable has no artifact directory",
            )
        })?
        .join("fairypam-agent-guardian.exe");
    if !guardian.is_file() {
        return Err(AgentError::new(
            "dev.testbed.guardian_unavailable",
            "Dev artifact is missing fairypam-agent-guardian.exe",
        ));
    }
    Ok(guardian)
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
        AgentAttemptContractV1, AttemptRef, BeginTaskAttempt, CloseTarget, CommandRef,
        EnumerateTargets, FocusTarget, InputLease, InspectTaskAttempt, LockTarget, SessionRef,
        StartCapture, StopCapture, TaskAttemptState, TaskCommandRef,
    };
    use sha2::{Digest, Sha256};

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

        #[cfg(all(windows, feature = "dev-automation"))]
        fn testbed_pulse(
            &mut self,
            _profile: &VerifiedProfile,
            _expires_at: Instant,
        ) -> Result<(), AgentError> {
            Ok(())
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

    fn task_contract(profile: &VerifiedProfile) -> AgentAttemptContractV1 {
        let mut contract = AgentAttemptContractV1 {
            task_run_id: "11111111-1111-4111-8111-111111111111".into(),
            attempt_id: "22222222-2222-4222-8222-222222222222".into(),
            agent_build_id: option_env!("FAIRYPAM_BUILD_ID").unwrap_or("unknown").into(),
            profile_id: profile.profile().id.clone(),
            profile_digest: profile.content_sha256().into(),
            cleanup_policy: "close_owned_target".into(),
            contract_version: 1,
            contract_digest: String::new(),
        };
        let canonical =
            fairypam_agent_protocol::canonical_agent_attempt_contract(&contract).unwrap();
        contract.contract_digest = Sha256::digest(canonical.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        contract
    }

    fn task_ref(contract: &AgentAttemptContractV1, command_id: &str) -> TaskCommandRef {
        TaskCommandRef {
            command: Some(CommandRef {
                session: Some(SessionRef {
                    agent_id: "agent".into(),
                    session_id: "session".into(),
                    generation: 1,
                }),
                command_id: command_id.into(),
                sequence: 1,
                expires_at_unix_ms: i64::MAX,
            }),
            attempt: Some(AttemptRef {
                task_run_id: contract.task_run_id.clone(),
                attempt_id: contract.attempt_id.clone(),
                contract_version: contract.contract_version,
                contract_digest: contract.contract_digest.clone(),
            }),
            payload_digest: "c".repeat(64),
        }
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
    fn begin_and_inspect_return_typed_claim_receipts() {
        let profile = verified_profile();
        let contract = task_contract(&profile);
        let mut executor = CommandExecutor::with_platform(
            ProfileStore::from_verified_profiles([profile]).unwrap(),
            Box::new(FakePlatform::default()),
        );
        let begin = HubControlCommand {
            payload: Some(hub_control_command::Payload::BeginTaskAttempt(
                BeginTaskAttempt {
                    task: Some(task_ref(&contract, "begin-1")),
                    contract: Some(contract.clone()),
                },
            )),
        };
        let CommandOutcome::TaskAck { receipt, .. } = executor.execute(
            &begin,
            &ExecutionSession::test(),
            Arc::new(CollectFrames::default()),
        ) else {
            panic!("task attempt claim was rejected");
        };
        assert_eq!(receipt.attempt_state, TaskAttemptState::Claimed as i32);

        let inspect = HubControlCommand {
            payload: Some(hub_control_command::Payload::InspectTaskAttempt(
                InspectTaskAttempt {
                    task: Some(task_ref(&contract, "inspect-1")),
                },
            )),
        };
        assert!(matches!(
            executor.execute(
                &inspect,
                &ExecutionSession::test(),
                Arc::new(CollectFrames::default()),
            ),
            CommandOutcome::TaskAck { receipt, .. }
                if receipt.attempt_state == TaskAttemptState::Claimed as i32
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
