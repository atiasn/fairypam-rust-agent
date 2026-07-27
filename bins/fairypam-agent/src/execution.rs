use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::{CaptureRegion, VerifiedProfile};
use fairypam_agent_core::target::{TargetBinding, TargetCandidate, TargetSelector, TargetSnapshot};
use fairypam_agent_core::AgentError;
use fairypam_agent_local_protocol::LocalCommand;
use fairypam_agent_protocol::v1::{
    agent_control_event, hub_control_command, AgentControlEvent, AttemptRef, FramePacket,
    HubControlCommand, SafetyEvent, SessionRef, TaskAttemptReceiptV1, TaskCommandOutcomeV1,
};
use fairypam_agent_transport::{SessionFrameSlot, VerifiedSession};
use serde_json::json;

use crate::profile_store::ProfileStore;
use crate::task_attempt::{TaskAttemptRuntime, TaskCommandResult};

const MAX_CLOSE_TIMEOUT_MS: u32 = 5_000;
const MAX_INPUT_LEASE_MS: u32 = 5_000;
const CAPTURE_NO_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const M1_ACTION_ID: &str = "interaction.confirm";
type CaptureFailure = (AgentError, Option<AttemptRef>);
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
    fn start_task_target(&mut self, profile: &VerifiedProfile)
        -> Result<TargetBinding, AgentError>;

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

    fn start_task_input(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
        session: &SessionRef,
        expires_at: Instant,
    ) -> Result<(), AgentError>;

    fn pulse_task_action(
        &mut self,
        binding: &TargetBinding,
        session: &SessionRef,
        action_id: &str,
        now: Instant,
    ) -> Result<(), AgentError>;

    fn release_task_input(&mut self) -> Result<(), AgentError>;

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

    fn task(result: TaskCommandResult) -> Self {
        Self::TaskAck {
            result: "{}".into(),
            outcome: Some(result.outcome),
            receipt: Box::new(result.receipt),
        }
    }
}

struct CaptureWorker {
    source_id: String,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<CaptureFailure>>>,
    thread: Option<JoinHandle<()>>,
}

impl CaptureWorker {
    fn failure(&self) -> Result<Option<(AgentError, Option<AttemptRef>)>, AgentError> {
        let failure = self
            .failure
            .lock()
            .map_err(|error| AgentError::new("capture.worker_failed", error.to_string()))
            .map(|failure| failure.clone())?;
        if failure.is_none() && self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(Some((
                AgentError::new(
                    "capture.worker_failed",
                    "capture worker exited unexpectedly",
                ),
                None,
            )));
        }
        Ok(failure)
    }

    fn stop(mut self) -> Result<(), AgentError> {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            join_capture_thread(thread)?;
        }
        self.failure()?.map_or(Ok(()), |(error, _)| Err(error))
    }
}

fn join_capture_thread(thread: JoinHandle<()>) -> Result<(), AgentError> {
    let deadline = Instant::now() + CAPTURE_JOIN_TIMEOUT;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            tracing::error!("capture thread did not stop; aborting Agent before unsafe detach");
            std::process::abort();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    thread
        .join()
        .map_err(|_| AgentError::new("capture.worker_failed", "capture worker panicked"))
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
        let emergency_stopped = self.task_attempt.emergency_stopped()?;
        if emergency_stopped
            && !matches!(
                command,
                LocalCommand::Status | LocalCommand::ReleaseAll | LocalCommand::ResetEmergencyStop
            )
        {
            return Err(AgentError::new(
                "emergency_stopped",
                "only local emergency cleanup or reset is allowed while stopped",
            ));
        }
        if self.task_attempt.is_active()?
            && !matches!(command, LocalCommand::Status | LocalCommand::ReleaseAll)
        {
            return Err(AgentError::new(
                "task_command_not_allowed",
                "active M1 task attempt rejects this local command",
            ));
        }
        match command {
            LocalCommand::Status => Ok(json!({
                "state": if emergency_stopped {
                    "EmergencyStopped"
                } else if self.binding.is_some() {
                    "TargetLocked"
                } else {
                    "ConnectedIdle"
                },
                "capture_active": self.capture.is_some(),
                "build_id": option_env!("FAIRYPAM_BUILD_ID").unwrap_or("unknown"),
                "suite_version": env!("CARGO_PKG_VERSION"),
                "guardian_state": if emergency_stopped {
                    "emergency_stopped"
                } else if self.binding.is_none() && self.capture.is_none() {
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
            LocalCommand::ReleaseAll => self.emergency_stop(),
            LocalCommand::ResetEmergencyStop => {
                self.task_attempt.reset_emergency()?;
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
        let payload = command.payload.as_ref();
        if self.task_attempt.emergency_stopped()?
            && !matches!(payload, Some(Payload::InspectTaskAttempt(_)))
        {
            return Err(AgentError::new(
                "emergency_stopped",
                "remote commands cannot reset a local emergency stop",
            ));
        }
        if self.task_attempt.is_active()? && !task_payload_allowed(payload) {
            return Err(AgentError::new(
                "task_command_not_allowed",
                "active M1 task attempt rejects this command kind",
            ));
        }
        match payload {
            Some(Payload::LaunchTarget(value)) => {
                if self.binding.is_some() {
                    return Err(AgentError::new(
                        "target.active",
                        "launch requires no active target",
                    ));
                }
                let profile = self.profiles.get(&value.profile_id)?.clone();
                let binding = self.platform.start_task_target(&profile)?;
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
                self.platform.release_task_input()?;
                let capture_error = self.stop_capture(None).err();
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
                        "capture_error": capture_error.as_ref().map(AgentError::code),
                        "state": "ConnectedIdle",
                    })
                    .to_string(),
                ))
            }
            Some(Payload::StartCapture(value)) => {
                let task = value.task.as_ref();
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
                if let Some(task) = task {
                    if self.task_attempt.profile_id(task)? != profile.profile().id {
                        return Err(AgentError::new(
                            "profile_mismatch",
                            "task capture Profile does not match the claimed attempt",
                        ));
                    }
                    if let Some(result) = self.task_attempt.prepare(task, false)? {
                        return Ok(CommandOutcome::task(result));
                    }
                }
                self.stop_capture(None)?;
                let capture =
                    match self
                        .platform
                        .start_capture(&binding, source.region.clone(), encoding)
                    {
                        Ok(capture) => capture,
                        Err(error) => {
                            if let Some(task) = task {
                                return Ok(CommandOutcome::task(
                                    self.task_attempt.complete_capture(
                                        task,
                                        false,
                                        Some(error.code()),
                                    )?,
                                ));
                            }
                            return Err(error);
                        }
                    };
                let frame_sequence = Arc::clone(
                    self.frame_sequences
                        .entry(value.source_id.clone())
                        .or_insert_with(|| Arc::new(AtomicU64::new(0))),
                );
                let attempt = task
                    .map(|task| self.task_attempt.attempt_ref(task))
                    .transpose()?;
                let worker = spawn_capture_worker(
                    capture,
                    frame_sequence,
                    value.source_id.clone(),
                    value.fps,
                    encoding,
                    session,
                    frames,
                    attempt,
                    CAPTURE_NO_FRAME_TIMEOUT,
                );
                let worker = match worker {
                    Ok(worker) => worker,
                    Err(error) => {
                        if let Some(task) = task {
                            return Ok(CommandOutcome::task(self.task_attempt.complete_capture(
                                task,
                                false,
                                Some(error.code()),
                            )?));
                        }
                        return Err(error);
                    }
                };
                self.capture = Some(worker);
                if let Some(task) = task {
                    return Ok(CommandOutcome::task(
                        self.task_attempt.complete_capture(task, true, None)?,
                    ));
                }
                Ok(CommandOutcome::Ack(
                    json!({"capture_source_id": value.source_id, "state": "running"}).to_string(),
                ))
            }
            Some(Payload::StopCapture(value)) => {
                if let Some(task) = value.task.as_ref() {
                    if let Some(result) = self.task_attempt.prepare(task, false)? {
                        return Ok(CommandOutcome::task(result));
                    }
                    if let Err(error) = self.stop_capture(Some(&value.source_id)) {
                        return Ok(CommandOutcome::task(self.task_attempt.complete_capture(
                            task,
                            true,
                            Some(error.code()),
                        )?));
                    }
                    return Ok(CommandOutcome::task(
                        self.task_attempt.complete_capture(task, false, None)?,
                    ));
                }
                self.stop_capture(Some(&value.source_id))?;
                Ok(CommandOutcome::Ack(
                    json!({"capture_source_id": value.source_id, "state": "stopped"}).to_string(),
                ))
            }
            Some(Payload::ReleaseAll(value)) => {
                if let Some(task) = value.task.as_ref() {
                    if let Some(result) = self.task_attempt.prepare(task, false)? {
                        return Ok(CommandOutcome::task(result));
                    }
                    let error = self.platform.release_task_input().err();
                    return Ok(CommandOutcome::task(
                        self.task_attempt
                            .complete_release(task, error.as_ref().map(AgentError::code))?,
                    ));
                }
                Ok(CommandOutcome::Ack(
                    json!({"state": "DryRun", "holds": 0}).to_string(),
                ))
            }
            Some(Payload::StopSession(_)) => {
                self.platform.release_task_input()?;
                self.stop_capture(None)?;
                self.active_profile = None;
                self.binding = None;
                Ok(CommandOutcome::Ack(
                    json!({"state": "ConnectedIdle"}).to_string(),
                ))
            }
            Some(Payload::InputLease(value)) if value.task.is_some() => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
                if !(1..=MAX_INPUT_LEASE_MS).contains(&value.ttl_ms)
                    || !value.desired_hold_actions.is_empty()
                {
                    return Err(AgentError::new(
                        "input_lease_invalid",
                        "M1 input lease must be bounded and contain no hold actions",
                    ));
                }
                if let Some(result) = self.task_attempt.prepare(task, false)? {
                    return Ok(CommandOutcome::task(result));
                }
                let profile_id = self.task_attempt.profile_id(task)?;
                let profile = self.profiles.get(&profile_id)?.clone();
                let binding = self
                    .binding
                    .clone()
                    .ok_or_else(|| AgentError::new("target_invalid", "task target is not ready"))?;
                let session = task
                    .command
                    .as_ref()
                    .and_then(|command| command.session.as_ref())
                    .ok_or_else(task_reference_invalid)?;
                let expires_at = Instant::now() + Duration::from_millis(u64::from(value.ttl_ms));
                let error = self
                    .platform
                    .start_task_input(&profile, &binding, session, expires_at)
                    .err();
                Ok(CommandOutcome::task(
                    self.task_attempt
                        .complete_input_lease(task, error.as_ref().map(AgentError::code))?,
                ))
            }
            Some(Payload::PulseAction(value)) if value.task.is_some() => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
                if value.action_id != M1_ACTION_ID {
                    return Err(AgentError::new(
                        "task_command_not_allowed",
                        "M1 task allows only interaction.confirm",
                    ));
                }
                if let Some(result) = self.task_attempt.replay(task)? {
                    return Ok(CommandOutcome::task(result));
                }
                let source_frame_sequence = value.source_frame_sequence.ok_or_else(|| {
                    AgentError::new(
                        "source_frame_stale",
                        "M1 pulse action requires a current source frame",
                    )
                })?;
                let current_frame_sequence = self
                    .frame_sequences
                    .get("client")
                    .map(|sequence| sequence.load(Ordering::Acquire))
                    .unwrap_or_default();
                if source_frame_sequence == 0 || source_frame_sequence != current_frame_sequence {
                    return Err(AgentError::new(
                        "source_frame_stale",
                        "pulse action source frame is not the latest task frame",
                    ));
                }
                if let Some(result) = self.task_attempt.prepare(task, true)? {
                    return Ok(CommandOutcome::task(result));
                }
                let binding = self
                    .binding
                    .clone()
                    .ok_or_else(|| AgentError::new("target_invalid", "task target is not ready"))?;
                let session = task
                    .command
                    .as_ref()
                    .and_then(|command| command.session.as_ref())
                    .ok_or_else(task_reference_invalid)?;
                let error = self
                    .platform
                    .pulse_task_action(&binding, session, &value.action_id, Instant::now())
                    .err();
                Ok(CommandOutcome::task(self.task_attempt.complete_pulse(
                    task,
                    source_frame_sequence,
                    error.is_none(),
                    error.as_ref().map(AgentError::code),
                )?))
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
            Some(Payload::StartTaskTarget(value)) => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
                if let Some(result) = self.task_attempt.prepare(task, true)? {
                    return Ok(CommandOutcome::task(result));
                }
                let profile_id = self.task_attempt.profile_id(task)?;
                let profile = self.profiles.get(&profile_id)?.clone();
                let started = self.platform.start_task_target(&profile);
                match started {
                    Ok(binding) => {
                        self.active_profile = Some(profile);
                        self.binding = Some(binding.clone());
                        Ok(CommandOutcome::task(
                            self.task_attempt
                                .complete_target_start(task, Some(binding), None)?,
                        ))
                    }
                    Err(error) => Ok(CommandOutcome::task(
                        self.task_attempt
                            .complete_target_start(task, None, Some(error.code()))?,
                    )),
                }
            }
            Some(Payload::FinishTaskAttempt(value)) => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
                if let Some(result) = self.task_attempt.prepare_finish(task)? {
                    return Ok(CommandOutcome::task(result));
                }
                let release_error = self.platform.release_task_input().err();
                let capture_stopped = self.stop_capture(None).is_ok();
                let owned_target = self.task_attempt.owned_target(task)?;
                let close_error = owned_target.as_ref().and_then(|binding| {
                    self.platform
                        .close(
                            binding,
                            Duration::from_millis(u64::from(MAX_CLOSE_TIMEOUT_MS)),
                        )
                        .err()
                });
                let target_closed = close_error.is_none();
                if target_closed {
                    self.active_profile = None;
                    self.binding = None;
                }
                let error_code = release_error
                    .as_ref()
                    .or(close_error.as_ref())
                    .map(AgentError::code);
                Ok(CommandOutcome::task(self.task_attempt.complete_finish(
                    task,
                    release_error.is_none(),
                    capture_stopped,
                    target_closed,
                    error_code,
                )?))
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
            worker.stop()?;
        }
        Ok(())
    }

    pub fn capture_failure_event(
        &mut self,
        session: &ExecutionSession,
    ) -> Result<Option<AgentControlEvent>, AgentError> {
        let Some((failure, attempt)) = self
            .capture
            .as_ref()
            .map(CaptureWorker::failure)
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        let source_id = self
            .capture
            .as_ref()
            .expect("checked above")
            .source_id
            .clone();
        let release_error = self.platform.release_task_input().err();
        let _ = self.capture.take().expect("checked above").stop();
        self.frame_sequences.remove(&source_id);
        if let Some(error) = release_error {
            return Err(error);
        }
        Ok(Some(AgentControlEvent {
            payload: Some(agent_control_event::Payload::SafetyEvent(SafetyEvent {
                session: Some(session.reference.clone()),
                reason: failure.code().to_owned(),
                state: "capture_failed".to_owned(),
                attempt,
            })),
        }))
    }

    pub fn reset(&mut self) -> Result<(), AgentError> {
        if self.task_attempt.is_active()? || self.task_attempt.emergency_stopped()? {
            self.emergency_stop()?;
            return Ok(());
        }
        self.platform.release_task_input()?;
        self.stop_capture(None)?;
        self.active_profile = None;
        self.binding = None;
        self.frame_sequences.clear();
        Ok(())
    }

    fn emergency_stop(&mut self) -> Result<serde_json::Value, AgentError> {
        self.task_attempt.set_emergency_stopped(true)?;
        let release_error = self.platform.release_task_input().err();
        let capture_error = self.stop_capture(None).err();
        let owned_target = self.task_attempt.active_owned_target()?;
        let close_error = owned_target.as_ref().and_then(|binding| {
            self.platform
                .close(
                    binding,
                    Duration::from_millis(u64::from(MAX_CLOSE_TIMEOUT_MS)),
                )
                .err()
        });
        let target_closed = close_error.is_none();
        if target_closed {
            self.active_profile = None;
            self.binding = None;
        }
        self.frame_sequences.clear();
        let error_code = capture_error
            .as_ref()
            .or(release_error.as_ref())
            .or(close_error.as_ref())
            .map(AgentError::code);
        let receipt = self.task_attempt.emergency_finish(
            release_error.is_none(),
            capture_error.is_none(),
            target_closed,
            error_code,
        )?;
        Ok(json!({
            "state": "EmergencyStopped",
            "holds": 0,
            "cleanup_complete": receipt.as_ref().and_then(|value| value.cleanup_complete),
            "error_code": receipt.as_ref().and_then(|value| value.error_code.as_deref()),
        }))
    }

    pub fn emergency_release_input(&mut self) -> Result<(), AgentError> {
        self.platform.release_task_input()
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

fn task_payload_allowed(payload: Option<&hub_control_command::Payload>) -> bool {
    use hub_control_command::Payload;
    match payload {
        Some(
            Payload::BeginTaskAttempt(_)
            | Payload::StartTaskTarget(_)
            | Payload::FinishTaskAttempt(_)
            | Payload::InspectTaskAttempt(_),
        ) => true,
        Some(Payload::StartCapture(value)) => value.task.is_some(),
        Some(Payload::StopCapture(value)) => value.task.is_some(),
        Some(Payload::InputLease(value)) => value.task.is_some(),
        Some(Payload::PulseAction(value)) => value.task.is_some(),
        Some(Payload::ReleaseAll(value)) => value.task.is_some(),
        _ => false,
    }
}

impl Drop for CommandExecutor {
    fn drop(&mut self) {
        let _ = self.stop_capture(None);
        let _ = self.platform.release_task_input();
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

#[allow(clippy::too_many_arguments)]
fn spawn_capture_worker(
    mut capture: Box<dyn RuntimeCapture>,
    frame_sequence: Arc<AtomicU64>,
    source_id: String,
    fps: u32,
    encoding: RuntimeCaptureEncoding,
    session: &ExecutionSession,
    frames: Arc<dyn FrameSink>,
    attempt: Option<AttemptRef>,
    no_frame_timeout: Duration,
) -> Result<CaptureWorker, AgentError> {
    let stop = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(Mutex::new(None));
    let worker_stop = Arc::clone(&stop);
    let worker_failure = Arc::clone(&failure);
    let worker_source = source_id.clone();
    let session = session.reference.clone();
    let thread = std::thread::Builder::new()
        .name(format!("fairypam-capture-{source_id}"))
        .spawn(move || {
            let interval = Duration::from_secs_f64(1.0 / f64::from(fps));
            let mut reported_overwrites = 0;
            let mut last_frame_at = Instant::now();
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
                                record_capture_failure(
                                    &worker_failure,
                                    AgentError::new(
                                        "capture.sequence_exhausted",
                                        "capture frame sequence exhausted",
                                    ),
                                    attempt.clone(),
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
                            attempt: attempt.clone(),
                        };
                        if let Err(error) = frames.publish(packet) {
                            tracing::error!(code = error.code(), %error, "frame publish failed");
                            record_capture_failure(&worker_failure, error, attempt.clone());
                            break;
                        }
                        last_frame_at = Instant::now();
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
                    Err(error) if error.code() == "capture.deadline" => {
                        if worker_stop.load(Ordering::Acquire) {
                            break;
                        }
                        if last_frame_at.elapsed() >= no_frame_timeout {
                            record_capture_failure(
                                &worker_failure,
                                AgentError::new(
                                    "capture.no_frame_timeout",
                                    "capture produced no frame within the bounded deadline",
                                ),
                                attempt.clone(),
                            );
                            break;
                        }
                        tracing::debug!(
                            capture_source_id = %worker_source,
                            "capture frame deadline missed"
                        );
                    }
                    Err(error) => {
                        tracing::error!(code = error.code(), %error, "capture failed");
                        if !worker_stop.load(Ordering::Acquire) {
                            record_capture_failure(&worker_failure, error, attempt.clone());
                        }
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
        failure,
        thread: Some(thread),
    })
}

fn record_capture_failure(
    failure: &Mutex<Option<CaptureFailure>>,
    error: AgentError,
    attempt: Option<AttemptRef>,
) {
    if let Ok(mut failure) = failure.lock() {
        failure.get_or_insert((error, attempt));
    }
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
    fn start_task_target(
        &mut self,
        _profile: &VerifiedProfile,
    ) -> Result<TargetBinding, AgentError> {
        Err(AgentError::new(
            "target.platform_unsupported",
            "task target startup requires Windows",
        ))
    }

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

    fn start_task_input(
        &mut self,
        _profile: &VerifiedProfile,
        _binding: &TargetBinding,
        _session: &SessionRef,
        _expires_at: Instant,
    ) -> Result<(), AgentError> {
        Err(AgentError::new(
            "input.platform_unsupported",
            "task input requires Windows",
        ))
    }

    fn pulse_task_action(
        &mut self,
        _binding: &TargetBinding,
        _session: &SessionRef,
        _action_id: &str,
        _now: Instant,
    ) -> Result<(), AgentError> {
        Err(AgentError::new(
            "input.platform_unsupported",
            "task input requires Windows",
        ))
    }

    fn release_task_input(&mut self) -> Result<(), AgentError> {
        Ok(())
    }
}

#[cfg(windows)]
struct WindowsRuntimePlatform {
    targets: fairypam_agent_windows::WindowsTargetPlatform<fairypam_agent_windows::NativeWindows>,
    owned: Option<OwnedTaskProcess>,
    task_input: Option<WindowsTaskInput>,
}

#[cfg(windows)]
struct OwnedTaskProcess {
    _child: std::process::Child,
    job: usize,
    binding: TargetBinding,
}

#[cfg(windows)]
struct OwnedJob(usize);

#[cfg(windows)]
impl OwnedJob {
    fn into_raw(self) -> usize {
        let raw = self.0;
        std::mem::forget(self);
        raw
    }
}

#[cfg(windows)]
impl Drop for OwnedJob {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};

        // SAFETY: this value owns the Job Object handle until this drop.
        let _ = unsafe { CloseHandle(HANDLE(self.0 as _)) };
    }
}

#[cfg(windows)]
impl Drop for OwnedTaskProcess {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};

        // SAFETY: this value owns the Job Object handle until this drop.
        let _ = unsafe { CloseHandle(HANDLE(self.job as _)) };
    }
}

#[cfg(windows)]
struct WindowsTaskInput {
    machine: fairypam_agent_core::state::Machine,
    input: fairypam_agent_windows::WindowsInput<fairypam_agent_input::GuardianProcessClient>,
    session: fairypam_agent_input::SessionKey,
}

#[cfg(windows)]
struct TaskAuthorization {
    expires_at: Instant,
}

#[cfg(windows)]
impl fairypam_agent_core::platform::LocalAuthorization for TaskAuthorization {
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

#[cfg(windows)]
impl WindowsRuntimePlatform {
    fn new() -> Self {
        Self {
            targets: fairypam_agent_windows::WindowsTargetPlatform::new(
                fairypam_agent_windows::NativeWindows,
            ),
            owned: None,
            task_input: None,
        }
    }

    fn task_guardian_path() -> Result<std::path::PathBuf, AgentError> {
        let executable = std::env::current_exe()
            .map_err(|error| AgentError::new("guardian.unavailable", error.to_string()))?;
        let guardian = executable
            .parent()
            .ok_or_else(|| AgentError::new("guardian.unavailable", "Agent path has no parent"))?
            .join("fairypam-agent-guardian.exe");
        if !guardian.is_file() {
            return Err(AgentError::new(
                "guardian.unavailable",
                "Agent artifact is missing fairypam-agent-guardian.exe",
            ));
        }
        Ok(guardian)
    }
}

#[cfg(windows)]
impl Drop for WindowsRuntimePlatform {
    fn drop(&mut self) {
        let _ = <Self as RuntimePlatform>::release_task_input(self);
        self.owned = None;
    }
}

#[cfg(windows)]
fn kill_on_close_job() -> Result<OwnedJob, AgentError> {
    use windows::core::PCWSTR;
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    // SAFETY: the unnamed Job Object has no borrowed security attributes.
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|error| AgentError::new("target.launch_failed", error.to_string()))?;
    let owned = OwnedJob(job.0 as usize);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: limits is a correctly sized value for JobObjectExtendedLimitInformation.
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    }
    .map_err(|error| AgentError::new("target.launch_failed", error.to_string()))?;
    Ok(owned)
}

#[cfg(windows)]
impl RuntimePlatform for WindowsRuntimePlatform {
    fn start_task_target(
        &mut self,
        profile: &VerifiedProfile,
    ) -> Result<TargetBinding, AgentError> {
        use fairypam_agent_core::platform::TargetPlatform;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::JobObjects::AssignProcessToJobObject;

        if let Some(owned) = self.owned.as_ref() {
            if owned.binding.profile_id != profile.profile().id {
                return Err(AgentError::new(
                    "target_invalid",
                    "an Agent-owned target for another Profile is already active",
                ));
            }
            let process_id = owned.binding.process_id;
            let candidate = self
                .targets
                .enumerate(profile)?
                .into_iter()
                .find(|candidate| candidate.process_id == process_id)
                .ok_or_else(|| {
                    AgentError::new(
                        "target_invalid",
                        "the Agent-owned target is no longer a signed Profile candidate",
                    )
                })?;
            let binding = self.targets.lock(profile, candidate.selector)?;
            self.owned.as_mut().expect("checked above").binding = binding.clone();
            return Ok(binding);
        }
        let executable = crate::observability::resolve_profile_executable(profile)?;
        let working_directory = executable.parent().ok_or_else(|| {
            AgentError::new(
                "target_invalid",
                "trusted executable has no working directory",
            )
        })?;
        let job = kill_on_close_job()?;
        let mut child = std::process::Command::new(&executable)
            .current_dir(working_directory)
            .spawn()
            .map_err(|error| AgentError::new("target.launch_failed", error.to_string()))?;
        // SAFETY: child owns a valid process handle and job owns a configured Job Object handle.
        if unsafe { AssignProcessToJobObject(HANDLE(job.0 as _), HANDLE(child.as_raw_handle())) }
            .is_err()
        {
            let _ = child.kill();
            return Err(AgentError::new(
                "target.launch_failed",
                "task target could not be assigned to its cleanup Job Object",
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        let binding = loop {
            if child
                .try_wait()
                .map_err(|error| AgentError::new("target.launch_failed", error.to_string()))?
                .is_some()
            {
                return Err(AgentError::new(
                    "target.launch_failed",
                    "task target exited before its trusted window was ready",
                ));
            }
            if let Some(candidate) = self
                .targets
                .enumerate(profile)?
                .into_iter()
                .find(|candidate| candidate.process_id == child.id())
            {
                break self.targets.lock(profile, candidate.selector)?;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                return Err(AgentError::new(
                    "target.launch_failed",
                    "task target window did not become ready within 60 seconds",
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        self.owned = Some(OwnedTaskProcess {
            _child: child,
            job: job.into_raw(),
            binding: binding.clone(),
        });
        Ok(binding)
    }

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
        if let Some(owned) = self.owned.as_ref() {
            if owned.binding.process_id != binding.process_id
                || owned.binding.window_handle != binding.window_handle
            {
                return Err(AgentError::new(
                    "target_invalid",
                    "refusing to close a target not owned by this task",
                ));
            }
        }
        if let Err(error) = self.targets.close(binding, timeout) {
            if self.owned.is_some() || !matches!(error.code(), "target.stale" | "target.not_found")
            {
                return Err(error);
            }
        }
        self.owned = None;
        Ok(())
    }

    fn start_task_input(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
        session: &SessionRef,
        expires_at: Instant,
    ) -> Result<(), AgentError> {
        use fairypam_agent_core::state::{Machine, SessionIdentity};
        use fairypam_agent_input::{ActionMap, GuardianProcessClient, InputLease, InputPermit};

        self.release_task_input()?;
        let now = Instant::now();
        let snapshot = self.targets.focus(binding)?;
        let session = SessionIdentity {
            agent_id: session.agent_id.clone(),
            session_id: session.session_id.clone(),
            generation: session.generation,
        };
        let authorization = TaskAuthorization { expires_at };
        let mut machine = Machine::new();
        machine.start_completed()?;
        machine.control_connected(session.clone())?;
        machine.activate_profile(profile)?;
        machine.lock_target(binding.clone())?;
        machine.preflight_passed(snapshot.clone())?;
        machine.enter_dry_run()?;
        machine.request_arm(&authorization, now, expires_at)?;
        machine.begin_control(now)?;
        let action_map = ActionMap::from_verified_profile(profile)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        let guardian = GuardianProcessClient::spawn(
            &Self::task_guardian_path()?,
            action_map.physical_holds(),
            Duration::from_millis(300),
        )
        .map_err(|error| AgentError::new("guardian.unavailable", error.to_string()))?;
        let mut input = self
            .targets
            .start_input(profile, binding.clone(), guardian)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        {
            let permit =
                InputPermit::from_capability(machine.issue_input_capability(now, &snapshot, true)?);
            input
                .apply_lease(
                    InputLease {
                        session: session.clone(),
                        sequence: 1,
                        expires_at,
                        desired_holds: std::collections::BTreeSet::new(),
                    },
                    &permit,
                    now,
                )
                .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        }
        self.task_input = Some(WindowsTaskInput {
            machine,
            input,
            session,
        });
        Ok(())
    }

    fn pulse_task_action(
        &mut self,
        binding: &TargetBinding,
        session: &SessionRef,
        action_id: &str,
        now: Instant,
    ) -> Result<(), AgentError> {
        use fairypam_agent_core::platform::TargetPlatform;
        use fairypam_agent_input::{ActionId, InputPermit};

        let snapshot = self.targets.revalidate(binding)?;
        if !snapshot.foreground || snapshot.minimized || !snapshot.capturable {
            let _ = self.release_task_input();
            return Err(AgentError::new(
                "local_authorization_denied",
                "task target lost foreground or capture eligibility",
            ));
        }
        let input = self.task_input.as_ref().ok_or_else(|| {
            AgentError::new("input_lease_invalid", "task input lease is not active")
        })?;
        if input.session.agent_id != session.agent_id
            || input.session.session_id != session.session_id
            || input.session.generation != session.generation
        {
            let _ = self.release_task_input();
            return Err(AgentError::new(
                "input_lease_invalid",
                "task input lease belongs to another Control session",
            ));
        }
        let input = self.task_input.as_mut().ok_or_else(|| {
            AgentError::new("input_lease_invalid", "task input lease is not active")
        })?;
        let permit = InputPermit::from_capability(
            input.machine.issue_input_capability(now, &snapshot, true)?,
        );
        let action = ActionId::new(action_id.to_owned())
            .map_err(|error| AgentError::new("task_command_not_allowed", error.to_string()))?;
        input
            .input
            .execute_pulse(&action, &input.session, &permit, now)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))
    }

    fn release_task_input(&mut self) -> Result<(), AgentError> {
        use fairypam_agent_input::ReleaseReason;

        let Some(mut input) = self.task_input.take() else {
            return Ok(());
        };
        input
            .input
            .release_all(ReleaseReason::SessionChanged)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))
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
        EnumerateTargets, FinishTaskAttempt, FocusTarget, InputLease, InspectTaskAttempt,
        LaunchTarget, LockTarget, PulseAction, SessionRef, StartCapture, StartTaskTarget,
        StopCapture, TaskAttemptState, TaskCommandOutcomeState, TaskCommandRef,
        TaskSideEffectState,
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
                actions: BTreeMap::from([
                    (
                        "move.forward".into(),
                        ActionDefinition::Hold { scan_code: 17 },
                    ),
                    (
                        M1_ACTION_ID.into(),
                        ActionDefinition::Pulse { scan_code: 33 },
                    ),
                ]),
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
                .ok_or_else(|| AgentError::new("capture.deadline", "test frame gap"))
        }
    }

    struct DeadlineThenFrameCapture {
        calls: u8,
    }

    impl RuntimeCapture for DeadlineThenFrameCapture {
        fn next_frame(&mut self, _deadline: Instant) -> Result<RuntimeCapturedFrame, AgentError> {
            self.calls += 1;
            match self.calls {
                1 => Err(AgentError::new("capture.deadline", "transient frame gap")),
                2 => Ok(RuntimeCapturedFrame {
                    bytes: vec![1, 2, 3],
                    width: 1280,
                    height: 720,
                    sequence: 1,
                }),
                _ => Err(AgentError::new("capture.deadline", "test frame gap")),
            }
        }
    }

    struct DeadlineCapture;

    impl RuntimeCapture for DeadlineCapture {
        fn next_frame(&mut self, _deadline: Instant) -> Result<RuntimeCapturedFrame, AgentError> {
            Err(AgentError::new("capture.deadline", "no frame"))
        }
    }

    #[derive(Default)]
    struct FakePlatformState {
        launch_calls: usize,
        target_owned: bool,
        focus_calls: Vec<TargetBinding>,
        close_calls: Vec<(TargetBinding, Duration)>,
        input_active: bool,
        pulse_calls: Vec<String>,
        fail_close: bool,
    }

    #[derive(Default)]
    struct FakePlatform {
        state: Arc<Mutex<FakePlatformState>>,
    }

    impl RuntimePlatform for FakePlatform {
        fn start_task_target(
            &mut self,
            _profile: &VerifiedProfile,
        ) -> Result<TargetBinding, AgentError> {
            let mut state = self.state.lock().unwrap();
            if !state.target_owned {
                state.launch_calls += 1;
                state.target_owned = true;
            }
            Ok(binding())
        }

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
                state.target_owned = false;
                Ok(())
            }
        }

        fn start_task_input(
            &mut self,
            _profile: &VerifiedProfile,
            _binding: &TargetBinding,
            _session: &SessionRef,
            _expires_at: Instant,
        ) -> Result<(), AgentError> {
            self.state.lock().unwrap().input_active = true;
            Ok(())
        }

        fn pulse_task_action(
            &mut self,
            _binding: &TargetBinding,
            _session: &SessionRef,
            action_id: &str,
            _now: Instant,
        ) -> Result<(), AgentError> {
            let mut state = self.state.lock().unwrap();
            if !state.input_active {
                return Err(AgentError::new(
                    "input_lease_invalid",
                    "fake input lease is not active",
                ));
            }
            state.pulse_calls.push(action_id.into());
            Ok(())
        }

        fn release_task_input(&mut self) -> Result<(), AgentError> {
            self.state.lock().unwrap().input_active = false;
            Ok(())
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

    #[test]
    fn transient_capture_deadline_does_not_stop_the_worker() {
        let sink = Arc::new(CollectFrames::default());
        let worker = spawn_capture_worker(
            Box::new(DeadlineThenFrameCapture { calls: 0 }),
            Arc::new(AtomicU64::new(0)),
            "client".into(),
            100,
            RuntimeCaptureEncoding::Jpeg { quality: 80 },
            &ExecutionSession::test(),
            sink.clone(),
            None,
            Duration::from_secs(1),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        worker.stop().unwrap();

        assert_eq!(sink.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn persistent_capture_deadline_reports_a_bounded_failure() {
        let worker = spawn_capture_worker(
            Box::new(DeadlineCapture),
            Arc::new(AtomicU64::new(0)),
            "client".into(),
            100,
            RuntimeCaptureEncoding::Jpeg { quality: 80 },
            &ExecutionSession::test(),
            Arc::new(CollectFrames::default()),
            None,
            Duration::from_millis(30),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));

        assert_eq!(
            worker.failure().unwrap().unwrap().0.code(),
            "capture.no_frame_timeout"
        );
        assert_eq!(
            worker.stop().unwrap_err().code(),
            "capture.no_frame_timeout"
        );
    }

    #[test]
    fn capture_failure_releases_input_before_join_and_emits_safety_event() {
        let (mut executor, state) = executor_with_state();
        let sequence = Arc::new(AtomicU64::new(0));
        executor
            .frame_sequences
            .insert("client".into(), sequence.clone());
        executor.capture = Some(
            spawn_capture_worker(
                Box::new(DeadlineCapture),
                sequence,
                "client".into(),
                100,
                RuntimeCaptureEncoding::Jpeg { quality: 80 },
                &ExecutionSession::test(),
                Arc::new(CollectFrames::default()),
                None,
                Duration::from_millis(30),
            )
            .unwrap(),
        );
        state.lock().unwrap().input_active = true;
        std::thread::sleep(Duration::from_millis(100));

        let event = executor
            .capture_failure_event(&ExecutionSession::test())
            .unwrap()
            .unwrap();

        assert!(!state.lock().unwrap().input_active);
        assert!(executor.capture.is_none());
        assert!(!executor.frame_sequences.contains_key("client"));
        assert!(matches!(
            event.payload,
            Some(agent_control_event::Payload::SafetyEvent(SafetyEvent {
                ref reason,
                ref state,
                ..
            })) if reason == "capture.no_frame_timeout" && state == "capture_failed"
        ));
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
    fn generic_launch_is_profile_only_and_task_reuses_the_agent_owned_target() {
        let profile = verified_profile();
        let contract = task_contract(&profile);
        let (mut executor, state) = executor_with_state();
        let sink = Arc::new(CollectFrames::default());
        let launch = HubControlCommand {
            payload: Some(hub_control_command::Payload::LaunchTarget(LaunchTarget {
                profile_id: "testbed".into(),
                ..LaunchTarget::default()
            })),
        };
        assert!(matches!(
            executor.execute(&launch, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Ack(ref result) if result.contains("\"pid\":42")
        ));

        let begin = HubControlCommand {
            payload: Some(hub_control_command::Payload::BeginTaskAttempt(
                BeginTaskAttempt {
                    task: Some(task_ref(&contract, "begin-prelaunched")),
                    contract: Some(contract.clone()),
                },
            )),
        };
        assert!(matches!(
            executor.execute(&begin, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { .. }
        ));
        let start = HubControlCommand {
            payload: Some(hub_control_command::Payload::StartTaskTarget(
                StartTaskTarget {
                    task: Some(task_ref(&contract, "target-prelaunched")),
                },
            )),
        };
        assert!(matches!(
            executor.execute(&start, &ExecutionSession::test(), sink),
            CommandOutcome::TaskAck { .. }
        ));
        assert_eq!(state.lock().unwrap().launch_calls, 1);
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
    fn task_target_frame_pulse_and_finish_stay_attempt_bound_and_idempotent() {
        let profile = verified_profile();
        let contract = task_contract(&profile);
        let state = Arc::new(Mutex::new(FakePlatformState::default()));
        let mut executor = CommandExecutor::with_platform(
            ProfileStore::from_verified_profiles([profile]).unwrap(),
            Box::new(FakePlatform {
                state: Arc::clone(&state),
            }),
        );
        let sink = Arc::new(CollectFrames::default());
        let begin = HubControlCommand {
            payload: Some(hub_control_command::Payload::BeginTaskAttempt(
                BeginTaskAttempt {
                    task: Some(task_ref(&contract, "begin-1")),
                    contract: Some(contract.clone()),
                },
            )),
        };
        assert!(matches!(
            executor.execute(&begin, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { .. }
        ));

        let start_target = HubControlCommand {
            payload: Some(hub_control_command::Payload::StartTaskTarget(
                StartTaskTarget {
                    task: Some(task_ref(&contract, "target-1")),
                },
            )),
        };
        assert!(matches!(
            executor.execute(&start_target, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { ref outcome, .. }
                if outcome.as_ref().unwrap().outcome == TaskCommandOutcomeState::Applied as i32
        ));

        let start_capture = HubControlCommand {
            payload: Some(hub_control_command::Payload::StartCapture(StartCapture {
                source_id: "client".into(),
                fps: 10,
                encoding: "jpeg".into(),
                quality: 80,
                task: Some(task_ref(&contract, "capture-1")),
                ..StartCapture::default()
            })),
        };
        assert!(matches!(
            executor.execute(&start_capture, &ExecutionSession::test(), sink.clone(),),
            CommandOutcome::TaskAck { .. }
        ));
        std::thread::sleep(Duration::from_millis(150));

        let lease = HubControlCommand {
            payload: Some(hub_control_command::Payload::InputLease(InputLease {
                ttl_ms: 1_000,
                task: Some(task_ref(&contract, "lease-1")),
                ..InputLease::default()
            })),
        };
        assert!(matches!(
            executor.execute(&lease, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { .. }
        ));
        let stale_pulse = HubControlCommand {
            payload: Some(hub_control_command::Payload::PulseAction(PulseAction {
                action_id: M1_ACTION_ID.into(),
                source_frame_sequence: Some(2),
                task: Some(task_ref(&contract, "pulse-stale")),
                ..PulseAction::default()
            })),
        };
        assert!(matches!(
            executor.execute(&stale_pulse, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Nack { ref code, .. } if code == "source_frame_stale"
        ));
        let inspect_after_stale = HubControlCommand {
            payload: Some(hub_control_command::Payload::InspectTaskAttempt(
                InspectTaskAttempt {
                    task: Some(task_ref(&contract, "inspect-after-stale")),
                },
            )),
        };
        assert!(matches!(
            executor.execute(
                &inspect_after_stale,
                &ExecutionSession::test(),
                sink.clone(),
            ),
            CommandOutcome::TaskAck { ref receipt, .. }
                if receipt.side_effect_state == TaskSideEffectState::Applied as i32
                    && receipt.last_side_effect_command_id == "target-1"
        ));

        let pulse = HubControlCommand {
            payload: Some(hub_control_command::Payload::PulseAction(PulseAction {
                action_id: M1_ACTION_ID.into(),
                source_frame_sequence: Some(1),
                task: Some(task_ref(&contract, "pulse-1")),
                ..PulseAction::default()
            })),
        };
        assert!(matches!(
            executor.execute(&pulse, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { ref outcome, .. }
                if outcome.as_ref().unwrap().outcome
                    == TaskCommandOutcomeState::Applied as i32
        ));
        executor
            .frame_sequences
            .get("client")
            .unwrap()
            .store(2, Ordering::Release);
        assert!(matches!(
            executor.execute(&pulse, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { ref outcome, .. }
                if outcome.as_ref().unwrap().outcome
                    == TaskCommandOutcomeState::Applied as i32
        ));
        let mut changed_payload = pulse.clone();
        if let Some(hub_control_command::Payload::PulseAction(value)) =
            changed_payload.payload.as_mut()
        {
            value.task.as_mut().unwrap().payload_digest = "d".repeat(64);
        }
        assert!(matches!(
            executor.execute(&changed_payload, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::Nack { ref code, .. } if code == "command_payload_mismatch"
        ));
        assert_eq!(state.lock().unwrap().pulse_calls, vec![M1_ACTION_ID]);

        let finish = HubControlCommand {
            payload: Some(hub_control_command::Payload::FinishTaskAttempt(
                FinishTaskAttempt {
                    task: Some(task_ref(&contract, "finish-1")),
                },
            )),
        };
        assert!(matches!(
            executor.execute(&finish, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { ref receipt, .. }
                if receipt.attempt_state == TaskAttemptState::Terminal as i32
                    && receipt.cleanup_complete == Some(true)
        ));
        let frames = sink.0.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].attempt.as_ref().unwrap().attempt_id,
            contract.attempt_id
        );
        assert_eq!(state.lock().unwrap().launch_calls, 1);
        assert_eq!(state.lock().unwrap().close_calls.len(), 1);
    }

    #[test]
    fn local_emergency_stop_cleans_active_attempt_and_requires_local_reset() {
        let profile = verified_profile();
        let contract = task_contract(&profile);
        let state = Arc::new(Mutex::new(FakePlatformState::default()));
        let mut executor = CommandExecutor::with_platform(
            ProfileStore::from_verified_profiles([profile]).unwrap(),
            Box::new(FakePlatform {
                state: Arc::clone(&state),
            }),
        );
        let sink = Arc::new(CollectFrames::default());
        for command in [
            HubControlCommand {
                payload: Some(hub_control_command::Payload::BeginTaskAttempt(
                    BeginTaskAttempt {
                        task: Some(task_ref(&contract, "begin-emergency")),
                        contract: Some(contract.clone()),
                    },
                )),
            },
            HubControlCommand {
                payload: Some(hub_control_command::Payload::StartTaskTarget(
                    StartTaskTarget {
                        task: Some(task_ref(&contract, "target-emergency")),
                    },
                )),
            },
            HubControlCommand {
                payload: Some(hub_control_command::Payload::StartCapture(StartCapture {
                    source_id: "client".into(),
                    fps: 10,
                    encoding: "jpeg".into(),
                    quality: 80,
                    task: Some(task_ref(&contract, "capture-emergency")),
                    ..StartCapture::default()
                })),
            },
            HubControlCommand {
                payload: Some(hub_control_command::Payload::InputLease(InputLease {
                    ttl_ms: 1_000,
                    task: Some(task_ref(&contract, "lease-emergency")),
                    ..InputLease::default()
                })),
            },
        ] {
            assert!(matches!(
                executor.execute(&command, &ExecutionSession::test(), sink.clone()),
                CommandOutcome::TaskAck { .. }
            ));
        }

        let stopped = executor.execute_local(&LocalCommand::ReleaseAll).unwrap();
        assert_eq!(stopped["state"], "EmergencyStopped");
        assert_eq!(stopped["cleanup_complete"], true);
        assert!(!state.lock().unwrap().input_active);
        assert_eq!(state.lock().unwrap().close_calls.len(), 1);
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["state"],
            "EmergencyStopped"
        );

        let new_attempt = HubControlCommand {
            payload: Some(hub_control_command::Payload::BeginTaskAttempt(
                BeginTaskAttempt {
                    task: Some(task_ref(&contract, "begin-after-emergency")),
                    contract: Some(contract),
                },
            )),
        };
        assert!(matches!(
            executor.execute(&new_attempt, &ExecutionSession::test(), sink),
            CommandOutcome::Nack { ref code, .. } if code == "emergency_stopped"
        ));
        assert_eq!(
            executor
                .execute_local(&LocalCommand::ResetEmergencyStop)
                .unwrap()["state"],
            "ConnectedIdle"
        );
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["state"],
            "ConnectedIdle"
        );
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
