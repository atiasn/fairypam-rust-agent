use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::runtime_api::{InputProbeAction, RuntimeCommand as LocalCommand};
use fairypam_agent_core::profile::{CaptureRegion, VerifiedProfile};
use fairypam_agent_core::target::{TargetBinding, TargetCandidate, TargetSelector, TargetSnapshot};
use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v1::{
    agent_control_event, hub_control_command, AgentControlEvent, AttemptRef, FramePacket,
    HubControlCommand, SafetyEvent, SessionRef, TaskAttemptReceiptV1, TaskCommandOutcomeV1,
};
use fairypam_agent_protocol::v2;
use fairypam_agent_transport::{SessionFrameSlot, VerifiedSession};
use serde_json::json;

use crate::profile_store::ProfileStore;
use crate::task_attempt::{TaskAttemptRuntime, TaskCommandResult};

const MAX_CLOSE_TIMEOUT_MS: u32 = 5_000;
const MAX_INPUT_LEASE_MS: u32 = 5_000;
const CAPTURE_NO_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const M1_ACTION_ID: &str = "gadget.quick_use";
type CaptureFailure = (AgentError, Option<AttemptRef>);

fn frame_sequence_key(source_id: &str, attempt: Option<&AttemptRef>) -> String {
    attempt.map_or_else(
        || source_id.to_owned(),
        |attempt| {
            format!(
                "{}:{}:{}",
                attempt.attempt_id, attempt.contract_digest, source_id
            )
        },
    )
}

fn ensure_current_source_frame(source_frame: Option<(&AtomicU64, u64)>) -> Result<(), AgentError> {
    if source_frame.is_some_and(|(current, expected)| {
        expected == 0 || current.load(Ordering::Acquire) != expected
    }) {
        return Err(AgentError::new(
            "source_frame_stale",
            "input frame source is not the latest task frame",
        ));
    }
    Ok(())
}

fn next_frame_sequence(sequence: &AtomicU64) -> Result<u64, AgentError> {
    sequence
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map(|previous| previous + 1)
        .map_err(|_| {
            AgentError::new(
                "capture.sequence_exhausted",
                "capture frame sequence exhausted",
            )
        })
}

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

    fn publish_required(&self, frame: FramePacket) -> Result<(), AgentError> {
        self.publish(frame)
    }

    fn overwritten_frames(&self) -> u64 {
        0
    }
}

impl FrameSink for SessionFrameSlot {
    fn publish(&self, frame: FramePacket) -> Result<(), AgentError> {
        SessionFrameSlot::publish(self, v2_frame(frame))
            .map_err(|error| AgentError::new(error.code(), error.to_string()))
    }

    fn overwritten_frames(&self) -> u64 {
        SessionFrameSlot::overwritten_frames(self)
    }

    fn publish_required(&self, frame: FramePacket) -> Result<(), AgentError> {
        match SessionFrameSlot::publish_if_accepting(self, v2_frame(frame)) {
            Ok(true) => Ok(()),
            Ok(false) => Err(AgentError::new(
                "transport.frame_paused",
                "single-frame capture cannot be published while Frame transmission is paused",
            )),
            Err(error) => Err(AgentError::new(error.code(), error.to_string())),
        }
    }
}

fn v2_frame(frame: FramePacket) -> fairypam_agent_protocol::v2::FramePacket {
    fairypam_agent_protocol::v2::FramePacket {
        session: frame
            .session
            .map(|session| fairypam_agent_protocol::v2::SessionRef {
                agent_id: session.agent_id,
                session_id: session.session_id,
                generation: session.generation,
            }),
        capture_source_id: frame.capture_source_id,
        frame_sequence: frame.frame_sequence,
        captured_at_unix_us: frame.captured_at_unix_us,
        width: frame.width,
        height: frame.height,
        encoding: frame.encoding,
        payload: frame.payload,
        attempt: frame
            .attempt
            .map(|attempt| fairypam_agent_protocol::v2::AttemptRef {
                task_run_id: attempt.task_run_id,
                attempt_id: attempt.attempt_id,
                contract_version: 2,
                contract_digest: attempt.contract_digest,
            }),
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
    fn begin_attempt_monitor(&mut self) -> Result<bool, AgentError> {
        Ok(false)
    }

    fn check_attempt_environment(&mut self) -> Result<(), AgentError> {
        Ok(())
    }

    fn finish_attempt_monitor(&mut self) {}

    fn start_task_target(&mut self, profile: &VerifiedProfile)
        -> Result<TargetBinding, AgentError>;

    fn enumerate(&mut self, profile: &VerifiedProfile) -> Result<Vec<TargetCandidate>, AgentError>;

    fn lock(
        &mut self,
        profile: &VerifiedProfile,
        selector: TargetSelector,
    ) -> Result<TargetBinding, AgentError>;

    fn rediscover_target(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
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

    #[allow(clippy::too_many_arguments)]
    fn apply_task_input_frame(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
        session: &SessionRef,
        input_sequence: u64,
        expires_at: Instant,
        keys: &[v2::PhysicalKey],
        mouse_buttons: &[i32],
        wheel_delta: i32,
        source_frame: Option<(&AtomicU64, u64)>,
        client_point: Option<(i32, u32, u32)>,
    ) -> Result<(), AgentError>;

    fn release_task_input(&mut self) -> Result<(), AgentError>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum CommandOutcome {
    Ack(String),
    TaskAck {
        result: String,
        outcome: Option<TaskCommandOutcomeV1>,
        receipt: Box<TaskAttemptReceiptV1>,
        local_diagnostic: Option<String>,
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
            local_diagnostic: None,
        }
    }

    fn task_with_diagnostic(result: TaskCommandResult, error: &AgentError) -> Self {
        Self::TaskAck {
            result: "{}".into(),
            outcome: Some(result.outcome),
            receipt: Box::new(result.receipt),
            local_diagnostic: Some(error.to_string()),
        }
    }

    pub(crate) fn local_diagnostic(&self) -> Option<&str> {
        match self {
            Self::TaskAck {
                local_diagnostic: Some(message),
                ..
            } => Some(message),
            _ => None,
        }
    }
}

struct CaptureWorker {
    source_id: String,
    plan: CapturePlan,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<CaptureFailure>>>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct CapturePlan {
    region: CaptureRegion,
    source_id: String,
    fps: u32,
    encoding: RuntimeCaptureEncoding,
    session: ExecutionSession,
    frames: Arc<dyn FrameSink>,
    attempt: Option<AttemptRef>,
    no_frame_timeout: Duration,
    rediscovery_allowed: bool,
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
    runtime_mode: &'static str,
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
            "production",
        )
    }

    pub fn with_platform(profiles: ProfileStore, platform: Box<dyn RuntimePlatform>) -> Self {
        Self::with_platform_and_attempts(
            profiles,
            platform,
            TaskAttemptRuntime::memory(),
            "dry_run",
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn without_devices_for_test() -> Self {
        Self::with_platform(ProfileStore::default(), Box::new(UnsupportedPlatform))
    }

    fn with_platform_and_attempts(
        profiles: ProfileStore,
        platform: Box<dyn RuntimePlatform>,
        task_attempt: TaskAttemptRuntime,
        runtime_mode: &'static str,
    ) -> Self {
        Self {
            profiles,
            platform,
            runtime_mode,
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

    pub fn execute_v2_begin(
        &mut self,
        task: &fairypam_agent_protocol::v1::TaskCommandRef,
        contract: &v2::ExecutionContract,
    ) -> CommandOutcome {
        let result = (|| {
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
            let monitor_started = self.platform.begin_attempt_monitor()?;
            let receipt = match self.task_attempt.begin_v2(task, contract) {
                Ok(receipt) => receipt,
                Err(error) => {
                    if monitor_started {
                        self.platform.finish_attempt_monitor();
                    }
                    return Err(error);
                }
            };
            Ok(CommandOutcome::TaskAck {
                result: "{}".into(),
                outcome: None,
                receipt: Box::new(receipt),
                local_diagnostic: None,
            })
        })();
        result.unwrap_or_else(CommandOutcome::from_error)
    }

    pub fn execute_v2_input_frame(
        &mut self,
        task: &fairypam_agent_protocol::v1::TaskCommandRef,
        frame: &v2::InputFrame,
        client_point: Option<(i32, u32, u32)>,
    ) -> CommandOutcome {
        let result = (|| {
            if let Some(result) = self.task_attempt.replay(task)? {
                return Ok(CommandOutcome::task(result));
            }
            let source_frame = if let Some(source) = frame.source_frame_sequence {
                let attempt = self.task_attempt.attempt_ref(task)?;
                let frame_key = frame_sequence_key("client", Some(&attempt));
                let current = self
                    .frame_sequences
                    .get(&frame_key)
                    .cloned()
                    .ok_or_else(|| {
                        AgentError::new(
                            "source_frame_stale",
                            "input frame source is not the latest task frame",
                        )
                    })?;
                ensure_current_source_frame(Some((&current, source)))?;
                Some((current, source))
            } else {
                None
            };
            if let Some(result) = self.task_attempt.prepare(task, true)? {
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
            let expires_at = Instant::now() + Duration::from_millis(u64::from(frame.lease_ms));
            let error = self
                .platform
                .apply_task_input_frame(
                    &profile,
                    &binding,
                    session,
                    frame.input_sequence,
                    expires_at,
                    &frame.held_keys,
                    &frame.held_mouse_buttons,
                    frame.wheel_delta,
                    source_frame
                        .as_ref()
                        .map(|(current, expected)| (current.as_ref(), *expected)),
                    client_point,
                )
                .err();
            Ok(CommandOutcome::task(
                self.task_attempt.complete_input_frame(
                    task,
                    frame.source_frame_sequence,
                    error.is_none(),
                    !frame.held_keys.is_empty() || !frame.held_mouse_buttons.is_empty(),
                    error.as_ref().map(AgentError::code),
                )?,
            ))
        })();
        result.unwrap_or_else(CommandOutcome::from_error)
    }

    pub fn v2_payload_digest_conflict(
        &mut self,
        task: &fairypam_agent_protocol::v1::TaskCommandRef,
    ) -> CommandOutcome {
        self.task_attempt
            .payload_digest_conflict(task)
            .map(CommandOutcome::task)
            .unwrap_or_else(CommandOutcome::from_error)
    }

    pub fn reject_v2_task(
        &mut self,
        task: &fairypam_agent_protocol::v1::TaskCommandRef,
        error_code: &str,
    ) -> CommandOutcome {
        self.task_attempt
            .reject(task, error_code)
            .map(CommandOutcome::task)
            .unwrap_or_else(CommandOutcome::from_error)
    }

    pub fn execute_local(
        &mut self,
        command: &LocalCommand,
    ) -> Result<serde_json::Value, AgentError> {
        let read_only = matches!(
            command,
            LocalCommand::Status | LocalCommand::Doctor | LocalCommand::ListProfiles
        );
        let emergency_stopped = self.task_attempt.emergency_stopped()?;
        let task_active = self.task_attempt.is_active()?;
        if emergency_stopped
            && !read_only
            && !matches!(
                command,
                LocalCommand::ReleaseAll | LocalCommand::ResetEmergencyStop
            )
        {
            return Err(AgentError::new(
                "emergency_stopped",
                "only local emergency cleanup or reset is allowed while stopped",
            ));
        }
        if task_active && !read_only && !matches!(command, LocalCommand::ReleaseAll) {
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
                } else if task_active {
                    "TaskActive"
                } else {
                    "ConnectedIdle"
                },
                "task_active": task_active,
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
                Ok(json!({"profiles": self.profiles.ids(), "runtime": self.runtime_mode}))
            }
            LocalCommand::ListProfiles => Ok(json!({"profiles": self.profiles.ids()})),
            LocalCommand::LaunchTarget { profile_id } => {
                let profile = self.profiles.get(profile_id)?.clone();
                let binding = self.platform.start_task_target(&profile)?;
                self.active_profile = Some(profile);
                self.binding = Some(binding.clone());
                Ok(
                    json!({"profile_id": binding.profile_id, "pid": binding.process_id, "state": "TargetLocked"}),
                )
            }
            LocalCommand::CloseTarget => {
                let Some(binding) = self.binding.clone() else {
                    return Ok(json!({"closed": true, "state": "ConnectedIdle"}));
                };
                self.platform.release_task_input()?;
                self.stop_capture(None)?;
                self.platform.close(
                    &binding,
                    Duration::from_millis(u64::from(MAX_CLOSE_TIMEOUT_MS)),
                )?;
                self.active_profile = None;
                self.binding = None;
                Ok(
                    json!({"profile_id": binding.profile_id, "closed": true, "state": "ConnectedIdle"}),
                )
            }
            LocalCommand::CapturePreview => {
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
                    .find(|source| {
                        source.id == "client"
                            && source.encodings.iter().any(|value| value == "jpeg")
                    })
                    .ok_or_else(|| {
                        AgentError::new(
                            "capture.source_not_allowed",
                            "Profile has no client JPEG source",
                        )
                    })?;
                let mut capture = self.platform.start_capture(
                    &binding,
                    source.region.clone(),
                    RuntimeCaptureEncoding::Jpeg { quality: 80 },
                )?;
                let frame = capture.next_frame(Instant::now() + Duration::from_secs(5))?;
                Ok(
                    json!({"mime_type": "image/jpeg", "width": frame.width, "height": frame.height, "bytes": frame.bytes}),
                )
            }
            LocalCommand::InputProbe { action } => match action {
                InputProbeAction::MoveForward => self.local_input_pulse(
                    &[v2::PhysicalKey {
                        scan_code: 17,
                        extended: false,
                    }],
                    &[],
                ),
                InputProbeAction::QuickUse => self.local_input_pulse(
                    &[v2::PhysicalKey {
                        scan_code: 44,
                        extended: false,
                    }],
                    &[],
                ),
                InputProbeAction::MouseLeft => self.local_input_pulse(&[], &[1]),
            },
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
                let Some(binding) = self.binding.clone() else {
                    return Ok(CommandOutcome::Ack(
                        json!({"closed": true, "state": "ConnectedIdle"}).to_string(),
                    ));
                };
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
                let attempt = task
                    .map(|task| self.task_attempt.attempt_ref(task))
                    .transpose()?;
                let frame_key = frame_sequence_key(&value.source_id, attempt.as_ref());
                let frame_sequence = Arc::clone(
                    self.frame_sequences
                        .entry(frame_key)
                        .or_insert_with(|| Arc::new(AtomicU64::new(0))),
                );
                let plan = CapturePlan {
                    region: source.region.clone(),
                    source_id: value.source_id.clone(),
                    fps: value.fps,
                    encoding,
                    session: session.clone(),
                    frames,
                    attempt,
                    no_frame_timeout: CAPTURE_NO_FRAME_TIMEOUT,
                    rediscovery_allowed: true,
                };
                let worker = spawn_capture_worker(capture, frame_sequence, plan);
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
            Some(Payload::CaptureFrame(value)) => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
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
                let region = source.region.clone();
                let encoding = parse_encoding(&value.encoding, value.quality, &source.encodings)?;
                if self.task_attempt.profile_id(task)? != profile.profile().id {
                    return Err(AgentError::new(
                        "profile_mismatch",
                        "task capture Profile does not match the claimed attempt",
                    ));
                }
                if let Some(result) = self.task_attempt.prepare(task, false)? {
                    return Ok(CommandOutcome::task(result));
                }
                if self.capture.is_some() {
                    return Ok(CommandOutcome::task(
                        self.task_attempt.complete_capture_frame(
                            task,
                            None,
                            Some("capture.already_started"),
                        )?,
                    ));
                }
                let attempt = self.task_attempt.attempt_ref(task)?;
                let result: Result<u64, AgentError> = (|| {
                    let mut capture = self.platform.start_capture(&binding, region, encoding)?;
                    let frame = capture.next_frame(Instant::now() + CAPTURE_NO_FRAME_TIMEOUT)?;
                    let frame_sequence = Arc::clone(
                        self.frame_sequences
                            .entry(frame_sequence_key(&value.source_id, Some(&attempt)))
                            .or_insert_with(|| Arc::new(AtomicU64::new(0))),
                    );
                    let sequence = next_frame_sequence(&frame_sequence)?;
                    frames.publish_required(FramePacket {
                        session: Some(session.reference.clone()),
                        capture_source_id: value.source_id.clone(),
                        frame_sequence: sequence,
                        captured_at_unix_us: now_unix_us(),
                        width: frame.width,
                        height: frame.height,
                        encoding: match encoding {
                            RuntimeCaptureEncoding::Jpeg { .. } => "jpeg".into(),
                            RuntimeCaptureEncoding::Png => "png".into(),
                        },
                        payload: frame.bytes,
                        attempt: Some(attempt),
                    })?;
                    Ok(sequence)
                })();
                match result {
                    Ok(sequence) => Ok(CommandOutcome::task(
                        self.task_attempt
                            .complete_capture_frame(task, Some(sequence), None)?,
                    )),
                    Err(error) => {
                        let release_error = self.platform.release_task_input().err();
                        let error = AgentError::new(
                            error.code(),
                            match release_error {
                                Some(release) => {
                                    format!("{error}; input release failed: {release}")
                                }
                                None => error.to_string(),
                            },
                        );
                        Ok(CommandOutcome::task_with_diagnostic(
                            self.task_attempt.complete_capture_frame(
                                task,
                                None,
                                Some(error.code()),
                            )?,
                            &error,
                        ))
                    }
                }
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
                    if let Some(result) = self.task_attempt.prepare_recovery(task)? {
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
                        "M1 task allows only gadget.quick_use",
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
                    .get(&frame_sequence_key(
                        "client",
                        Some(&self.task_attempt.attempt_ref(task)?),
                    ))
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
                let monitor_started = self.platform.begin_attempt_monitor()?;
                let receipt = match self.task_attempt.begin(task, contract) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        if monitor_started {
                            self.platform.finish_attempt_monitor();
                        }
                        return Err(error);
                    }
                };
                Ok(CommandOutcome::TaskAck {
                    result: "{}".into(),
                    outcome: None,
                    receipt: Box::new(receipt),
                    local_diagnostic: None,
                })
            }
            Some(Payload::InspectTaskAttempt(value)) => {
                let task = value.task.as_ref().ok_or_else(task_reference_invalid)?;
                Ok(CommandOutcome::TaskAck {
                    result: "{}".into(),
                    outcome: None,
                    receipt: Box::new(self.task_attempt.inspect(task)?),
                    local_diagnostic: None,
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
                self.platform.finish_attempt_monitor();
                let managed_target_running = self.binding.is_some();
                let error_code = release_error.as_ref().map(AgentError::code);
                Ok(CommandOutcome::task(self.task_attempt.complete_finish(
                    task,
                    release_error.is_none(),
                    capture_stopped,
                    managed_target_running,
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
        let Some((mut failure, attempt)) = self
            .capture
            .as_ref()
            .map(CaptureWorker::failure)
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        let worker = self.capture.take().expect("checked above");
        let source_id = worker.source_id.clone();
        let plan = worker.plan.clone();
        let frame_key = frame_sequence_key(&source_id, plan.attempt.as_ref());
        let release_error = self.platform.release_task_input().err();
        let _ = worker.stop();
        if let Some(error) = release_error {
            return Err(error);
        }
        if plan.rediscovery_allowed
            && matches!(
                failure.code(),
                "capture.no_frame_timeout" | "target.stale" | "target.not_found"
            )
        {
            match self.restart_capture_after_rediscovery(plan) {
                Ok(worker) => {
                    tracing::warn!(
                        capture_source_id = source_id,
                        reason = failure.code(),
                        "capture rebuilt after one signed-Profile target rediscovery"
                    );
                    self.capture = Some(worker);
                    return Ok(None);
                }
                Err(error) => failure = error,
            }
        }
        self.frame_sequences.remove(&frame_key);
        Ok(Some(AgentControlEvent {
            payload: Some(agent_control_event::Payload::SafetyEvent(SafetyEvent {
                session: Some(session.reference.clone()),
                reason: failure.code().to_owned(),
                state: "capture_failed".to_owned(),
                attempt,
            })),
        }))
    }

    fn restart_capture_after_rediscovery(
        &mut self,
        mut plan: CapturePlan,
    ) -> Result<CaptureWorker, AgentError> {
        let profile = self.active_profile.clone().ok_or_else(|| {
            AgentError::new(
                "target.not_found",
                "capture recovery requires an active signed Profile",
            )
        })?;
        let binding = self.binding.clone().ok_or_else(|| {
            AgentError::new(
                "target.not_found",
                "capture recovery requires an active target binding",
            )
        })?;
        let refreshed = self.platform.rediscover_target(&profile, &binding)?;
        if let Some(attempt) = plan.attempt.as_ref() {
            self.task_attempt
                .refresh_owned_target(attempt, refreshed.clone())?;
        }
        self.binding = Some(refreshed.clone());
        let capture =
            self.platform
                .start_capture(&refreshed, plan.region.clone(), plan.encoding)?;
        let frame_key = frame_sequence_key(&plan.source_id, plan.attempt.as_ref());
        let frame_sequence = Arc::clone(
            self.frame_sequences
                .entry(frame_key)
                .or_insert_with(|| Arc::new(AtomicU64::new(0))),
        );
        plan.rediscovery_allowed = false;
        spawn_capture_worker(capture, frame_sequence, plan)
    }

    fn local_input_pulse(
        &mut self,
        keys: &[v2::PhysicalKey],
        mouse_buttons: &[i32],
    ) -> Result<serde_json::Value, AgentError> {
        let profile = self.active_profile.clone().ok_or_else(|| {
            AgentError::new("profile.not_active", "input requires an active Profile")
        })?;
        let binding = self.binding.clone().ok_or_else(|| {
            AgentError::new("target.not_locked", "input requires a locked target")
        })?;
        let session = SessionRef {
            agent_id: "local-gui".into(),
            session_id: "local-gui".into(),
            generation: 1,
        };
        let now = Instant::now();
        let expires_at = now + Duration::from_millis(500);
        self.platform
            .start_task_input(&profile, &binding, &session, expires_at)?;
        let result = self
            .platform
            .apply_task_input_frame(
                &profile,
                &binding,
                &session,
                1,
                expires_at,
                keys,
                mouse_buttons,
                0,
                None,
                None,
            )
            .and_then(|()| {
                self.platform.apply_task_input_frame(
                    &profile,
                    &binding,
                    &session,
                    2,
                    expires_at,
                    &[],
                    &[],
                    0,
                    None,
                    None,
                )
            });
        let release = self.platform.release_task_input();
        result?;
        release?;
        Ok(json!({"state": "released"}))
    }

    pub fn reload_profiles(&mut self, profiles: ProfileStore) {
        self.profiles = profiles;
    }

    pub fn reset_session(&mut self) -> Result<(), AgentError> {
        if self.task_attempt.is_active()? || self.task_attempt.emergency_stopped()? {
            self.emergency_stop()?;
        }
        self.platform.release_task_input()?;
        self.stop_capture(None)?;
        self.platform.finish_attempt_monitor();
        self.frame_sequences.clear();
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), AgentError> {
        self.reset_session()?;
        if let Some(binding) = self.binding.clone() {
            self.platform.close(
                &binding,
                Duration::from_millis(u64::from(MAX_CLOSE_TIMEOUT_MS)),
            )?;
        }
        self.active_profile = None;
        self.binding = None;
        self.frame_sequences.clear();
        Ok(())
    }

    fn emergency_stop(&mut self) -> Result<serde_json::Value, AgentError> {
        self.task_attempt.set_emergency_stopped(true)?;
        let release_error = self.platform.release_task_input().err();
        let capture_error = self.stop_capture(None).err();
        self.platform.finish_attempt_monitor();
        let managed_target_running = self.binding.is_some();
        self.frame_sequences.clear();
        let error_code = capture_error
            .as_ref()
            .or(release_error.as_ref())
            .map(AgentError::code);
        let receipt = self.task_attempt.emergency_finish(
            release_error.is_none(),
            capture_error.is_none(),
            managed_target_running,
            error_code,
        )?;
        let cleanup_complete = receipt
            .as_ref()
            .and_then(|value| value.cleanup_complete)
            .unwrap_or(release_error.is_none() && capture_error.is_none());
        let response_error_code = receipt
            .as_ref()
            .and_then(|value| value.error_code.as_deref())
            .or(error_code);
        Ok(json!({
            "state": "EmergencyStopped",
            "holds": 0,
            "cleanup_complete": cleanup_complete,
            "error_code": response_error_code,
        }))
    }

    pub fn emergency_release_input(&mut self) -> Result<(), AgentError> {
        self.platform.release_task_input()
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
        Some(Payload::CaptureFrame(value)) => value.task.is_some(),
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

fn spawn_capture_worker(
    mut capture: Box<dyn RuntimeCapture>,
    frame_sequence: Arc<AtomicU64>,
    plan: CapturePlan,
) -> Result<CaptureWorker, AgentError> {
    let source_id = plan.source_id.clone();
    let fps = plan.fps;
    let encoding = plan.encoding;
    let session = plan.session.reference.clone();
    let frames = Arc::clone(&plan.frames);
    let attempt = plan.attempt.clone();
    let no_frame_timeout = plan.no_frame_timeout;
    let stop = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(Mutex::new(None));
    let worker_stop = Arc::clone(&stop);
    let worker_failure = Arc::clone(&failure);
    let worker_source = source_id.clone();
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
                        let sequence = match next_frame_sequence(&frame_sequence) {
                            Ok(sequence) => sequence,
                            Err(error) => {
                                record_capture_failure(&worker_failure, error, attempt.clone());
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
        plan,
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

#[cfg(any(not(windows), test, feature = "test-support"))]
struct UnsupportedPlatform;

#[cfg(any(not(windows), test, feature = "test-support"))]
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

    fn apply_task_input_frame(
        &mut self,
        _profile: &VerifiedProfile,
        _binding: &TargetBinding,
        _session: &SessionRef,
        _input_sequence: u64,
        _expires_at: Instant,
        _keys: &[v2::PhysicalKey],
        _mouse_buttons: &[i32],
        _wheel_delta: i32,
        _source_frame: Option<(&AtomicU64, u64)>,
        _client_point: Option<(i32, u32, u32)>,
    ) -> Result<(), AgentError> {
        Err(AgentError::new(
            "input.platform_unsupported",
            "task input requires Windows",
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

    fn rediscover_target(
        &mut self,
        _profile: &VerifiedProfile,
        _binding: &TargetBinding,
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
    managed: Option<ManagedGameProcess>,
    task_input: Option<WindowsTaskInput>,
    input_monitor: Option<fairypam_agent_windows::LocalInputMonitor>,
    rediscovery_used: bool,
}

#[cfg(windows)]
struct ManagedGameProcess {
    _child: Option<std::process::Child>,
    job: Option<usize>,
    executable: std::path::PathBuf,
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
impl Drop for ManagedGameProcess {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};

        if let Some(job) = self.job {
            // SAFETY: this value owns the Job Object handle until this drop.
            let _ = unsafe { CloseHandle(HANDLE(job as _)) };
        }
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
fn semantic_mouse_button(
    button: i32,
) -> Result<fairypam_agent_input::SemanticMouseButton, AgentError> {
    use fairypam_agent_input::SemanticMouseButton;

    match v2::MouseButton::try_from(button) {
        Ok(v2::MouseButton::Left) => Ok(SemanticMouseButton::Left),
        Ok(v2::MouseButton::Right) => Ok(SemanticMouseButton::Right),
        Ok(v2::MouseButton::Middle) => Ok(SemanticMouseButton::Middle),
        Ok(v2::MouseButton::X1) => Ok(SemanticMouseButton::X1),
        Ok(v2::MouseButton::X2) => Ok(SemanticMouseButton::X2),
        _ => Err(AgentError::new(
            "input.frame_invalid",
            "input command contains an invalid mouse button",
        )),
    }
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
            managed: None,
            task_input: None,
            input_monitor: None,
            rediscovery_used: false,
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

    fn validate_task_input_session(&mut self, session: &SessionRef) -> Result<(), AgentError> {
        let Some(input) = self.task_input.as_ref() else {
            return Err(AgentError::new(
                "input_lease_invalid",
                "task input lease is not active",
            ));
        };
        let matches = input.session.agent_id == session.agent_id
            && input.session.session_id == session.session_id
            && input.session.generation == session.generation;
        if matches {
            return Ok(());
        }
        let release_error = self.release_task_input().err();
        Err(AgentError::new(
            "input_lease_invalid",
            match release_error {
                Some(error) => format!(
                    "task input lease belongs to another Control session; release failed: {error}"
                ),
                None => "task input lease belongs to another Control session".into(),
            },
        ))
    }

    fn focus_task_input_target(
        &mut self,
        binding: &TargetBinding,
    ) -> Result<TargetSnapshot, AgentError> {
        self.targets.focus(binding).map_err(|error| {
            let release_error = self.release_task_input().err();
            AgentError::new(
                error.code(),
                match release_error {
                    Some(release) => format!("{error}; input release failed: {release}"),
                    None => error.to_string(),
                },
            )
        })
    }

    fn wait_for_process_window(
        &mut self,
        profile: &VerifiedProfile,
        process_id: u32,
        deadline: Instant,
    ) -> Result<TargetBinding, AgentError> {
        use fairypam_agent_core::platform::TargetPlatform;

        loop {
            let mut candidates = self
                .targets
                .enumerate(profile)?
                .into_iter()
                .filter(|candidate| candidate.process_id == process_id);
            if let Some(candidate) = candidates.next() {
                if candidates.next().is_some() {
                    return Err(AgentError::new(
                        "target.ambiguous",
                        "the signed Profile process exposes multiple trusted windows",
                    ));
                }
                return self.targets.lock(profile, candidate.selector);
            }
            if Instant::now() >= deadline {
                return Err(AgentError::new(
                    "target.launch_failed",
                    "trusted target window did not become ready within 120 seconds",
                ));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsRuntimePlatform {
    fn drop(&mut self) {
        let _ = <Self as RuntimePlatform>::release_task_input(self);
        if let Some(binding) = self.managed.as_ref().map(|target| target.binding.clone()) {
            let _ = <Self as RuntimePlatform>::close(self, &binding, Duration::from_secs(5));
        }
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
    fn begin_attempt_monitor(&mut self) -> Result<bool, AgentError> {
        if self.input_monitor.is_some() {
            return Ok(false);
        }
        self.input_monitor = Some(fairypam_agent_windows::LocalInputMonitor::start()?);
        Ok(true)
    }

    fn check_attempt_environment(&mut self) -> Result<(), AgentError> {
        let Some(monitor) = self.input_monitor.as_ref() else {
            return Ok(());
        };
        if let Err(error) = monitor.check() {
            let release_error = self.release_task_input().err();
            return Err(AgentError::new(
                error.code(),
                match release_error {
                    Some(release) => format!("{error}; input release failed: {release}"),
                    None => error.to_string(),
                },
            ));
        }
        Ok(())
    }

    fn finish_attempt_monitor(&mut self) {
        self.input_monitor = None;
    }

    fn start_task_target(
        &mut self,
        profile: &VerifiedProfile,
    ) -> Result<TargetBinding, AgentError> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::JobObjects::AssignProcessToJobObject;

        let executable = crate::observability::resolve_profile_executable(profile)?;
        if let Some(managed) = self.managed.as_ref() {
            if managed.binding.profile_id != profile.profile().id {
                return Err(AgentError::new(
                    "target_invalid",
                    "an Agent-managed target for another Profile is already active",
                ));
            }
            let process_id = managed.binding.process_id;
            if !fairypam_agent_windows::process_matches_executable(process_id, &executable)? {
                self.managed = None;
            } else {
                let binding = self.wait_for_process_window(
                    profile,
                    process_id,
                    Instant::now() + Duration::from_secs(120),
                )?;
                self.managed.as_mut().expect("checked above").binding = binding.clone();
                self.rediscovery_used = false;
                return Ok(binding);
            }
        }
        let existing = fairypam_agent_windows::matching_process_ids(&executable)?;
        if existing.len() > 1 {
            return Err(AgentError::new(
                "target.ambiguous",
                "multiple signed Profile processes are already running",
            ));
        }
        if let Some(process_id) = existing.first().copied() {
            let binding = self.wait_for_process_window(
                profile,
                process_id,
                Instant::now() + Duration::from_secs(120),
            )?;
            self.managed = Some(ManagedGameProcess {
                _child: None,
                job: None,
                executable,
                binding: binding.clone(),
            });
            self.rediscovery_used = false;
            return Ok(binding);
        }
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
        let deadline = Instant::now() + Duration::from_secs(120);
        let binding = match self.wait_for_process_window(profile, child.id(), deadline) {
            Ok(binding) => binding,
            Err(error) => {
                let _ = child.kill();
                return Err(error);
            }
        };
        self.managed = Some(ManagedGameProcess {
            _child: Some(child),
            job: Some(job.into_raw()),
            executable,
            binding: binding.clone(),
        });
        self.rediscovery_used = false;
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
        let binding = self.targets.lock(profile, selector)?;
        self.rediscovery_used = false;
        Ok(binding)
    }

    fn rediscover_target(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
    ) -> Result<TargetBinding, AgentError> {
        if self.rediscovery_used {
            return Err(AgentError::new(
                "target.not_found",
                "the active target has already used its one rediscovery attempt",
            ));
        }
        self.rediscovery_used = true;
        let refreshed = self.targets.rediscover(profile, binding)?;
        if let Some(managed) = self.managed.as_mut() {
            if managed.binding.process_id != refreshed.process_id
                || managed.binding.process_started_at_unix_ms
                    != refreshed.process_started_at_unix_ms
                || managed.binding.process_path_sha256 != refreshed.process_path_sha256
            {
                return Err(AgentError::new(
                    "target.stale",
                    "rediscovered window does not belong to the Agent-managed process",
                ));
            }
            managed.binding = refreshed.clone();
        }
        Ok(refreshed)
    }

    fn start_capture(
        &mut self,
        binding: &TargetBinding,
        region: CaptureRegion,
        encoding: RuntimeCaptureEncoding,
    ) -> Result<Box<dyn RuntimeCapture>, AgentError> {
        use fairypam_agent_windows::CaptureEncoding;
        self.check_attempt_environment()?;
        let encoding = match encoding {
            RuntimeCaptureEncoding::Jpeg { quality } => CaptureEncoding::Jpeg { quality },
            RuntimeCaptureEncoding::Png => CaptureEncoding::Png,
        };
        let capture = self
            .targets
            .start_capture(binding, region, encoding)
            .map_err(|error| {
                let release_error = self.release_task_input().err();
                AgentError::new(
                    error.code(),
                    match release_error {
                        Some(release) => format!("{error}; input release failed: {release}"),
                        None => error.to_string(),
                    },
                )
            })?;
        Ok(Box::new(WindowsCapture { capture }))
    }

    fn focus(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError> {
        self.targets.focus(binding)
    }

    fn close(&mut self, binding: &TargetBinding, _timeout: Duration) -> Result<(), AgentError> {
        let Some(managed) = self.managed.as_ref() else {
            return Ok(());
        };
        if managed.binding.process_id != binding.process_id
            || managed.binding.process_started_at_unix_ms != binding.process_started_at_unix_ms
            || managed.binding.process_path_sha256 != binding.process_path_sha256
        {
            return Err(AgentError::new(
                "target_invalid",
                "refusing to close a target not managed by this Agent",
            ));
        }
        let executable = managed.executable.clone();
        if let Err(error) = self.targets.close(binding, Duration::from_secs(5)) {
            let still_running = fairypam_agent_windows::matching_process_ids(&executable)?
                .contains(&binding.process_id);
            if !still_running {
                self.managed = None;
                return Ok(());
            }
            if error.code() == "target.stale" {
                return Err(error);
            }
            self.targets.terminate(binding, Duration::from_secs(5))?;
        }
        self.managed = None;
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
        use fairypam_agent_input::{ActionMap, GuardianProcessClient};

        self.check_attempt_environment()?;
        self.release_task_input()?;
        let now = Instant::now();
        let snapshot = self.targets.focus(binding)?;
        self.check_attempt_environment()?;
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
            None,
        )
        .map_err(|error| AgentError::new("guardian.unavailable", error.to_string()))?;
        let input = self
            .targets
            .start_input(profile, binding.clone(), guardian)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        self.task_input = Some(WindowsTaskInput {
            machine,
            input,
            session,
        });
        Ok(())
    }

    fn apply_task_input_frame(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
        session: &SessionRef,
        input_sequence: u64,
        expires_at: Instant,
        keys: &[v2::PhysicalKey],
        mouse_buttons: &[i32],
        wheel_delta: i32,
        source_frame: Option<(&AtomicU64, u64)>,
        client_point: Option<(i32, u32, u32)>,
    ) -> Result<(), AgentError> {
        use fairypam_agent_input::InputPermit;

        self.check_attempt_environment()?;
        if self.task_input.is_none() {
            self.start_task_input(profile, binding, session, expires_at)?;
        }
        let now = Instant::now();
        self.validate_task_input_session(session)?;
        let snapshot = self.focus_task_input_target(binding)?;
        self.check_attempt_environment()?;
        if !snapshot.foreground || snapshot.minimized || !snapshot.capturable {
            let _ = self.release_task_input();
            return Err(AgentError::new(
                "local_authorization_denied",
                "task target lost foreground or capture eligibility",
            ));
        }
        let buttons = mouse_buttons
            .iter()
            .map(|button| semantic_mouse_button(*button))
            .collect::<Result<Vec<_>, _>>()?;
        let keys = keys
            .iter()
            .map(|key| (key.scan_code as u16, key.extended))
            .collect::<Vec<_>>();
        let input = self.task_input.as_mut().ok_or_else(|| {
            AgentError::new("input_lease_invalid", "task input lease is not active")
        })?;
        let permit = InputPermit::from_capability(
            input.machine.issue_input_capability(now, &snapshot, true)?,
        );
        ensure_current_source_frame(source_frame)?;
        input
            .input
            .apply_physical_frame(
                input.session.clone(),
                input_sequence,
                expires_at,
                &keys,
                &buttons,
                wheel_delta,
                &permit,
                now,
            )
            .and_then(|()| {
                let Some((button, x_ppm, y_ppm)) = client_point else {
                    return Ok(());
                };
                ensure_current_source_frame(source_frame).map_err(|error| {
                    fairypam_agent_input::SafetyError::new(error.code(), error.to_string())
                })?;
                input.input.execute_client_point(
                    semantic_mouse_button(button)?,
                    x_ppm,
                    y_ppm,
                    &input.session,
                    &permit,
                    now,
                )
            })
            .map_err(|error| AgentError::new(error.code(), error.to_string()))
    }

    fn pulse_task_action(
        &mut self,
        binding: &TargetBinding,
        session: &SessionRef,
        action_id: &str,
        now: Instant,
    ) -> Result<(), AgentError> {
        use fairypam_agent_input::{ActionId, InputPermit};

        self.check_attempt_environment()?;
        self.validate_task_input_session(session)?;
        let snapshot = self.focus_task_input_target(binding)?;
        self.check_attempt_environment()?;
        if !snapshot.foreground || snapshot.minimized || !snapshot.capturable {
            let _ = self.release_task_input();
            return Err(AgentError::new(
                "local_authorization_denied",
                "task target lost foreground or capture eligibility",
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
        profile_content_sha256, verify_profile, ActionDefinition, CaptureSource, ClientPointButton,
        Ed25519SignatureVerifier, Profile, ProfileContent, ProfileEnvelope, TargetRules,
    };
    use fairypam_agent_core::target::{ClientRect, IntegrityLevel, TargetSnapshot};
    use fairypam_agent_protocol::v1::{
        AgentAttemptContractV1, AttemptRef, BeginTaskAttempt, CaptureFrame, CloseTarget,
        CommandRef, EnumerateTargets, FinishTaskAttempt, FocusTarget, InputLease,
        InspectTaskAttempt, LaunchTarget, LockTarget, PulseAction, SessionRef, StartCapture,
        StartTaskTarget, StopCapture, TaskAttemptState, TaskCommandOutcomeState, TaskCommandRef,
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
                        ActionDefinition::Pulse { scan_code: 44 },
                    ),
                    (
                        "combat.normal_attack".into(),
                        ActionDefinition::ClientPointClick {
                            button: ClientPointButton::Left,
                        },
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
        rediscovery_calls: usize,
        target_owned: bool,
        focus_calls: Vec<TargetBinding>,
        close_calls: Vec<(TargetBinding, Duration)>,
        input_active: bool,
        pulse_calls: Vec<String>,
        point_clicks: usize,
        advance_source_before_click: bool,
        begin_monitor_calls: usize,
        finish_monitor_calls: usize,
        monitor_active: bool,
        fail_begin_monitor: bool,
        fail_close: bool,
        capture_error: Option<AgentError>,
    }

    #[derive(Default)]
    struct FakePlatform {
        state: Arc<Mutex<FakePlatformState>>,
    }

    impl RuntimePlatform for FakePlatform {
        fn begin_attempt_monitor(&mut self) -> Result<bool, AgentError> {
            let mut state = self.state.lock().unwrap();
            state.begin_monitor_calls += 1;
            if state.fail_begin_monitor {
                return Err(AgentError::new(
                    "environment.monitor_failed",
                    "simulated input monitor failure",
                ));
            }
            if state.monitor_active {
                return Ok(false);
            }
            state.monitor_active = true;
            Ok(true)
        }

        fn finish_attempt_monitor(&mut self) {
            let mut state = self.state.lock().unwrap();
            state.finish_monitor_calls += 1;
            state.monitor_active = false;
        }

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

        fn rediscover_target(
            &mut self,
            _profile: &VerifiedProfile,
            binding: &TargetBinding,
        ) -> Result<TargetBinding, AgentError> {
            let mut state = self.state.lock().unwrap();
            state.rediscovery_calls += 1;
            let mut refreshed = binding.clone();
            refreshed.window_handle = 200;
            Ok(refreshed)
        }

        fn start_capture(
            &mut self,
            _binding: &TargetBinding,
            _region: CaptureRegion,
            _encoding: RuntimeCaptureEncoding,
        ) -> Result<Box<dyn RuntimeCapture>, AgentError> {
            if let Some(error) = self.state.lock().unwrap().capture_error.clone() {
                return Err(error);
            }
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

        fn apply_task_input_frame(
            &mut self,
            _profile: &VerifiedProfile,
            _binding: &TargetBinding,
            _session: &SessionRef,
            _sequence: u64,
            _expires_at: Instant,
            _keys: &[v2::PhysicalKey],
            _buttons: &[i32],
            _wheel_delta: i32,
            source_frame: Option<(&AtomicU64, u64)>,
            client_point: Option<(i32, u32, u32)>,
        ) -> Result<(), AgentError> {
            let mut state = self.state.lock().unwrap();
            ensure_current_source_frame(source_frame)?;
            state.input_active = true;
            if client_point.is_some() && state.advance_source_before_click {
                if let Some((current, _)) = source_frame {
                    current.fetch_add(1, Ordering::Release);
                }
            }
            ensure_current_source_frame(source_frame)?;
            state.point_clicks += usize::from(client_point.is_some());
            Ok(())
        }

        fn release_task_input(&mut self) -> Result<(), AgentError> {
            self.state.lock().unwrap().input_active = false;
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

    struct PausedFrames;

    impl FrameSink for PausedFrames {
        fn publish(&self, _frame: FramePacket) -> Result<(), AgentError> {
            Ok(())
        }

        fn publish_required(&self, _frame: FramePacket) -> Result<(), AgentError> {
            Err(AgentError::new(
                "transport.frame_paused",
                "Frame transmission is paused",
            ))
        }
    }

    fn capture_plan(
        frames: Arc<dyn FrameSink>,
        no_frame_timeout: Duration,
        rediscovery_allowed: bool,
    ) -> CapturePlan {
        CapturePlan {
            region: CaptureRegion::FullClient,
            source_id: "client".into(),
            fps: 100,
            encoding: RuntimeCaptureEncoding::Jpeg { quality: 80 },
            session: ExecutionSession::test(),
            frames,
            attempt: None,
            no_frame_timeout,
            rediscovery_allowed,
        }
    }

    #[test]
    fn transient_capture_deadline_does_not_stop_the_worker() {
        let sink = Arc::new(CollectFrames::default());
        let worker = spawn_capture_worker(
            Box::new(DeadlineThenFrameCapture { calls: 0 }),
            Arc::new(AtomicU64::new(0)),
            capture_plan(sink.clone(), Duration::from_secs(1), false),
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
            capture_plan(
                Arc::new(CollectFrames::default()),
                Duration::from_millis(30),
                false,
            ),
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
                capture_plan(
                    Arc::new(CollectFrames::default()),
                    Duration::from_millis(30),
                    false,
                ),
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

    #[test]
    fn capture_failure_rediscovery_rebuilds_once_then_fails_closed() {
        let (mut executor, state) = executor_with_state();
        let sequence = Arc::new(AtomicU64::new(0));
        executor.active_profile = Some(verified_profile());
        executor.binding = Some(binding());
        executor
            .frame_sequences
            .insert("client".into(), sequence.clone());
        executor.capture = Some(
            spawn_capture_worker(
                Box::new(DeadlineCapture),
                sequence,
                capture_plan(
                    Arc::new(CollectFrames::default()),
                    Duration::from_millis(30),
                    true,
                ),
            )
            .unwrap(),
        );
        std::thread::sleep(Duration::from_millis(100));

        assert!(executor
            .capture_failure_event(&ExecutionSession::test())
            .unwrap()
            .is_none());
        assert_eq!(executor.binding.as_ref().unwrap().window_handle, 200);
        assert_eq!(state.lock().unwrap().rediscovery_calls, 1);

        std::thread::sleep(Duration::from_millis(100));
        let event = executor
            .capture_failure_event(&ExecutionSession::test())
            .unwrap()
            .unwrap();
        assert_eq!(state.lock().unwrap().rediscovery_calls, 1);
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

    #[test]
    fn production_executor_reports_production_runtime_mode() {
        let executor = CommandExecutor::production(ProfileStore::default());

        assert_eq!(executor.runtime_mode, "production");
    }

    #[test]
    fn session_reset_keeps_the_managed_target_until_agent_shutdown() {
        let (mut executor, state) = executor_with_state();
        executor.active_profile = Some(verified_profile());
        executor.binding = Some(binding());
        state.lock().unwrap().target_owned = true;

        executor.reset_session().unwrap();
        assert!(executor.binding.is_some());
        assert!(state.lock().unwrap().close_calls.is_empty());

        executor.shutdown().unwrap();
        assert!(executor.binding.is_none());
        assert_eq!(state.lock().unwrap().close_calls.len(), 1);
    }

    #[test]
    fn v2_client_point_click_reaches_the_device_path() {
        let profile = verified_profile();
        let mut contract = v2::ExecutionContract {
            task_run_id: "11111111-1111-4111-8111-111111111111".into(),
            attempt_id: "22222222-2222-4222-8222-222222222222".into(),
            agent_build_id: option_env!("FAIRYPAM_BUILD_ID").unwrap_or("unknown").into(),
            profile_id: profile.profile().id.clone(),
            profile_digest: profile.content_sha256().into(),
            allowed_capabilities: vec![1, 2, 3, 5],
            deadline_unix_ms: i64::MAX,
            max_input_lease_ms: 1000,
            cleanup_policy: v2::CleanupPolicy::ReleaseInputKeepManagedTarget as i32,
            contract_version: 2,
            contract_digest: String::new(),
        };
        contract.contract_digest = format!(
            "{:x}",
            Sha256::digest(
                fairypam_agent_protocol::canonical_execution_contract(&contract).unwrap()
            )
        );
        let reference = AgentAttemptContractV1 {
            task_run_id: contract.task_run_id.clone(),
            attempt_id: contract.attempt_id.clone(),
            agent_build_id: contract.agent_build_id.clone(),
            profile_id: contract.profile_id.clone(),
            profile_digest: contract.profile_digest.clone(),
            cleanup_policy: "close_owned_target".into(),
            contract_version: contract.contract_version,
            contract_digest: contract.contract_digest.clone(),
        };
        let (mut executor, state) = executor_with_state();
        state.lock().unwrap().fail_begin_monitor = true;
        assert!(matches!(
            executor.execute_v2_begin(&task_ref(&reference, "begin"), &contract),
            CommandOutcome::Nack { ref code, .. } if code == "environment.monitor_failed"
        ));
        state.lock().unwrap().fail_begin_monitor = false;
        assert!(matches!(
            executor.execute_v2_begin(&task_ref(&reference, "begin"), &contract),
            CommandOutcome::TaskAck { .. }
        ));
        assert_eq!(state.lock().unwrap().begin_monitor_calls, 2);
        executor.binding = Some(binding());
        let click = task_ref(&reference, "click");
        let attempt = click.attempt.as_ref().unwrap();
        executor.frame_sequences.insert(
            frame_sequence_key("client", Some(attempt)),
            Arc::new(AtomicU64::new(7)),
        );

        assert!(matches!(
            executor.execute_v2_input_frame(
                &click,
                &v2::InputFrame {
                    input_sequence: 1,
                    lease_ms: 500,
                    source_frame_sequence: Some(7),
                    ..v2::InputFrame::default()
                },
                Some((v2::MouseButton::Left as i32, 500_000, 583_333)),
            ),
            CommandOutcome::TaskAck { .. }
        ));
        assert_eq!(state.lock().unwrap().point_clicks, 1);

        let (mut stale_executor, stale_state) = executor_with_state();
        assert!(matches!(
            stale_executor.execute_v2_begin(&task_ref(&reference, "stale-begin"), &contract),
            CommandOutcome::TaskAck { .. }
        ));
        stale_executor.binding = Some(binding());
        let stale_click = task_ref(&reference, "stale-click");
        let stale_attempt = stale_click.attempt.as_ref().unwrap();
        stale_executor.frame_sequences.insert(
            frame_sequence_key("client", Some(stale_attempt)),
            Arc::new(AtomicU64::new(7)),
        );
        stale_state.lock().unwrap().advance_source_before_click = true;
        let outcome = stale_executor.execute_v2_input_frame(
            &stale_click,
            &v2::InputFrame {
                input_sequence: 1,
                lease_ms: 500,
                source_frame_sequence: Some(7),
                ..v2::InputFrame::default()
            },
            Some((v2::MouseButton::Left as i32, 500_000, 583_333)),
        );

        assert!(matches!(
            outcome,
            CommandOutcome::TaskAck {
                receipt,
                ..
            } if receipt.error_code.as_deref() == Some("source_frame_stale")
        ));
        assert_eq!(stale_state.lock().unwrap().point_clicks, 0);
    }

    #[test]
    fn local_gui_reuses_launch_capture_input_and_close_safety_path() {
        let (mut executor, state) = executor_with_state();

        let launched = executor
            .execute_local(&LocalCommand::LaunchTarget {
                profile_id: "testbed".into(),
            })
            .unwrap();
        assert_eq!(launched["state"], "TargetLocked");
        let preview = executor
            .execute_local(&LocalCommand::CapturePreview)
            .unwrap();
        assert_eq!(preview["bytes"], json!([1, 2, 3]));
        executor
            .execute_local(&LocalCommand::InputProbe {
                action: InputProbeAction::MoveForward,
            })
            .unwrap();
        assert!(!state.lock().unwrap().input_active);
        let closed = executor.execute_local(&LocalCommand::CloseTarget).unwrap();
        assert_eq!(closed["closed"], true);
        assert_eq!(state.lock().unwrap().close_calls.len(), 1);
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

    static NEXT_TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn task_ref(contract: &AgentAttemptContractV1, command_id: &str) -> TaskCommandRef {
        TaskCommandRef {
            command: Some(CommandRef {
                session: Some(SessionRef {
                    agent_id: "agent".into(),
                    session_id: "session".into(),
                    generation: 1,
                }),
                command_id: command_id.into(),
                sequence: NEXT_TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed),
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
        let attempt = match pulse.payload.as_ref() {
            Some(hub_control_command::Payload::PulseAction(value)) => {
                value.task.as_ref().unwrap().attempt.as_ref()
            }
            _ => unreachable!(),
        };
        executor
            .frame_sequences
            .get(&frame_sequence_key("client", attempt))
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
            CommandOutcome::TaskAck { ref outcome, ref receipt, .. }
                if outcome.as_ref().unwrap().outcome
                    == TaskCommandOutcomeState::Uncertain as i32
                    && receipt.error_code.as_deref()
                        == Some("command.payload_digest_conflict")
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
            CommandOutcome::TaskAck { ref outcome, ref receipt, .. }
                if receipt.attempt_state == TaskAttemptState::Terminal as i32
                    && receipt.cleanup_complete == Some(false)
                    && outcome.as_ref().unwrap().outcome
                        == TaskCommandOutcomeState::Uncertain as i32
        ));
        let frames = sink.0.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].attempt.as_ref().unwrap().attempt_id,
            contract.attempt_id
        );
        assert_eq!(state.lock().unwrap().launch_calls, 1);
        assert!(state.lock().unwrap().close_calls.is_empty());
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
        let begin = HubControlCommand {
            payload: Some(hub_control_command::Payload::BeginTaskAttempt(
                BeginTaskAttempt {
                    task: Some(task_ref(&contract, "begin-emergency")),
                    contract: Some(contract.clone()),
                },
            )),
        };
        assert!(matches!(
            executor.execute(&begin, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { .. }
        ));
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["state"],
            "TaskActive"
        );
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["task_active"],
            true
        );

        for command in [
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

        assert_eq!(
            executor.execute_local(&LocalCommand::Doctor).unwrap()["runtime"],
            "dry_run"
        );
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["state"],
            "TargetLocked"
        );
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["task_active"],
            true
        );

        let stopped = executor.execute_local(&LocalCommand::ReleaseAll).unwrap();
        assert_eq!(stopped["state"], "EmergencyStopped");
        assert_eq!(stopped["cleanup_complete"], true);
        assert!(!state.lock().unwrap().input_active);
        assert!(state.lock().unwrap().close_calls.is_empty());
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["state"],
            "EmergencyStopped"
        );
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["task_active"],
            false
        );
        assert_eq!(
            executor.execute_local(&LocalCommand::Doctor).unwrap()["runtime"],
            "dry_run"
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
            "TargetLocked"
        );
        assert_eq!(
            executor.execute_local(&LocalCommand::Status).unwrap()["task_active"],
            false
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
    fn task_capture_frame_publishes_exactly_one_receipted_frame() {
        let profile = verified_profile();
        let contract = task_contract(&profile);
        let (mut executor, state) = executor_with_state();
        let sink = Arc::new(CollectFrames::default());
        for command in [
            HubControlCommand {
                payload: Some(hub_control_command::Payload::BeginTaskAttempt(
                    BeginTaskAttempt {
                        task: Some(task_ref(&contract, "begin-capture-frame")),
                        contract: Some(contract.clone()),
                    },
                )),
            },
            HubControlCommand {
                payload: Some(hub_control_command::Payload::StartTaskTarget(
                    StartTaskTarget {
                        task: Some(task_ref(&contract, "target-capture-frame")),
                    },
                )),
            },
        ] {
            assert!(matches!(
                executor.execute(&command, &ExecutionSession::test(), sink.clone()),
                CommandOutcome::TaskAck { .. }
            ));
        }

        let capture = HubControlCommand {
            payload: Some(hub_control_command::Payload::CaptureFrame(CaptureFrame {
                source_id: "client".into(),
                encoding: "jpeg".into(),
                quality: 85,
                task: Some(task_ref(&contract, "capture-frame-1")),
                ..CaptureFrame::default()
            })),
        };
        assert!(matches!(
            executor.execute(&capture, &ExecutionSession::test(), sink.clone()),
            CommandOutcome::TaskAck { ref outcome, ref receipt, .. }
                if outcome.as_ref().unwrap().source_frame_sequence == Some(1)
                    && receipt.capture_state == fairypam_agent_protocol::v1::TaskCaptureState::Stopped as i32
        ));
        assert!(executor.capture.is_none());
        let frames = sink.0.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_sequence, 1);
        assert_eq!(frames[0].payload, vec![1, 2, 3]);
        assert_eq!(
            frames[0].attempt.as_ref().unwrap().attempt_id,
            contract.attempt_id
        );
        drop(frames);

        let paused_capture = HubControlCommand {
            payload: Some(hub_control_command::Payload::CaptureFrame(CaptureFrame {
                source_id: "client".into(),
                encoding: "jpeg".into(),
                quality: 85,
                task: Some(task_ref(&contract, "capture-frame-paused")),
                ..CaptureFrame::default()
            })),
        };
        assert!(matches!(
            executor.execute(
                &paused_capture,
                &ExecutionSession::test(),
                Arc::new(PausedFrames),
            ),
            CommandOutcome::TaskAck { ref outcome, ref receipt, .. }
                if outcome.as_ref().unwrap().outcome
                    == TaskCommandOutcomeState::NotApplied as i32
                    && outcome.as_ref().unwrap().source_frame_sequence.is_none()
                    && receipt.error_code.as_deref() == Some("transport.frame_paused")
        ));

        {
            let mut state = state.lock().unwrap();
            state.input_active = true;
            state.capture_error = Some(AgentError::new(
                "target.focus_failed",
                "target did not become the foreground window; request_accepted=false, foreground_pid=42, target_pid=84",
            ));
        }
        let focus_failed = HubControlCommand {
            payload: Some(hub_control_command::Payload::CaptureFrame(CaptureFrame {
                source_id: "client".into(),
                encoding: "jpeg".into(),
                quality: 85,
                task: Some(task_ref(&contract, "capture-frame-focus-failed")),
                ..CaptureFrame::default()
            })),
        };
        assert!(matches!(
            executor.execute(&focus_failed, &ExecutionSession::test(), sink),
            CommandOutcome::TaskAck {
                ref outcome,
                ref receipt,
                local_diagnostic: Some(ref diagnostic),
                ..
            } if outcome.as_ref().unwrap().outcome
                    == TaskCommandOutcomeState::NotApplied as i32
                && receipt.error_code.as_deref() == Some("target.focus_failed")
                && diagnostic.contains("request_accepted=false")
                && diagnostic.contains("foreground_pid=42")
                && diagnostic.contains("target_pid=84")
        ));
        assert!(!state.lock().unwrap().input_active);
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
