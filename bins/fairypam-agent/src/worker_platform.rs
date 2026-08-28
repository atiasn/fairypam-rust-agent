use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fairypam_agent_core::profile::{CaptureRegion, VerifiedProfile};
use fairypam_agent_core::target::{TargetBinding, TargetCandidate, TargetSelector, TargetSnapshot};
use fairypam_agent_core::AgentError;
use fairypam_agent_maa::worker_client::windows::{WorkerProcess, WorkerProcessConfig};
use fairypam_agent_protocol::internal_v1::{AttemptRef, SessionRef};
use fairypam_agent_protocol::v3::{
    agent_control_event, AgentControlEvent, AttemptRef as AgentAttemptRef, RealtimeProgramEvent,
    RealtimeProgramMetrics, RealtimeProgramState as AgentRealtimeProgramState,
    SessionRef as AgentSessionRef,
};
use fairypam_agent_protocol::worker_realtime_metrics_digest;
use fairypam_agent_protocol::worker_v1::{
    worker_event, worker_request, AttachTarget, CaptureOnce, DetachTarget, GenericClick,
    GenericKeyDown, GenericKeyUp, GenericScroll, GenericSwipe, GetHealth, RealtimeProgramState,
    ReleaseAll, StartGenericCapture, StartRealtimeProgram, StopGenericCapture, StopRealtimeProgram,
    WindowsIoMode, WorkerEvent, WorkerOutcome, WorkerResponse,
};

use super::{
    ensure_current_source_frame, RuntimeCapture, RuntimeCaptureEncoding, RuntimeCapturedFrame,
    RuntimePlatform, SourceFrameMap, WindowsRuntimePlatform,
};
use crate::profile_store::ProfileStore;

const WORKER_TIMEOUT: Duration = Duration::from_secs(5);
const FRAME_SLOT_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct WorkerRuntimePlatform {
    target: WindowsRuntimePlatform,
    worker: Arc<Mutex<WorkerState>>,
    faulted: Arc<AtomicBool>,
    profile: Option<VerifiedProfile>,
    binding: Option<TargetBinding>,
    session: Option<SessionRef>,
    input_expires_at: Option<Instant>,
    held_actions: BTreeSet<String>,
    realtime_program: Option<String>,
    realtime_attempt: Option<AttemptRef>,
    realtime_terminal: Option<RealtimeProgramState>,
    realtime_events: VecDeque<AgentControlEvent>,
    root_public_key: Option<String>,
    source_frames: Arc<Mutex<SourceFrameMap>>,
}

struct WorkerState {
    config: Option<WorkerProcessConfig>,
    process: Option<WorkerProcess>,
    attached_generation: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttachmentDecision {
    Reuse,
    Attach,
    Replace,
}

fn attachment_decision(
    same_target: bool,
    process_generation: Option<&str>,
    attached_generation: Option<&str>,
) -> AttachmentDecision {
    if !same_target {
        AttachmentDecision::Replace
    } else if process_generation.is_some() && process_generation == attached_generation {
        AttachmentDecision::Reuse
    } else {
        AttachmentDecision::Attach
    }
}

fn retain_input_lease_for_holds(
    held_actions: &BTreeSet<String>,
    input_expires_at: &mut Option<Instant>,
) -> bool {
    let holds_active = !held_actions.is_empty();
    if !holds_active {
        *input_expires_at = None;
    }
    holds_active
}

impl WorkerRuntimePlatform {
    pub(super) fn new(profiles: &ProfileStore, root_public_key: Option<&str>) -> Self {
        let root_public_key = root_public_key.map(str::to_owned);
        let config = worker_config(profiles.root(), root_public_key.as_deref()).ok();
        Self {
            target: WindowsRuntimePlatform::new(),
            worker: Arc::new(Mutex::new(WorkerState {
                config,
                process: None,
                attached_generation: None,
            })),
            faulted: Arc::new(AtomicBool::new(false)),
            profile: None,
            binding: None,
            session: None,
            input_expires_at: None,
            held_actions: BTreeSet::new(),
            realtime_program: None,
            realtime_attempt: None,
            realtime_terminal: None,
            realtime_events: VecDeque::new(),
            root_public_key,
            source_frames: Arc::new(Mutex::new(SourceFrameMap::default())),
        }
    }

    fn clear_source_frames(&self) -> Result<(), AgentError> {
        self.source_frames
            .lock()
            .map_err(|error| AgentError::new("worker.state_poisoned", error.to_string()))?
            .clear();
        Ok(())
    }

    fn runtime_source_frame(&self, public_sequence: u64) -> Result<u64, AgentError> {
        self.source_frames
            .lock()
            .map_err(|error| AgentError::new("worker.state_poisoned", error.to_string()))?
            .runtime_sequence(public_sequence)
            .ok_or_else(|| {
                AgentError::new(
                    "input.frame_invalid",
                    "published source frame is no longer mapped to the Win32 Worker",
                )
            })
    }

    fn attach(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
    ) -> Result<(), AgentError> {
        let mut state = self.lock_worker()?;
        let same_target = matches!(
            (&self.profile, &self.binding),
            (Some(active_profile), Some(active_binding))
                if active_profile.content_sha256() == profile.content_sha256()
                && active_binding.window_handle == binding.window_handle
                && active_binding.process_id == binding.process_id
        );
        let decision = attachment_decision(
            same_target,
            state.process.as_ref().map(WorkerProcess::generation),
            state.attached_generation.as_deref(),
        );
        if decision == AttachmentDecision::Reuse {
            return Ok(());
        }
        self.clear_source_frames()?;
        if decision == AttachmentDecision::Replace {
            if let Some(process) = state.process.as_mut() {
                let _ = request_applied(
                    process,
                    worker_request::Payload::DetachTarget(DetachTarget {}),
                    WORKER_TIMEOUT,
                );
            }
            state.process = None;
            state.attached_generation = None;
        }
        let process = ensure_process(&mut state)?;
        let attach = request_applied(
            process,
            worker_request::Payload::AttachTarget(AttachTarget {
                hwnd: binding.window_handle,
                process_id: binding.process_id,
                profile_id: profile.profile().id.clone(),
                profile_digest: profile.content_sha256().to_owned(),
            }),
            WORKER_TIMEOUT,
        );
        let generation = process.generation().to_owned();
        if attach.is_err() {
            process.terminate();
            state.process = None;
            state.attached_generation = None;
        } else {
            state.attached_generation = Some(generation);
        }
        drop(state);
        attach?;
        self.profile = Some(profile.clone());
        self.binding = Some(binding.clone());
        Ok(())
    }

    fn release_emergency(&mut self, reason: &'static str) -> Result<(), AgentError> {
        let worker_error = match self.worker.try_lock() {
            Ok(mut state) => match state.process.as_mut() {
                Some(process) => {
                    let expected_generation = process.generation().to_owned();
                    let expected_target_generation = process.target_generation();
                    let minimum_input_owner_epoch = process.input_owner_epoch();
                    let result = request_applied_response(
                        process,
                        worker_request::Payload::ReleaseAll(ReleaseAll {
                            reason_code: reason.to_owned(),
                        }),
                        Duration::from_secs(2),
                    )
                    .and_then(|response| {
                        verify_release_health(
                            response.health.as_ref(),
                            &expected_generation,
                            expected_target_generation,
                            minimum_input_owner_epoch,
                        )
                    });
                    if let Err(error) = result {
                        process.terminate();
                        state.process = None;
                        Some(error)
                    } else {
                        process.take_events();
                        None
                    }
                }
                None => None,
            },
            Err(std::sync::TryLockError::WouldBlock) => Some(AgentError::new(
                "input.release_uncertain",
                "Win32 Worker is busy while ReleaseAll is required",
            )),
            Err(std::sync::TryLockError::Poisoned(error)) => {
                Some(AgentError::new("worker.state_poisoned", error.to_string()))
            }
        };
        let rust_release = self.profile.as_ref().map_or(Ok(()), |profile| {
            fairypam_agent_windows::emergency_release_profile(profile)
                .map_err(|error| AgentError::new(error.code(), error.to_string()))
        });
        let release = match (worker_error, rust_release.err()) {
            (None, None) => Ok(()),
            (Some(worker), None) => Err(worker),
            (None, Some(release)) => Err(release),
            (Some(worker), Some(release)) => Err(AgentError::new(
                "input.release_uncertain",
                format!("{worker}; Rust emergency release failed: {release}"),
            )),
        };
        match (release, self.clear_source_frames()) {
            (Ok(()), Ok(())) => {
                self.held_actions.clear();
                self.session = None;
                self.input_expires_at = None;
                self.realtime_program = None;
                self.realtime_attempt = None;
                self.realtime_terminal = None;
                self.realtime_events.clear();
                Ok(())
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(release), Err(frames)) => Err(AgentError::new(
                "input.release_uncertain",
                format!("{release}; source frame cleanup failed: {frames}"),
            )),
        }
    }

    fn handle_side_effect<T>(&mut self, result: Result<T, AgentError>) -> Result<T, AgentError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) if error.code() == "worker.not_applied" => Err(error),
            Err(error) => Err(self.mark_uncertain(error)),
        }
    }

    fn mark_uncertain(&mut self, error: AgentError) -> AgentError {
        self.faulted.store(true, Ordering::Release);
        let release = self.release_emergency("worker-side-effect-uncertain").err();
        AgentError::new(
            if release.is_some() {
                "input.release_uncertain"
            } else {
                "worker.side_effect_uncertain"
            },
            release.map_or_else(
                || error.to_string(),
                |release| format!("{error}; {release}"),
            ),
        )
    }

    fn request_in_sequence(
        &mut self,
        payload: worker_request::Payload,
        applied_any: &mut bool,
    ) -> Result<(), AgentError> {
        match self.request(payload) {
            Ok(()) => {
                *applied_any = true;
                Ok(())
            }
            Err(error) if *applied_any && error.code() == "worker.not_applied" => {
                Err(self.mark_uncertain(error))
            }
            Err(error) => Err(error),
        }
    }

    fn request(&mut self, payload: worker_request::Payload) -> Result<(), AgentError> {
        let (result, generation, events, held_action_ids) = {
            let mut state = self.lock_worker()?;
            let process = ensure_process(&mut state)?;
            let result = request_applied(process, payload, WORKER_TIMEOUT);
            (
                result,
                process.generation().to_owned(),
                process.take_events(),
                process.held_action_ids().to_vec(),
            )
        };
        self.held_actions = held_action_ids.into_iter().collect();
        if let Err(error) = self.queue_worker_events(&generation, events) {
            let terminal_events = std::mem::take(&mut self.realtime_events);
            let error = self.mark_uncertain(error);
            self.realtime_events = terminal_events;
            return Err(error);
        }
        self.handle_side_effect(result)
    }

    fn queue_worker_events(
        &mut self,
        generation: &str,
        events: Vec<WorkerEvent>,
    ) -> Result<(), AgentError> {
        let mut release_uncertain = false;
        for event in events {
            if event.worker_generation != generation {
                return Err(AgentError::new(
                    "worker.generation_stale",
                    "Worker event generation is stale",
                ));
            }
            let Some(worker_event::Payload::RealtimeProgram(program)) = event.payload else {
                continue;
            };
            let session = self.session.as_ref().ok_or_else(|| {
                AgentError::new(
                    "worker.event_invalid",
                    "Realtime Program event has no active input session",
                )
            })?;
            let session = AgentSessionRef {
                agent_id: session.agent_id.clone(),
                session_id: session.session_id.clone(),
                generation: session.generation,
            };
            let attempt = self.realtime_attempt.as_ref().ok_or_else(|| {
                AgentError::new(
                    "worker.event_invalid",
                    "Realtime Program event has no active attempt",
                )
            })?;
            let attempt = AgentAttemptRef {
                task_run_id: attempt.task_run_id.clone(),
                attempt_id: attempt.attempt_id.clone(),
                contract_version: attempt.contract_version,
                contract_digest: attempt.contract_digest.clone(),
            };
            let state = RealtimeProgramState::try_from(program.state).map_err(|_| {
                AgentError::new(
                    "worker.event_invalid",
                    "Realtime Program event state is invalid",
                )
            })?;
            if state == RealtimeProgramState::Unspecified
                || self.realtime_program.as_deref() != Some(program.program_id.as_str())
            {
                return Err(AgentError::new(
                    "worker.event_invalid",
                    "Realtime Program event does not match the active program",
                ));
            }
            if program.metrics_digest.as_deref().is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            }) {
                return Err(AgentError::new(
                    "worker.event_invalid",
                    "Realtime Program metrics digest is invalid",
                ));
            }
            if let Some(metrics) = program.metrics.as_ref() {
                let expected_digest = worker_realtime_metrics_digest(metrics);
                if program.metrics_digest.as_deref() != Some(expected_digest.as_str()) {
                    return Err(AgentError::new(
                        "worker.event_invalid",
                        "Realtime Program metrics digest does not match its payload",
                    ));
                }
            }
            let agent_state = map_realtime_state(state);
            self.realtime_events.push_back(AgentControlEvent {
                payload: Some(agent_control_event::Payload::RealtimeProgramEvent(
                    RealtimeProgramEvent {
                        session: Some(session.clone()),
                        attempt: Some(attempt.clone()),
                        program_id: program.program_id.clone(),
                        worker_generation: event.worker_generation.clone(),
                        state: agent_state as i32,
                        started_at_unix_ms: program.started_at_unix_ms,
                        ended_at_unix_ms: program.ended_at_unix_ms,
                        error_code: program.error_code.clone(),
                        metrics_digest: program.metrics_digest.clone(),
                    },
                )),
            });
            if let Some(metrics) = program.metrics {
                self.realtime_events.push_back(AgentControlEvent {
                    payload: Some(agent_control_event::Payload::RealtimeProgramMetrics(
                        RealtimeProgramMetrics {
                            session: Some(session),
                            attempt: Some(attempt),
                            program_id: program.program_id.clone(),
                            worker_generation: event.worker_generation,
                            sample_count: metrics.sample_count,
                            transition_count: metrics.transition_count,
                            missed_deadlines: metrics.missed_deadlines,
                            stale_events: metrics.stale_events,
                            queue_overflows: metrics.queue_overflows,
                            sample_interval_p50_us: metrics.sample_interval_p50_us,
                            sample_interval_p95_us: metrics.sample_interval_p95_us,
                            sample_interval_p99_us: metrics.sample_interval_p99_us,
                            scheduler_lateness_p99_us: metrics.scheduler_lateness_p99_us,
                            detection_to_input_p99_us: metrics.detection_to_input_p99_us,
                            chord_skew_p99_us: metrics.chord_skew_p99_us,
                            metrics_digest: program.metrics_digest.unwrap_or_default(),
                        },
                    )),
                });
            }
            if matches!(
                state,
                RealtimeProgramState::Completed
                    | RealtimeProgramState::Failed
                    | RealtimeProgramState::Cancelled
                    | RealtimeProgramState::ReleaseUncertain
            ) {
                self.realtime_terminal = Some(state);
            }
            release_uncertain |= state == RealtimeProgramState::ReleaseUncertain;
        }
        if release_uncertain {
            Err(AgentError::new(
                "realtime.release_uncertain",
                "Realtime Program could not prove input release",
            ))
        } else {
            Ok(())
        }
    }

    fn require_session(&self, session: &SessionRef) -> Result<(), AgentError> {
        if self.session.as_ref() == Some(session) {
            Ok(())
        } else {
            Err(AgentError::new(
                "input_lease_invalid",
                "input lease does not belong to the current session",
            ))
        }
    }

    fn guard_local_input(&mut self) -> Result<(), AgentError> {
        match <WindowsRuntimePlatform as RuntimePlatform>::check_attempt_environment(
            &mut self.target,
        ) {
            Err(error) if error.code() == "environment.local_input_detected" => {
                self.release_emergency("local-input-pause")?;
                Err(error)
            }
            result => result,
        }
    }

    fn lock_worker(&self) -> Result<std::sync::MutexGuard<'_, WorkerState>, AgentError> {
        self.worker
            .lock()
            .map_err(|error| AgentError::new("worker.state_poisoned", error.to_string()))
    }

    fn detach_worker(&mut self) {
        if let Ok(mut state) = self.worker.lock() {
            if let Some(process) = state.process.as_mut() {
                let _ = request_applied(
                    process,
                    worker_request::Payload::DetachTarget(DetachTarget {}),
                    WORKER_TIMEOUT,
                );
                process.terminate();
            }
            state.process = None;
            state.attached_generation = None;
        }
        self.profile = None;
        self.binding = None;
        self.faulted.store(false, Ordering::Release);
        if self.clear_source_frames().is_err() {
            self.faulted.store(true, Ordering::Release);
        }
    }
}

fn verify_release_health(
    health: Option<&fairypam_agent_protocol::worker_v1::WorkerHealth>,
    expected_generation: &str,
    expected_target_generation: u64,
    minimum_input_owner_epoch: u64,
) -> Result<(), AgentError> {
    let health = health.ok_or_else(|| {
        AgentError::new(
            "input.release_uncertain",
            "Worker ReleaseAll response has no health proof",
        )
    })?;
    let mode = WindowsIoMode::try_from(health.io_mode).unwrap_or(WindowsIoMode::Unspecified);
    if health.worker_generation != expected_generation
        || health.target_generation != expected_target_generation
        || health.input_owner_epoch < minimum_input_owner_epoch
        || !matches!(mode, WindowsIoMode::Detached | WindowsIoMode::Generic)
        || !health.held_action_ids.is_empty()
    {
        return Err(AgentError::new(
            "input.release_uncertain",
            "Worker still reports active or uncertain input after ReleaseAll",
        ));
    }
    Ok(())
}

impl RuntimePlatform for WorkerRuntimePlatform {
    fn ensure_worker_ready(&mut self) -> Result<Option<super::WindowsIoRuntimeInfo>, AgentError> {
        let mut state = self.lock_worker()?;
        let result = ensure_process(&mut state).and_then(|process| {
            request_applied(
                process,
                worker_request::Payload::GetHealth(GetHealth {}),
                WORKER_TIMEOUT,
            )?;
            let info = process.runtime_info();
            Ok(super::WindowsIoRuntimeInfo {
                maa_runtime_version: info.maa_runtime_version.clone(),
                capture_backend: info.capture_backend.clone(),
                input_backend: info.input_backend.clone(),
            })
        });
        match result {
            Ok(info) => Ok(Some(info)),
            Err(error) => {
                self.faulted.store(true, Ordering::Release);
                if let Some(process) = state.process.as_mut() {
                    process.terminate();
                }
                state.process = None;
                Err(error)
            }
        }
    }

    fn configure_worker(
        &mut self,
        profile_root: Option<&Path>,
        root_public_key: Option<&str>,
    ) -> Result<(), AgentError> {
        if let Some(key) = root_public_key {
            self.root_public_key = Some(key.to_owned());
        }
        let config = Some(worker_config(
            profile_root,
            self.root_public_key.as_deref(),
        )?);
        let mut state = self.lock_worker()?;
        if matches!((&state.config, &config), (Some(current), Some(next)) if
            current.profile_dir == next.profile_dir
                && current.profile_root_public_key == next.profile_root_public_key
                && current.runtime_root_public_key == next.runtime_root_public_key
                && current.runtime_root == next.runtime_root
                && current.executable == next.executable)
        {
            return Ok(());
        }
        if let Some(process) = state.process.as_mut() {
            process.terminate();
        }
        state.process = None;
        state.attached_generation = None;
        state.config = config;
        drop(state);
        self.profile = None;
        self.binding = None;
        self.session = None;
        self.input_expires_at = None;
        self.held_actions.clear();
        self.realtime_program = None;
        self.realtime_attempt = None;
        self.realtime_terminal = None;
        self.realtime_events.clear();
        self.clear_source_frames()?;
        Ok(())
    }

    fn begin_attempt_monitor(&mut self) -> Result<bool, AgentError> {
        <WindowsRuntimePlatform as RuntimePlatform>::begin_attempt_monitor(&mut self.target)
    }

    fn check_attempt_environment(&mut self) -> Result<(), AgentError> {
        <WindowsRuntimePlatform as RuntimePlatform>::check_attempt_environment(&mut self.target)
    }

    fn finish_attempt_monitor(&mut self) {
        <WindowsRuntimePlatform as RuntimePlatform>::finish_attempt_monitor(&mut self.target)
    }

    fn start_task_target(
        &mut self,
        profile: &VerifiedProfile,
    ) -> Result<TargetBinding, AgentError> {
        let binding = <WindowsRuntimePlatform as RuntimePlatform>::start_task_target(
            &mut self.target,
            profile,
        )?;
        self.attach(profile, &binding)?;
        Ok(binding)
    }

    fn enumerate(&mut self, profile: &VerifiedProfile) -> Result<Vec<TargetCandidate>, AgentError> {
        <WindowsRuntimePlatform as RuntimePlatform>::enumerate(&mut self.target, profile)
    }

    fn lock(
        &mut self,
        profile: &VerifiedProfile,
        selector: TargetSelector,
    ) -> Result<TargetBinding, AgentError> {
        let binding =
            <WindowsRuntimePlatform as RuntimePlatform>::lock(&mut self.target, profile, selector)?;
        self.attach(profile, &binding)?;
        Ok(binding)
    }

    fn rediscover_target(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
    ) -> Result<TargetBinding, AgentError> {
        let binding = <WindowsRuntimePlatform as RuntimePlatform>::rediscover_target(
            &mut self.target,
            profile,
            binding,
        )?;
        self.attach(profile, &binding)?;
        Ok(binding)
    }

    fn capture_once(
        &mut self,
        binding: &TargetBinding,
        source_id: &str,
        region: CaptureRegion,
        _fps: u32,
        encoding: RuntimeCaptureEncoding,
        deadline: Instant,
    ) -> Result<RuntimeCapturedFrame, AgentError> {
        if region != CaptureRegion::FullClient {
            return Err(AgentError::new(
                "capture.region_unsupported",
                "MAA Generic capture only exposes the full client frame",
            ));
        }
        self.tick_input_safety(Instant::now())?;
        let profile = self
            .profile
            .clone()
            .ok_or_else(|| AgentError::new("profile.not_active", "worker has no active Profile"))?;
        self.attach(&profile, binding)?;
        let (encoding, quality) = match encoding {
            RuntimeCaptureEncoding::Jpeg { quality } => ("jpeg", u32::from(quality)),
            RuntimeCaptureEncoding::Png => ("png", 0),
        };
        let sequence = {
            let mut state = self.lock_worker()?;
            let response = request_applied_response(
                ensure_process(&mut state)?,
                worker_request::Payload::CaptureOnce(CaptureOnce {
                    capture_source_id: source_id.to_owned(),
                    encoding: encoding.to_owned(),
                    quality,
                }),
                WORKER_TIMEOUT,
            )?;
            response.frame_sequence.ok_or_else(|| {
                AgentError::new(
                    "worker.response_invalid",
                    "Worker CaptureOnce response has no frame sequence",
                )
            })?
        };
        let mut capture = WorkerCapture {
            worker: Arc::clone(&self.worker),
            faulted: Arc::clone(&self.faulted),
            profile,
            source_id: None,
            last_sequence: sequence.saturating_sub(1),
            source_frames: Arc::clone(&self.source_frames),
        };
        let frame = capture.next_frame(deadline)?;
        if frame.sequence != sequence {
            return Err(AgentError::new(
                "worker.frame_sequence_invalid",
                "Worker CaptureOnce frame does not match its response",
            ));
        }
        self.source_frames
            .lock()
            .map_err(|error| AgentError::new("worker.state_poisoned", error.to_string()))?
            .record(frame.sequence, frame.sequence);
        Ok(frame)
    }

    fn start_capture(
        &mut self,
        binding: &TargetBinding,
        source_id: &str,
        region: CaptureRegion,
        fps: u32,
        encoding: RuntimeCaptureEncoding,
    ) -> Result<Box<dyn RuntimeCapture>, AgentError> {
        if region != CaptureRegion::FullClient {
            return Err(AgentError::new(
                "capture.region_unsupported",
                "MAA Generic capture only exposes the full client frame",
            ));
        }
        let profile = self
            .profile
            .clone()
            .ok_or_else(|| AgentError::new("profile.not_active", "worker has no active Profile"))?;
        self.attach(&profile, binding)?;
        let (encoding_name, quality) = match encoding {
            RuntimeCaptureEncoding::Jpeg { quality } => ("jpeg", u32::from(quality)),
            RuntimeCaptureEncoding::Png => ("png", 0),
        };
        {
            self.clear_source_frames()?;
            let mut state = self.lock_worker()?;
            request_applied(
                ensure_process(&mut state)?,
                worker_request::Payload::StartGenericCapture(StartGenericCapture {
                    capture_source_id: source_id.to_owned(),
                    fps,
                    encoding: encoding_name.to_owned(),
                    quality,
                }),
                WORKER_TIMEOUT,
            )?;
        }
        Ok(Box::new(WorkerCapture {
            worker: Arc::clone(&self.worker),
            faulted: Arc::clone(&self.faulted),
            profile,
            source_id: Some(source_id.to_owned()),
            last_sequence: 0,
            source_frames: Arc::clone(&self.source_frames),
        }))
    }

    fn focus(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError> {
        <WindowsRuntimePlatform as RuntimePlatform>::focus(&mut self.target, binding)
    }

    fn local_foreground_input_token(
        &mut self,
        binding: &TargetBinding,
    ) -> Result<Option<u32>, AgentError> {
        <WindowsRuntimePlatform as RuntimePlatform>::local_foreground_input_token(
            &mut self.target,
            binding,
        )
    }

    fn close(&mut self, binding: &TargetBinding, timeout: Duration) -> Result<(), AgentError> {
        let release = self.release_emergency("target-close");
        self.detach_worker();
        <WindowsRuntimePlatform as RuntimePlatform>::close(&mut self.target, binding, timeout)?;
        release
    }

    fn close_with_progress(
        &mut self,
        binding: &TargetBinding,
        timeout: Duration,
        on_force: &mut dyn FnMut(),
    ) -> Result<fairypam_agent_protocol::v3::ManagedGameCloseResult, AgentError> {
        let release = self.release_emergency("target-close");
        self.detach_worker();
        let close = <WindowsRuntimePlatform as RuntimePlatform>::close_with_progress(
            &mut self.target,
            binding,
            timeout,
            on_force,
        );
        match (close, release) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(close), Err(release)) => Err(AgentError::new(
                "target.close_release_failed",
                format!("{close}; input release failed: {release}"),
            )),
        }
    }

    fn start_task_input(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
        session: &SessionRef,
        expires_at: Instant,
    ) -> Result<(), AgentError> {
        self.guard_local_input()?;
        if self.faulted.load(Ordering::Acquire) {
            return Err(AgentError::new(
                "worker.reobservation_required",
                "Hub must observe a new frame after Worker recovery",
            ));
        }
        self.attach(profile, binding)?;
        self.session = Some(session.clone());
        self.input_expires_at = Some(expires_at);
        Ok(())
    }

    fn tick_input_safety(&mut self, now: Instant) -> Result<bool, AgentError> {
        if self
            .input_expires_at
            .is_some_and(|deadline| deadline <= now)
        {
            self.release_emergency("input-lease-expired")?;
            return Ok(true);
        }
        Ok(false)
    }

    fn pulse_task_action(
        &mut self,
        binding: &TargetBinding,
        session: &SessionRef,
        action_id: &str,
        now: Instant,
    ) -> Result<(), AgentError> {
        let deadline = self.input_expires_at.unwrap_or(now + WORKER_TIMEOUT);
        self.guard_local_input()?;
        if self.session.is_none() {
            let profile = self.profile.clone().ok_or_else(|| {
                AgentError::new("worker.not_attached", "worker input profile is unavailable")
            })?;
            self.start_task_input(&profile, binding, session, deadline)?;
        }
        self.require_session(session)?;
        let mut applied_any = false;
        self.request_in_sequence(
            worker_request::Payload::GenericKeyDown(GenericKeyDown {
                action_id: action_id.to_owned(),
            }),
            &mut applied_any,
        )?;
        self.request_in_sequence(
            worker_request::Payload::GenericKeyUp(GenericKeyUp {
                action_id: action_id.to_owned(),
            }),
            &mut applied_any,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_task_input_frame(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
        session: &SessionRef,
        _input_sequence: u64,
        expires_at: Instant,
        held_action_ids: &[String],
        wheel_action_id: &str,
        wheel_delta: i32,
        wheel_point: Option<(u32, u32)>,
        source_frame: Option<(&AtomicU64, u64)>,
        client_point: Option<(&str, u32, u32)>,
        client_swipe: Option<(&str, u32, u32, u32, u32, u32)>,
    ) -> Result<bool, AgentError> {
        if expires_at <= Instant::now() {
            return Err(AgentError::new(
                "input_lease_expired",
                "input lease expired",
            ));
        }
        self.guard_local_input()?;
        if self.session.is_none() {
            self.start_task_input(profile, binding, session, expires_at)?;
        }
        self.require_session(session)?;
        self.input_expires_at = Some(expires_at);
        ensure_current_source_frame(source_frame)?;
        let runtime_source_frame =
            if wheel_delta != 0 || client_point.is_some() || client_swipe.is_some() {
                source_frame
                    .map(|(_, sequence)| self.runtime_source_frame(sequence))
                    .transpose()?
            } else {
                None
            };
        let requested = held_action_ids.iter().cloned().collect::<BTreeSet<_>>();
        let mut applied_any = false;
        for action_id in self
            .held_actions
            .difference(&requested)
            .cloned()
            .collect::<Vec<_>>()
        {
            self.request_in_sequence(
                worker_request::Payload::GenericKeyUp(GenericKeyUp {
                    action_id: action_id.clone(),
                }),
                &mut applied_any,
            )?;
            self.held_actions.remove(&action_id);
        }
        for action_id in requested
            .difference(&self.held_actions)
            .cloned()
            .collect::<Vec<_>>()
        {
            self.request_in_sequence(
                worker_request::Payload::GenericKeyDown(GenericKeyDown {
                    action_id: action_id.clone(),
                }),
                &mut applied_any,
            )?;
            self.held_actions.insert(action_id);
        }
        if wheel_delta != 0 {
            self.request_in_sequence(
                worker_request::Payload::GenericScroll(GenericScroll {
                    action_id: wheel_action_id.to_owned(),
                    delta: wheel_delta,
                    x_ppm: wheel_point.map(|value| value.0),
                    y_ppm: wheel_point.map(|value| value.1),
                    source_frame_sequence: runtime_source_frame,
                }),
                &mut applied_any,
            )?;
        }
        if let Some((action_id, x_ppm, y_ppm)) = client_point {
            let source_frame_sequence = runtime_source_frame.ok_or_else(|| {
                AgentError::new("input.frame_invalid", "click requires a source frame")
            })?;
            self.request_in_sequence(
                worker_request::Payload::GenericClick(GenericClick {
                    action_id: action_id.to_owned(),
                    x_ppm,
                    y_ppm,
                    source_frame_sequence,
                }),
                &mut applied_any,
            )?;
        }
        if let Some((action_id, start_x_ppm, start_y_ppm, end_x_ppm, end_y_ppm, duration_ms)) =
            client_swipe
        {
            let source_frame_sequence = runtime_source_frame.ok_or_else(|| {
                AgentError::new("input.frame_invalid", "swipe requires a source frame")
            })?;
            self.request_in_sequence(
                worker_request::Payload::GenericSwipe(GenericSwipe {
                    action_id: action_id.to_owned(),
                    start_x_ppm,
                    start_y_ppm,
                    end_x_ppm,
                    end_y_ppm,
                    duration_ms,
                    source_frame_sequence,
                }),
                &mut applied_any,
            )?;
        }
        Ok(retain_input_lease_for_holds(
            &self.held_actions,
            &mut self.input_expires_at,
        ))
    }

    fn release_task_input(&mut self) -> Result<(), AgentError> {
        self.release_emergency("agent-release-all")
    }

    fn start_realtime_program(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
        session: &SessionRef,
        attempt: &AttemptRef,
        program_id: &str,
        program_schema_version: u32,
        program_digest: &str,
        maximum_duration: Duration,
        supervision_lease: Duration,
    ) -> Result<(), AgentError> {
        self.start_task_input(profile, binding, session, Instant::now() + maximum_duration)?;
        if !self.held_actions.is_empty() {
            self.release_emergency("realtime-transition")?;
            self.session = Some(session.clone());
        }
        let maximum_duration_ms = u32::try_from(maximum_duration.as_millis()).map_err(|_| {
            AgentError::new(
                "realtime.maximum_duration_invalid",
                "maximum duration is too large",
            )
        })?;
        let supervision_lease_ms = (!supervision_lease.is_zero())
            .then(|| u32::try_from(supervision_lease.as_millis()))
            .transpose()
            .map_err(|_| {
                AgentError::new(
                    "realtime.supervision_invalid",
                    "supervision lease is too large",
                )
            })?;
        self.realtime_program = Some(program_id.to_owned());
        self.realtime_attempt = Some(attempt.clone());
        self.realtime_terminal = None;
        let result = self.request(worker_request::Payload::StartRealtimeProgram(
            StartRealtimeProgram {
                program_id: program_id.to_owned(),
                program_schema_version,
                program_digest: program_digest.to_owned(),
                maximum_duration_ms,
                supervision_lease_ms,
            },
        ));
        if result.is_err() {
            self.realtime_program = None;
            self.realtime_attempt = None;
            self.realtime_terminal = None;
        } else {
            self.input_expires_at = None;
        }
        result
    }

    fn renew_realtime_program(
        &mut self,
        program_id: &str,
        supervision_lease: Duration,
    ) -> Result<(), AgentError> {
        if self.realtime_program.as_deref() != Some(program_id) {
            return Err(AgentError::new(
                "realtime.program_not_running",
                "Realtime Program id does not match the active program",
            ));
        }
        if self.realtime_terminal.is_some() {
            return Err(AgentError::new(
                "realtime.program_not_running",
                "Realtime Program already reached a terminal state",
            ));
        }
        let supervision_lease_ms = u32::try_from(supervision_lease.as_millis()).map_err(|_| {
            AgentError::new(
                "realtime.supervision_invalid",
                "supervision lease is too large",
            )
        })?;
        self.request(worker_request::Payload::RenewRealtimeProgram(
            fairypam_agent_protocol::worker_v1::RenewRealtimeProgram {
                program_id: program_id.to_owned(),
                supervision_lease_ms,
            },
        ))
    }

    fn stop_realtime_program(
        &mut self,
        program_id: &str,
    ) -> Result<Option<AgentError>, AgentError> {
        if self.realtime_program.as_deref() != Some(program_id) {
            return Err(AgentError::new(
                "realtime.program_not_running",
                "Realtime Program id does not match the active program",
            ));
        }
        if let Some(state) = self.realtime_terminal.take() {
            self.realtime_program = None;
            self.realtime_attempt = None;
            return if state == RealtimeProgramState::ReleaseUncertain {
                Err(AgentError::new(
                    "realtime.release_uncertain",
                    "Realtime Program could not prove input release",
                ))
            } else {
                Ok(None)
            };
        }
        self.request(worker_request::Payload::StopRealtimeProgram(
            StopRealtimeProgram {
                program_id: program_id.to_owned(),
            },
        ))?;
        self.realtime_program = None;
        self.realtime_attempt = None;
        self.realtime_terminal = None;
        Ok(None)
    }

    fn poll_realtime_program_events(&mut self) -> Result<Vec<AgentControlEvent>, AgentError> {
        if self.realtime_program.is_some() && self.realtime_terminal.is_none() {
            self.request(worker_request::Payload::GetHealth(GetHealth {}))?;
        }
        Ok(self.realtime_events.drain(..).collect())
    }
}

fn map_realtime_state(state: RealtimeProgramState) -> AgentRealtimeProgramState {
    match state {
        RealtimeProgramState::Starting => AgentRealtimeProgramState::Starting,
        RealtimeProgramState::Running => AgentRealtimeProgramState::Running,
        RealtimeProgramState::Stopping => AgentRealtimeProgramState::Stopping,
        RealtimeProgramState::Completed => AgentRealtimeProgramState::Completed,
        RealtimeProgramState::Failed => AgentRealtimeProgramState::Failed,
        RealtimeProgramState::Cancelled => AgentRealtimeProgramState::Cancelled,
        RealtimeProgramState::ReleaseUncertain => AgentRealtimeProgramState::ReleaseUncertain,
        RealtimeProgramState::Unspecified => AgentRealtimeProgramState::Unspecified,
    }
}

struct WorkerCapture {
    worker: Arc<Mutex<WorkerState>>,
    faulted: Arc<AtomicBool>,
    profile: VerifiedProfile,
    source_id: Option<String>,
    last_sequence: u64,
    source_frames: Arc<Mutex<SourceFrameMap>>,
}

impl RuntimeCapture for WorkerCapture {
    fn next_frame(&mut self, deadline: Instant) -> Result<RuntimeCapturedFrame, AgentError> {
        let result = self
            .worker
            .lock()
            .map_err(|error| AgentError::new("worker.state_poisoned", error.to_string()))?
            .process
            .as_mut()
            .ok_or_else(|| AgentError::new("worker.crashed", "Win32 Worker is unavailable"))?
            .next_frame(self.last_sequence, deadline)
            .map_err(map_worker_error);
        match result {
            Ok(frame) => {
                self.last_sequence = frame.sequence;
                self.faulted.store(false, Ordering::Release);
                Ok(RuntimeCapturedFrame {
                    bytes: frame.bytes,
                    width: frame.width,
                    height: frame.height,
                    sequence: frame.sequence,
                    captured_at_unix_us: frame.captured_at_unix_us,
                    backend: frame.backend,
                })
            }
            Err(error) => {
                self.faulted.store(true, Ordering::Release);
                if let Ok(mut state) = self.worker.lock() {
                    if let Some(process) = state.process.as_mut() {
                        process.terminate();
                    }
                    state.process = None;
                }
                let release = fairypam_agent_windows::emergency_release_profile(&self.profile)
                    .map_err(|release| AgentError::new(release.code(), release.to_string()))
                    .err();
                Err(AgentError::new(
                    "worker.capture_failed",
                    release.map_or_else(
                        || error.to_string(),
                        |release| format!("{error}; {release}"),
                    ),
                ))
            }
        }
    }

    fn bind_frame_sequence(
        &mut self,
        runtime_sequence: u64,
        public_sequence: u64,
    ) -> Result<(), AgentError> {
        self.source_frames
            .lock()
            .map_err(|error| AgentError::new("worker.state_poisoned", error.to_string()))?
            .record(public_sequence, runtime_sequence);
        Ok(())
    }
}

impl Drop for WorkerCapture {
    fn drop(&mut self) {
        let Some(source_id) = self.source_id.as_ref() else {
            return;
        };
        if let Ok(mut state) = self.worker.lock() {
            if let Some(process) = state.process.as_mut() {
                let _ = request_applied(
                    process,
                    worker_request::Payload::StopGenericCapture(StopGenericCapture {
                        capture_source_id: source_id.clone(),
                    }),
                    Duration::from_secs(2),
                );
            }
        }
    }
}

fn ensure_process(state: &mut WorkerState) -> Result<&mut WorkerProcess, AgentError> {
    if state.process.is_none() {
        state.attached_generation = None;
        let config = state.config.as_ref().ok_or_else(|| {
            AgentError::new(
                "maa.runtime_unavailable",
                "Worker runtime or signed Profile directory is not configured",
            )
        })?;
        state.process = Some(WorkerProcess::spawn(config).map_err(map_worker_error)?);
    }
    Ok(state.process.as_mut().unwrap())
}

fn request_applied(
    process: &mut WorkerProcess,
    payload: worker_request::Payload,
    timeout: Duration,
) -> Result<(), AgentError> {
    request_applied_response(process, payload, timeout).map(drop)
}

fn request_applied_response(
    process: &mut WorkerProcess,
    payload: worker_request::Payload,
    timeout: Duration,
) -> Result<WorkerResponse, AgentError> {
    let expected_action = match &payload {
        worker_request::Payload::GenericClick(value) => Some(value.action_id.clone()),
        worker_request::Payload::GenericSwipe(value) => Some(value.action_id.clone()),
        worker_request::Payload::GenericKeyDown(value) => Some(value.action_id.clone()),
        worker_request::Payload::GenericKeyUp(value) => Some(value.action_id.clone()),
        worker_request::Payload::GenericScroll(value) => Some(value.action_id.clone()),
        worker_request::Payload::GenericRelativeMove(value) => Some(value.action_id.clone()),
        _ => None,
    };
    let response = process
        .request(payload, timeout)
        .map_err(map_worker_error)?;
    match WorkerOutcome::try_from(response.outcome).unwrap_or(WorkerOutcome::Unspecified) {
        WorkerOutcome::Applied
            if expected_action.as_deref().is_none_or(|expected| {
                response.applied_action_ids.len() == 1 && response.applied_action_ids[0] == expected
            }) =>
        {
            Ok(response)
        }
        WorkerOutcome::Applied => Err(AgentError::new(
            "worker.side_effect_uncertain",
            "Worker Applied result does not identify the requested action",
        )),
        WorkerOutcome::NotApplied => Err(AgentError::new(
            "worker.not_applied",
            response
                .error_code
                .unwrap_or_else(|| "worker.not_applied".to_owned()),
        )),
        WorkerOutcome::Uncertain | WorkerOutcome::Unspecified => Err(AgentError::new(
            "worker.side_effect_uncertain",
            response
                .error_code
                .unwrap_or_else(|| "worker.side_effect_uncertain".to_owned()),
        )),
    }
}

fn worker_config(
    profile_root: Option<&Path>,
    root_public_key: Option<&str>,
) -> Result<WorkerProcessConfig, AgentError> {
    let profile_dir = profile_root.map(Path::to_path_buf);
    let profile_root_public_key = match &profile_dir {
        Some(_) => Some(
            root_public_key
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AgentError::new(
                        "profile.root_key_unavailable",
                        "Profile Root key is unavailable",
                    )
                })?
                .to_owned(),
        ),
        None => None,
    };
    let executable = std::env::current_exe()
        .map_err(|error| AgentError::new("worker.start_failed", error.to_string()))?;
    let install_root = executable
        .parent()
        .ok_or_else(|| AgentError::new("worker.start_failed", "Agent executable has no parent"))?;
    let worker_executable = install_root.join("fairypam-win32-worker.exe");
    let runtime_root = std::env::var_os("FAIRYPAM_MAA_RUNTIME_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| install_root.join("runtime").join("maa"));
    let runtime_root_public_key = option_env!("FAIRYPAM_MAA_RUNTIME_ROOT_PUBLIC_KEY_HEX")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(WorkerProcessConfig {
        executable: worker_executable,
        runtime_root,
        profile_dir,
        profile_root_public_key,
        runtime_root_public_key,
        frame_slot_bytes: FRAME_SLOT_BYTES,
    })
}

fn map_worker_error(error: fairypam_agent_maa::MaaRuntimeError) -> AgentError {
    tracing::error!(error_code = error.code(), error = %error, "Win32 Worker operation failed");
    AgentError::new(error.code(), error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    use fairypam_agent_protocol::worker_v1::{WindowsIoMode, WorkerHealth};

    use super::{
        attachment_decision, retain_input_lease_for_holds, verify_release_health,
        AttachmentDecision, RuntimePlatform, WorkerRuntimePlatform,
    };
    use crate::profile_store::ProfileStore;

    #[test]
    fn empty_profile_store_configures_an_idle_worker() {
        let mut platform = WorkerRuntimePlatform::new(&ProfileStore::default(), None);

        RuntimePlatform::configure_worker(&mut platform, None, Some("profile-root-key")).unwrap();

        let state = platform.worker.lock().unwrap();
        let config = state.config.as_ref().unwrap();
        assert!(config.profile_dir.is_none());
        assert!(config.profile_root_public_key.is_none());
        assert!(config.runtime_root_public_key.is_none());
        assert!(state.process.is_none());
        assert!(state.attached_generation.is_none());
    }

    #[test]
    fn configured_profile_root_still_requires_its_signing_key() {
        let mut platform = WorkerRuntimePlatform::new(&ProfileStore::default(), None);

        let error = RuntimePlatform::configure_worker(
            &mut platform,
            Some(std::path::Path::new("profiles")),
            None,
        )
        .unwrap_err();

        assert_eq!(error.code(), "profile.root_key_unavailable");
    }

    #[test]
    fn new_worker_requires_attach_for_the_same_target() {
        assert_eq!(
            attachment_decision(true, Some("worker-1"), Some("worker-1")),
            AttachmentDecision::Reuse
        );
        assert_eq!(
            attachment_decision(true, Some("worker-2"), Some("worker-1")),
            AttachmentDecision::Attach
        );
        assert_eq!(
            attachment_decision(true, Some("worker-2"), None),
            AttachmentDecision::Attach
        );
        assert_eq!(
            attachment_decision(false, Some("worker-2"), Some("worker-2")),
            AttachmentDecision::Replace
        );
    }

    #[test]
    fn transient_input_does_not_leave_an_expiring_lease() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut expires_at = Some(deadline);

        assert!(!retain_input_lease_for_holds(
            &BTreeSet::new(),
            &mut expires_at
        ));
        assert_eq!(expires_at, None);

        expires_at = Some(deadline);
        assert!(retain_input_lease_for_holds(
            &BTreeSet::from(["movement.forward".to_owned()]),
            &mut expires_at,
        ));
        assert_eq!(expires_at, Some(deadline));
    }

    #[test]
    fn release_health_requires_a_non_realtime_worker_with_no_holds() {
        let clean = WorkerHealth {
            io_mode: WindowsIoMode::Generic as i32,
            worker_generation: "worker-1".into(),
            target_generation: 7,
            input_owner_epoch: 2,
            ..WorkerHealth::default()
        };
        assert!(verify_release_health(Some(&clean), "worker-1", 7, 1).is_ok());

        let mut realtime = clean.clone();
        realtime.io_mode = WindowsIoMode::Realtime as i32;
        assert_eq!(
            verify_release_health(Some(&realtime), "worker-1", 7, 1)
                .unwrap_err()
                .code(),
            "input.release_uncertain"
        );

        let mut held = clean;
        held.held_action_ids.push("movement.forward".into());
        assert_eq!(
            verify_release_health(Some(&held), "worker-1", 7, 1)
                .unwrap_err()
                .code(),
            "input.release_uncertain"
        );
        assert_eq!(
            verify_release_health(None, "worker-1", 7, 1)
                .unwrap_err()
                .code(),
            "input.release_uncertain"
        );

        let mut stale = WorkerHealth {
            io_mode: WindowsIoMode::Generic as i32,
            worker_generation: "worker-0".into(),
            target_generation: 7,
            input_owner_epoch: 2,
            ..WorkerHealth::default()
        };
        assert!(verify_release_health(Some(&stale), "worker-1", 7, 1).is_err());
        stale.worker_generation = "worker-1".into();
        stale.target_generation = 6;
        assert!(verify_release_health(Some(&stale), "worker-1", 7, 1).is_err());
        stale.target_generation = 7;
        stale.input_owner_epoch = 0;
        assert!(verify_release_health(Some(&stale), "worker-1", 7, 1).is_err());
    }
}
