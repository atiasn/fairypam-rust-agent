#[cfg(windows)]
mod windows_impl {
    use std::collections::{HashSet, VecDeque};
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use fairypam_agent_core::profile::Ed25519SignatureVerifier;
    use fairypam_agent_maa::MaaRuntimeError;
    use fairypam_agent_protocol::worker_v1::{
        local_envelope, worker_event, worker_request, FrameEncoding, LocalEnvelope, PixelFormat,
        RealtimeProgramEvent, RealtimeProgramMetrics as WorkerRealtimeProgramMetrics,
        RealtimeProgramState, WindowsIoMode, WorkerCapabilities, WorkerEvent, WorkerHealth,
        WorkerOutcome, WorkerReady, WorkerRequest, WorkerResponse,
    };
    use fairypam_agent_protocol::{
        decode_local_envelope, encode_local_envelope, verify_worker_request,
        worker_realtime_metrics_digest, LOCAL_PROTOCOL_MAJOR, LOCAL_PROTOCOL_MINOR,
        MAX_LOCAL_MESSAGE_BYTES,
    };
    use fairypam_agent_realtime::input_batch::windows::WindowsPhysicalInputBatch;
    use fairypam_agent_realtime::input_batch::PhysicalInputBatch;
    use fairypam_agent_realtime::program::StartProgram;
    use fairypam_agent_realtime::spec::VerifiedRealtimeSpec;
    use image::codecs::jpeg::JpegEncoder;
    use image::codecs::png::PngEncoder;
    use image::{ExtendedColorType, ImageEncoder};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        LocalFree, ERROR_PIPE_CONNECTED, HLOCAL, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PeekNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    use crate::frame_ring::FrameRing;
    use crate::generic_controller::GenericController;
    use crate::maa_loader::LoadedMaaRuntime;
    use crate::realtime_host::{RealtimeHost, WindowsIoArbiter};

    const MAX_SEEN_COMMANDS: usize = 4096;
    const MAA_RUNTIME_VERSION: &str = "5.12.3";

    pub fn run() -> Result<(), MaaRuntimeError> {
        let config = Config::parse(std::env::args_os().skip(1))?;
        let profile_verifier = config
            .profile_root_public_key
            .as_deref()
            .map(Ed25519SignatureVerifier::from_public_key_hex)
            .transpose()
            .map_err(|error| MaaRuntimeError::new(error.code(), error.to_string()))?;
        let loaded_runtime =
            LoadedMaaRuntime::load_active(&config.runtime_root, &config.runtime_root_public_key)?;
        let controller = Arc::new(Mutex::new(GenericController::new()?));
        let ring = Arc::new(Mutex::new(FrameRing::create(
            &config.frame_mapping_name,
            &config.frame_event_name,
            config.frame_slot_bytes,
            &config.worker_generation,
        )?));
        let mut server = Server::new(config, profile_verifier, loaded_runtime, controller, ring);
        let result = server.serve();
        let _ = server.stop_capture();
        let release = server.release_current_mode();
        result.and(release)
    }

    struct Config {
        pipe_name: String,
        runtime_root: PathBuf,
        profile_dir: Option<PathBuf>,
        profile_root_public_key: Option<String>,
        runtime_root_public_key: String,
        worker_generation: String,
        frame_mapping_name: String,
        frame_event_name: String,
        frame_slot_bytes: usize,
    }

    impl Config {
        fn parse(
            values: impl Iterator<Item = std::ffi::OsString>,
        ) -> Result<Self, MaaRuntimeError> {
            let values = values.collect::<Vec<_>>();
            if values.len() % 2 != 0 {
                return Err(config_error("worker arguments must be --name value pairs"));
            }
            let value = |name: &str| -> Result<std::ffi::OsString, MaaRuntimeError> {
                values
                    .chunks_exact(2)
                    .find(|pair| pair[0] == name)
                    .map(|pair| pair[1].clone())
                    .ok_or_else(|| config_error(&format!("missing {name}")))
            };
            let text = |name: &str, value: std::ffi::OsString| {
                value
                    .into_string()
                    .map_err(|_| config_error(&format!("{name} must be Unicode")))
            };
            let optional_value = |name: &str| {
                values
                    .chunks_exact(2)
                    .find(|pair| pair[0] == name)
                    .map(|pair| pair[1].clone())
            };
            let pipe_name = text("--pipe-name", value("--pipe-name")?)?;
            let (profile_dir, profile_root_public_key) = match (
                optional_value("--profile-dir"),
                optional_value("--profile-root-public-key"),
            ) {
                (None, None) => (None, None),
                (Some(profile_dir), Some(profile_root_public_key)) => (
                    Some(PathBuf::from(profile_dir)),
                    Some(text("--profile-root-public-key", profile_root_public_key)?),
                ),
                _ => return Err(config_error("profile arguments must be provided together")),
            };
            let runtime_root_public_key = text(
                "--runtime-root-public-key",
                value("--runtime-root-public-key")?,
            )?;
            let worker_generation = text("--worker-generation", value("--worker-generation")?)?;
            let frame_mapping_name = text("--frame-mapping-name", value("--frame-mapping-name")?)?;
            let frame_event_name = text("--frame-event-name", value("--frame-event-name")?)?;
            let frame_slot_bytes = text("--frame-slot-bytes", value("--frame-slot-bytes")?)?
                .parse::<usize>()
                .map_err(|_| config_error("frame slot size is invalid"))?;
            if !pipe_name.starts_with(r"\\.\pipe\FairyPam-")
                || worker_generation.is_empty()
                || worker_generation.len() >= 64
                || !worker_generation
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || frame_mapping_name.is_empty()
                || frame_event_name.is_empty()
                || !(1024 * 1024..=256 * 1024 * 1024).contains(&frame_slot_bytes)
            {
                return Err(config_error(
                    "worker arguments are outside the local IPC policy",
                ));
            }
            Ok(Self {
                pipe_name,
                runtime_root: PathBuf::from(value("--runtime-root")?),
                profile_dir,
                profile_root_public_key,
                runtime_root_public_key,
                worker_generation,
                frame_mapping_name,
                frame_event_name,
                frame_slot_bytes,
            })
        }
    }

    struct CaptureLoop {
        source_id: String,
        stop: Arc<AtomicBool>,
        thread: JoinHandle<()>,
        error_code: Arc<Mutex<Option<String>>>,
    }

    struct Server {
        config: Config,
        verifier: Option<Ed25519SignatureVerifier>,
        _loaded_runtime: LoadedMaaRuntime,
        controller: Arc<Mutex<GenericController>>,
        ring: Arc<Mutex<FrameRing>>,
        arbiter: WindowsIoArbiter,
        target_generation: u64,
        realtime: RealtimeHost,
        realtime_program_id: Option<String>,
        realtime_started_at: Option<i64>,
        capture: Option<CaptureLoop>,
        seen_commands: HashSet<String>,
        seen_order: VecDeque<String>,
    }

    impl Server {
        fn new(
            config: Config,
            verifier: Option<Ed25519SignatureVerifier>,
            loaded_runtime: LoadedMaaRuntime,
            controller: Arc<Mutex<GenericController>>,
            ring: Arc<Mutex<FrameRing>>,
        ) -> Self {
            Self {
                config,
                verifier,
                _loaded_runtime: loaded_runtime,
                controller,
                ring,
                arbiter: WindowsIoArbiter::default(),
                target_generation: 0,
                realtime: RealtimeHost::new(),
                realtime_program_id: None,
                realtime_started_at: None,
                capture: None,
                seen_commands: HashSet::new(),
                seen_order: VecDeque::new(),
            }
        }

        fn serve(&mut self) -> Result<(), MaaRuntimeError> {
            let mut pipe = create_pipe(&self.config.pipe_name)?;
            self.write(
                &mut pipe,
                local_envelope::Payload::Hello(fairypam_agent_protocol::worker_v1::WorkerHello {
                    worker_generation: self.config.worker_generation.clone(),
                    process_id: std::process::id(),
                    build_id: env!("CARGO_PKG_VERSION").to_owned(),
                }),
            )?;
            self.write(
                &mut pipe,
                local_envelope::Payload::Ready(WorkerReady {
                    worker_generation: self.config.worker_generation.clone(),
                    capabilities: Some(self.capabilities()),
                    health: Some(self.health()),
                }),
            )?;
            loop {
                if let Some(event) = self.finish_realtime_if_ready()? {
                    self.write(&mut pipe, local_envelope::Payload::Event(event))?;
                }
                if !pipe_has_data(&pipe)? {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                let envelope = read_envelope(&mut pipe)?;
                let Some(local_envelope::Payload::Request(request)) = envelope.payload else {
                    return Err(MaaRuntimeError::new(
                        "worker.request_invalid",
                        "Agent sent a non-request envelope",
                    ));
                };
                let command_id = request
                    .identity
                    .as_ref()
                    .map(|value| value.local_command_id.clone())
                    .unwrap_or_default();
                let mut event = None;
                let mut shutdown = false;
                let response = match self.validate(&request) {
                    Ok(()) => match self.dispatch(&request) {
                        Ok(result) => {
                            event = result.event;
                            shutdown = result.shutdown;
                            self.response(
                                command_id,
                                result.outcome,
                                None,
                                result.actions,
                                result.frame_sequence,
                            )
                        }
                        Err(error) => {
                            let outcome = outcome_for_error(&request, error.code());
                            if outcome == WorkerOutcome::Uncertain {
                                let _ = self.emergency_release();
                                self.arbiter.fault();
                            }
                            self.response(command_id, outcome, Some(error.code()), Vec::new(), None)
                        }
                    },
                    Err(error) => self.response(
                        command_id,
                        WorkerOutcome::NotApplied,
                        Some(error.code()),
                        Vec::new(),
                        None,
                    ),
                };
                if let Some(event) = event {
                    self.write(&mut pipe, local_envelope::Payload::Event(event))?;
                }
                self.write(&mut pipe, local_envelope::Payload::Response(response))?;
                if shutdown {
                    return Ok(());
                }
            }
        }

        fn validate(&mut self, request: &WorkerRequest) -> Result<(), MaaRuntimeError> {
            verify_worker_request(
                request,
                &self.config.worker_generation,
                self.target_generation,
                self.arbiter.input_owner_epoch(),
                unix_ms(),
            )
            .map_err(|error| MaaRuntimeError::new(error.code(), error.to_string()))?;
            let command_id = &request.identity.as_ref().unwrap().local_command_id;
            if !self.seen_commands.insert(command_id.clone()) {
                return Err(MaaRuntimeError::new(
                    "worker.command_replayed",
                    "local command id was already processed",
                ));
            }
            self.seen_order.push_back(command_id.clone());
            if self.seen_order.len() > MAX_SEEN_COMMANDS {
                if let Some(oldest) = self.seen_order.pop_front() {
                    self.seen_commands.remove(&oldest);
                }
            }
            Ok(())
        }

        fn dispatch(&mut self, request: &WorkerRequest) -> Result<CommandResult, MaaRuntimeError> {
            let identity = request.identity.as_ref().unwrap();
            match request.payload.as_ref().unwrap() {
                worker_request::Payload::AttachTarget(value) => {
                    if self.arbiter.mode() != WindowsIoMode::Detached {
                        return Err(io_error("worker.io_mode_invalid"));
                    }
                    let (profile_dir, verifier) = self.profile_config()?;
                    self.lock_controller()?.attach(
                        value.hwnd,
                        value.process_id,
                        &value.profile_id,
                        &value.profile_digest,
                        profile_dir,
                        verifier,
                    )?;
                    if let Err(code) = self.arbiter.attach() {
                        let _ = self.lock_controller()?.detach();
                        return Err(io_error(code));
                    }
                    self.advance_target()?;
                    Ok(CommandResult::applied())
                }
                worker_request::Payload::DetachTarget(_) => {
                    self.stop_capture()?;
                    self.release_current_mode()?;
                    self.arbiter.detach().map_err(io_error)?;
                    self.lock_controller()?.detach()?;
                    self.advance_target()?;
                    Ok(CommandResult::applied())
                }
                worker_request::Payload::GetCapabilities(_) => Ok(CommandResult::applied()),
                worker_request::Payload::GetHealth(_) => Ok(CommandResult::applied()),
                worker_request::Payload::StartGenericCapture(value) => {
                    self.require_generic()?;
                    self.start_capture(
                        value.capture_source_id.clone(),
                        value.fps,
                        &value.encoding,
                        value.quality,
                    )?;
                    Ok(CommandResult::applied())
                }
                worker_request::Payload::CaptureOnce(value) => {
                    self.require_generic()?;
                    let sequence = self.capture_once(
                        &value.capture_source_id,
                        &value.encoding,
                        value.quality,
                    )?;
                    Ok(CommandResult::applied().frame(sequence))
                }
                worker_request::Payload::StopGenericCapture(value) => {
                    if self
                        .capture
                        .as_ref()
                        .is_some_and(|capture| capture.source_id != value.capture_source_id)
                    {
                        return Err(MaaRuntimeError::new(
                            "worker.capture_source_stale",
                            "capture source does not match the running stream",
                        ));
                    }
                    self.stop_capture()?;
                    Ok(CommandResult::applied())
                }
                worker_request::Payload::GenericClick(value) => {
                    self.arbiter
                        .allow_generic_input(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    self.lock_controller()?.click(
                        &value.action_id,
                        value.x_ppm,
                        value.y_ppm,
                        value.source_frame_sequence,
                    )?;
                    Ok(CommandResult::applied().action(&value.action_id))
                }
                worker_request::Payload::GenericSwipe(value) => {
                    self.arbiter
                        .allow_generic_input(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    self.lock_controller()?.swipe(
                        &value.action_id,
                        (value.start_x_ppm, value.start_y_ppm),
                        (value.end_x_ppm, value.end_y_ppm),
                        value.duration_ms,
                        value.source_frame_sequence,
                    )?;
                    Ok(CommandResult::applied().action(&value.action_id))
                }
                worker_request::Payload::GenericKeyDown(value) => {
                    self.arbiter
                        .allow_generic_input(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    let held = {
                        let mut controller = self.lock_controller()?;
                        controller.key_down(&value.action_id)?;
                        controller.held_action_ids()
                    };
                    self.arbiter
                        .record_generic_holds(identity.input_owner_epoch, held)
                        .map_err(io_error)?;
                    Ok(CommandResult::applied().action(&value.action_id))
                }
                worker_request::Payload::GenericKeyUp(value) => {
                    self.arbiter
                        .allow_generic_input(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    let held = {
                        let mut controller = self.lock_controller()?;
                        controller.key_up(&value.action_id)?;
                        controller.held_action_ids()
                    };
                    self.arbiter
                        .record_generic_holds(identity.input_owner_epoch, held)
                        .map_err(io_error)?;
                    Ok(CommandResult::applied().action(&value.action_id))
                }
                worker_request::Payload::GenericScroll(value) => {
                    self.arbiter
                        .allow_generic_input(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    self.lock_controller()?.scroll(
                        &value.action_id,
                        value.delta,
                        value.x_ppm,
                        value.y_ppm,
                        value.source_frame_sequence,
                    )?;
                    Ok(CommandResult::applied().action(&value.action_id))
                }
                worker_request::Payload::GenericRelativeMove(value) => {
                    self.arbiter
                        .allow_generic_input(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    self.lock_controller()?
                        .relative_move(&value.action_id, value.dx, value.dy)?;
                    Ok(CommandResult::applied().action(&value.action_id))
                }
                worker_request::Payload::GenericInactive(_) => {
                    self.arbiter
                        .allow_generic_input(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    self.lock_controller()?.inactive()?;
                    Ok(CommandResult::applied())
                }
                worker_request::Payload::StartRealtimeProgram(value) => {
                    let spec = self.load_realtime_spec(&value.program_id)?;
                    StartProgram {
                        program_id: value.program_id.clone(),
                        schema_version: value.program_schema_version,
                        digest: value.program_digest.clone(),
                        maximum_duration: Duration::from_millis(u64::from(
                            value.maximum_duration_ms,
                        )),
                        supervision_lease: value
                            .supervision_lease_ms
                            .map(|ms| Duration::from_millis(u64::from(ms))),
                    }
                    .bind(&spec)
                    .map_err(realtime_error)?;
                    self.stop_capture()?;
                    self.arbiter
                        .begin_realtime(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    let drain_result = (|| {
                        let mut controller = self.lock_controller()?;
                        controller.inactive()?;
                        controller.release_all()?;
                        drop(controller);
                        self.emergency_release()?;
                        self.arbiter.generic_drained().map_err(io_error)
                    })();
                    if let Err(error) = drain_result {
                        return Err(self.rollback_realtime_start(error));
                    }
                    self.arbiter.realtime_started().map_err(io_error)?;
                    let start_result = (|| {
                        let controller = self.lock_controller()?;
                        let hwnd = controller.hwnd()?;
                        let profile = controller.profile()?.clone();
                        drop(controller);
                        self.realtime
                            .start(
                                hwnd,
                                &spec,
                                &profile,
                                Duration::from_millis(u64::from(value.maximum_duration_ms)),
                                value
                                    .supervision_lease_ms
                                    .map(|ms| Duration::from_millis(u64::from(ms))),
                            )
                            .map_err(realtime_error)
                    })();
                    if let Err(error) = start_result {
                        return Err(self.rollback_realtime_start(error));
                    }
                    let started = unix_ms();
                    self.realtime_program_id = Some(value.program_id.clone());
                    self.realtime_started_at = Some(started);
                    Ok(CommandResult::applied().event(self.realtime_event(
                        &value.program_id,
                        RealtimeProgramState::Running,
                        Some(started),
                        None,
                        None,
                        None,
                        None,
                    )))
                }
                worker_request::Payload::RenewRealtimeProgram(value) => {
                    if self.arbiter.mode() != WindowsIoMode::Realtime {
                        return Err(io_error("worker.io_mode_invalid"));
                    }
                    self.realtime
                        .renew(Duration::from_millis(u64::from(value.supervision_lease_ms)))
                        .map_err(realtime_error)?;
                    Ok(CommandResult::applied())
                }
                worker_request::Payload::StopRealtimeProgram(value) => {
                    if self.arbiter.mode() != WindowsIoMode::Realtime {
                        return Err(io_error("worker.io_mode_invalid"));
                    }
                    self.arbiter
                        .begin_realtime_release(identity.input_owner_epoch)
                        .map_err(io_error)?;
                    let result = self.realtime.stop().ok_or_else(|| {
                        MaaRuntimeError::new(
                            "realtime.program_not_running",
                            "realtime program is not running",
                        )
                    })?;
                    let emergency = self.emergency_release();
                    let release_uncertain = result.release_uncertain || emergency.is_err();
                    if release_uncertain {
                        self.arbiter.fault();
                    } else {
                        self.arbiter.realtime_released().map_err(io_error)?;
                    }
                    let event =
                        self.result_event(&value.program_id, result, true, emergency.is_err());
                    self.realtime_program_id = None;
                    self.realtime_started_at = None;
                    Ok(CommandResult::applied().event(event))
                }
                worker_request::Payload::ReleaseAll(_) => {
                    self.stop_capture()?;
                    self.release_current_mode()?;
                    Ok(CommandResult::applied())
                }
                worker_request::Payload::Shutdown(_) => {
                    self.stop_capture()?;
                    self.release_current_mode()?;
                    Ok(CommandResult::applied().shutdown())
                }
            }
        }

        fn start_capture(
            &mut self,
            source_id: String,
            fps: u32,
            encoding: &str,
            quality: u32,
        ) -> Result<(), MaaRuntimeError> {
            if self.capture.is_some() || source_id.is_empty() || !(1..=60).contains(&fps) {
                return Err(MaaRuntimeError::new(
                    "worker.capture_invalid",
                    "capture stream configuration is invalid",
                ));
            }
            let wire_encoding = CaptureEncoding::parse(encoding, quality)?;
            {
                let mut controller = self.lock_controller()?;
                controller.validate_capture_source(&source_id, Some(fps), encoding)?;
                controller.start_capture()?;
            }
            let stop = Arc::new(AtomicBool::new(false));
            let error_code = Arc::new(Mutex::new(None));
            let worker_stop = Arc::clone(&stop);
            let worker_error = Arc::clone(&error_code);
            let controller = Arc::clone(&self.controller);
            let ring = Arc::clone(&self.ring);
            let interval = Duration::from_micros(1_000_000 / u64::from(fps));
            let thread = std::thread::Builder::new()
                .name("fairypam-maa-capture".into())
                .spawn(move || {
                    while !worker_stop.load(Ordering::Acquire) {
                        let started = std::time::Instant::now();
                        if let Err(error) = capture_and_publish(&controller, &ring, wire_encoding) {
                            if let Ok(mut slot) = worker_error.lock() {
                                *slot = Some(error.code().to_owned());
                            }
                            break;
                        }
                        if let Some(delay) = interval.checked_sub(started.elapsed()) {
                            std::thread::sleep(delay);
                        }
                    }
                })
                .map_err(|error| {
                    MaaRuntimeError::new("worker.capture_start_failed", error.to_string())
                })?;
            self.capture = Some(CaptureLoop {
                source_id,
                stop,
                thread,
                error_code,
            });
            Ok(())
        }

        fn stop_capture(&mut self) -> Result<(), MaaRuntimeError> {
            if let Some(capture) = self.capture.take() {
                capture.stop.store(true, Ordering::Release);
                capture.thread.join().map_err(|_| {
                    MaaRuntimeError::new("worker.capture_panicked", "capture worker panicked")
                })?;
                if let Some(code) = capture
                    .error_code
                    .lock()
                    .ok()
                    .and_then(|value| value.clone())
                {
                    self.lock_controller()?.stop_capture()?;
                    return Err(MaaRuntimeError::new(
                        "worker.capture_failed",
                        format!("capture worker stopped with {code}"),
                    ));
                }
            }
            self.lock_controller()?.stop_capture()
        }

        fn capture_once(
            &self,
            source_id: &str,
            encoding: &str,
            quality: u32,
        ) -> Result<u64, MaaRuntimeError> {
            let wire_encoding = CaptureEncoding::parse(encoding, quality)?;
            self.lock_controller()?
                .validate_capture_source(source_id, None, encoding)?;
            capture_and_publish(&self.controller, &self.ring, wire_encoding)
        }

        fn release_current_mode(&mut self) -> Result<(), MaaRuntimeError> {
            let mut first_error = None;
            if self.arbiter.mode() == WindowsIoMode::Realtime {
                let owner = self.arbiter.input_owner_epoch();
                self.arbiter
                    .begin_realtime_release(owner)
                    .map_err(io_error)?;
                if let Some(result) = self.realtime.stop() {
                    if let Some(error) = result.error {
                        first_error.get_or_insert(realtime_error(error));
                    }
                    if result.release_uncertain {
                        first_error.get_or_insert_with(|| {
                            MaaRuntimeError::new(
                                "realtime.release_uncertain",
                                "realtime engine could not prove release",
                            )
                        });
                    }
                }
                if let Err(error) = self.emergency_release() {
                    first_error.get_or_insert(error);
                }
                if first_error.is_some() {
                    self.arbiter.fault();
                } else {
                    self.arbiter.realtime_released().map_err(io_error)?;
                }
                self.realtime_program_id = None;
                self.realtime_started_at = None;
            } else {
                if matches!(
                    self.arbiter.mode(),
                    WindowsIoMode::Generic | WindowsIoMode::Faulted
                ) {
                    if let Err(error) = self.lock_controller()?.release_all() {
                        first_error.get_or_insert(error);
                    }
                }
                if self.arbiter.mode() == WindowsIoMode::Generic {
                    let owner = self.arbiter.input_owner_epoch();
                    if let Err(code) = self.arbiter.record_generic_holds(owner, Vec::new()) {
                        first_error.get_or_insert(io_error(code));
                    }
                }
                if let Err(error) = self.emergency_release() {
                    first_error.get_or_insert(error);
                }
            }
            first_error.map_or(Ok(()), Err)
        }

        fn rollback_realtime_start(&mut self, cause: MaaRuntimeError) -> MaaRuntimeError {
            if let Err(release) = self.emergency_release() {
                self.arbiter.fault();
                return MaaRuntimeError::new(
                    "realtime.release_uncertain",
                    format!("{cause}; emergency release failed: {release}"),
                );
            }
            let rollback = match self.arbiter.mode() {
                WindowsIoMode::GenericDraining | WindowsIoMode::RealtimeStarting => {
                    self.arbiter.cancel_realtime_start()
                }
                WindowsIoMode::Realtime => {
                    let owner = self.arbiter.input_owner_epoch();
                    self.arbiter
                        .begin_realtime_release(owner)
                        .and_then(|()| self.arbiter.realtime_released().map(|_| ()))
                }
                _ => Err("worker.io_mode_invalid"),
            };
            if let Err(code) = rollback {
                self.arbiter.fault();
                return MaaRuntimeError::new(
                    "realtime.release_uncertain",
                    format!("{cause}; transition rollback failed: {code}"),
                );
            }
            cause
        }

        fn emergency_release(&self) -> Result<(), MaaRuntimeError> {
            let keys = if self.arbiter.mode() == WindowsIoMode::Detached {
                Vec::new()
            } else {
                self.lock_controller()?.emergency_keys()?
            };
            WindowsPhysicalInputBatch::new(keys)
                .and_then(|mut input| input.release_all())
                .map_err(realtime_error)
        }

        fn finish_realtime_if_ready(&mut self) -> Result<Option<WorkerEvent>, MaaRuntimeError> {
            let Some(result) = self.realtime.take_finished() else {
                return Ok(None);
            };
            let owner = self.arbiter.input_owner_epoch();
            self.arbiter
                .begin_realtime_release(owner)
                .map_err(io_error)?;
            let emergency_failed = self.emergency_release().is_err();
            if result.release_uncertain || emergency_failed {
                self.arbiter.fault();
            } else {
                self.arbiter.realtime_released().map_err(io_error)?;
            }
            let program_id = self.realtime_program_id.take().ok_or_else(|| {
                MaaRuntimeError::new(
                    "realtime.program_invalid",
                    "running Realtime Program lost its program id",
                )
            })?;
            let event = self.result_event(&program_id, result, false, emergency_failed);
            self.realtime_started_at = None;
            Ok(Some(event))
        }

        fn load_realtime_spec(
            &self,
            program_id: &str,
        ) -> Result<VerifiedRealtimeSpec, MaaRuntimeError> {
            if program_id.is_empty()
                || !program_id.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-')
                })
            {
                return Err(MaaRuntimeError::new(
                    "realtime.program_invalid",
                    "program id is invalid",
                ));
            }
            let profile_id = self.lock_controller()?.profile()?.profile().id.clone();
            let (profile_dir, verifier) = self.profile_config()?;
            VerifiedRealtimeSpec::verify(
                &fs::read(
                    profile_dir
                        .join(profile_id)
                        .join("realtime")
                        .join(format!("{program_id}.json")),
                )?,
                verifier,
            )
            .map_err(realtime_error)
        }

        fn profile_config(&self) -> Result<(&Path, &Ed25519SignatureVerifier), MaaRuntimeError> {
            self.config
                .profile_dir
                .as_deref()
                .zip(self.verifier.as_ref())
                .ok_or_else(|| {
                    MaaRuntimeError::new(
                        "profile.store_unavailable",
                        "signed Profile Catalog is not configured",
                    )
                })
        }

        fn result_event(
            &self,
            program_id: &str,
            result: fairypam_agent_realtime::music_engine::windows::MusicProgramResult,
            cancelled: bool,
            emergency_failed: bool,
        ) -> WorkerEvent {
            let release_uncertain = result.release_uncertain || emergency_failed;
            let error_code = result.error.as_ref().map(|error| error.code().to_owned());
            let state = if release_uncertain {
                RealtimeProgramState::ReleaseUncertain
            } else if cancelled {
                RealtimeProgramState::Cancelled
            } else if result.error.is_some() {
                RealtimeProgramState::Failed
            } else {
                RealtimeProgramState::Completed
            };
            let summary = result.metrics.summary();
            let metrics = WorkerRealtimeProgramMetrics {
                sample_count: summary.sample_count,
                transition_count: summary.transition_count,
                missed_deadlines: summary.missed_deadlines,
                stale_events: summary.stale_events,
                queue_overflows: summary.queue_overflows,
                sample_interval_p50_us: summary.sample_interval_p50_us,
                sample_interval_p95_us: summary.sample_interval_p95_us,
                sample_interval_p99_us: summary.sample_interval_p99_us,
                scheduler_lateness_p99_us: summary.scheduler_lateness_p99_us,
                detection_to_input_p99_us: summary.detection_to_input_p99_us,
                chord_skew_p99_us: summary.chord_skew_p99_us,
            };
            let metrics_digest = worker_realtime_metrics_digest(&metrics);
            self.realtime_event(
                program_id,
                state,
                self.realtime_started_at,
                Some(unix_ms()),
                error_code,
                Some(metrics_digest),
                Some(metrics),
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn realtime_event(
            &self,
            program_id: &str,
            state: RealtimeProgramState,
            started_at: Option<i64>,
            ended_at: Option<i64>,
            error_code: Option<String>,
            metrics_digest: Option<String>,
            metrics: Option<WorkerRealtimeProgramMetrics>,
        ) -> WorkerEvent {
            WorkerEvent {
                worker_generation: self.config.worker_generation.clone(),
                payload: Some(worker_event::Payload::RealtimeProgram(
                    RealtimeProgramEvent {
                        program_id: program_id.to_owned(),
                        state: state as i32,
                        started_at_unix_ms: started_at,
                        ended_at_unix_ms: ended_at,
                        error_code,
                        metrics_digest,
                        metrics,
                    },
                )),
            }
        }

        fn response(
            &self,
            command_id: String,
            outcome: WorkerOutcome,
            error_code: Option<&str>,
            actions: Vec<String>,
            frame_sequence: Option<u64>,
        ) -> WorkerResponse {
            WorkerResponse {
                local_command_id: command_id,
                outcome: outcome as i32,
                error_code: error_code.map(str::to_owned),
                applied_action_ids: actions,
                frame_sequence,
                capabilities: Some(self.capabilities()),
                health: Some(self.health()),
            }
        }

        fn capabilities(&self) -> WorkerCapabilities {
            WorkerCapabilities {
                maa_runtime_version: MAA_RUNTIME_VERSION.into(),
                capture_backends: vec!["maa-win32-all".into()],
                input_backends: vec!["maa-win32".into(), "rust-sendinput-realtime".into()],
                realtime_program_ids: vec![
                    fairypam_agent_realtime::program::MUSIC_AUTOPLAY_PROGRAM_ID.into(),
                ],
            }
        }

        fn health(&self) -> WorkerHealth {
            let (maa, mut error_code) = match self.controller.lock() {
                Ok(controller) => (controller.health(), None),
                Err(_) => (
                    fairypam_agent_maa::health::RuntimeHealth::default(),
                    Some("worker.controller_unavailable".to_owned()),
                ),
            };
            let capture_error =
                self.capture
                    .as_ref()
                    .and_then(|capture| match capture.error_code.lock() {
                        Ok(value) => value.clone(),
                        Err(_) => Some("worker.capture_state_unavailable".to_owned()),
                    });
            error_code = capture_error.or(error_code).or(maa.last_error_code.clone());
            let realtime = matches!(
                self.arbiter.mode(),
                WindowsIoMode::Realtime
                    | WindowsIoMode::RealtimeStarting
                    | WindowsIoMode::RealtimeReleasing
            );
            let held_action_ids = if realtime {
                match self.realtime.held_action_ids() {
                    Ok(held) => held,
                    Err(_) => {
                        error_code
                            .get_or_insert_with(|| "realtime.input_state_unavailable".to_owned());
                        Vec::new()
                    }
                }
            } else {
                self.arbiter.held_action_ids()
            };
            WorkerHealth {
                io_mode: self.arbiter.mode() as i32,
                worker_generation: self.config.worker_generation.clone(),
                target_generation: self.target_generation,
                target_valid: self.arbiter.mode() != WindowsIoMode::Detached,
                runtime_verified: true,
                capture_backend: Some(format!("maa-win32:{}", maa.backend)),
                input_backend: Some(if realtime {
                    "rust-sendinput-realtime".to_owned()
                } else {
                    format!("maa-win32:{}", maa.backend)
                }),
                error_code,
                input_owner_epoch: self.arbiter.input_owner_epoch(),
                maa_event_count: maa.event_count,
                last_maa_event: maa.last_event,
                held_action_ids,
            }
        }

        fn require_generic(&self) -> Result<(), MaaRuntimeError> {
            (self.arbiter.mode() == WindowsIoMode::Generic)
                .then_some(())
                .ok_or_else(|| io_error("worker.io_mode_invalid"))
        }

        fn advance_target(&mut self) -> Result<(), MaaRuntimeError> {
            self.target_generation = self.target_generation.checked_add(1).ok_or_else(|| {
                MaaRuntimeError::new(
                    "worker.target_generation_exhausted",
                    "target generation exhausted",
                )
            })?;
            Ok(())
        }

        fn lock_controller(
            &self,
        ) -> Result<std::sync::MutexGuard<'_, GenericController>, MaaRuntimeError> {
            self.controller.lock().map_err(|_| {
                MaaRuntimeError::new(
                    "worker.controller_unavailable",
                    "MAA controller lock is poisoned",
                )
            })
        }

        fn write(
            &self,
            pipe: &mut fs::File,
            payload: local_envelope::Payload,
        ) -> Result<(), MaaRuntimeError> {
            pipe.write_all(
                &encode_local_envelope(&LocalEnvelope {
                    protocol_major: LOCAL_PROTOCOL_MAJOR,
                    protocol_minor: LOCAL_PROTOCOL_MINOR,
                    payload: Some(payload),
                })
                .map_err(|error| MaaRuntimeError::new(error.code(), error.to_string()))?,
            )?;
            pipe.flush()?;
            Ok(())
        }
    }

    struct CommandResult {
        outcome: WorkerOutcome,
        actions: Vec<String>,
        frame_sequence: Option<u64>,
        event: Option<WorkerEvent>,
        shutdown: bool,
    }

    impl CommandResult {
        fn applied() -> Self {
            Self {
                outcome: WorkerOutcome::Applied,
                actions: Vec::new(),
                frame_sequence: None,
                event: None,
                shutdown: false,
            }
        }

        fn action(mut self, action_id: &str) -> Self {
            self.actions.push(action_id.to_owned());
            self
        }

        fn frame(mut self, sequence: u64) -> Self {
            self.frame_sequence = Some(sequence);
            self
        }

        fn event(mut self, event: WorkerEvent) -> Self {
            self.event = Some(event);
            self
        }

        fn shutdown(mut self) -> Self {
            self.shutdown = true;
            self
        }
    }

    #[derive(Clone, Copy)]
    enum CaptureEncoding {
        Raw,
        Jpeg(u8),
        Png,
    }

    impl CaptureEncoding {
        fn parse(value: &str, quality: u32) -> Result<Self, MaaRuntimeError> {
            match value {
                "raw" => Ok(Self::Raw),
                "jpeg" if (1..=100).contains(&quality) => Ok(Self::Jpeg(quality as u8)),
                "png" => Ok(Self::Png),
                _ => Err(MaaRuntimeError::new(
                    "worker.capture_encoding_invalid",
                    "capture encoding or quality is invalid",
                )),
            }
        }
    }

    fn capture_and_publish(
        controller: &Arc<Mutex<GenericController>>,
        ring: &Arc<Mutex<FrameRing>>,
        encoding: CaptureEncoding,
    ) -> Result<u64, MaaRuntimeError> {
        let (sequence, frame) = controller
            .lock()
            .map_err(|_| {
                MaaRuntimeError::new(
                    "worker.controller_unavailable",
                    "MAA controller lock is poisoned",
                )
            })?
            .capture_once()?;
        let captured_at = unix_us();
        let (payload, wire_encoding) = encode_frame(&frame, encoding)?;
        ring.lock()
            .map_err(|_| {
                MaaRuntimeError::new("worker.frame_unavailable", "frame ring lock is poisoned")
            })?
            .publish(
                sequence,
                captured_at,
                frame.width,
                frame.height,
                frame.stride,
                PixelFormat::Bgr8,
                wire_encoding,
                "maa-win32-all",
                0,
                &payload,
            )?;
        Ok(sequence)
    }

    fn encode_frame(
        frame: &fairypam_agent_maa::controller::CapturedFrame,
        encoding: CaptureEncoding,
    ) -> Result<(Vec<u8>, FrameEncoding), MaaRuntimeError> {
        if matches!(encoding, CaptureEncoding::Raw) {
            return Ok((frame.bgr.clone(), FrameEncoding::Raw));
        }
        let mut rgb = frame.bgr.clone();
        for pixel in rgb.chunks_exact_mut(3) {
            pixel.swap(0, 2);
        }
        let mut output = Cursor::new(Vec::new());
        match encoding {
            CaptureEncoding::Jpeg(quality) => {
                JpegEncoder::new_with_quality(&mut output, quality)
                    .encode(&rgb, frame.width, frame.height, ExtendedColorType::Rgb8)
                    .map_err(|error| {
                        MaaRuntimeError::new("worker.capture_encode_failed", error.to_string())
                    })?;
                Ok((output.into_inner(), FrameEncoding::Jpeg))
            }
            CaptureEncoding::Png => {
                PngEncoder::new(&mut output)
                    .write_image(&rgb, frame.width, frame.height, ExtendedColorType::Rgb8)
                    .map_err(|error| {
                        MaaRuntimeError::new("worker.capture_encode_failed", error.to_string())
                    })?;
                Ok((output.into_inner(), FrameEncoding::Png))
            }
            CaptureEncoding::Raw => unreachable!(),
        }
    }

    fn create_pipe(name: &str) -> Result<fs::File, MaaRuntimeError> {
        let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)");
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| MaaRuntimeError::new("worker.pipe_acl_failed", error.to_string()))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let name = wide(name);
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                Some(&attributes),
            )
        };
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(MaaRuntimeError::new(
                "worker.pipe_create_failed",
                windows::core::Error::from_thread().to_string(),
            ));
        }
        if let Err(error) = unsafe { ConnectNamedPipe(handle, None) } {
            if error.code() != windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                return Err(MaaRuntimeError::new(
                    "worker.pipe_connect_failed",
                    error.to_string(),
                ));
            }
        }
        Ok(unsafe { fs::File::from_raw_handle(handle.0) })
    }

    fn pipe_has_data(pipe: &fs::File) -> Result<bool, MaaRuntimeError> {
        use std::os::windows::io::AsRawHandle;
        let handle = windows::Win32::Foundation::HANDLE(pipe.as_raw_handle());
        let mut available = 0;
        unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) }
            .map_err(|error| MaaRuntimeError::new("worker.pipe_read_failed", error.to_string()))?;
        Ok(available >= 4)
    }

    fn read_envelope(pipe: &mut fs::File) -> Result<LocalEnvelope, MaaRuntimeError> {
        let mut length = [0; 4];
        pipe.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length > MAX_LOCAL_MESSAGE_BYTES {
            return Err(MaaRuntimeError::new(
                "worker.message_too_large",
                "local message exceeds the limit",
            ));
        }
        let mut framed = Vec::with_capacity(length + 4);
        framed.extend_from_slice(&(length as u32).to_le_bytes());
        framed.resize(length + 4, 0);
        pipe.read_exact(&mut framed[4..])?;
        decode_local_envelope(&framed)
            .map_err(|error| MaaRuntimeError::new(error.code(), error.to_string()))
    }

    fn outcome_for_error(request: &WorkerRequest, code: &str) -> WorkerOutcome {
        let side_effect = matches!(
            request.payload.as_ref(),
            Some(
                worker_request::Payload::GenericClick(_)
                    | worker_request::Payload::GenericSwipe(_)
                    | worker_request::Payload::GenericKeyDown(_)
                    | worker_request::Payload::GenericKeyUp(_)
                    | worker_request::Payload::GenericScroll(_)
                    | worker_request::Payload::GenericRelativeMove(_)
                    | worker_request::Payload::GenericInactive(_)
                    | worker_request::Payload::StartRealtimeProgram(_)
                    | worker_request::Payload::StopRealtimeProgram(_)
                    | worker_request::Payload::ReleaseAll(_)
                    | worker_request::Payload::Shutdown(_)
            )
        );
        if code == "realtime.input_uncertain"
            || code == "realtime.release_uncertain"
            || (side_effect && matches!(code, "maa.operation_failed" | "maa.operation_timeout"))
        {
            WorkerOutcome::Uncertain
        } else {
            WorkerOutcome::NotApplied
        }
    }

    fn realtime_error(error: fairypam_agent_realtime::RealtimeError) -> MaaRuntimeError {
        MaaRuntimeError::new(error.code(), error.to_string())
    }

    fn io_error(code: &'static str) -> MaaRuntimeError {
        MaaRuntimeError::new(code, code)
    }

    fn config_error(message: &str) -> MaaRuntimeError {
        MaaRuntimeError::new("worker.config_invalid", message)
    }

    fn unix_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64
    }

    fn unix_us() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .min(i64::MAX as u128) as i64
    }

    fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::Config;

        fn base_arguments() -> Vec<std::ffi::OsString> {
            [
                "--pipe-name",
                r"\\.\pipe\FairyPam-idle-test",
                "--runtime-root",
                "runtime",
                "--runtime-root-public-key",
                "00",
                "--worker-generation",
                "idle-test",
                "--frame-mapping-name",
                "Local\\FairyPam.Frame.Test",
                "--frame-event-name",
                "Local\\FairyPam.FrameEvent.Test",
                "--frame-slot-bytes",
                "1048576",
            ]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect()
        }

        #[test]
        fn idle_worker_rejects_partial_profile_authority() {
            let idle = Config::parse(base_arguments().into_iter()).unwrap();
            assert!(idle.profile_dir.is_none());
            assert!(idle.profile_root_public_key.is_none());

            let mut partial = base_arguments();
            partial.extend(["--profile-dir", "profiles"].map(std::ffi::OsString::from));
            let error = Config::parse(partial.into_iter()).err().unwrap();
            assert_eq!(error.code(), "worker.config_invalid");
        }
    }
}

#[cfg(windows)]
pub use windows_impl::run;
