use std::collections::VecDeque;
use std::io::{Read, Write};

use fairypam_agent_protocol::worker_v1::{
    local_envelope, LocalEnvelope, WorkerEvent, WorkerRequest, WorkerResponse,
};
use fairypam_agent_protocol::{
    decode_local_envelope, encode_local_envelope, LOCAL_PROTOCOL_MAJOR, LOCAL_PROTOCOL_MINOR,
    MAX_LOCAL_MESSAGE_BYTES,
};

use crate::MaaRuntimeError;

pub struct WorkerClient<S> {
    stream: S,
    worker_generation: String,
    events: VecDeque<WorkerEvent>,
}

impl<S: Read + Write> WorkerClient<S> {
    pub fn new(stream: S, worker_generation: String) -> Self {
        Self {
            stream,
            worker_generation,
            events: VecDeque::new(),
        }
    }

    pub fn round_trip(
        &mut self,
        request: WorkerRequest,
    ) -> Result<WorkerResponse, MaaRuntimeError> {
        let identity = request.identity.as_ref().ok_or_else(|| {
            MaaRuntimeError::new("worker.identity_invalid", "worker request has no identity")
        })?;
        if identity.worker_generation != self.worker_generation {
            return Err(MaaRuntimeError::new(
                "worker.generation_stale",
                "worker request generation is stale",
            ));
        }
        let command_id = identity.local_command_id.clone();
        let envelope = encode_local_envelope(&LocalEnvelope {
            protocol_major: LOCAL_PROTOCOL_MAJOR,
            protocol_minor: LOCAL_PROTOCOL_MINOR,
            payload: Some(local_envelope::Payload::Request(request)),
        })
        .map_err(|error| MaaRuntimeError::new("worker.write_failed", error.to_string()))?;
        self.stream.write_all(&envelope)?;
        self.stream.flush()?;
        loop {
            match read_envelope(&mut self.stream)?.payload {
                Some(local_envelope::Payload::Response(value))
                    if value.local_command_id == command_id =>
                {
                    return Ok(value);
                }
                Some(local_envelope::Payload::Event(value)) => self.events.push_back(value),
                _ => {
                    return Err(MaaRuntimeError::new(
                        "worker.response_invalid",
                        "worker response does not match the command",
                    ))
                }
            }
        }
    }

    pub fn take_events(&mut self) -> Vec<WorkerEvent> {
        self.events.drain(..).collect()
    }
}

pub fn read_envelope(stream: &mut impl Read) -> Result<LocalEnvelope, MaaRuntimeError> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_LOCAL_MESSAGE_BYTES {
        return Err(MaaRuntimeError::new(
            "worker.message_too_large",
            "worker response exceeds the protocol limit",
        ));
    }
    let mut framed = Vec::with_capacity(length + 4);
    framed.extend_from_slice(&(length as u32).to_le_bytes());
    framed.resize(length + 4, 0);
    stream.read_exact(&mut framed[4..])?;
    decode_local_envelope(&framed)
        .map_err(|error| MaaRuntimeError::new("worker.read_failed", error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use fairypam_agent_protocol::worker_v1::{
        local_envelope, LocalEnvelope, WorkerCommandIdentity, WorkerEvent, WorkerRequest,
        WorkerResponse,
    };
    use fairypam_agent_protocol::{
        encode_local_envelope, LOCAL_PROTOCOL_MAJOR, LOCAL_PROTOCOL_MINOR,
    };

    use super::WorkerClient;

    struct ScriptedStream {
        reads: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.reads.read(buffer)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.writes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn round_trip_queues_events_that_precede_the_matching_response() {
        let generation = "worker-1";
        let event = WorkerEvent {
            worker_generation: generation.into(),
            payload: None,
        };
        let response = WorkerResponse {
            local_command_id: "command-1".into(),
            ..WorkerResponse::default()
        };
        let mut reads = encode_local_envelope(&LocalEnvelope {
            protocol_major: LOCAL_PROTOCOL_MAJOR,
            protocol_minor: LOCAL_PROTOCOL_MINOR,
            payload: Some(local_envelope::Payload::Event(event.clone())),
        })
        .unwrap();
        reads.extend(
            encode_local_envelope(&LocalEnvelope {
                protocol_major: LOCAL_PROTOCOL_MAJOR,
                protocol_minor: LOCAL_PROTOCOL_MINOR,
                payload: Some(local_envelope::Payload::Response(response.clone())),
            })
            .unwrap(),
        );
        let mut client = WorkerClient::new(
            ScriptedStream {
                reads: Cursor::new(reads),
                writes: Vec::new(),
            },
            generation.into(),
        );
        let actual = client
            .round_trip(WorkerRequest {
                identity: Some(WorkerCommandIdentity {
                    worker_generation: generation.into(),
                    local_command_id: "command-1".into(),
                    ..WorkerCommandIdentity::default()
                }),
                payload: None,
            })
            .unwrap();

        assert_eq!(actual, response);
        assert_eq!(client.take_events(), vec![event]);
    }
}

#[cfg(windows)]
pub mod windows {
    use std::ffi::c_void;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{fence, AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use fairypam_agent_protocol::worker_v1::{
        local_envelope, worker_request, LocalEnvelope, WorkerCapabilities, WorkerCommandIdentity,
        WorkerEvent, WorkerHealth, WorkerRequest, WorkerResponse,
    };
    use fairypam_agent_protocol::{
        worker_request_digest, LOCAL_PROTOCOL_MAJOR, LOCAL_PROTOCOL_MINOR,
    };
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Memory::{
        MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_READ,
    };
    use windows::Win32::System::Pipes::PeekNamedPipe;
    use windows::Win32::System::Threading::{
        OpenEventW, WaitForSingleObject, CREATE_NO_WINDOW, EVENT_MODIFY_STATE,
        SYNCHRONIZATION_SYNCHRONIZE,
    };

    use super::{read_envelope, WorkerClient};
    use crate::MaaRuntimeError;

    const MAGIC: [u8; 8] = *b"FPRING1\0";
    const SLOT_COUNT: usize = 2;

    #[derive(Clone, Debug)]
    pub struct WorkerProcessConfig {
        pub executable: PathBuf,
        pub runtime_root: PathBuf,
        pub profile_dir: Option<PathBuf>,
        pub profile_root_public_key: Option<String>,
        pub runtime_root_public_key: Option<String>,
        pub frame_slot_bytes: usize,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct WorkerRuntimeInfo {
        pub maa_runtime_version: String,
        pub capture_backend: String,
        pub input_backend: String,
    }

    pub struct WorkerProcess {
        _job: OwnedJob,
        child: Child,
        client: WorkerClient<NamedPipeStream>,
        ring: SharedFrameReader,
        generation: String,
        target_generation: u64,
        input_owner_epoch: u64,
        held_action_ids: Vec<String>,
        runtime_info: WorkerRuntimeInfo,
        command_sequence: u64,
    }

    const _: fn() = || {
        fn assert_send<T: Send>() {}
        assert_send::<WorkerProcess>();
    };

    impl WorkerProcess {
        pub fn spawn(
            config: &WorkerProcessConfig,
            deadline: Instant,
        ) -> Result<Self, MaaRuntimeError> {
            let runtime_root_public_key =
                required_runtime_root_public_key(config.runtime_root_public_key.as_deref())?;
            let generation = generation_id();
            let suffix = format!("{}-{generation}", std::process::id());
            let pipe_name = format!(r"\\.\pipe\FairyPam-Win32-{suffix}");
            let mapping_name = format!(r"Local\FairyPam.Win32.Frame.{suffix}");
            let event_name = format!(r"Local\FairyPam.Win32.FrameEvent.{suffix}");
            let runtime_root = config.runtime_root.to_string_lossy().into_owned();
            let frame_slot_bytes = config.frame_slot_bytes.to_string();
            let mut command = Command::new(&config.executable);
            command.args([
                "--pipe-name",
                &pipe_name,
                "--runtime-root",
                &runtime_root,
                "--runtime-root-public-key",
                runtime_root_public_key,
                "--worker-generation",
                &generation,
                "--frame-mapping-name",
                &mapping_name,
                "--frame-event-name",
                &event_name,
                "--frame-slot-bytes",
                &frame_slot_bytes,
            ]);
            if let (Some(profile_dir), Some(profile_root_public_key)) =
                (&config.profile_dir, &config.profile_root_public_key)
            {
                command.args([
                    "--profile-dir",
                    profile_dir.to_string_lossy().as_ref(),
                    "--profile-root-public-key",
                    profile_root_public_key,
                ]);
            }
            command
                .env_clear()
                .env("SystemDrive", r"C:")
                .creation_flags(CREATE_NO_WINDOW.0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Some(system_root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", system_root);
            }
            let mut child = command
                .spawn()
                .map_err(|error| MaaRuntimeError::new("worker.start_failed", error.to_string()))?;
            let job = assign_kill_on_close_job(&mut child)?;
            let stream = match connect_pipe(&pipe_name, &mut child, deadline) {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            let mut stream = NamedPipeStream::new(stream, deadline);
            let hello = read_startup_envelope(&mut stream, deadline)?;
            if hello.protocol_major != LOCAL_PROTOCOL_MAJOR
                || hello.protocol_minor != LOCAL_PROTOCOL_MINOR
            {
                return Err(invalid("worker protocol version is incompatible"));
            }
            match hello.payload {
                Some(local_envelope::Payload::Hello(value))
                    if value.worker_generation == generation && value.process_id == child.id() => {}
                _ => return Err(invalid("worker hello is invalid")),
            }
            let ready = read_startup_envelope(&mut stream, deadline)?;
            if ready.protocol_major != LOCAL_PROTOCOL_MAJOR
                || ready.protocol_minor != LOCAL_PROTOCOL_MINOR
            {
                return Err(invalid("worker protocol version is incompatible"));
            }
            let (capabilities, health) = match ready.payload {
                Some(local_envelope::Payload::Ready(value))
                    if value.worker_generation == generation =>
                {
                    (
                        value
                            .capabilities
                            .ok_or_else(|| invalid("worker ready capabilities are missing"))?,
                        value
                            .health
                            .ok_or_else(|| invalid("worker ready health is missing"))?,
                    )
                }
                _ => return Err(invalid("worker ready is invalid")),
            };
            let runtime_info = runtime_info(&capabilities, &health)?;
            if !health.runtime_verified || health.worker_generation != generation {
                return Err(invalid("worker runtime is not verified"));
            }
            let ring = SharedFrameReader::open(
                &mapping_name,
                &event_name,
                config.frame_slot_bytes,
                &generation,
            )?;
            Ok(Self {
                _job: job,
                child,
                client: WorkerClient::new(stream, generation.clone()),
                ring,
                generation,
                target_generation: health.target_generation,
                input_owner_epoch: health.input_owner_epoch,
                held_action_ids: health.held_action_ids,
                runtime_info,
                command_sequence: 0,
            })
        }

        pub fn request(
            &mut self,
            payload: worker_request::Payload,
            deadline: Instant,
        ) -> Result<WorkerResponse, MaaRuntimeError> {
            if self.child.try_wait()?.is_some() {
                return Err(MaaRuntimeError::new(
                    "worker.crashed",
                    "Win32 Worker exited unexpectedly",
                ));
            }
            self.command_sequence = self
                .command_sequence
                .checked_add(1)
                .ok_or_else(|| invalid("worker command sequence exhausted"))?;
            let mut request = WorkerRequest {
                identity: Some(WorkerCommandIdentity {
                    worker_generation: self.generation.clone(),
                    local_command_id: format!("{}-{}", self.generation, self.command_sequence),
                    deadline_unix_ms: wire_deadline_unix_ms(deadline)?,
                    target_generation: self.target_generation,
                    input_owner_epoch: self.input_owner_epoch,
                    request_digest: String::new(),
                }),
                payload: Some(payload),
            };
            request.identity.as_mut().unwrap().request_digest = worker_request_digest(&request);
            self.client.stream.set_deadline(deadline);
            let response = self.client.round_trip(request)?;
            if let Some(health) = response.health.as_ref() {
                self.update_health(health)?;
            }
            Ok(response)
        }

        pub fn next_frame(
            &mut self,
            after_sequence: u64,
            deadline: Instant,
        ) -> Result<SharedFrame, MaaRuntimeError> {
            self.ring.next_after(after_sequence, deadline)
        }

        pub fn take_events(&mut self) -> Vec<WorkerEvent> {
            self.client.take_events()
        }

        pub const fn target_generation(&self) -> u64 {
            self.target_generation
        }

        pub const fn input_owner_epoch(&self) -> u64 {
            self.input_owner_epoch
        }

        pub fn held_action_ids(&self) -> &[String] {
            &self.held_action_ids
        }

        pub fn runtime_info(&self) -> &WorkerRuntimeInfo {
            &self.runtime_info
        }

        pub fn generation(&self) -> &str {
            &self.generation
        }

        pub fn terminate(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }

        fn update_health(&mut self, health: &WorkerHealth) -> Result<(), MaaRuntimeError> {
            if health.worker_generation != self.generation {
                return Err(invalid("worker health generation is stale"));
            }
            self.target_generation = health.target_generation;
            self.input_owner_epoch = health.input_owner_epoch;
            self.held_action_ids.clone_from(&health.held_action_ids);
            if let Some(backend) = health.capture_backend.as_ref() {
                self.runtime_info.capture_backend.clone_from(backend);
            }
            if let Some(backend) = health.input_backend.as_ref() {
                self.runtime_info.input_backend.clone_from(backend);
            }
            Ok(())
        }
    }

    fn runtime_info(
        capabilities: &WorkerCapabilities,
        health: &WorkerHealth,
    ) -> Result<WorkerRuntimeInfo, MaaRuntimeError> {
        let capture_backend = health
            .capture_backend
            .clone()
            .ok_or_else(|| invalid("worker capture backend is missing"))?;
        let input_backend = health
            .input_backend
            .clone()
            .ok_or_else(|| invalid("worker input backend is missing"))?;
        if capabilities.maa_runtime_version != "5.12.3"
            || capture_backend.is_empty()
            || input_backend.is_empty()
        {
            return Err(invalid("worker runtime metadata is invalid"));
        }
        Ok(WorkerRuntimeInfo {
            maa_runtime_version: capabilities.maa_runtime_version.clone(),
            capture_backend,
            input_backend,
        })
    }

    impl Drop for WorkerProcess {
        fn drop(&mut self) {
            self.terminate();
        }
    }

    struct OwnedJob(usize);

    impl Drop for OwnedJob {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(HANDLE(self.0 as _)) };
        }
    }

    fn assign_kill_on_close_job(child: &mut Child) -> Result<OwnedJob, MaaRuntimeError> {
        let job = unsafe { CreateJobObjectW(None, None) }
            .map_err(|error| MaaRuntimeError::new("worker.job_create_failed", error.to_string()))?;
        let owned = OwnedJob(job.0 as usize);
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &information as *const _ as *const c_void,
                std::mem::size_of_val(&information) as u32,
            )
        }
        .map_err(|error| MaaRuntimeError::new("worker.job_config_failed", error.to_string()))?;
        unsafe { AssignProcessToJobObject(job, HANDLE(child.as_raw_handle())) }.map_err(
            |error| {
                let _ = child.kill();
                let _ = child.wait();
                MaaRuntimeError::new("worker.job_assign_failed", error.to_string())
            },
        )?;
        Ok(owned)
    }

    #[derive(Debug)]
    pub struct SharedFrame {
        pub bytes: Vec<u8>,
        pub width: u32,
        pub height: u32,
        pub sequence: u64,
        pub captured_at_unix_us: i64,
        pub encoding: i32,
        pub backend: String,
        pub health_flags: u64,
    }

    pub struct SharedFrameReader {
        mapping: HANDLE,
        event: HANDLE,
        view: *mut u8,
        slot_payload_bytes: usize,
        expected_generation: [u8; 64],
    }

    unsafe impl Send for SharedFrameReader {}

    impl SharedFrameReader {
        fn open(
            mapping_name: &str,
            event_name: &str,
            slot_payload_bytes: usize,
            generation: &str,
        ) -> Result<Self, MaaRuntimeError> {
            let mapping_name = wide(mapping_name);
            let mapping =
                unsafe { OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(mapping_name.as_ptr())) }
                    .map_err(|error| {
                        MaaRuntimeError::new("worker.frame_map_failed", error.to_string())
                    })?;
            let total = std::mem::size_of::<RingHeader>()
                + SLOT_COUNT * (std::mem::size_of::<FrameHeader>() + slot_payload_bytes);
            let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, total) };
            if view.Value.is_null() {
                let _ = unsafe { CloseHandle(mapping) };
                return Err(invalid("worker frame mapping is empty"));
            }
            let event_name = wide(event_name);
            let event = unsafe {
                OpenEventW(
                    SYNCHRONIZATION_SYNCHRONIZE | EVENT_MODIFY_STATE,
                    false,
                    PCWSTR(event_name.as_ptr()),
                )
            }
            .map_err(|error| {
                let _ = unsafe { UnmapViewOfFile(view) };
                let _ = unsafe { CloseHandle(mapping) };
                MaaRuntimeError::new("worker.frame_event_failed", error.to_string())
            })?;
            let mut expected_generation = [0; 64];
            expected_generation[..generation.len()].copy_from_slice(generation.as_bytes());
            let reader = Self {
                mapping,
                event,
                view: view.Value.cast(),
                slot_payload_bytes,
                expected_generation,
            };
            let header = unsafe { &*reader.view.cast::<RingHeader>() };
            if header.magic != MAGIC
                || header.schema_version != 1
                || header.slot_count != SLOT_COUNT as u32
                || header.slot_bytes as usize
                    != std::mem::size_of::<FrameHeader>() + slot_payload_bytes
            {
                return Err(invalid("worker frame ring header is invalid"));
            }
            Ok(reader)
        }

        fn next_after(
            &mut self,
            after_sequence: u64,
            deadline: Instant,
        ) -> Result<SharedFrame, MaaRuntimeError> {
            loop {
                let published = unsafe {
                    (*self.view.cast::<RingHeader>())
                        .published_sequence
                        .load(Ordering::Acquire)
                };
                if published > after_sequence {
                    if let Some(frame) = self.read_sequence(published)? {
                        return Ok(frame);
                    }
                    continue;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(MaaRuntimeError::new(
                        "worker.frame_timeout",
                        "worker frame deadline expired",
                    ));
                }
                let wait_ms = remaining.as_millis().clamp(1, 100) as u32;
                match unsafe { WaitForSingleObject(self.event, wait_ms) } {
                    WAIT_OBJECT_0 | WAIT_TIMEOUT => {}
                    _ => {
                        return Err(MaaRuntimeError::new(
                            "worker.frame_event_failed",
                            "worker frame event wait failed",
                        ))
                    }
                }
            }
        }

        fn read_sequence(&self, sequence: u64) -> Result<Option<SharedFrame>, MaaRuntimeError> {
            let slot_bytes = std::mem::size_of::<FrameHeader>() + self.slot_payload_bytes;
            let slot = unsafe {
                self.view.add(
                    std::mem::size_of::<RingHeader>() + sequence as usize % SLOT_COUNT * slot_bytes,
                )
            };
            let header = unsafe { slot.cast::<FrameHeader>().read() };
            fence(Ordering::Acquire);
            if header.schema_version != 1
                || header.frame_sequence != sequence
                || header.worker_generation != self.expected_generation
                || header.payload_size as usize > self.slot_payload_bytes
            {
                return Ok(None);
            }
            let payload = unsafe {
                std::slice::from_raw_parts(
                    slot.add(std::mem::size_of::<FrameHeader>()),
                    header.payload_size as usize,
                )
            }
            .to_vec();
            fence(Ordering::Acquire);
            let published = unsafe {
                (*self.view.cast::<RingHeader>())
                    .published_sequence
                    .load(Ordering::Acquire)
            };
            if published != sequence {
                return Ok(None);
            }
            Ok(Some(SharedFrame {
                bytes: payload,
                width: header.width,
                height: header.height,
                sequence,
                captured_at_unix_us: header.captured_at_unix_us,
                encoding: header.encoding,
                backend: c_string(&header.backend)?,
                health_flags: header.health_flags,
            }))
        }
    }

    impl Drop for SharedFrameReader {
        fn drop(&mut self) {
            let _ = unsafe {
                UnmapViewOfFile(windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.view.cast::<c_void>(),
                })
            };
            let _ = unsafe { CloseHandle(self.event) };
            let _ = unsafe { CloseHandle(self.mapping) };
        }
    }

    #[repr(C)]
    struct RingHeader {
        magic: [u8; 8],
        schema_version: u32,
        slot_count: u32,
        slot_bytes: u64,
        published_sequence: AtomicU64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FrameHeader {
        schema_version: u32,
        worker_generation: [u8; 64],
        frame_sequence: u64,
        captured_at_unix_us: i64,
        width: u32,
        height: u32,
        stride: u32,
        pixel_format: i32,
        encoding: i32,
        payload_size: u64,
        backend: [u8; 64],
        health_flags: u64,
    }

    struct NamedPipeStream {
        file: File,
        read_deadline: Instant,
    }

    impl NamedPipeStream {
        fn new(file: File, deadline: Instant) -> Self {
            Self {
                file,
                read_deadline: deadline,
            }
        }

        fn set_deadline(&mut self, deadline: Instant) {
            self.read_deadline = deadline;
        }
    }

    impl Read for NamedPipeStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            loop {
                let mut available = 0;
                let handle = HANDLE(self.file.as_raw_handle());
                unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) }
                    .map_err(std::io::Error::other)?;
                if available > 0 {
                    return self.file.read(buffer);
                }
                if Instant::now() >= self.read_deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "worker response deadline expired",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    impl Write for NamedPipeStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.file.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }

    fn connect_pipe(
        pipe_name: &str,
        child: &mut Child,
        deadline: Instant,
    ) -> Result<File, MaaRuntimeError> {
        loop {
            match OpenOptions::new().read(true).write(true).open(pipe_name) {
                Ok(stream) => return Ok(stream),
                Err(error) if Instant::now() < deadline && child.try_wait()?.is_none() => {
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(25)),
                    );
                    let _ = error;
                }
                Err(_) if Instant::now() >= deadline => return Err(deadline_expired()),
                Err(error) => {
                    return Err(MaaRuntimeError::new(
                        "worker.start_failed",
                        error.to_string(),
                    ))
                }
            }
        }
    }

    fn read_startup_envelope(
        stream: &mut impl Read,
        deadline: Instant,
    ) -> Result<LocalEnvelope, MaaRuntimeError> {
        read_envelope(stream).map_err(|error| {
            if Instant::now() >= deadline {
                deadline_expired()
            } else {
                error
            }
        })
    }

    fn remaining_timeout(deadline: Instant) -> Result<Duration, MaaRuntimeError> {
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(deadline_expired)
    }

    fn wire_deadline_unix_ms(deadline: Instant) -> Result<i64, MaaRuntimeError> {
        let now_unix_ms = unix_ms();
        let remaining = remaining_timeout(deadline)?;
        Ok(now_unix_ms.saturating_add(remaining.as_millis() as i64))
    }

    fn deadline_expired() -> MaaRuntimeError {
        MaaRuntimeError::new(
            "worker.deadline_expired",
            "Worker deadline expired before dispatch",
        )
    }

    fn generation_id() -> String {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{now:x}-{:x}", NEXT.fetch_add(1, Ordering::Relaxed))
    }

    fn unix_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }

    fn c_string(bytes: &[u8]) -> Result<String, MaaRuntimeError> {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end])
            .map(str::to_owned)
            .map_err(|_| invalid("worker frame string is invalid"))
    }

    fn required_runtime_root_public_key(value: Option<&str>) -> Result<&str, MaaRuntimeError> {
        value.filter(|value| !value.is_empty()).ok_or_else(|| {
            MaaRuntimeError::new(
                "maa.runtime_root_key_unavailable",
                "MAA Runtime release public key is not embedded in the Agent build",
            )
        })
    }

    fn invalid(message: &str) -> MaaRuntimeError {
        MaaRuntimeError::new("worker.response_invalid", message)
    }

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;
        use std::time::{Duration, Instant};

        use super::{wire_deadline_unix_ms, WorkerProcess, WorkerProcessConfig};

        #[test]
        fn wire_deadline_does_not_move_when_request_preparation_takes_time() {
            let deadline = Instant::now() + Duration::from_millis(100);
            let first = wire_deadline_unix_ms(deadline).unwrap();
            std::thread::sleep(Duration::from_millis(25));
            let second = wire_deadline_unix_ms(deadline).unwrap();

            assert!(second <= first + 1);
        }

        #[test]
        fn worker_spawn_requires_runtime_root_public_key() {
            let error = WorkerProcess::spawn(
                &WorkerProcessConfig {
                    executable: PathBuf::from(r"Z:\__fairypam_missing_worker__.exe"),
                    runtime_root: PathBuf::from(r"Z:\__fairypam_missing_runtime__"),
                    profile_dir: None,
                    profile_root_public_key: None,
                    runtime_root_public_key: None,
                    frame_slot_bytes: 1024 * 1024,
                },
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .unwrap();

            assert_eq!(error.code(), "maa.runtime_root_key_unavailable");
        }
    }
}
