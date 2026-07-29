use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use fairypam_agent_guardian_protocol::{
    decode_response, encode_line, read_bounded_line, GuardianRequest, GuardianResponse,
    PhysicalHold,
};

use crate::{ActionId, GuardianClient, ReleaseReason, SafetyError};

pub struct GuardianProcessClient {
    #[cfg(not(windows))]
    child: Child,
    #[cfg(windows)]
    child_id: u32,
    requests: mpsc::SyncSender<IoRequest>,
    worker_done: mpsc::Receiver<()>,
    worker: Option<JoinHandle<()>>,
    physical_holds: BTreeMap<ActionId, PhysicalHold>,
    isolation_status: Option<i32>,
}

enum IoRequest {
    Request {
        message: GuardianRequest,
        reply: mpsc::SyncSender<Result<GuardianResponse, SafetyError>>,
    },
    Stop,
}

impl GuardianProcessClient {
    pub fn spawn(
        executable: &Path,
        physical_holds: BTreeMap<ActionId, PhysicalHold>,
        heartbeat_timeout: Duration,
        isolation_key_name: Option<&str>,
    ) -> Result<Self, SafetyError> {
        let timeout_ms = u32::try_from(heartbeat_timeout.as_millis()).map_err(|_| {
            SafetyError::new(
                "guardian.timeout_invalid",
                "guardian heartbeat timeout exceeds protocol bounds",
            )
        })?;
        if timeout_ms == 0 || timeout_ms > 5_000 {
            return Err(SafetyError::new(
                "guardian.timeout_invalid",
                "guardian heartbeat timeout must be between 1 and 5000 ms",
            ));
        }
        #[cfg(windows)]
        let (child_id, stdin, stdout, agent_process_handle) =
            spawn_restricted_guardian(executable)?;
        #[cfg(not(windows))]
        let (child, stdin, stdout, agent_process_handle) = {
            let mut child = Command::new(executable)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|error| SafetyError::new("guardian.spawn_failed", error.to_string()))?;
            let stdin = child.stdin.take().ok_or_else(|| {
                SafetyError::new("guardian.spawn_failed", "guardian stdin is unavailable")
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                SafetyError::new("guardian.spawn_failed", "guardian stdout is unavailable")
            })?;
            (child, stdin, stdout, 1_u64)
        };
        let (requests, receiver) = mpsc::sync_channel(1);
        let (worker_done_sender, worker_done) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("fairypam-guardian-io".into())
            .spawn(move || {
                let mut stdin = stdin;
                let mut stdout = BufReader::new(stdout);
                while let Ok(request) = receiver.recv() {
                    match request {
                        IoRequest::Request { message, reply } => {
                            let _ = reply.send(exchange(&mut stdin, &mut stdout, message));
                        }
                        IoRequest::Stop => break,
                    }
                }
                let _ = worker_done_sender.send(());
            })
            .map_err(|error| SafetyError::new("guardian.spawn_failed", error.to_string()))?;
        let mut client = Self {
            #[cfg(not(windows))]
            child,
            #[cfg(windows)]
            child_id,
            requests,
            worker_done,
            worker: Some(worker),
            physical_holds,
            isolation_status: None,
        };
        let response = client.request(GuardianRequest::RegisterAgent {
            agent_pid: std::process::id(),
            agent_process_handle,
            heartbeat_timeout_ms: timeout_ms,
            isolation_key_name: isolation_key_name.map(str::to_owned),
        })?;
        let GuardianResponse::Ack { isolation_status } = response else {
            return Err(SafetyError::new(
                "guardian.protocol_error",
                "Guardian registration returned a non-ack response",
            ));
        };
        if isolation_key_name.is_some() != isolation_status.is_some() {
            return Err(SafetyError::new(
                "guardian.key_access_unexpected",
                "Guardian registration did not prove the requested isolation boundary",
            ));
        }
        client.isolation_status = isolation_status;
        Ok(client)
    }

    fn request(&mut self, request: GuardianRequest) -> Result<GuardianResponse, SafetyError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .try_send(IoRequest::Request {
                message: request,
                reply,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    SafetyError::new("guardian.busy", "guardian is still handling a request")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    SafetyError::new("guardian.disconnected", "guardian I/O worker disconnected")
                }
            })?;
        receiver
            .recv_timeout(Duration::from_millis(250))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    SafetyError::new("guardian.deadline", "guardian response exceeded 250 ms")
                }
                mpsc::RecvTimeoutError::Disconnected => {
                    SafetyError::new("guardian.disconnected", "guardian I/O worker disconnected")
                }
            })?
    }

    fn require_ack(&mut self, request: GuardianRequest) -> Result<(), SafetyError> {
        match self.request(request)? {
            GuardianResponse::Ack { .. } => Ok(()),
            _ => Err(SafetyError::new(
                "guardian.protocol_error",
                "guardian returned a non-ack response",
            )),
        }
    }

    pub fn child_id(&self) -> u32 {
        #[cfg(not(windows))]
        {
            self.child.id()
        }
        #[cfg(windows)]
        {
            self.child_id
        }
    }

    pub const fn isolation_status(&self) -> Option<i32> {
        self.isolation_status
    }
}

impl GuardianClient for GuardianProcessClient {
    fn register_intent(
        &mut self,
        sequence: u64,
        holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError> {
        let physical = holds
            .iter()
            .map(|id| {
                self.physical_holds.get(id).cloned().ok_or_else(|| {
                    SafetyError::new(
                        "guardian.hold_not_registered",
                        format!("no physical hold for {}", id.as_str()),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.require_ack(GuardianRequest::RegisterIntent {
            sequence,
            holds: physical,
        })
    }

    fn commit_holds(
        &mut self,
        sequence: u64,
        _holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError> {
        self.require_ack(GuardianRequest::CommitHolds { sequence })
    }

    fn heartbeat(&mut self, sequence: u64) -> Result<(), SafetyError> {
        self.require_ack(GuardianRequest::Heartbeat { sequence })
    }

    fn release_all(&mut self, reason: ReleaseReason) -> Result<(), SafetyError> {
        self.require_ack(GuardianRequest::ReleaseAll { reason })
    }
}

impl Drop for GuardianProcessClient {
    fn drop(&mut self) {
        let _ = self.require_ack(GuardianRequest::ReleaseAll {
            reason: ReleaseReason::AgentDisconnected,
        });
        let _ = self.requests.try_send(IoRequest::Stop);
        if let Some(worker) = self.worker.take() {
            match self.worker_done.recv_timeout(Duration::from_millis(100)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = worker.join();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    drop(worker);
                }
            }
        }
    }
}

fn exchange<W: Write, R: BufRead>(
    stdin: &mut W,
    stdout: &mut R,
    request: GuardianRequest,
) -> Result<GuardianResponse, SafetyError> {
    let encoded = encode_line(&request)
        .map_err(|error| SafetyError::new("guardian.protocol_error", error.to_string()))?;
    stdin
        .write_all(&encoded)
        .and_then(|()| stdin.flush())
        .map_err(|error| SafetyError::new("guardian.io_failed", error.to_string()))?;
    let response = read_bounded_line(stdout)
        .map_err(|error| SafetyError::new("guardian.protocol_error", error.to_string()))?
        .ok_or_else(|| {
            SafetyError::new(
                "guardian.disconnected",
                "guardian closed its response stream",
            )
        })?;
    let response = decode_response(&response)
        .map_err(|error| SafetyError::new("guardian.protocol_error", error.to_string()))?;
    match response {
        GuardianResponse::Error { code, message } => Err(SafetyError::new(
            "guardian.rejected",
            format!("{code}: {message}"),
        )),
        response => Ok(response),
    }
}

#[cfg(windows)]
fn spawn_restricted_guardian(
    executable: &Path,
) -> Result<(u32, std::fs::File, std::fs::File, u64), SafetyError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows::core::HSTRING;
    use windows::Win32::Foundation::{
        CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
    };
    use windows::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, EqualSid, TokenGroups, TokenRestrictedSids,
        WinBuiltinUsersSid, DISABLE_MAX_PRIVILEGE, PSID, SECURITY_ATTRIBUTES,
        SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
        TOKEN_GROUPS, TOKEN_QUERY,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess,
        GetCurrentProcessId, InitializeProcThreadAttributeList, OpenProcess, OpenProcessToken,
        UpdateProcThreadAttribute, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROCESS_SYNCHRONIZE,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    };

    fn owned(handle: HANDLE) -> OwnedHandle {
        // SAFETY: each returned Windows handle is transferred into exactly one owner.
        unsafe { OwnedHandle::from_raw_handle(handle.0) }
    }

    fn token_groups_buffer(
        token: HANDLE,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, SafetyError> {
        use windows::Win32::Security::GetTokenInformation;

        let mut bytes = 0_u32;
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut bytes) };
        if bytes < std::mem::size_of::<TOKEN_GROUPS>() as u32 || bytes > 1024 * 1024 {
            return Err(SafetyError::new(
                "guardian.token_invalid",
                "Windows token groups are unavailable",
            ));
        }
        let words = (bytes as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(buffer.as_mut_ptr().cast()),
                bytes,
                &mut bytes,
            )
        }
        .map_err(|_| {
            SafetyError::new(
                "guardian.token_invalid",
                "Windows token groups are unavailable",
            )
        })?;
        Ok(buffer)
    }

    fn group_slice(buffer: &[usize]) -> &[SID_AND_ATTRIBUTES] {
        let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) }
    }

    let mut source = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut source,
        )
    }
    .map_err(|_| SafetyError::new("guardian.token_failed", "Agent token is unavailable"))?;
    let source = owned(source);
    let groups = token_groups_buffer(HANDLE(source.as_raw_handle()), TokenGroups)?;
    let logon = group_slice(&groups)
        .iter()
        .find(|group| group.Attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32)
        .ok_or_else(|| SafetyError::new("guardian.token_failed", "logon SID is unavailable"))?;

    let mut users_buffer = vec![0_usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let users_sid = PSID(users_buffer.as_mut_ptr().cast());
    let mut users_size = SECURITY_MAX_SID_SIZE;
    unsafe { CreateWellKnownSid(WinBuiltinUsersSid, None, Some(users_sid), &mut users_size) }
        .map_err(|_| SafetyError::new("guardian.token_failed", "Users SID is unavailable"))?;
    let restricting = [
        SID_AND_ATTRIBUTES {
            Sid: logon.Sid,
            Attributes: Default::default(),
        },
        SID_AND_ATTRIBUTES {
            Sid: users_sid,
            Attributes: Default::default(),
        },
    ];
    let mut restricted = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            HANDLE(source.as_raw_handle()),
            DISABLE_MAX_PRIVILEGE,
            None,
            None,
            Some(&restricting),
            &mut restricted,
        )
    }
    .map_err(|_| {
        SafetyError::new(
            "guardian.token_failed",
            "restricted Guardian token could not be created",
        )
    })?;
    let restricted = owned(restricted);
    let restricted_groups =
        token_groups_buffer(HANDLE(restricted.as_raw_handle()), TokenRestrictedSids)?;
    let restricted_groups = group_slice(&restricted_groups);
    if restricted_groups.len() != 2
        || !restricting.iter().all(|expected| {
            restricted_groups
                .iter()
                .any(|actual| unsafe { EqualSid(actual.Sid, expected.Sid) }.is_ok())
        })
    {
        return Err(SafetyError::new(
            "guardian.token_invalid",
            "restricted Guardian token did not preserve the exact SID boundary",
        ));
    }

    let agent_process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, true, GetCurrentProcessId()) }
        .map(owned)
        .map_err(|_| {
            SafetyError::new(
                "guardian.spawn_failed",
                "Agent synchronization handle is unavailable",
            )
        })?;
    let agent_process_handle = agent_process.as_raw_handle() as usize as u64;

    let inheritable = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut child_stdin = HANDLE::default();
    let mut parent_stdin = HANDLE::default();
    unsafe { CreatePipe(&mut child_stdin, &mut parent_stdin, Some(&inheritable), 0) }
        .map_err(|_| SafetyError::new("guardian.spawn_failed", "stdin pipe is unavailable"))?;
    let child_stdin = owned(child_stdin);
    let parent_stdin = owned(parent_stdin);
    let mut parent_stdout = HANDLE::default();
    let mut child_stdout = HANDLE::default();
    unsafe { CreatePipe(&mut parent_stdout, &mut child_stdout, Some(&inheritable), 0) }
        .map_err(|_| SafetyError::new("guardian.spawn_failed", "stdout pipe is unavailable"))?;
    let parent_stdout = owned(parent_stdout);
    let child_stdout = owned(child_stdout);
    let pipe_policy = unsafe {
        SetHandleInformation(
            HANDLE(parent_stdin.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAGS(0),
        )
        .and_then(|_| {
            SetHandleInformation(
                HANDLE(parent_stdout.as_raw_handle()),
                HANDLE_FLAG_INHERIT.0,
                HANDLE_FLAGS(0),
            )
        })
    };
    pipe_policy.map_err(|_| {
        SafetyError::new(
            "guardian.spawn_failed",
            "Guardian pipe inheritance could not be constrained",
        )
    })?;
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .open("NUL")
        .map_err(|_| SafetyError::new("guardian.spawn_failed", "stderr sink is unavailable"))?;
    unsafe {
        SetHandleInformation(
            HANDLE(stderr.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAG_INHERIT,
        )
    }
    .map_err(|_| {
        SafetyError::new(
            "guardian.spawn_failed",
            "Guardian stderr inheritance could not be constrained",
        )
    })?;
    let inherited = [
        HANDLE(child_stdin.as_raw_handle()),
        HANDLE(child_stdout.as_raw_handle()),
        HANDLE(agent_process.as_raw_handle()),
        HANDLE(stderr.as_raw_handle()),
    ];
    let mut attribute_size = 0_usize;
    let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut attribute_size) };
    if attribute_size == 0 || attribute_size > 1024 * 1024 {
        return Err(SafetyError::new(
            "guardian.spawn_failed",
            "Guardian handle allowlist is unavailable",
        ));
    }
    let mut attribute_buffer = vec![0_usize; attribute_size.div_ceil(std::mem::size_of::<usize>())];
    let attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_buffer.as_mut_ptr().cast());
    unsafe {
        InitializeProcThreadAttributeList(Some(attribute_list), 1, None, &mut attribute_size)
    }
    .map_err(|_| {
        SafetyError::new(
            "guardian.spawn_failed",
            "Guardian handle allowlist could not be initialized",
        )
    })?;
    let allowlist = unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(inherited.as_ptr().cast()),
            std::mem::size_of_val(&inherited),
            None,
            None,
        )
    };
    if allowlist.is_err() {
        unsafe { DeleteProcThreadAttributeList(attribute_list) };
        return Err(SafetyError::new(
            "guardian.spawn_failed",
            "Guardian handle allowlist could not be applied",
        ));
    }
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: inherited[0],
            hStdOutput: inherited[1],
            hStdError: inherited[3],
            ..Default::default()
        },
        lpAttributeList: attribute_list,
    };
    let mut process = PROCESS_INFORMATION::default();
    let directory = executable.parent().ok_or_else(|| {
        SafetyError::new("guardian.spawn_failed", "Guardian directory is unavailable")
    })?;
    let created = unsafe {
        CreateProcessAsUserW(
            Some(HANDLE(restricted.as_raw_handle())),
            &HSTRING::from(executable.to_string_lossy().as_ref()),
            None,
            None,
            None,
            true,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            None,
            &HSTRING::from(directory.to_string_lossy().as_ref()),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut process,
        )
    };
    unsafe { DeleteProcThreadAttributeList(attribute_list) };
    created.map_err(|_| {
        SafetyError::new(
            "guardian.spawn_failed",
            "restricted Guardian process could not be created",
        )
    })?;
    let _ = unsafe { CloseHandle(process.hThread) };
    let _ = unsafe { CloseHandle(process.hProcess) };
    drop((child_stdin, child_stdout, agent_process, stderr));
    Ok((
        process.dwProcessId,
        std::fs::File::from(parent_stdin),
        std::fs::File::from(parent_stdout),
        agent_process_handle,
    ))
}
