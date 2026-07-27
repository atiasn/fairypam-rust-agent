use std::{fs, io, mem::size_of, os::windows::io::AsRawHandle, path::Path};

use fairypam_agent_local_protocol::MAX_FRAME_BYTES;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
};
use windows::{
    core::{GUID, HSTRING, PWSTR},
    Win32::{
        Foundation::{CloseHandle, LocalFree, ERROR_ACCESS_DENIED, HANDLE, HLOCAL},
        Security::{
            Authorization::ConvertSidToStringSidW, GetSidSubAuthority, GetSidSubAuthorityCount,
            GetTokenInformation, TokenElevation, TokenIntegrityLevel, TokenSessionId, TokenUser,
            PSID, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateFileW, GetFileAttributesW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
            FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_WRITE_DATA, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING, WRITE_DAC,
            WRITE_OWNER,
        },
        System::{
            Com::CoTaskMemFree,
            Pipes::GetNamedPipeServerProcessId,
            SystemServices::SECURITY_MANDATORY_HIGH_RID,
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
                PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
        UI::Shell::{
            FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
        },
    },
};

use crate::{windows_path_is_within, LocalClientError, LocalTransport};

/// The Windows-only client transport. It depends solely on Tokio's Named Pipe
/// APIs and does not pull in the Agent's input, capture or server crate.
pub struct WindowsNamedPipeClientTransport {
    pipe_name: String,
    expected_server_path: Result<Option<std::path::PathBuf>, ()>,
    require_nonwritable_server: bool,
    pipe: Option<NamedPipeClient>,
}

impl WindowsNamedPipeClientTransport {
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            expected_server_path: Ok(None),
            require_nonwritable_server: false,
            pipe: None,
        }
    }

    pub fn new_verified_sibling(
        pipe_name: impl Into<String>,
        expected_server_sibling: impl Into<String>,
    ) -> Self {
        let expected_server_path = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|directory| directory.to_path_buf()))
            .map(|directory| Some(directory.join(expected_server_sibling.into())))
            .ok_or(());
        Self {
            pipe_name: pipe_name.into(),
            expected_server_path,
            require_nonwritable_server: true,
            pipe: None,
        }
    }

    pub fn new_verified_dev_sibling(
        pipe_name: impl Into<String>,
        expected_server_sibling: impl Into<String>,
    ) -> Self {
        let expected_server_path = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|directory| directory.to_path_buf()))
            .map(|directory| Some(directory.join(expected_server_sibling.into())))
            .ok_or(());
        Self {
            pipe_name: pipe_name.into(),
            expected_server_path,
            require_nonwritable_server: false,
            pipe: None,
        }
    }

    /// Used only by the elevated fixed installer after it validates the full
    /// protected install tree; its admin token is expected to write Program Files.
    pub fn new_verified_maintenance_path(
        pipe_name: impl Into<String>,
        expected_server_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            expected_server_path: Ok(Some(expected_server_path.into())),
            require_nonwritable_server: false,
            pipe: None,
        }
    }

    fn pipe_mut(&mut self) -> Result<&mut NamedPipeClient, LocalClientError> {
        self.pipe
            .as_mut()
            .ok_or_else(LocalClientError::disconnected)
    }
}

impl LocalTransport for WindowsNamedPipeClientTransport {
    async fn connect(&mut self) -> Result<(), LocalClientError> {
        if self.pipe.is_none() {
            let pipe = ClientOptions::new()
                .open(&self.pipe_name)
                .map_err(pipe_error)?;
            match &self.expected_server_path {
                Ok(Some(expected_server_path)) => {
                    verify_fixed_agent_server(
                        &pipe,
                        expected_server_path,
                        self.require_nonwritable_server,
                    )?;
                }
                Ok(None) => {}
                Err(()) => {
                    return Err(LocalClientError::identity("server_image_unavailable"));
                }
            }
            self.pipe = Some(pipe);
        }
        Ok(())
    }

    async fn send(&mut self, frame: Vec<u8>) -> Result<(), LocalClientError> {
        let pipe = self.pipe_mut()?;
        pipe.write_all(&frame).await.map_err(pipe_error)?;
        pipe.flush().await.map_err(pipe_error)
    }

    async fn receive(&mut self) -> Result<Vec<u8>, LocalClientError> {
        let pipe = self.pipe_mut()?;
        let mut prefix = [0_u8; 4];
        pipe.read_exact(&mut prefix).await.map_err(pipe_error)?;
        let payload_length = u32::from_le_bytes(prefix) as usize;
        if payload_length > MAX_FRAME_BYTES {
            return Err(LocalClientError::protocol_message(
                "local.protocol.frame_too_large",
                "response frame exceeded the local protocol limit",
            ));
        }

        let mut frame = Vec::with_capacity(4 + payload_length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + payload_length, 0);
        pipe.read_exact(&mut frame[4..]).await.map_err(pipe_error)?;
        Ok(frame)
    }

    async fn close(&mut self) {
        self.pipe.take();
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct ProcessIdentity {
    user_sid: String,
    session_id: u32,
    integrity_rid: u32,
    elevated: bool,
    image: String,
}

/// The GUI must establish the pipe peer before writing a protocol frame.  Pipe
/// ACLs only constrain who can create/connect; the server PID and token bind
/// this connection to the elevated sibling Agent actually running in this UI's
/// artifact directory.
fn verify_fixed_agent_server(
    pipe: &NamedPipeClient,
    expected_server_path: &Path,
    require_nonwritable_server: bool,
) -> Result<(), LocalClientError> {
    let mut pid = 0;
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }
        .map_err(|_| LocalClientError::identity("server_pid_unavailable"))?;
    if pid == 0 {
        return Err(LocalClientError::identity("server_pid_invalid"));
    }

    let server = process_identity(pid)?;
    let current = current_process_identity()?;
    if server.user_sid != current.user_sid {
        return Err(LocalClientError::identity("server_sid_mismatch"));
    }
    // NOTE: Logon SID is intentionally not part of this check. UAC `runas`
    // produces a split token: the elevated sibling Agent receives a fresh
    // Logon Identifier while the unelevated GUI keeps the original logon.
    // Comparing those values always rejects the
    // legitimate product flow. The remaining checks (same user SID, same
    // Windows session, high integrity + elevated token, sibling Agent image,
    // protected Program Files install) already bind the pipe peer to the
    // sibling Agent the GUI just spawned, so an attacker cannot substitute a
    // different logon session. See `product-live-start-diagnosis:01`.
    if server.session_id != current.session_id {
        return Err(LocalClientError::identity("server_session_mismatch"));
    }
    if server.integrity_rid < SECURITY_MANDATORY_HIGH_RID as u32 || !server.elevated {
        return Err(LocalClientError::identity("server_integrity_mismatch"));
    }
    if !same_windows_path(&expected_server_path.to_string_lossy(), &server.image) {
        return Err(LocalClientError::identity("server_image_mismatch"));
    }
    if require_nonwritable_server {
        verify_protected_program_files_path(Path::new(&server.image))?;
    }
    Ok(())
}

/// Product auto-elevation is permitted only from OS-owned Program Files roots.
pub fn verify_protected_program_files_path(path: &Path) -> Result<(), LocalClientError> {
    let roots = [FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86]
        .iter()
        .filter_map(|folder| known_folder_path(folder).ok())
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    for root in roots {
        if protected_install_path(path, &root)? {
            return Ok(());
        }
    }
    Err(LocalClientError::identity("install_root_unprotected"))
}

fn protected_install_path(path: &Path, root: &Path) -> Result<bool, LocalClientError> {
    if has_reparse_component(root) || has_reparse_component(path) {
        return Ok(false);
    }
    let (Ok(final_root), Ok(final_path)) = (fs::canonicalize(root), fs::canonicalize(path)) else {
        return Ok(false);
    };
    if !fs::metadata(&final_path).is_ok_and(|metadata| metadata.is_file()) {
        return Ok(false);
    }
    Ok(
        windows_path_is_within(&final_path.to_string_lossy(), &final_root.to_string_lossy())
            && protected_install_chain(&final_root, &final_path)?,
    )
}

fn protected_install_chain(root: &Path, target: &Path) -> Result<bool, LocalClientError> {
    let Ok(relative) = target.strip_prefix(root) else {
        return Ok(false);
    };
    let mut current = root.to_path_buf();
    if path_is_writable(&current)? {
        return Ok(false);
    }
    for component in relative {
        current.push(component);
        if has_reparse_component(&current) || path_is_writable(&current)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn has_reparse_component(path: &Path) -> bool {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !matches!(component, std::path::Component::Normal(_)) {
            continue;
        }
        let attributes =
            unsafe { GetFileAttributesW(&HSTRING::from(current.to_string_lossy().as_ref())) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        {
            return true;
        }
    }
    false
}

fn path_is_writable(path: &Path) -> Result<bool, LocalClientError> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(true);
    };
    let (access, flags) = if metadata.is_dir() {
        (
            [
                DELETE.0,
                FILE_ADD_FILE.0,
                FILE_ADD_SUBDIRECTORY.0,
                FILE_DELETE_CHILD.0,
                WRITE_DAC.0,
                WRITE_OWNER.0,
            ],
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    } else {
        (
            [
                DELETE.0,
                FILE_WRITE_DATA.0,
                FILE_APPEND_DATA.0,
                WRITE_DAC.0,
                WRITE_OWNER.0,
                0,
            ],
            FILE_ATTRIBUTE_NORMAL,
        )
    };
    for access in access.into_iter().filter(|access| *access != 0) {
        let handle = unsafe {
            CreateFileW(
                &HSTRING::from(path.to_string_lossy().as_ref()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        };
        match handle {
            Ok(handle) => {
                let _ = unsafe { CloseHandle(handle) };
                return Ok(true);
            }
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
            Err(_) => return Err(LocalClientError::identity("install_access_unavailable")),
        }
    }
    Ok(false)
}

fn known_folder_path(folder: &GUID) -> Result<String, LocalClientError> {
    let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None) }
        .map_err(|_| LocalClientError::identity("install_root_unavailable"))?;
    let result = unsafe { path.to_string() }
        .map_err(|_| LocalClientError::identity("install_root_unavailable"));
    unsafe { CoTaskMemFree(Some(path.0.cast())) };
    result
}

fn current_process_identity() -> Result<ProcessIdentity, LocalClientError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|_| LocalClientError::identity("server_token_unavailable"))?;
    token_identity(OwnedHandle(token))
}

fn process_identity(pid: u32) -> Result<ProcessIdentity, LocalClientError> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|_| LocalClientError::identity("server_process_unavailable"))?;
    let process = OwnedHandle(process);
    let image = process_image(process.0)?;
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) }
        .map_err(|_| LocalClientError::identity("server_token_unavailable"))?;
    let mut identity = token_identity(OwnedHandle(token))?;
    identity.image = image;
    Ok(identity)
}

fn token_identity(token: OwnedHandle) -> Result<ProcessIdentity, LocalClientError> {
    let user = token_information(token.0, TokenUser)?;
    let user = unsafe { &*(user.as_ptr().cast::<TOKEN_USER>()) };
    let session = token_information(token.0, TokenSessionId)?;
    let session_id = u32::from_ne_bytes(
        session[..size_of::<u32>()]
            .try_into()
            .expect("Windows token session id has a u32"),
    );
    let label = token_information(token.0, TokenIntegrityLevel)?;
    let label = unsafe { &*(label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    let elevation = token_information(token.0, TokenElevation)?;
    let elevation = unsafe { &*(elevation.as_ptr().cast::<TOKEN_ELEVATION>()) };
    Ok(ProcessIdentity {
        user_sid: sid_to_string(user.User.Sid)?,
        session_id,
        integrity_rid: integrity_rid(label.Label.Sid)?,
        elevated: elevation.TokenIsElevated != 0,
        image: String::new(),
    })
}

fn token_information(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>, LocalClientError> {
    let mut length = 0;
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut length) };
    if length == 0 {
        return Err(LocalClientError::identity("server_token_unavailable"));
    }
    let mut bytes = vec![0_u8; length as usize];
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(bytes.as_mut_ptr().cast()),
            length,
            &mut length,
        )
    }
    .map_err(|_| LocalClientError::identity("server_token_unavailable"))?;
    Ok(bytes)
}

fn sid_to_string(sid: PSID) -> Result<String, LocalClientError> {
    let mut value = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut value) }
        .map_err(|_| LocalClientError::identity("server_token_unavailable"))?;
    let text = unsafe { value.to_string() }
        .map_err(|_| LocalClientError::identity("server_token_unavailable"));
    let _ = unsafe { LocalFree(Some(HLOCAL(value.0.cast()))) };
    text
}

fn integrity_rid(sid: PSID) -> Result<u32, LocalClientError> {
    let count = unsafe { *GetSidSubAuthorityCount(sid) };
    if count == 0 {
        return Err(LocalClientError::identity("server_integrity_unavailable"));
    }
    Ok(unsafe { *GetSidSubAuthority(sid, (count - 1).into()) })
}

fn process_image(process: HANDLE) -> Result<String, LocalClientError> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|_| LocalClientError::identity("server_image_unavailable"))?;
    String::from_utf16(&buffer[..length as usize])
        .map_err(|_| LocalClientError::identity("server_image_unavailable"))
}

fn same_windows_path(expected: &str, actual: &str) -> bool {
    crate::normalize_windows_path(expected) == crate::normalize_windows_path(actual)
}

fn pipe_error(error: io::Error) -> LocalClientError {
    match error.kind() {
        io::ErrorKind::NotFound => LocalClientError::pipe_not_found(),
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::UnexpectedEof => LocalClientError::disconnected(),
        _ => LocalClientError::transport("local.transport.pipe_io", error.to_string()),
    }
}
