use thiserror::Error;

#[cfg(windows)]
use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(windows)]
use tokio::{
    io::AsyncReadExt,
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};

#[cfg(windows)]
use windows::{
    core::{GUID, HSTRING, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, LocalFree, ERROR_ACCESS_DENIED, HANDLE, HLOCAL},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
            ImpersonateLoggedOnUser, RevertToSelf, TokenIntegrityLevel, TokenSessionId,
            TokenStatistics, TokenUser, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
            TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
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
            Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient},
            SystemServices::{
                SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID,
                SECURITY_MANDATORY_MEDIUM_RID,
            },
            Threading::{
                GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
                OpenThreadToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
        UI::Shell::{
            FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
        },
    },
};

#[cfg(windows)]
const FIRST_PREFIX_BYTE_TIMEOUT: Duration = Duration::from_secs(5);

/// The production pipe namespace; Dev uses a separate feature-gated namespace.
pub const fn default_production_pipe_name() -> &'static str {
    r"\\.\pipe\FairyPam.Agent.v1"
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    High,
    System,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeOwner {
    pub user_sid: String,
    pub logon_sid: String,
    pub session_id: u32,
    pub minimum_integrity: IntegrityLevel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPipeCaller {
    pub pid: u32,
    pub user_sid: String,
    pub logon_sid: String,
    pub session_id: u32,
    pub integrity: IntegrityLevel,
}

#[cfg(windows)]
fn logon_sid_from_luid(high_part: i32, low_part: u32) -> String {
    format!("S-1-5-5-{}-{low_part}", high_part as u32)
}

/// Reads the Agent process token to bind the production pipe to the interactive
/// Windows identity that owns the elevated Agent.  The pipe's DACL is only an
/// early filter; each connection is still impersonated and compared with this
/// complete identity before protocol bytes are accepted.
#[cfg(windows)]
pub fn current_process_pipe_owner(
    minimum_integrity: IntegrityLevel,
) -> Result<PipeOwner, LocalIdentityError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(windows_identity_error)?;
    let claims = token_claims(token, std::process::id());
    let _ = unsafe { CloseHandle(token) };
    let claims = claims?;
    Ok(PipeOwner {
        user_sid: claims.user_sid,
        logon_sid: claims.logon_sid,
        session_id: claims.session_id,
        minimum_integrity,
    })
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct LocalIdentityError {
    code: &'static str,
    message: String,
}

impl LocalIdentityError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    fn invalid_handle() -> Self {
        Self::new(
            "local.identity.client_pid_invalid",
            "named-pipe client PID is missing",
        )
    }

    fn sid_mismatch() -> Self {
        Self::new(
            "local.identity.sid_mismatch",
            "client user SID does not match pipe owner",
        )
    }

    fn logon_session_mismatch() -> Self {
        Self::new(
            "local.identity.logon_session_mismatch",
            "client logon SID does not match pipe owner",
        )
    }

    fn session_mismatch() -> Self {
        Self::new(
            "local.identity.session_mismatch",
            "client session does not match pipe owner",
        )
    }

    fn integrity_mismatch() -> Self {
        Self::new(
            "local.identity.integrity_mismatch",
            "client integrity level is below the pipe minimum",
        )
    }

    #[cfg(windows)]
    fn gui_image_mismatch() -> Self {
        Self::new(
            "local.identity.gui_image_mismatch",
            "RegisterHub requires the fixed FairyPam GUI sibling",
        )
    }

    #[cfg(windows)]
    fn install_root_mismatch() -> Self {
        Self::new(
            "local.identity.install_root_mismatch",
            "RegisterHub requires the protected FairyPam product installation",
        )
    }
}

/// Opaque native handle passed to the platform-specific identity provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeHandle(pub usize);

/// Gets facts from the operating-system pipe and token rather than accepting
/// client-provided identity claims.
pub trait PipeIdentityProvider {
    fn verify_client(
        &self,
        pipe: PipeHandle,
        owner: &PipeOwner,
    ) -> Result<VerifiedPipeCaller, LocalIdentityError>;
}

/// Deterministic boundary shared by the Windows implementation and tests.
pub fn verify_pipe_caller(
    owner: &PipeOwner,
    caller: VerifiedPipeCaller,
) -> Result<VerifiedPipeCaller, LocalIdentityError> {
    if caller.pid == 0 {
        return Err(LocalIdentityError::invalid_handle());
    }
    if caller.user_sid != owner.user_sid {
        return Err(LocalIdentityError::sid_mismatch());
    }
    if caller.logon_sid != owner.logon_sid {
        return Err(LocalIdentityError::logon_session_mismatch());
    }
    if caller.session_id != owner.session_id {
        return Err(LocalIdentityError::session_mismatch());
    }
    if caller.integrity < owner.minimum_integrity {
        return Err(LocalIdentityError::integrity_mismatch());
    }
    Ok(caller)
}

/// Confirms the process image is the fixed GUI sibling, not merely another
/// process running under the same interactive user.
pub fn fixed_gui_image_matches(expected: &str, actual: &str) -> bool {
    crate::normalize_process_path(expected) == crate::normalize_process_path(actual)
}

/// RegisterHub is the only local command that carries a registration secret.
/// Same-user pipe access is sufficient for normal read-only commands, but this
/// command additionally requires the shipped GUI executable.
#[cfg(windows)]
pub fn verify_fixed_gui_caller(pid: u32) -> Result<(), LocalIdentityError> {
    if pid == 0 {
        return Err(LocalIdentityError::invalid_handle());
    }
    let agent = std::env::current_exe().map_err(|_| LocalIdentityError::gui_image_mismatch())?;
    let expected = agent
        .parent()
        .map(|directory| directory.join("fairypam-agent-tauri-ui.exe"))
        .ok_or_else(LocalIdentityError::gui_image_mismatch)?;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(windows_identity_error)?;
    let result = (|| {
        let image = process_image(process)?;
        if !fixed_gui_image_matches(&expected.to_string_lossy(), &image) {
            return Err(LocalIdentityError::gui_image_mismatch());
        }
        if !protected_program_files_path(&image, process)? {
            return Err(LocalIdentityError::install_root_mismatch());
        }
        Ok(())
    })();
    let _ = unsafe { CloseHandle(process) };
    result
}

#[cfg(windows)]
fn protected_program_files_path(path: &str, process: HANDLE) -> Result<bool, LocalIdentityError> {
    let roots = [FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86]
        .iter()
        .filter_map(|folder| known_folder_path(folder).ok())
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Err(LocalIdentityError::install_root_mismatch());
    }
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) }
        .map_err(windows_identity_error)?;
    let impersonated = unsafe { ImpersonateLoggedOnUser(token) }.map_err(windows_identity_error);
    let result = impersonated.and_then(|_| {
        for root in &roots {
            if crate::process_path_is_within(path, root)
                && protected_install_path(Path::new(path), Path::new(root))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    });
    revert_or_abort();
    let _ = unsafe { CloseHandle(token) };
    result
}

/// A Program Files prefix alone is not a trust proof: junctions could redirect
/// the fixed GUI path outside the protected installation.
#[cfg(windows)]
fn protected_install_path(path: &Path, root: &Path) -> Result<bool, LocalIdentityError> {
    // Resolve only after checking the supplied path's components: a junction
    // must be rejected, never silently accepted because it resolves below a
    // Program Files root.
    if has_reparse_component(root) || has_reparse_component(path) {
        return Ok(false);
    }
    let (Ok(final_root), Ok(final_path)) =
        (std::fs::canonicalize(root), std::fs::canonicalize(path))
    else {
        return Ok(false);
    };
    Ok(
        crate::process_path_is_within(&final_path.to_string_lossy(), &final_root.to_string_lossy())
            && protected_install_chain(&final_root, &final_path)?,
    )
}

#[cfg(windows)]
fn protected_install_chain(root: &Path, target: &Path) -> Result<bool, LocalIdentityError> {
    if has_reparse_component(root) {
        return Ok(false);
    }
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

#[cfg(windows)]
fn path_is_writable(path: &Path) -> Result<bool, LocalIdentityError> {
    let Ok(metadata) = std::fs::metadata(path) else {
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
            Err(_) => return Err(LocalIdentityError::install_root_mismatch()),
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn has_reparse_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
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

#[cfg(windows)]
fn known_folder_path(folder: &GUID) -> Result<String, LocalIdentityError> {
    let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None) }
        .map_err(windows_identity_error)?;
    let result = unsafe { path.to_string() }.map_err(utf16_identity_error);
    unsafe { CoTaskMemFree(Some(path.0.cast())) };
    result
}

/// Produce the explicit, protected DACL used for a production server instance.
///
/// Only a syntactically SID-shaped owner is accepted, preventing an untrusted
/// provisioning value from escaping the SDDL trustee field.
pub fn explicit_owner_sddl(owner_sid: &str) -> Result<String, LocalIdentityError> {
    let Some(sid_body) = owner_sid.strip_prefix("S-1-") else {
        return Err(LocalIdentityError::new(
            "local.identity.owner_sid_invalid",
            "pipe owner SID is not valid for an explicit DACL",
        ));
    };
    if sid_body.is_empty()
        || sid_body
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || byte == b'-'))
    {
        return Err(LocalIdentityError::new(
            "local.identity.owner_sid_invalid",
            "pipe owner SID is not valid for an explicit DACL",
        ));
    }
    Ok(format!("D:P(A;;GRGW;;;{owner_sid})"))
}

#[cfg(windows)]
pub struct WindowsPipeIdentityProvider;

#[cfg(windows)]
impl PipeIdentityProvider for WindowsPipeIdentityProvider {
    fn verify_client(
        &self,
        pipe: PipeHandle,
        owner: &PipeOwner,
    ) -> Result<VerifiedPipeCaller, LocalIdentityError> {
        let pipe = HANDLE(pipe.0 as *mut c_void);
        let mut pid = 0;
        unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.map_err(windows_identity_error)?;
        unsafe { ImpersonateNamedPipeClient(pipe) }.map_err(windows_identity_error)?;

        let result = (|| {
            let mut token = HANDLE::default();
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &mut token) }
                .map_err(windows_identity_error)?;
            let claims = token_claims(token, pid);
            let _ = unsafe { CloseHandle(token) };
            claims
        })();
        revert_or_abort();
        let caller = result?;
        verify_pipe_caller(owner, caller)
    }
}

#[cfg(windows)]
fn revert_or_abort() {
    if unsafe { RevertToSelf() }.is_err() {
        // Continuing under an untrusted client token would corrupt every later
        // authorization decision in this Agent process.
        std::process::abort();
    }
}

/// A one-client server instance with a DACL created from the configured owner
/// SID. `connect_and_verify` must complete before any protocol bytes are parsed.
#[cfg(windows)]
pub struct WindowsNamedPipeServer {
    owner: PipeOwner,
    server: NamedPipeServer,
}

#[cfg(windows)]
impl WindowsNamedPipeServer {
    pub fn create(pipe_name: &str, owner: PipeOwner) -> Result<Self, LocalIdentityError> {
        let sddl = explicit_owner_sddl(&owner.user_sid)?;
        let mut wide = sddl.encode_utf16().collect::<Vec<_>>();
        wide.push(0);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                1,
                &mut descriptor,
                None,
            )
        }
        .map_err(windows_identity_error)?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let server = unsafe {
            ServerOptions::new().create_with_security_attributes_raw(
                pipe_name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
        }
        .map_err(pipe_create_error);
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        Ok(Self {
            owner,
            server: server?,
        })
    }

    pub async fn connect_and_verify(
        &mut self,
    ) -> Result<(VerifiedPipeCaller, u8), LocalIdentityError> {
        self.server.connect().await.map_err(io_identity_error)?;
        // ponytail: Win32 impersonates the last read message; retain one unparsed prefix byte until identity verification.
        let mut first_prefix_byte = [0_u8; 1];
        tokio::time::timeout(
            FIRST_PREFIX_BYTE_TIMEOUT,
            self.server.read_exact(&mut first_prefix_byte),
        )
        .await
        .map_err(|_| pipe_idle_timeout())?
        .map_err(io_identity_error)?;
        let caller = WindowsPipeIdentityProvider.verify_client(
            PipeHandle(self.server.as_raw_handle() as usize),
            &self.owner,
        )?;
        Ok((caller, first_prefix_byte[0]))
    }

    pub fn pipe_mut(&mut self) -> &mut NamedPipeServer {
        &mut self.server
    }
}

#[cfg(windows)]
fn token_claims(token: HANDLE, pid: u32) -> Result<VerifiedPipeCaller, LocalIdentityError> {
    let user = token_information(token, TokenUser)?;
    let user = unsafe { &*(user.as_ptr().cast::<TOKEN_USER>()) };
    let statistics = token_information(token, TokenStatistics)?;
    let statistics = unsafe { &*(statistics.as_ptr().cast::<TOKEN_STATISTICS>()) };
    let session = token_information(token, TokenSessionId)?;
    let session_id = u32::from_ne_bytes(
        session[..size_of::<u32>()]
            .try_into()
            .expect("Windows token session id has a u32"),
    );
    let label = token_information(token, TokenIntegrityLevel)?;
    let label = unsafe { &*(label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    Ok(VerifiedPipeCaller {
        pid,
        user_sid: sid_to_string(user.User.Sid)?,
        logon_sid: logon_sid_from_luid(
            statistics.AuthenticationId.HighPart,
            statistics.AuthenticationId.LowPart,
        ),
        session_id,
        integrity: integrity_level(label.Label.Sid)?,
    })
}

#[cfg(windows)]
fn token_information(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>, LocalIdentityError> {
    let mut length = 0;
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut length) };
    if length == 0 {
        return Err(LocalIdentityError::new(
            "local.identity.token_query_failed",
            "Windows did not report a token-information buffer length",
        ));
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
    .map_err(windows_identity_error)?;
    Ok(bytes)
}

#[cfg(windows)]
fn process_image(process: HANDLE) -> Result<String, LocalIdentityError> {
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
    .map_err(windows_identity_error)?;
    String::from_utf16(&buffer[..length as usize]).map_err(utf16_identity_error)
}

#[cfg(windows)]
fn sid_to_string(sid: PSID) -> Result<String, LocalIdentityError> {
    let mut value = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut value) }.map_err(windows_identity_error)?;
    let text = unsafe { value.to_string() }.map_err(utf16_identity_error);
    let _ = unsafe { LocalFree(Some(HLOCAL(value.0.cast()))) };
    text
}

#[cfg(windows)]
fn integrity_level(sid: PSID) -> Result<IntegrityLevel, LocalIdentityError> {
    let count = unsafe { *GetSidSubAuthorityCount(sid) };
    if count == 0 {
        return Err(LocalIdentityError::new(
            "local.identity.integrity_missing",
            "integrity SID has no sub-authority",
        ));
    }
    let rid = unsafe { *GetSidSubAuthority(sid, (count - 1).into()) } as i32;
    Ok(if rid < SECURITY_MANDATORY_LOW_RID {
        IntegrityLevel::Untrusted
    } else if rid < SECURITY_MANDATORY_MEDIUM_RID {
        IntegrityLevel::Low
    } else if rid < SECURITY_MANDATORY_HIGH_RID {
        IntegrityLevel::Medium
    } else {
        IntegrityLevel::High
    })
}

#[cfg(windows)]
fn windows_identity_error(error: windows::core::Error) -> LocalIdentityError {
    LocalIdentityError::new("local.identity.token_query_failed", error.to_string())
}

#[cfg(windows)]
fn io_identity_error(error: std::io::Error) -> LocalIdentityError {
    LocalIdentityError::new("local.identity.pipe_connect_failed", error.to_string())
}

#[cfg(windows)]
fn pipe_create_error(error: std::io::Error) -> LocalIdentityError {
    LocalIdentityError::new("local.identity.pipe_create_failed", error.to_string())
}

#[cfg(windows)]
fn pipe_idle_timeout() -> LocalIdentityError {
    LocalIdentityError::new(
        "local.transport.pipe_idle_timeout",
        "named-pipe client did not start a request before the idle deadline",
    )
}

#[cfg(windows)]
fn utf16_identity_error(error: std::string::FromUtf16Error) -> LocalIdentityError {
    LocalIdentityError::new("local.identity.sid_string_invalid", error.to_string())
}

#[cfg(all(test, windows))]
mod tests {
    use super::logon_sid_from_luid;

    #[test]
    fn derives_logon_sid_from_unsigned_luid_parts() {
        assert_eq!(logon_sid_from_luid(-1, 42), "S-1-5-5-4294967295-42");
    }
}
