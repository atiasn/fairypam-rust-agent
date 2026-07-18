use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio_util::sync::CancellationToken;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    EqualSid, GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    TokenIntegrityLevel, TokenLogonSid, TokenSessionId, TokenUser, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::SystemServices::{
    SE_GROUP_LOGON_ID,
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
    SECURITY_MANDATORY_SYSTEM_RID,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::{CallerIdentity, ClientIntegrity, LocalClientError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeFlavor {
    Production,
    #[cfg(feature = "dev-automation")]
    Development,
}

impl PipeFlavor {
    const fn label(self) -> &'static str {
        match self {
            Self::Production => "prod",
            #[cfg(feature = "dev-automation")]
            Self::Development => "dev",
        }
    }
}

pub struct PipeIdentity {
    pipe_name: String,
    user_sid: OwnedSid,
    logon_sid: OwnedSid,
    user_sid_string: String,
    session_id: u32,
}

impl PipeIdentity {
    pub fn current(flavor: PipeFlavor) -> Result<Self, LocalClientError> {
        let process = unsafe { GetCurrentProcess() };
        let token = OwnedHandle::process_token(process)?;
        let user_sid = token_sid(token.0, TokenUser)?;
        let logon_sid = token_logon_sid(token.0)?;
        let user_sid_string = sid_string(user_sid.as_sid())?;
        let session_id = token_session_id(token.0)?;
        let hash = sid_hash(logon_sid.as_sid())?;
        let pipe_name = format!(
            r"\\.\pipe\FairyPam.Agent.{}.v1.{}",
            flavor.label(),
            &hash[..24]
        );
        Ok(Self {
            pipe_name,
            user_sid,
            logon_sid,
            user_sid_string,
            session_id,
        })
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub fn user_sid(&self) -> &str {
        &self.user_sid_string
    }

    pub fn user_sid_hash(&self) -> Result<String, LocalClientError> {
        sid_hash(self.user_sid.as_sid())
    }

    pub fn logon_sid_hash(&self) -> Result<String, LocalClientError> {
        sid_hash(self.logon_sid.as_sid())
    }
}

pub async fn open_client(
    pipe_name: &str,
    cancellation: &CancellationToken,
) -> Result<NamedPipeClient, LocalClientError> {
    loop {
        match ClientOptions::new().read(true).write(true).open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(231) => {
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(LocalClientError::Cancelled),
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(LocalClientError::Unavailable)
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(LocalClientError::PermissionDenied)
            }
            Err(error) => return Err(LocalClientError::Io(error)),
        }
    }
}

pub fn create_server(
    identity: &PipeIdentity,
    first_instance: bool,
) -> Result<NamedPipeServer, LocalClientError> {
    let security = PipeSecurity::new(&identity.user_sid_string)?;
    let mut options = ServerOptions::new();
    options
        .access_inbound(true)
        .access_outbound(true)
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .max_instances(8);
    // SAFETY: `security.attributes` and its descriptor remain live for the
    // synchronous CreateNamedPipeW call; Windows copies the descriptor.
    unsafe {
        options
            .create_with_security_attributes_raw(
                identity.pipe_name(),
                ptr::addr_of!(security.attributes).cast_mut().cast(),
            )
            .map_err(LocalClientError::Io)
    }
}

pub fn validate_client(
    pipe: &NamedPipeServer,
    expected: &PipeIdentity,
) -> Result<CallerIdentity, LocalClientError> {
    let handle = HANDLE(pipe.as_raw_handle());
    let mut process_id = 0_u32;
    unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) }
        .map_err(|_| LocalClientError::PermissionDenied)?;
    if process_id == 0 {
        return Err(LocalClientError::PermissionDenied);
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
        .map_err(|_| LocalClientError::PermissionDenied)?;
    let process = OwnedHandle(process);
    let token = OwnedHandle::process_token(process.0)?;
    let user_sid = token_sid(token.0, TokenUser)?;
    let logon_sid = token_logon_sid(token.0)?;
    let session_id = token_session_id(token.0)?;
    let integrity = token_integrity(token.0)?;
    let caller = CallerIdentity {
        process_id,
        user_sid_hash: sid_hash(user_sid.as_sid())?,
        logon_sid_hash: sid_hash(logon_sid.as_sid())?,
        session_id,
        integrity,
    };
    if !same_sid(user_sid.as_sid(), expected.user_sid.as_sid())
        || !same_sid(logon_sid.as_sid(), expected.logon_sid.as_sid())
        || !identity_facts_match(
            &caller,
            &expected.user_sid_hash()?,
            &expected.logon_sid_hash()?,
            expected.session_id,
        )
    {
        return Err(LocalClientError::PermissionDenied);
    }
    Ok(caller)
}

struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn new(user_sid: &str) -> Result<Self, LocalClientError> {
        let sddl = pipe_sddl(user_sid);
        let wide = wide(&sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| LocalClientError::Protocol(format!("invalid pipe DACL: {error}")))?;
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: false.into(),
            },
        })
    }
}

fn pipe_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GRGW;;;SY)(A;;GRGW;;;{user_sid})")
}

fn identity_facts_match(
    caller: &CallerIdentity,
    expected_user_sid_hash: &str,
    expected_logon_sid_hash: &str,
    expected_session_id: u32,
) -> bool {
    caller.user_sid_hash == expected_user_sid_hash
        && caller.logon_sid_hash == expected_logon_sid_hash
        && caller.session_id == expected_session_id
        // The fixed updater/installer tasks run with the same user, logon SID and
        // session at high integrity. Identity remains exact; only SYSTEM/unknown
        // callers stay excluded from this per-user control pipe.
        && matches!(caller.integrity, ClientIntegrity::Low | ClientIntegrity::Medium | ClientIntegrity::High)
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn process_token(process: HANDLE) -> Result<Self, LocalClientError> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
            .map_err(|_| LocalClientError::PermissionDenied)?;
        Ok(Self(token))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct TokenBuffer {
    words: Vec<usize>,
}

impl TokenBuffer {
    fn query(
        token: HANDLE,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<Self, LocalClientError> {
        let mut length = 0_u32;
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut length) };
        if length == 0 {
            return Err(LocalClientError::PermissionDenied);
        }
        let words = (length as usize)
            .checked_add(size_of::<usize>() - 1)
            .and_then(|length| length.checked_div(size_of::<usize>()))
            .ok_or_else(|| LocalClientError::Protocol("token metadata is too large".into()))?;
        let mut buffer = Self {
            words: vec![0; words],
        };
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(buffer.words.as_mut_ptr().cast()),
                length,
                &mut length,
            )
        }
        .map_err(|_| LocalClientError::PermissionDenied)?;
        Ok(buffer)
    }

    fn as_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast()
    }
}

struct OwnedSid {
    words: Vec<usize>,
}

impl OwnedSid {
    fn copy(sid: PSID) -> Result<Self, LocalClientError> {
        let length = unsafe { GetLengthSid(sid) } as usize;
        if length == 0 {
            return Err(LocalClientError::PermissionDenied);
        }
        let words = length
            .checked_add(size_of::<usize>() - 1)
            .and_then(|length| length.checked_div(size_of::<usize>()))
            .ok_or_else(|| LocalClientError::Protocol("SID is too large".into()))?;
        let mut storage = vec![0_usize; words];
        unsafe {
            ptr::copy_nonoverlapping(sid.0.cast::<u8>(), storage.as_mut_ptr().cast(), length);
        }
        Ok(Self { words: storage })
    }

    fn as_sid(&self) -> PSID {
        PSID(self.words.as_ptr().cast_mut().cast())
    }
}

fn token_sid(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<OwnedSid, LocalClientError> {
    let buffer = TokenBuffer::query(token, class)?;
    let user = unsafe { &*buffer.as_ptr::<TOKEN_USER>() };
    OwnedSid::copy(user.User.Sid)
}

fn token_logon_sid(token: HANDLE) -> Result<OwnedSid, LocalClientError> {
    let buffer = TokenBuffer::query(token, TokenLogonSid)?;
    let groups = unsafe { &*buffer.as_ptr::<TOKEN_GROUPS>() };
    let groups =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    let group = groups
        .iter()
        .find(|group| group.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
        .ok_or(LocalClientError::PermissionDenied)?;
    OwnedSid::copy(group.Sid)
}

fn token_session_id(token: HANDLE) -> Result<u32, LocalClientError> {
    let buffer = TokenBuffer::query(token, TokenSessionId)?;
    Ok(unsafe { *buffer.as_ptr::<u32>() })
}

fn token_integrity(token: HANDLE) -> Result<ClientIntegrity, LocalClientError> {
    let buffer = TokenBuffer::query(token, TokenIntegrityLevel)?;
    let label = unsafe { &*buffer.as_ptr::<TOKEN_MANDATORY_LABEL>() };
    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) } as u32;
    if count == 0 {
        return Ok(ClientIntegrity::Unknown);
    }
    let rid = unsafe { *GetSidSubAuthority(label.Label.Sid, count - 1) };
    Ok(match rid as i32 {
        SECURITY_MANDATORY_LOW_RID => ClientIntegrity::Low,
        SECURITY_MANDATORY_MEDIUM_RID => ClientIntegrity::Medium,
        SECURITY_MANDATORY_HIGH_RID => ClientIntegrity::High,
        SECURITY_MANDATORY_SYSTEM_RID => ClientIntegrity::System,
        _ => ClientIntegrity::Unknown,
    })
}

fn same_sid(left: PSID, right: PSID) -> bool {
    unsafe { EqualSid(left, right) }.is_ok()
}

fn sid_hash(sid: PSID) -> Result<String, LocalClientError> {
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length == 0 {
        return Err(LocalClientError::PermissionDenied);
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), length) };
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn sid_string(sid: PSID) -> Result<String, LocalClientError> {
    let mut value = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut value) }
        .map_err(|_| LocalClientError::PermissionDenied)?;
    let result = unsafe { value.to_string() }
        .map_err(|error| LocalClientError::Protocol(format!("invalid SID string: {error}")));
    unsafe {
        let _ = LocalFree(Some(HLOCAL(value.0.cast())));
    }
    result
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> CallerIdentity {
        CallerIdentity {
            process_id: 42,
            user_sid_hash: "user".into(),
            logon_sid_hash: "logon".into(),
            session_id: 7,
            integrity: ClientIntegrity::Medium,
        }
    }

    #[test]
    fn explicit_dacl_is_protected_and_has_no_world_or_authenticated_users_ace() {
        let sddl = pipe_sddl("S-1-5-21-1-2-3-1001");
        assert!(sddl.starts_with("D:P"));
        assert!(sddl.contains(";;;SY"));
        assert!(sddl.contains(";;;S-1-5-21-1-2-3-1001"));
        assert!(!sddl.contains(";;;WD"));
        assert!(!sddl.contains(";;;AU"));
    }

    #[test]
    fn wrong_user_logon_session_or_integrity_fails_closed() {
        let mut value = caller();
        assert!(identity_facts_match(&value, "user", "logon", 7));
        value.user_sid_hash = "other".into();
        assert!(!identity_facts_match(&value, "user", "logon", 7));
        value = caller();
        value.logon_sid_hash = "other".into();
        assert!(!identity_facts_match(&value, "user", "logon", 7));
        value = caller();
        value.session_id = 8;
        assert!(!identity_facts_match(&value, "user", "logon", 7));
        value = caller();
        value.integrity = ClientIntegrity::High;
        assert!(identity_facts_match(&value, "user", "logon", 7));
        value.integrity = ClientIntegrity::System;
        assert!(!identity_facts_match(&value, "user", "logon", 7));
    }
}
