//! Elevated Agent-side enrollment. Registration material is accepted only from
//! the authenticated local pipe and is never included in an error or log.

use std::fs;
use std::io::Write;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::AgentError;
use fairypam_agent_local_protocol::validate_registration_request;
use http::Uri;
use serde_json::{json, Value};
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HLOCAL};
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileAttributesW, MoveFileExW, CREATE_NEW, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_ALWAYS, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(crate) const PRODUCT_STATE_ROOT: &str = r"C:\ProgramData\FairyPam.Agent";
pub(crate) const STATE_PARENT: &str = r"C:\ProgramData\FairyPam.Agent\Agent";
pub(crate) const STATE_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\enrollment";
pub(crate) const AUDIT_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\audit";
pub(crate) const LOG_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\logs";
const PRIVATE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const CLAIM_DEADLINE: Duration = Duration::from_secs(15);
const CLAIM_OPERATION_TIMEOUT_MS: i32 = 5_000;
/// The elevated Agent claims the one-time code after the protected Pipe has
/// authenticated the GUI caller. No desktop confirmation is required.
pub fn register(hub_address: &str, registration_code: &str) -> Result<(), AgentError> {
    validate_registration_request(hub_address, registration_code).map_err(|_| invalid())?;
    ensure_elevated()?;
    let deadline = Instant::now() + CLAIM_DEADLINE;
    register_before(hub_address, registration_code, deadline)
}

fn register_before(
    hub_address: &str,
    registration_code: &str,
    deadline: Instant,
) -> Result<(), AgentError> {
    let (host, port, path) = claim_target(hub_address)?;
    let payload = claim(&host, port, &path, registration_code, deadline)?;
    persist(&payload)
}

fn claim_target(value: &str) -> Result<(String, u16, String), AgentError> {
    let uri = value.parse::<Uri>().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    let prefix = uri.path().trim_end_matches('/');
    Ok((
        authority.host().to_owned(),
        authority.port_u16().unwrap_or(443),
        format!("{prefix}/api/v1/agent-enrollment/claim"),
    ))
}

fn claim(
    host: &str,
    port: u16,
    path: &str,
    code: &str,
    deadline: Instant,
) -> Result<Value, AgentError> {
    let body = serde_json::to_vec(&json!({"code": code})).map_err(|_| failed())?;
    let session = unsafe {
        WinHttpOpen(
            &HSTRING::from("FairyPam Agent enrollment"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            &HSTRING::new(),
            &HSTRING::new(),
            0,
        )
    };
    if session.is_null() {
        return Err(network());
    }
    if set_remaining_timeouts(session, deadline).is_err() {
        close(session);
        return Err(network());
    }
    let connection = unsafe { WinHttpConnect(session, &HSTRING::from(host), port, 0) };
    if connection.is_null() {
        close(session);
        return Err(network());
    }
    let request = unsafe {
        WinHttpOpenRequest(
            connection,
            &HSTRING::from("POST"),
            &HSTRING::from(path),
            &HSTRING::new(),
            &HSTRING::new(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        )
    };
    if request.is_null() {
        close(connection);
        close(session);
        return Err(network());
    }
    let headers = "Content-Type: application/json\r\n"
        .encode_utf16()
        .collect::<Vec<_>>();
    let result = set_remaining_timeouts(request, deadline)
        .and_then(|_| unsafe {
            WinHttpSendRequest(
                request,
                Some(&headers),
                Some(body.as_ptr().cast()),
                body.len() as u32,
                body.len() as u32,
                0,
            )
            .map_err(|_| failed())
        })
        .and_then(|_| set_remaining_timeouts(request, deadline))
        .and_then(|_| unsafe {
            WinHttpReceiveResponse(request, std::ptr::null_mut()).map_err(|_| failed())
        })
        .and_then(|_| ensure_success_status(request))
        .and_then(|_| read_response(request, deadline));
    close(request);
    close(connection);
    close(session);
    result
}

fn set_remaining_timeouts(
    handle: *mut core::ffi::c_void,
    deadline: Instant,
) -> Result<(), AgentError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(network());
    }
    let timeout = remaining
        .as_millis()
        .min(CLAIM_OPERATION_TIMEOUT_MS as u128)
        .max(1) as i32;
    unsafe { WinHttpSetTimeouts(handle, timeout, timeout, timeout, timeout) }.map_err(|_| network())
}

fn ensure_success_status(request: *mut core::ffi::c_void) -> Result<(), AgentError> {
    let mut status = 0_u32;
    let mut length = std::mem::size_of::<u32>() as u32;
    unsafe {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            windows::core::PCWSTR::null(),
            Some((&mut status as *mut u32).cast()),
            &mut length,
            std::ptr::null_mut(),
        )
    }
    .map_err(|_| failed())?;
    (200..300)
        .contains(&status)
        .then_some(())
        .ok_or_else(failed)
}

fn read_response(request: *mut core::ffi::c_void, deadline: Instant) -> Result<Value, AgentError> {
    let mut bytes = Vec::new();
    loop {
        set_remaining_timeouts(request, deadline)?;
        let mut buffer = [0_u8; 4096];
        let mut read = 0;
        unsafe {
            WinHttpReadData(
                request,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
            )
        }
        .map_err(|_| failed())?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
        if bytes.len() > 65_536 {
            return Err(failed());
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| failed())
}

fn persist(payload: &Value) -> Result<(), AgentError> {
    for name in [
        "agent_id",
        "control_endpoint",
        "frame_endpoint",
        "hub_server_name",
        "profile_root_public_key_hex",
        "ca_pem",
        "client_cert_pem",
        "client_key_pem",
        "expires_at",
    ] {
        required(payload, name)?;
    }

    let root = PathBuf::from(STATE_ROOT);
    ensure_private_directory(&root)?;

    let generation = format!(
        "g-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failed())?
            .as_nanos()
    );
    let directory = root.join(&generation);
    create_private_directory(&directory)?;

    let temporary = root.join(format!("current-{generation}.tmp"));
    let result = (|| {
        // Credentials live only in their private files; runtime.json contains no PEM material.
        let runtime = json!({
            "agent_id": required(payload, "agent_id")?,
            "control_endpoint": required(payload, "control_endpoint")?,
            "frame_endpoint": required(payload, "frame_endpoint")?,
            "hub_server_name": required(payload, "hub_server_name")?,
            "profile_root_public_key_hex": required(payload, "profile_root_public_key_hex")?,
            "expires_at": required(payload, "expires_at")?,
        });
        write_private(
            &directory.join("runtime.json"),
            &serde_json::to_vec(&runtime).map_err(|_| failed())?,
        )?;
        for (field, file) in [
            ("ca_pem", "ca.pem"),
            ("client_cert_pem", "client-cert.pem"),
            ("client_key_pem", "client-key.pem"),
        ] {
            write_private(&directory.join(file), required(payload, field)?.as_bytes())?;
        }

        // ponytail: validate the complete candidate before changing the active pointer.
        crate::runtime::validate_enrollment_candidate(&root, &generation).map_err(|_| failed())?;
        write_private(
            &temporary,
            &serde_json::to_vec(&json!({"generation": generation})).map_err(|_| failed())?,
        )?;
        let pointer = root.join("current.json");
        unsafe {
            MoveFileExW(
                &HSTRING::from(temporary.to_string_lossy().as_ref()),
                &HSTRING::from(pointer.to_string_lossy().as_ref()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| failed())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

fn required<'a>(payload: &'a Value, name: &str) -> Result<&'a str, AgentError> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(failed)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    let mut file = open_private_file(path, GENERIC_WRITE.0, CREATE_NEW)?;
    file.write_all(bytes).map_err(|_| failed())?;
    file.sync_all().map_err(|_| failed())?;
    verify_private_file(path)
}

pub(crate) fn append_private(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    let mut file = open_private_file(path, FILE_APPEND_DATA.0, OPEN_ALWAYS)?;
    file.write_all(bytes).map_err(|_| failed())?;
    file.flush().map_err(|_| failed())?;
    verify_private_file(path)
}

pub(crate) fn open_private_read(path: &Path) -> Result<fs::File, AgentError> {
    open_private_file(path, GENERIC_READ.0, OPEN_EXISTING)
}

/// State roots are provisioned by the privileged installer. The running Agent
/// deliberately never creates this chain and repairs its ACL afterwards: that
/// pattern can follow a low-integrity junction during the creation window.
pub(crate) fn ensure_private_directory(path: &Path) -> Result<(), AgentError> {
    let enrollment = Path::new(STATE_ROOT);
    let audit = Path::new(AUDIT_ROOT);
    let logs = Path::new(LOG_ROOT);
    if path != enrollment && path != audit && path != logs {
        return Err(failed());
    }

    verify_nonreparse_directory(Path::new(r"C:\ProgramData"))?;
    verify_private_directory(Path::new(PRODUCT_STATE_ROOT))?;
    verify_private_directory(Path::new(STATE_PARENT))?;
    verify_private_directory(path)
}

fn verify_nonreparse_directory(path: &Path) -> Result<(), AgentError> {
    let metadata = path.symlink_metadata().map_err(|_| failed())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(failed());
    }
    let attributes = unsafe { GetFileAttributesW(&HSTRING::from(path.to_string_lossy().as_ref())) };
    if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(failed());
    }
    Ok(())
}

fn verify_private_directory(path: &Path) -> Result<(), AgentError> {
    verify_nonreparse_directory(path)?;
    private_security(path).then_some(()).ok_or_else(failed)
}

pub(crate) fn verify_private_file(path: &Path) -> Result<(), AgentError> {
    let metadata = path.symlink_metadata().map_err(|_| failed())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(failed());
    }
    let attributes = unsafe { GetFileAttributesW(&HSTRING::from(path.to_string_lossy().as_ref())) };
    if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(failed());
    }
    private_security(path).then_some(()).ok_or_else(failed)
}

fn private_security(path: &Path) -> bool {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    if status.0 != 0 {
        return false;
    }
    let mut text = PWSTR::null();
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    };
    let result = converted.is_ok()
        && unsafe { text.to_string() }
            .is_ok_and(|value| value == PRIVATE_SDDL || value == "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)");
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(text.0.cast()))) };
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result
}

fn create_private_directory(path: &Path) -> Result<(), AgentError> {
    with_private_security_attributes(|attributes| unsafe {
        CreateDirectoryW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            Some(attributes),
        )
        .map_err(|_| failed())
    })?;
    verify_private_directory(path)
}

fn open_private_file(
    path: &Path,
    access: u32,
    disposition: windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
) -> Result<fs::File, AgentError> {
    let handle = with_private_security_attributes(|attributes| unsafe {
        CreateFileW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(attributes),
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        .map_err(|_| failed())
    })?;
    // SAFETY: CreateFileW returned an owned handle and File assumes exactly that ownership.
    let file = unsafe { fs::File::from_raw_handle(handle.0) };
    verify_private_file(path)?;
    Ok(file)
}

fn with_private_security_attributes<T>(
    operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> Result<T, AgentError>,
) -> Result<T, AgentError> {
    let mut descriptor = Default::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(PRIVATE_SDDL),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|_| failed())?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let result = operation(&attributes);
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result
}

fn ensure_elevated() -> Result<(), AgentError> {
    let mut token = Default::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|_| failed())?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    result.map_err(|_| failed())?;
    (elevation.TokenIsElevated != 0)
        .then_some(())
        .ok_or_else(|| AgentError::new("enrollment.elevation_required", "elevated Agent required"))
}

fn close(handle: *mut core::ffi::c_void) {
    let _ = unsafe { WinHttpCloseHandle(handle) };
}

fn invalid() -> AgentError {
    AgentError::new(
        "enrollment.request_invalid",
        "registration request is invalid",
    )
}

fn network() -> AgentError {
    AgentError::new(
        "enrollment.network_failed",
        "registration service is unreachable",
    )
}

fn failed() -> AgentError {
    AgentError::new("enrollment.failed", "registration could not be completed")
}
