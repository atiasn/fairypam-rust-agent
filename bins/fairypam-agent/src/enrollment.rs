//! Elevated Agent-side enrollment. Registration material is accepted only from
//! the authenticated local pipe and is never included in an error or log.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::AgentError;
use fairypam_agent_local_protocol::validate_registration_request;
use http::Uri;
use serde_json::{json, Value};
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HLOCAL};
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
    GetTokenInformation, SetFileSecurityW, TokenElevation, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
};

const STATE_ROOT: &str = r"C:\ProgramData\FairyPam\Agent\enrollment";
const STATE_PARENT: &str = r"C:\ProgramData\FairyPam\Agent";
const AUDIT_ROOT: &str = r"C:\ProgramData\FairyPam\Agent\audit";
const LOG_ROOT: &str = r"C:\ProgramData\FairyPam\Agent\logs";
const PRIVATE_DACL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
const CLAIM_DEADLINE: Duration = Duration::from_secs(15);
const CLAIM_OPERATION_TIMEOUT_MS: i32 = 5_000;
const REPLACEMENT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(8);

/// The Agent owns the whole enrollment transaction: the trusted elevated
/// confirmation always happens before the Hub receives the one-time code.
pub fn register_with_confirmation(
    hub_address: &str,
    registration_code: &str,
    replaces_existing_registration: bool,
) -> Result<(), AgentError> {
    validate_registration_request(hub_address, registration_code).map_err(|_| invalid())?;
    // The confirmation itself is part of the security boundary. Do not let a
    // medium-integrity fallback process obtain apparent user consent.
    ensure_elevated()?;
    let deadline = Instant::now() + CLAIM_DEADLINE;
    confirm_registration(hub_address, replaces_existing_registration, deadline)?;
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

fn confirm_registration(
    hub_address: &str,
    replaces_existing_registration: bool,
    deadline: Instant,
) -> Result<(), AgentError> {
    let uri = hub_address.parse::<Uri>().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    let host = match authority.port_u16() {
        Some(port) => format!("{}:{port}", authority.host()),
        None => authority.host().to_owned(),
    };
    let message = if replaces_existing_registration {
        format!(
            "FairyPam Agent 已经注册。\n\n是否重新注册到 Hub：\n{host}\n\n此操作将替换当前证书和信任配置。"
        )
    } else {
        format!("是否将 FairyPam Agent 注册到 Hub：\n{host}\n\n只有确认后才会使用一次性注册码。")
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = unsafe {
            MessageBoxW(
                None,
                &HSTRING::from(message),
                &HSTRING::from("FairyPam 重新注册确认"),
                MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
            )
        };
        let _ = sender.send(result == IDYES);
    });
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .min(REPLACEMENT_CONFIRMATION_TIMEOUT);
    if receiver
        .recv_timeout(timeout)
        .is_ok_and(|accepted| accepted)
    {
        return Ok(());
    }
    Err(AgentError::new(
        "enrollment.replacement_cancelled",
        "Hub registration replacement was not authorized",
    ))
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
    fs::create_dir(&directory).map_err(|_| failed())?;
    if let Err(error) = restrict_path(&directory) {
        let _ = fs::remove_dir(&directory);
        return Err(error);
    }

    let temporary = root.join("current.json.tmp");
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
    fs::write(path, bytes).map_err(|_| failed())?;
    restrict_path(path)
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
    verify_private_directory(Path::new(r"C:\ProgramData\FairyPam"))?;
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
    private_dacl(path).then_some(()).ok_or_else(failed)
}

fn private_dacl(path: &Path) -> bool {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
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
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    };
    let result = converted.is_ok()
        && unsafe { text.to_string() }
            .is_ok_and(|value| value == PRIVATE_DACL || value == "D:P(A;;FA;;;BA)(A;;FA;;;SY)");
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(text.0.cast()))) };
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result
}

pub(crate) fn restrict_path(path: &Path) -> Result<(), AgentError> {
    let mut descriptor = Default::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|_| failed())?;
    let result = unsafe {
        SetFileSecurityW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
        .ok()
    };
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result.map_err(|_| failed())
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
