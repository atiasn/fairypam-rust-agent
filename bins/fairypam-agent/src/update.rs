//! Agent-side discovery handoff. The stable installer helper remains the only
//! component allowed to switch an installed suite.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v1::UpdateDirective;
use fairypam_agent_suite::{
    compare_versions, extract_update_package, resolve_active_suite, validate_update_package,
    validate_update_request, verify_authenticode_publisher, UpdateRequest,
};
use http::Uri;
use windows::core::HSTRING;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_FLAG_SECURE,
    WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};

const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(120);
const OPERATION_TIMEOUT_MS: i32 = 10_000;
pub(crate) const PENDING_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\updates\pending";
const SETTLING_PATH: &str = r"C:\ProgramData\FairyPam.Agent\Agent\updates\settling.json";
const LAST_RESULT_PATH: &str = r"C:\ProgramData\FairyPam.Agent\Agent\updates\last-result.json";

pub(crate) fn stage(
    agent_id: &str,
    directive: &UpdateDirective,
) -> Result<UpdateRequest, AgentError> {
    let install_root = install_root()?;
    let active = resolve_active_suite(&install_root).map_err(|_| invalid())?;
    let request = UpdateRequest {
        schema_version: 1,
        update_id: directive.update_id.clone(),
        source_build_id: active.pointer.build_id.clone(),
        target_build_id: directive.target_build_id.clone(),
        suite_version: directive.suite_version.clone(),
        artifact_sha256: directive.artifact_sha256.clone(),
        artifact_size: directive.artifact_size,
        manifest_sha256: directive.manifest_sha256.clone(),
    };
    validate_update_request(&request).map_err(|_| invalid())?;
    if compare_versions(&request.suite_version, &active.pointer.suite_version)
        .map_err(|_| invalid())?
        != std::cmp::Ordering::Greater
    {
        return Err(AgentError::new(
            "update.version_not_monotonic",
            "candidate suite version is not newer than the active version",
        ));
    }
    let artifact_uri = crate::update_contract::artifact_uri(
        &directive.artifact_url,
        agent_id,
        &directive.update_id,
    )?;
    validate_token(&directive.artifact_token)?;

    crate::enrollment::ensure_private_directory(Path::new(crate::enrollment::UPDATE_ROOT))?;
    let pending = PathBuf::from(PENDING_ROOT);
    if pending.symlink_metadata().is_ok() {
        return Err(AgentError::new(
            "update.pending_exists",
            "a previous update handoff still requires repair",
        ));
    }
    fs::create_dir(&pending).map_err(|_| failed())?;
    let result = (|| {
        let package = pending.join("candidate.zip");
        download(
            &artifact_uri,
            &directive.artifact_token,
            &package,
            directive.artifact_size,
        )?;
        let verified = validate_update_package(
            &package,
            &directive.artifact_sha256,
            directive.artifact_size,
            &directive.target_build_id,
            &directive.manifest_sha256,
        )
        .map_err(|_| invalid())?;
        if verified.manifest.suite_version != directive.suite_version {
            return Err(invalid());
        }
        let extracted = pending.join("prevalidated");
        extract_update_package(&package, &install_root, &extracted, &verified)
            .map_err(|_| invalid())?;
        verify_authenticode_publisher(
            &install_root,
            &extracted,
            &verified.manifest,
            option_env!("FAIRYPAM_UPDATE_PUBLISHER").unwrap_or(""),
            option_env!("FAIRYPAM_UPDATE_CERT_THUMBPRINT").unwrap_or(""),
        )
        .map_err(|_| {
            AgentError::new(
                "update.authenticode_invalid",
                "candidate signature or publisher is invalid",
            )
        })?;
        write_new(
            &pending.join("staged.json"),
            &serde_json::to_vec(&request).map_err(|_| failed())?,
        )?;
        Ok(request.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&pending);
    }
    result
}

pub(crate) fn authorize_activation(request: &UpdateRequest) -> Result<(), AgentError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let pending = Path::new(PENDING_ROOT);
    let staged = pending.join("staged.json");
    let activation = pending.join("request.json");
    let bytes = fs::read(&staged).map_err(|_| failed())?;
    let persisted: UpdateRequest = serde_json::from_slice(&bytes).map_err(|_| failed())?;
    if &persisted != request || activation.symlink_metadata().is_ok() {
        return Err(failed());
    }
    let source = staged
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = activation
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| failed())
}

pub(crate) fn abort_staged(request: &UpdateRequest) -> Result<(), AgentError> {
    let pending = Path::new(PENDING_ROOT);
    let staged = pending.join("staged.json");
    let activation = pending.join("request.json");
    let bytes = fs::read(&staged).map_err(|_| failed())?;
    let persisted: UpdateRequest = serde_json::from_slice(&bytes).map_err(|_| failed())?;
    if &persisted != request || activation.symlink_metadata().is_ok() {
        return Err(failed());
    }
    fs::remove_dir_all(pending).map_err(|_| failed())
}

pub(crate) async fn wait_for_settlement() -> Result<(), AgentError> {
    for _ in 0..120 {
        match Path::new(SETTLING_PATH).symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            _ => return Err(failed()),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(AgentError::new(
        "update.settlement_timeout",
        "installer helper did not finalize the update transaction",
    ))
}

pub(crate) fn last_result() -> (String, String, String, String) {
    let Ok(bytes) = fs::read(LAST_RESULT_PATH) else {
        return Default::default();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Default::default();
    };
    (
        value["update_id"].as_str().unwrap_or("").to_owned(),
        value["target_build_id"].as_str().unwrap_or("").to_owned(),
        value["state"].as_str().unwrap_or("").to_owned(),
        value["rollback"].as_str().unwrap_or("").to_owned(),
    )
}

fn install_root() -> Result<PathBuf, AgentError> {
    let executable = std::env::current_exe().map_err(|_| invalid())?;
    let version_root = executable.parent().ok_or_else(invalid)?;
    let versions = version_root.parent().ok_or_else(invalid)?;
    if versions.file_name().and_then(|name| name.to_str()) != Some("versions") {
        return Err(invalid());
    }
    versions.parent().map(Path::to_path_buf).ok_or_else(invalid)
}

fn validate_token(token: &str) -> Result<(), AgentError> {
    if !(32..=256).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid());
    }
    Ok(())
}

fn download(
    endpoint: &Uri,
    token: &str,
    destination: &Path,
    expected_size: u64,
) -> Result<(), AgentError> {
    let authority = endpoint.authority().ok_or_else(invalid)?;
    let path = endpoint.path_and_query().ok_or_else(invalid)?.as_str();
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(443);
    let deadline = Instant::now() + DOWNLOAD_DEADLINE;
    let session = unsafe {
        WinHttpOpen(
            &HSTRING::from("FairyPam Agent update"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            &HSTRING::new(),
            &HSTRING::new(),
            0,
        )
    };
    if session.is_null() {
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
            &HSTRING::from("GET"),
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
    if let Err(error) = disable_redirects(request) {
        close(request);
        close(connection);
        close(session);
        return Err(error);
    }
    let headers = format!("X-FairyPam-Update-Token: {token}\r\n")
        .encode_utf16()
        .collect::<Vec<_>>();
    let result = (|| {
        set_timeout(request, deadline)?;
        unsafe { WinHttpSendRequest(request, Some(&headers), None, 0, 0, 0) }
            .map_err(|_| network())?;
        set_timeout(request, deadline)?;
        unsafe { WinHttpReceiveResponse(request, std::ptr::null_mut()) }.map_err(|_| network())?;
        ensure_success(request)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|_| failed())?;
        let mut total = 0_u64;
        loop {
            set_timeout(request, deadline)?;
            let mut buffer = [0_u8; 64 * 1024];
            let mut read = 0;
            unsafe {
                WinHttpReadData(
                    request,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut read,
                )
            }
            .map_err(|_| network())?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(u64::from(read));
            if total > expected_size {
                return Err(invalid());
            }
            file.write_all(&buffer[..read as usize])
                .map_err(|_| failed())?;
        }
        if total != expected_size {
            return Err(invalid());
        }
        file.sync_all().map_err(|_| failed())
    })();
    close(request);
    close(connection);
    close(session);
    result
}

fn disable_redirects(request: *mut core::ffi::c_void) -> Result<(), AgentError> {
    let policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_ne_bytes();
    unsafe {
        WinHttpSetOption(
            Some(request.cast_const()),
            WINHTTP_OPTION_REDIRECT_POLICY,
            Some(&policy),
        )
    }
    .map_err(|_| network())
}

fn set_timeout(handle: *mut core::ffi::c_void, deadline: Instant) -> Result<(), AgentError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(network());
    }
    let timeout = remaining
        .as_millis()
        .min(OPERATION_TIMEOUT_MS as u128)
        .max(1) as i32;
    unsafe { WinHttpSetTimeouts(handle, timeout, timeout, timeout, timeout) }.map_err(|_| network())
}

fn ensure_success(request: *mut core::ffi::c_void) -> Result<(), AgentError> {
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
    .map_err(|_| network())?;
    (status == 200).then_some(()).ok_or_else(network)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| failed())?;
    file.write_all(bytes).map_err(|_| failed())?;
    file.sync_all().map_err(|_| failed())
}

fn close(handle: *mut core::ffi::c_void) {
    if !handle.is_null() {
        let _ = unsafe { WinHttpCloseHandle(handle) };
    }
}

fn invalid() -> AgentError {
    AgentError::new("update.invalid", "update directive or artifact is invalid")
}

fn failed() -> AgentError {
    AgentError::new("update.stage_failed", "update staging failed")
}

fn network() -> AgentError {
    AgentError::new("update.download_failed", "update artifact download failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Networking::WinHttp::WinHttpQueryOption;

    #[test]
    fn update_request_disables_redirects() {
        let session = unsafe {
            WinHttpOpen(
                &HSTRING::from("FairyPam Agent update test"),
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                &HSTRING::new(),
                &HSTRING::new(),
                0,
            )
        };
        assert!(!session.is_null());
        let connection =
            unsafe { WinHttpConnect(session, &HSTRING::from("updates.example.test"), 443, 0) };
        assert!(!connection.is_null());
        let request = unsafe {
            WinHttpOpenRequest(
                connection,
                &HSTRING::from("GET"),
                &HSTRING::from("/artifact"),
                &HSTRING::new(),
                &HSTRING::new(),
                std::ptr::null(),
                WINHTTP_FLAG_SECURE,
            )
        };
        assert!(!request.is_null());
        disable_redirects(request).unwrap();

        let mut policy = u32::MAX;
        let mut length = std::mem::size_of::<u32>() as u32;
        unsafe {
            WinHttpQueryOption(
                request,
                WINHTTP_OPTION_REDIRECT_POLICY,
                Some((&mut policy as *mut u32).cast()),
                &mut length,
            )
        }
        .unwrap();
        assert_eq!(policy, WINHTTP_OPTION_REDIRECT_POLICY_NEVER);
        close(request);
        close(connection);
        close(session);
    }
}
