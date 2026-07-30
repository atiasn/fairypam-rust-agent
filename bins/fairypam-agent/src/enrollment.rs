//! Elevated Agent-side enrollment. Registration material is accepted only from
//! the authenticated local pipe and is never included in an error or log.

use std::fs;
use std::io::{Read, Write};
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fairypam_agent_core::AgentError;
use http::Uri;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, RsaKeySize, PKCS_RSA_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;
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
use zeroize::Zeroizing;

pub(crate) const PRODUCT_STATE_ROOT: &str = r"C:\ProgramData\FairyPam.Agent";
pub(crate) const STATE_PARENT: &str = r"C:\ProgramData\FairyPam.Agent\Agent";
pub(crate) const STATE_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\enrollment";
pub(crate) const AUDIT_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\audit";
pub(crate) const LOG_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\logs";
pub(crate) const UPDATE_ROOT: &str = r"C:\ProgramData\FairyPam.Agent\Agent\updates";
const PRIVATE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const PRIVATE_KEY_BEGIN: &str = concat!("-----BEGIN ", "PRIVATE KEY-----\n");
const PRIVATE_KEY_END: &str = concat!("-----END ", "PRIVATE KEY-----\n");
const CLAIM_DEADLINE: Duration = Duration::from_secs(15);
const CLAIM_OPERATION_TIMEOUT_MS: i32 = 5_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentResponse {
    agent_id: String,
    control_endpoint: String,
    frame_endpoint: String,
    hub_server_name: String,
    profile_root_public_key_hex: String,
    ca_pem: String,
    client_cert_pem: String,
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentRuntimeDocument {
    pub(crate) agent_id: String,
    pub(crate) control_endpoint: String,
    pub(crate) expires_at: String,
    pub(crate) frame_endpoint: String,
    pub(crate) hub_server_name: String,
    pub(crate) profile_root_public_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentPointer {
    generation: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapDocument {
    enrollment_base_url: String,
    schema_version: u32,
}

struct PendingDeviceIdentity {
    csr_pem: String,
    key_pem: Zeroizing<String>,
}
/// The elevated Agent claims the one-time code after the protected Pipe has
/// authenticated the GUI caller. No desktop confirmation is required.
pub fn register(registration_code: &str) -> Result<(), AgentError> {
    register_at_signed(Path::new(STATE_ROOT), registration_code)
}

pub(crate) fn register_at_signed(root: &Path, registration_code: &str) -> Result<(), AgentError> {
    let hub_address = bootstrap_enrollment_base_url()?;
    register_at(root, &hub_address, registration_code)
}

pub(crate) fn register_at(
    root: &Path,
    hub_address: &str,
    registration_code: &str,
) -> Result<(), AgentError> {
    validate_registration_request(hub_address, registration_code)?;
    ensure_elevated()?;
    let deadline = Instant::now() + CLAIM_DEADLINE;
    register_before(root, hub_address, registration_code, deadline)
}

fn validate_registration_request(
    hub_address: &str,
    registration_code: &str,
) -> Result<(), AgentError> {
    let valid_hub = valid_hub_address(hub_address);
    let valid_code = (16..=256).contains(&registration_code.len())
        && registration_code
            .bytes()
            .all(|byte| byte.is_ascii_graphic());
    if valid_hub && valid_code {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn valid_hub_address(hub_address: &str) -> bool {
    let uri = hub_address.parse::<Uri>().ok();
    hub_address.len() <= 2_048
        && uri.as_ref().is_some_and(|uri| {
            uri.scheme_str()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
                && uri.authority().is_some_and(|authority| {
                    !authority.as_str().contains('@')
                        && !authority.host().is_empty()
                        && authority.port_u16() != Some(0)
                        && !has_unparseable_explicit_port(authority)
                })
                && uri.query().is_none()
        })
}

pub(crate) fn bootstrap_enrollment_base_url() -> Result<String, AgentError> {
    let executable = std::env::current_exe().map_err(|_| bootstrap_invalid())?;
    let directory = executable.parent().ok_or_else(bootstrap_invalid)?;
    let document_path = directory.join("agent-bootstrap.json");
    let signature_path = directory.join("agent-bootstrap.json.sig");
    fairypam_agent_suite::windows_security::verify_trusted_install_entry(&document_path, false)
        .map_err(|_| bootstrap_invalid())?;
    fairypam_agent_suite::windows_security::verify_trusted_install_entry(&signature_path, false)
        .map_err(|_| bootstrap_invalid())?;
    let document_bytes = fs::read(&document_path).map_err(|_| bootstrap_invalid())?;
    if document_bytes.len() > 16 * 1024
        || document_bytes.last() != Some(&b'\n')
        || document_bytes[..document_bytes.len().saturating_sub(1)]
            .iter()
            .any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Err(bootstrap_invalid());
    }
    let document: BootstrapDocument =
        serde_json::from_slice(&document_bytes[..document_bytes.len() - 1])
            .map_err(|_| bootstrap_invalid())?;
    let canonical = serde_json::to_vec(&document).map_err(|_| bootstrap_invalid())?;
    if canonical != document_bytes[..document_bytes.len() - 1]
        || document.schema_version != 1
        || !valid_hub_address(&document.enrollment_base_url)
    {
        return Err(bootstrap_invalid());
    }
    let signature_bytes = fs::read(&signature_path).map_err(|_| bootstrap_invalid())?;
    if signature_bytes.len() != 129 || signature_bytes.last() != Some(&b'\n') {
        return Err(bootstrap_invalid());
    }
    let signature = decode_lower_hex::<64>(&signature_bytes[..128])?;
    let public_key = decode_lower_hex::<32>(
        option_env!("FAIRYPAM_BOOTSTRAP_PUBLIC_KEY_HEX")
            .ok_or_else(bootstrap_invalid)?
            .as_bytes(),
    )?;
    let verifier = VerifyingKey::from_bytes(&public_key).map_err(|_| bootstrap_invalid())?;
    verifier
        .verify(
            &sha2::Sha256::digest(&canonical),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| bootstrap_invalid())?;
    Ok(document.enrollment_base_url)
}

fn decode_lower_hex<const N: usize>(value: &[u8]) -> Result<[u8; N], AgentError> {
    if value.len() != N * 2
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(bootstrap_invalid());
    }
    let mut decoded = [0_u8; N];
    for (index, chunk) in value.chunks_exact(2).enumerate() {
        decoded[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| bootstrap_invalid())?,
            16,
        )
        .map_err(|_| bootstrap_invalid())?;
    }
    Ok(decoded)
}

fn has_unparseable_explicit_port(authority: &http::uri::Authority) -> bool {
    let value = authority.as_str();
    let has_explicit_port = if value.starts_with('[') {
        value
            .rsplit_once(']')
            .is_some_and(|(_, suffix)| !suffix.is_empty())
    } else {
        value.contains(':')
    };
    has_explicit_port && authority.port().is_none()
}

fn register_before(
    root: &Path,
    hub_address: &str,
    registration_code: &str,
    deadline: Instant,
) -> Result<(), AgentError> {
    ensure_private_directory(root)?;
    cleanup_retired_generations(root)?;
    let (host, port, path) = claim_target(hub_address)?;
    let identity = registration_identity()?;
    let payload = claim(
        &host,
        port,
        &path,
        registration_code,
        &identity.csr_pem,
        deadline,
    )?;
    persist(root, &payload, &identity)?;
    let _ = cleanup_retired_generations(root);
    Ok(())
}

fn registration_identity() -> Result<PendingDeviceIdentity, AgentError> {
    let key =
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).map_err(|_| failed())?;
    let key_pem = Zeroizing::new(key.serialize_pem());
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "FairyPam Agent Enrollment");
    let csr_pem = params
        .serialize_request(&key)
        .and_then(|csr| csr.pem())
        .map_err(|_| failed())?;
    if csr_pem.len() > 16 * 1024
        || !csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n")
        || !csr_pem.ends_with("-----END CERTIFICATE REQUEST-----\n")
        || csr_pem.contains('\r')
        || csr_pem.as_bytes().contains(&0)
        || key_pem.len() > 16 * 1024
        || !key_pem.starts_with(PRIVATE_KEY_BEGIN)
        || !key_pem.ends_with(PRIVATE_KEY_END)
    {
        return Err(failed());
    }
    Ok(PendingDeviceIdentity { csr_pem, key_pem })
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
    csr_pem: &str,
    deadline: Instant,
) -> Result<EnrollmentResponse, AgentError> {
    let body = claim_body(code, csr_pem)?;
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

fn claim_body(code: &str, csr_pem: &str) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    serde_json::to_vec(&json!({"code": code, "csr_pem": csr_pem}))
        .map(Zeroizing::new)
        .map_err(|_| failed())
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

fn read_response(
    request: *mut core::ffi::c_void,
    deadline: Instant,
) -> Result<EnrollmentResponse, AgentError> {
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

fn persist(
    root: &Path,
    payload: &EnrollmentResponse,
    identity: &PendingDeviceIdentity,
) -> Result<(), AgentError> {
    if [
        payload.agent_id.as_str(),
        payload.control_endpoint.as_str(),
        payload.frame_endpoint.as_str(),
        payload.hub_server_name.as_str(),
        payload.profile_root_public_key_hex.as_str(),
        payload.ca_pem.as_str(),
        payload.client_cert_pem.as_str(),
        payload.expires_at.as_str(),
    ]
    .into_iter()
    .any(str::is_empty)
    {
        return Err(failed());
    }
    ensure_private_directory(root)?;
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
        let runtime = EnrollmentRuntimeDocument {
            agent_id: payload.agent_id.clone(),
            control_endpoint: payload.control_endpoint.clone(),
            expires_at: payload.expires_at.clone(),
            frame_endpoint: payload.frame_endpoint.clone(),
            hub_server_name: payload.hub_server_name.clone(),
            profile_root_public_key_hex: payload.profile_root_public_key_hex.clone(),
        };
        write_private(
            &directory.join("runtime.json"),
            &serde_json::to_vec(&runtime).map_err(|_| failed())?,
        )?;
        for (contents, file) in [
            (payload.ca_pem.as_str(), "ca.pem"),
            (payload.client_cert_pem.as_str(), "client-cert.pem"),
            (identity.key_pem.as_str(), "client-key.pem"),
        ] {
            write_private(&directory.join(file), contents.as_bytes())?;
        }

        // ponytail: validate the complete candidate before changing the active pointer.
        crate::runtime::validate_enrollment_candidate(root, &generation).map_err(|_| failed())?;
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
        fs::remove_dir_all(&directory).map_err(|_| failed())?;
    }
    result
}

pub(crate) fn cleanup_retired_generations(root: &Path) -> Result<(), AgentError> {
    ensure_private_directory(root)?;
    let pointer_path = root.join("current.json");
    let active = match pointer_path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(failed()),
        Ok(_) => Some(load_private_json::<EnrollmentPointer>(&pointer_path)?.generation),
    };
    for entry in fs::read_dir(root).map_err(|_| failed())? {
        let entry = entry.map_err(|_| failed())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !valid_generation(name) || active.as_deref() == Some(name) {
            continue;
        }
        let directory = entry.path();
        verify_private_directory(&directory)?;
        fs::remove_dir_all(&directory).map_err(|_| failed())?;
    }
    Ok(())
}

fn load_private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, AgentError> {
    let mut bytes = Vec::new();
    open_private_read(path)?
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failed())?;
    if bytes.len() > 128 * 1024 {
        return Err(failed());
    }
    serde_json::from_slice(&bytes).map_err(|_| failed())
}

pub(crate) fn valid_generation(value: &str) -> bool {
    value.starts_with("g-")
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
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
    let updates = Path::new(UPDATE_ROOT);
    if path != enrollment && path != audit && path != logs && path != updates {
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
        && unsafe { text.to_string() }.is_ok_and(|value| private_sddl_matches(&value));
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(text.0.cast()))) };
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result
}

fn private_sddl_matches(value: &str) -> bool {
    matches!(
        value,
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
            | "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)"
            | "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)"
            | "O:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)"
    )
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

fn bootstrap_invalid() -> AgentError {
    AgentError::new(
        "enrollment.bootstrap_invalid",
        "signed enrollment bootstrap is unavailable or invalid",
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

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{claim_body, private_sddl_matches, valid_generation, EnrollmentResponse};

    #[cfg(windows)]
    #[test]
    fn enrollment_identity_generates_local_rsa_pem() {
        let identity = super::registration_identity().unwrap();

        assert!(identity
            .csr_pem
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
        assert!(identity.key_pem.starts_with(super::PRIVATE_KEY_BEGIN));
        assert!(!identity.csr_pem.contains(identity.key_pem.as_str()));
    }

    #[test]
    fn enrollment_claim_sends_the_csr_without_a_private_key() {
        let body = claim_body("fp_enroll_test", "test-csr").unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload["code"], "fp_enroll_test");
        assert_eq!(payload["csr_pem"], "test-csr");
        assert_eq!(payload.as_object().unwrap().len(), 2);
        assert!(payload.get("client_key_pem").is_none());
    }

    #[test]
    fn enrollment_response_rejects_private_or_unknown_fields() {
        let response = r#"{"agent_id":"11111111-1111-1111-1111-111111111111","control_endpoint":"https://hub.example:50051","frame_endpoint":"https://hub.example:50052","hub_server_name":"hub.example","profile_root_public_key_hex":"1111111111111111111111111111111111111111111111111111111111111111","ca_pem":"ca","client_cert_pem":"cert","expires_at":"2999-01-01T00:00:00Z"}"#;
        assert!(serde_json::from_str::<EnrollmentResponse>(response).is_ok());
        assert!(
            serde_json::from_str::<EnrollmentResponse>(&response.replace(
                "\"expires_at\":",
                "\"client_key_pem\":\"forbidden\",\"expires_at\":",
            ))
            .is_err()
        );
    }

    #[test]
    fn private_sddl_accepts_windows_auto_inherited_marker_without_inherited_aces() {
        assert!(private_sddl_matches("O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)"));
        assert!(!private_sddl_matches("O:BAD:PAI(A;ID;FA;;;SY)(A;;FA;;;BA)"));
        assert!(!private_sddl_matches(
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"
        ));
        assert!(!private_sddl_matches("O:BAD:AI(A;;FA;;;SY)(A;;FA;;;BA)"));
    }

    #[test]
    fn retired_cleanup_identifiers_are_bounded_and_exact() {
        assert!(valid_generation("g-123-456"));
        assert!(!valid_generation("../g-123"));
        assert!(!valid_generation("request-123"));
    }
}
