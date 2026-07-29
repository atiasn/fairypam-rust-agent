//! Elevated Agent-side enrollment. Registration material is accepted only from
//! the authenticated local pipe and is never included in an error or log.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fairypam_agent_core::AgentError;
use fairypam_agent_input::{
    ActionId, GuardianClient, GuardianProcessClient, PhysicalHold, ReleaseReason,
};
use fairypam_agent_transport::{
    certificate_sha256, cng_machine_rsa_public_key_der, create_cng_machine_key,
    delete_cng_machine_key, delete_local_machine_certificate, install_local_machine_certificate,
    prove_cng_machine_key_signature, sign_cng_machine_key_sha256, validate_cng_machine_key_policy,
};
use http::Uri;
use rcgen::{CertificateParams, DistinguishedName, DnType, PublicKeyData, SigningKey};
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
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TokenUser, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
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
    pub(crate) authorized_user_sid: String,
    pub(crate) certificate_sha256: String,
    pub(crate) control_endpoint: String,
    pub(crate) expires_at: String,
    pub(crate) frame_endpoint: String,
    pub(crate) hub_server_name: String,
    pub(crate) key_name: String,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingEnrollmentDocument {
    schema_version: u32,
    key_name: String,
    authorized_user_sid: String,
    certificate_sha256: Option<String>,
    generation: Option<String>,
}

struct PendingDeviceIdentity {
    root: PathBuf,
    key_name: String,
    authorized_user_sid: String,
    csr_pem: String,
    committed: bool,
}

impl PendingDeviceIdentity {
    fn update_journal(
        &self,
        certificate_sha256: Option<String>,
        generation: Option<String>,
    ) -> Result<(), AgentError> {
        replace_private_json(
            &self.root.join("pending.json"),
            &PendingEnrollmentDocument {
                schema_version: 1,
                key_name: self.key_name.clone(),
                authorized_user_sid: self.authorized_user_sid.clone(),
                certificate_sha256,
                generation,
            },
        )
    }

    fn install_certificate(
        &self,
        certificate_pem: &[u8],
        fingerprint: [u8; 32],
    ) -> Result<(), AgentError> {
        install_local_machine_certificate(certificate_pem, &self.key_name, &fingerprint)
            .map_err(|_| failed())?;
        Ok(())
    }

    fn commit(&mut self) {
        self.committed = true;
        let _ = fs::remove_file(self.root.join("pending.json"));
    }
}

struct CngCsrSigningKey {
    key_name: String,
    public_key_der: Vec<u8>,
}

impl PublicKeyData for CngCsrSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_der
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}

impl SigningKey for CngCsrSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        sign_cng_machine_key_sha256(&self.key_name, message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

impl Drop for PendingDeviceIdentity {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let _ = cleanup_pending_identity(&self.root);
    }
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
    cleanup_pending_identity(root)?;
    cleanup_retired_generations(root)?;
    let (host, port, path) = claim_target(hub_address)?;
    let mut identity = registration_identity(root)?;
    let payload = claim(
        &host,
        port,
        &path,
        registration_code,
        &identity.csr_pem,
        deadline,
    )?;
    persist(root, &payload, &mut identity)?;
    let _ = cleanup_retired_generations(root);
    Ok(())
}

fn registration_identity(root: &Path) -> Result<PendingDeviceIdentity, AgentError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failed())?
        .as_nanos();
    let key_name = format!("FairyPam.Agent.{}.{}", std::process::id(), nonce);
    let authorized_user_sid = current_user_sid()?;
    write_private(
        &root.join("pending.json"),
        &serde_json::to_vec(&PendingEnrollmentDocument {
            schema_version: 1,
            key_name: key_name.clone(),
            authorized_user_sid: authorized_user_sid.clone(),
            certificate_sha256: None,
            generation: None,
        })
        .map_err(|_| failed())?,
    )?;
    create_cng_machine_key(&key_name, &authorized_user_sid).map_err(|_| failed())?;
    let result = (|| {
        validate_cng_machine_key_policy(&key_name, &authorized_user_sid).map_err(|_| failed())?;
        prove_cng_machine_key_signature(&key_name).map_err(|_| failed())?;
        let signing_key = CngCsrSigningKey {
            public_key_der: cng_machine_rsa_public_key_der(&key_name).map_err(|_| failed())?,
            key_name: key_name.clone(),
        };
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "FairyPam Agent Enrollment");
        let csr_pem = params
            .serialize_request(&signing_key)
            .and_then(|csr| csr.pem())
            .map_err(|_| failed())?;
        if csr_pem.len() > 16 * 1024
            || !csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n")
            || !csr_pem.ends_with("-----END CERTIFICATE REQUEST-----\n")
            || csr_pem.contains('\r')
            || csr_pem.as_bytes().contains(&0)
        {
            return Err(failed());
        }
        validate_guardian_key_isolation(&key_name)?;
        Ok(csr_pem)
    })();
    match result {
        Ok(csr_pem) => Ok(PendingDeviceIdentity {
            root: root.to_owned(),
            key_name,
            authorized_user_sid,
            csr_pem,
            committed: false,
        }),
        Err(error) => {
            if delete_cng_machine_key(&key_name).is_ok() {
                let _ = fs::remove_file(root.join("pending.json"));
            }
            Err(error)
        }
    }
}

fn validate_guardian_key_isolation(key_name: &str) -> Result<(), AgentError> {
    let executable = std::env::current_exe().map_err(|_| failed())?;
    let guardian = executable
        .parent()
        .ok_or_else(failed)?
        .join("fairypam-agent-guardian.exe");
    fairypam_agent_suite::windows_security::verify_trusted_install_entry(&guardian, false)
        .map_err(|_| failed())?;
    let action = ActionId::new("enrollment.release_probe").map_err(|_| failed())?;
    let holds = BTreeMap::from([(
        action.clone(),
        PhysicalHold::ScanCode {
            action_id: action.clone(),
            scan_code: 17,
            extended: false,
        },
    )]);
    let mut client =
        GuardianProcessClient::spawn(&guardian, holds, Duration::from_secs(5), Some(key_name))
            .map_err(|_| failed())?;
    if client.isolation_status().is_none() {
        return Err(failed());
    }
    let registered = BTreeSet::from([action]);
    client
        .register_intent(1, &registered)
        .map_err(|_| failed())?;
    client.commit_holds(1, &registered).map_err(|_| failed())?;
    client
        .release_all(ReleaseReason::EmergencyStop)
        .map_err(|_| failed())
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
    identity: &mut PendingDeviceIdentity,
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
    let fingerprint =
        certificate_sha256(payload.client_cert_pem.as_bytes()).map_err(|_| failed())?;
    let fingerprint_hex = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let generation = format!(
        "g-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failed())?
            .as_nanos()
    );
    let directory = root.join(&generation);
    identity.update_journal(Some(fingerprint_hex.clone()), Some(generation.clone()))?;
    create_private_directory(&directory)?;

    let temporary = root.join(format!("current-{generation}.tmp"));
    let result = (|| {
        // Credentials live only in their private files; runtime.json contains no PEM material.
        let runtime = EnrollmentRuntimeDocument {
            agent_id: payload.agent_id.clone(),
            authorized_user_sid: identity.authorized_user_sid.clone(),
            certificate_sha256: fingerprint_hex,
            control_endpoint: payload.control_endpoint.clone(),
            expires_at: payload.expires_at.clone(),
            frame_endpoint: payload.frame_endpoint.clone(),
            hub_server_name: payload.hub_server_name.clone(),
            key_name: identity.key_name.clone(),
            profile_root_public_key_hex: payload.profile_root_public_key_hex.clone(),
        };
        write_private(
            &directory.join("runtime.json"),
            &serde_json::to_vec(&runtime).map_err(|_| failed())?,
        )?;
        for (contents, file) in [
            (payload.ca_pem.as_str(), "ca.pem"),
            (payload.client_cert_pem.as_str(), "client-cert.pem"),
        ] {
            write_private(&directory.join(file), contents.as_bytes())?;
        }

        crate::runtime::validate_enrollment_candidate_before_install(root, &generation)
            .map_err(|_| failed())?;
        identity.install_certificate(payload.client_cert_pem.as_bytes(), fingerprint)?;
        // ponytail: validate the installed association before changing the active pointer.
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
        identity.commit();
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

pub(crate) fn cleanup_pending_identity(root: &Path) -> Result<(), AgentError> {
    ensure_private_directory(root)?;
    let pending_path = root.join("pending.json");
    match pending_path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(failed()),
        Ok(_) => {}
    }
    let pending: PendingEnrollmentDocument = load_private_json(&pending_path)?;
    validate_pending_document(&pending)?;

    let active_generation = match root.join("current.json").symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(failed()),
        Ok(_) => {
            Some(load_private_json::<EnrollmentPointer>(&root.join("current.json"))?.generation)
        }
    };
    if let Some(active) = active_generation.as_deref() {
        if pending.generation.as_deref() == Some(active) {
            let runtime: EnrollmentRuntimeDocument =
                load_private_json(&root.join(active).join("runtime.json"))?;
            if pending.key_name == runtime.key_name
                && pending.certificate_sha256.as_deref()
                    == Some(runtime.certificate_sha256.as_str())
            {
                fs::remove_file(&pending_path).map_err(|_| failed())?;
                return Ok(());
            }
            return Err(failed());
        }
    }

    if let Some(value) = pending.certificate_sha256.as_deref() {
        delete_local_machine_certificate(&decode_fingerprint(value)?).map_err(|_| failed())?;
    }
    delete_cng_machine_key(&pending.key_name).map_err(|_| failed())?;
    if let Some(generation) = pending.generation.as_deref() {
        let directory = root.join(generation);
        match directory.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed()),
            Ok(_) => {
                verify_private_directory(&directory)?;
                fs::remove_dir_all(&directory).map_err(|_| failed())?;
            }
        }
    }
    fs::remove_file(&pending_path).map_err(|_| failed())
}

fn validate_pending_document(document: &PendingEnrollmentDocument) -> Result<(), AgentError> {
    let key_suffix = document
        .key_name
        .strip_prefix("FairyPam.Agent.")
        .unwrap_or_default();
    if document.schema_version != 1
        || key_suffix.is_empty()
        || document.key_name.len() > 128
        || !key_suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || !document.authorized_user_sid.starts_with("S-1-")
        || document.authorized_user_sid.len() > 184
        || document
            .certificate_sha256
            .as_deref()
            .is_some_and(|value| decode_fingerprint(value).is_err())
        || document
            .generation
            .as_deref()
            .is_some_and(|value| !valid_generation(value))
    {
        return Err(failed());
    }
    Ok(())
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
        let document: EnrollmentRuntimeDocument =
            load_private_json(&directory.join("runtime.json"))?;
        let fingerprint = decode_fingerprint(&document.certificate_sha256)?;
        delete_local_machine_certificate(&fingerprint).map_err(|_| failed())?;
        delete_cng_machine_key(&document.key_name).map_err(|_| failed())?;
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

pub(crate) fn decode_fingerprint(value: &str) -> Result<[u8; 32], AgentError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failed());
    }
    let mut fingerprint = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        fingerprint[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    Ok(fingerprint)
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

fn replace_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), AgentError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failed())?
        .as_nanos();
    let temporary = path.with_extension(format!("{nonce}.tmp"));
    write_private(
        &temporary,
        &serde_json::to_vec(value).map_err(|_| failed())?,
    )?;
    let result = unsafe {
        MoveFileExW(
            &HSTRING::from(temporary.to_string_lossy().as_ref()),
            &HSTRING::from(path.to_string_lossy().as_ref()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| failed());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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

fn current_user_sid() -> Result<String, AgentError> {
    let mut token = Default::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|_| failed())?;
    let result = (|| {
        let mut length = 0_u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut length) };
        if length < std::mem::size_of::<TOKEN_USER>() as u32 {
            return Err(failed());
        }
        let mut buffer = vec![0_u8; length as usize];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                length,
                &mut length,
            )
        }
        .map_err(|_| failed())?;
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(|_| failed())?;
        let sid = unsafe { text.to_string() };
        let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(text.0.cast()))) };
        let sid = sid.map_err(|_| failed())?;
        if !sid.starts_with("S-1-") || sid.len() > 184 {
            return Err(failed());
        }
        Ok(sid)
    })();
    let _ = unsafe { CloseHandle(token) };
    result
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

    use super::{
        claim_body, decode_fingerprint, private_sddl_matches, valid_generation, EnrollmentResponse,
    };

    #[cfg(windows)]
    #[test]
    fn cng_machine_key_policy_survives_reopen_and_can_sign() {
        let key_name = format!(
            "FairyPam.Agent.test.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let sid = super::current_user_sid().unwrap();
        fairypam_agent_transport::create_cng_machine_key(&key_name, &sid).unwrap();
        let result = (|| {
            fairypam_agent_transport::validate_cng_machine_key_policy(&key_name, &sid)?;
            fairypam_agent_transport::prove_cng_machine_key_signature(&key_name)
        })();
        let cleanup = fairypam_agent_transport::delete_cng_machine_key(&key_name);
        result.unwrap();
        cleanup.unwrap();
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
        assert!(decode_fingerprint(&"ab".repeat(32)).is_ok());
        assert!(decode_fingerprint(&"AB".repeat(32)).is_err());
    }
}
