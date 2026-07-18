use std::collections::VecDeque;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(windows)]
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use fairypam_agent_suite::{
    authenticode_publisher, verify_authenticode_suite, verify_protected_windows_path,
    windows_powershell, SuiteManifest,
};
use fairypam_agent_suite::{sha256_bytes, ProductionSecurityPolicy};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{LocalFree, HLOCAL};
#[cfg(windows)]
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
#[cfg(windows)]
use windows::Win32::Security::{LookupAccountNameW, SidTypeUser, PSID, SID_NAME_USE};
#[cfg(windows)]
use windows::Win32::System::Com::CoTaskMemFree;
#[cfg(windows)]
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSDomainName, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
    WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS,
};
#[cfg(windows)]
use windows::Win32::System::Threading::GetCurrentProcessId;
#[cfg(windows)]
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
    KF_FLAG_DEFAULT,
};

const PAYLOAD_MARKER_PREFIX: &[u8] = b"FAIRYPAM-SUITE-";
const PAYLOAD_MARKER_SUFFIX: &[u8] = b"PAYLOAD1";
const PAYLOAD_MARKER_LEN: usize = PAYLOAD_MARKER_PREFIX.len() + PAYLOAD_MARKER_SUFFIX.len();
const PAYLOAD_DIGEST_PREFIX: &[u8] = b"FAIRYPAM-SUITE-PAYLOAD-SHA256:";
#[used]
static EMBEDDED_PAYLOAD_DIGEST: [u8; 94] =
    *b"FAIRYPAM-SUITE-PAYLOAD-SHA256:0000000000000000000000000000000000000000000000000000000000000000";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("installer.failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    BootstrapInstall,
    Maintenance {
        mode: String,
        preserve_user_data: bool,
    },
}

fn parse_invocation(arguments: Vec<String>) -> Result<Invocation, String> {
    if arguments.is_empty() {
        return Ok(Invocation::BootstrapInstall);
    }

    let mut arguments = VecDeque::from(arguments);
    let mode = pop(&mut arguments)?;
    if !matches!(mode.as_str(), "repair" | "uninstall") {
        return Err(usage().into());
    }
    let preserve_user_data = match arguments.pop_front().as_deref() {
        None => true,
        Some("--remove-user-data") if mode == "uninstall" && arguments.is_empty() => false,
        _ => return Err(usage().into()),
    };
    Ok(Invocation::Maintenance {
        mode,
        preserve_user_data,
    })
}

#[cfg(windows)]
fn run(arguments: Vec<String>) -> Result<(), String> {
    match parse_invocation(arguments)? {
        Invocation::BootstrapInstall => bootstrap_install(),
        Invocation::Maintenance {
            mode,
            preserve_user_data,
        } => run_installed_maintenance(&mode, preserve_user_data),
    }
}

#[cfg(windows)]
fn run_installed_maintenance(mode: &str, preserve_user_data: bool) -> Result<(), String> {
    let roots = known_folders()?;
    let source = roots.program_files.join("FairyPam/Agent/active");
    let data_root = roots.program_data.join("FairyPam/Agent");
    let policy_path = data_root.join("security-policy.json");
    let state_path = data_root.join("install-state.json");
    for path in [&source, &policy_path, &state_path] {
        verify_protected_windows_path(path).map_err(|error| error.to_string())?;
    }
    let expected_setup = fs::canonicalize(source.join("FairyPamAgentSetup.exe"))
        .map_err(|error| error.to_string())?;
    let running_setup =
        fs::canonicalize(std::env::current_exe().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if running_setup != expected_setup {
        return Err("maintenance must run from the protected installed setup".into());
    }

    let suite = SuiteManifest::load_and_verify(&source).map_err(|error| error.to_string())?;
    let policy_bytes = fs::read(&policy_path).map_err(|error| error.to_string())?;
    let state_bytes = fs::read(&state_path).map_err(|error| error.to_string())?;
    let state = parse_installed_state(&state_bytes)?;
    if state.build_id != suite.manifest.build_id
        || state.suite_version != suite.manifest.suite_version
        || state.manifest_sha256 != suite.manifest_sha256
        || state.security_policy_sha256 != sha256_bytes(&policy_bytes)
    {
        return Err("protected installed state does not match the active suite".into());
    }
    run_transaction(
        mode,
        &source,
        &policy_path,
        &state.authorized_user_sid,
        preserve_user_data,
    )
}

#[derive(Debug, PartialEq, Eq)]
struct InstalledState {
    build_id: String,
    suite_version: String,
    manifest_sha256: String,
    security_policy_sha256: String,
    authorized_user_sid: String,
}

fn parse_installed_state(bytes: &[u8]) -> Result<InstalledState, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("installed state is invalid: {error}"))?;
    let object = value
        .as_object()
        .filter(|value| {
            value.len() == 6
                && value.get("schema_version") == Some(&serde_json::json!(1))
                && [
                    "build_id",
                    "suite_version",
                    "manifest_sha256",
                    "security_policy_sha256",
                    "authorized_user_sid",
                ]
                .iter()
                .all(|field| value.contains_key(*field))
        })
        .ok_or_else(|| "installed state fields are not exact".to_owned())?;
    let string = |name: &str| {
        object[name]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("installed state {name} is invalid"))
    };
    let state = InstalledState {
        build_id: string("build_id")?,
        suite_version: string("suite_version")?,
        manifest_sha256: string("manifest_sha256")?,
        security_policy_sha256: string("security_policy_sha256")?,
        authorized_user_sid: string("authorized_user_sid")?,
    };
    if !valid_sha256(&state.manifest_sha256) || !valid_sha256(&state.security_policy_sha256) {
        return Err("installed state digest is invalid".into());
    }
    validate_sid(&state.authorized_user_sid)?;
    Ok(state)
}

#[cfg(windows)]
fn bootstrap_install() -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let workspace = create_workspace()?;
    let result = (|| {
        let publisher = authenticode_publisher(&executable).map_err(|error| error.to_string())?;
        let archive = workspace.join("suite.zip");
        write_embedded_payload(&executable, &archive)?;
        let payload_root = workspace.join("payload");
        let status = Command::new(windows_powershell().map_err(|error| error.to_string())?)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force",
                text(&archive)?,
                text(&payload_root)?,
            ])
            .stdin(Stdio::null())
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!("embedded suite extraction exited with {status}"));
        }
        let source = payload_root.join("suite");
        let policy_path = payload_root.join("production-security-policy.json");
        for path in [&payload_root, &source, &policy_path] {
            verify_protected_windows_path(path).map_err(|error| error.to_string())?;
        }
        let policy_bytes = fs::read(&policy_path).map_err(|error| error.to_string())?;
        let policy = parse_policy(&policy_bytes)?;
        if policy.suite_authenticode_publisher != publisher {
            return Err("setup signer does not match the production suite publisher".into());
        }
        run_transaction(
            "install",
            &source,
            &policy_path,
            &interactive_user_sid()?,
            true,
        )
    })();
    let cleanup = fs::remove_dir_all(&workspace).map_err(|error| error.to_string());
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(format!("temporary installer cleanup failed: {error}")),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(windows)]
fn run_transaction(
    mode: &str,
    source: &Path,
    policy_path: &Path,
    authorized_user_sid: &str,
    preserve_user_data: bool,
) -> Result<(), String> {
    let suite = SuiteManifest::load_and_verify(source).map_err(|error| error.to_string())?;
    let policy_bytes = fs::read(policy_path).map_err(|error| error.to_string())?;
    let policy_sha256 = sha256_bytes(&policy_bytes);
    let policy = parse_policy(&policy_bytes)?;
    verify_authenticode_suite(&suite, &policy).map_err(|error| error.to_string())?;

    let roots = known_folders()?;
    let script = source.join("resources/install-windows-agent-suite.ps1");
    let status = Command::new(windows_powershell().map_err(|error| error.to_string())?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            text(&script)?,
            "-Mode",
            mode,
            "-SourceRoot",
            text(source)?,
            "-InstallRoot",
            text(&roots.program_files.join("FairyPam/Agent"))?,
            "-DataRoot",
            text(&roots.program_data.join("FairyPam/Agent"))?,
            "-UserRoot",
            text(&roots.local_app_data.join("FairyPam/Agent"))?,
            "-AuthorizedUserSid",
            authorized_user_sid,
            "-BuildId",
            &suite.manifest.build_id,
            "-SuiteVersion",
            &suite.manifest.suite_version,
            "-ManifestSha256",
            &suite.manifest_sha256,
            "-PreserveUserData",
            if preserve_user_data { "true" } else { "false" },
            "-SecurityPolicyPath",
            text(policy_path)?,
            "-SecurityPolicySha256",
            &policy_sha256,
        ])
        .stdin(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("lifecycle transaction exited with {status}"));
    }
    Ok(())
}

#[cfg(windows)]
fn create_workspace() -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let name = format!("FairyPamInstaller-{}-{nonce}", std::process::id());
    let program_data = known_folder(&FOLDERID_ProgramData, "ProgramData")?;
    let script = "$ErrorActionPreference='Stop';$root=$args[0];$path=[IO.Path]::Combine($root,$args[1]);$security=[Security.AccessControl.DirectorySecurity]::new();$security.SetAccessRuleProtection($true,$false);$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit';$prop=[Security.AccessControl.PropagationFlags]::None;$full=[Security.AccessControl.FileSystemRights]::FullControl;foreach($sid in 'S-1-5-18','S-1-5-32-544'){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$full,$inherit,$prop,[Security.AccessControl.AccessControlType]::Allow))};[IO.Directory]::CreateDirectory($path,$security)|Out-Null;$acl=Get-Acl -LiteralPath $path;$owner=([Security.Principal.NTAccount]::new($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value;$allowed=@('S-1-5-18','S-1-5-32-544');$rules=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]));if(-not $acl.AreAccessRulesProtected -or $owner -notin $allowed -or @($rules|?{$_.AccessControlType -ne 'Allow' -or $_.IdentityReference.Value -notin $allowed}).Count -ne 0){exit 12};[Console]::Out.Write($path)";
    let output = Command::new(windows_powershell().map_err(|error| error.to_string())?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            text(&program_data)?,
            &name,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err("protected installer staging could not be created".into());
    }
    let path = PathBuf::from(
        String::from_utf8(output.stdout)
            .map_err(|_| "protected installer staging path is not UTF-8".to_owned())?,
    );
    if !path.is_absolute() || !path.is_dir() {
        return Err("protected installer staging path is invalid".into());
    }
    verify_protected_windows_path(&path).map_err(|error| error.to_string())?;
    Ok(path)
}

#[cfg(windows)]
fn write_embedded_payload(executable: &Path, destination: &Path) -> Result<(), String> {
    // ponytail: setup runs once; use a reverse streaming scan if bundle size becomes material.
    let executable = fs::read(executable).map_err(|error| error.to_string())?;
    let (marker, payload) = embedded_payload_layout(&executable)?;
    verify_payload_digest(payload, &EMBEDDED_PAYLOAD_DIGEST)?;
    ensure_certificate_precedes_payload(&executable, marker - 8 - payload.len())?;
    fs::write(destination, payload).map_err(|error| error.to_string())
}

#[cfg(test)]
fn embedded_payload<'a>(executable: &'a [u8], digest_record: &[u8]) -> Result<&'a [u8], String> {
    let (_, payload) = embedded_payload_layout(executable)?;
    verify_payload_digest(payload, digest_record)?;
    Ok(payload)
}

fn verify_payload_digest(payload: &[u8], digest_record: &[u8]) -> Result<(), String> {
    let expected = digest_record
        .strip_prefix(PAYLOAD_DIGEST_PREFIX)
        .filter(|value| {
            value.len() == 64
                && value
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| "installer payload digest record is invalid".to_owned())?;
    if sha256_bytes(payload).as_bytes() != expected {
        return Err("installer payload digest mismatch".into());
    }
    Ok(())
}

fn embedded_payload_layout(executable: &[u8]) -> Result<(usize, &[u8]), String> {
    let mut invalid = None;
    for (marker, window) in executable.windows(PAYLOAD_MARKER_LEN).enumerate().rev() {
        if !window.starts_with(PAYLOAD_MARKER_PREFIX)
            || !window[PAYLOAD_MARKER_PREFIX.len()..].starts_with(PAYLOAD_MARKER_SUFFIX)
        {
            continue;
        }
        match payload_at_marker(executable, marker) {
            Ok(payload) => return Ok((marker, payload)),
            Err(error) if invalid.is_none() => invalid = Some(error),
            Err(_) => {}
        }
    }
    Err(invalid.unwrap_or_else(|| "installer payload is missing".to_owned()))
}

fn payload_at_marker(executable: &[u8], marker: usize) -> Result<&[u8], String> {
    let length_offset = marker
        .checked_sub(8)
        .ok_or_else(|| "installer payload trailer is invalid".to_owned())?;
    let payload_len = u64::from_le_bytes(
        executable[length_offset..marker]
            .try_into()
            .map_err(|_| "installer payload trailer is invalid".to_owned())?,
    );
    let payload_len = usize::try_from(payload_len)
        .map_err(|_| "installer payload trailer is invalid".to_owned())?;
    let payload_offset = length_offset
        .checked_sub(payload_len)
        .ok_or_else(|| "installer payload is truncated".to_owned())?;
    let payload = &executable[payload_offset..length_offset];
    if !payload.starts_with(b"PK\x03\x04") {
        return Err("installer payload is not a ZIP archive".into());
    }
    Ok(payload)
}

fn ensure_certificate_precedes_payload(
    executable: &[u8],
    payload_offset: usize,
) -> Result<(), String> {
    let pe_offset = read_u32(executable, 0x3c)? as usize;
    if executable.get(0..2) != Some(b"MZ")
        || executable.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0")
    {
        return Err("installer PE headers are invalid".into());
    }
    let optional = pe_offset + 24;
    let data_directories = match read_u16(executable, optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return Err("installer PE optional header is invalid".into()),
    };
    let certificate = data_directories + 4 * 8;
    let certificate_offset = read_u32(executable, certificate)? as usize;
    let certificate_size = read_u32(executable, certificate + 4)? as usize;
    if certificate_size == 0
        || certificate_offset
            .checked_add(certificate_size)
            .is_none_or(|end| end > payload_offset)
    {
        return Err("installer signature must precede the embedded payload".into());
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| "installer PE headers are truncated".into())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| "installer PE headers are truncated".into())
}

#[cfg(windows)]
fn interactive_user_sid() -> Result<String, String> {
    let mut session_id = 0_u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }
        .map_err(|_| "interactive user session could not be resolved".to_owned())?;
    let user = wts_session_text(session_id, WTSUserName)?;
    let domain = wts_session_text(session_id, WTSDomainName)?;
    let sid = account_sid(&session_account_name(&domain, &user)?)?;
    validate_sid(&sid)?;
    Ok(sid)
}

#[cfg(windows)]
fn wts_session_text(session_id: u32, class: WTS_INFO_CLASS) -> Result<String, String> {
    let mut buffer = PWSTR::null();
    let mut bytes = 0_u32;
    let query = unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session_id,
            class,
            &mut buffer,
            &mut bytes,
        )
    };
    let result = if query.is_err() || buffer.is_null() || bytes < 2 || bytes % 2 != 0 {
        Err("interactive user session identity could not be resolved".into())
    } else {
        let units = unsafe { std::slice::from_raw_parts(buffer.0, bytes as usize / 2) };
        units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| "interactive user session identity is invalid".to_owned())
            .and_then(|end| {
                String::from_utf16(&units[..end])
                    .map_err(|_| "interactive user session identity is invalid".to_owned())
            })
    };
    if !buffer.is_null() {
        unsafe { WTSFreeMemory(buffer.0.cast()) };
    }
    result
}

#[cfg(any(windows, test))]
fn session_account_name(domain: &str, user: &str) -> Result<String, String> {
    if user.is_empty() {
        return Err("interactive user session has no logged-on user".into());
    }
    Ok(if domain.is_empty() {
        user.to_owned()
    } else {
        format!(r"{domain}\{user}")
    })
}

#[cfg(windows)]
fn account_sid(account: &str) -> Result<String, String> {
    let account: Vec<u16> = account.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid_bytes = 0_u32;
    let mut domain_chars = 0_u32;
    let mut sid_type = SID_NAME_USE::default();
    let _ = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            None,
            &mut sid_bytes,
            None,
            &mut domain_chars,
            &mut sid_type,
        )
    };
    if sid_bytes == 0 {
        return Err("interactive user SID could not be resolved".into());
    }
    let words = (sid_bytes as usize)
        .checked_add(size_of::<usize>() - 1)
        .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
        .ok_or_else(|| "interactive user SID is too large".to_owned())?;
    let mut sid = vec![0_usize; words];
    let mut domain = vec![0_u16; domain_chars as usize];
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_bytes,
            (!domain.is_empty()).then(|| PWSTR(domain.as_mut_ptr())),
            &mut domain_chars,
            &mut sid_type,
        )
    }
    .map_err(|_| "interactive user SID could not be resolved".to_owned())?;
    if sid_type != SidTypeUser {
        return Err("interactive session identity is not a user account".into());
    }

    let mut value = PWSTR::null();
    unsafe { ConvertSidToStringSidW(PSID(sid.as_mut_ptr().cast()), &mut value) }
        .map_err(|_| "interactive user SID could not be encoded".to_owned())?;
    let result = unsafe { value.to_string() }
        .map_err(|_| "interactive user SID could not be encoded".to_owned());
    if !value.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(value.0.cast())));
        }
    }
    result
}

fn parse_policy(bytes: &[u8]) -> Result<ProductionSecurityPolicy, String> {
    let policy: ProductionSecurityPolicy = serde_json::from_slice(bytes)
        .map_err(|error| format!("security policy is invalid: {error}"))?;
    policy
        .validate_configuration()
        .map_err(|error| error.to_string())?;
    Ok(policy)
}

#[cfg(not(windows))]
fn run(_arguments: Vec<String>) -> Result<(), String> {
    Err("Windows is required".into())
}

fn pop(arguments: &mut VecDeque<String>) -> Result<String, String> {
    arguments.pop_front().ok_or_else(|| usage().into())
}

fn validate_sid(value: &str) -> Result<(), String> {
    if !value.starts_with("S-1-")
        || value.len() > 184
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
    {
        return Err("authorized user SID is invalid".into());
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(windows)]
struct KnownFolders {
    program_files: PathBuf,
    program_data: PathBuf,
    local_app_data: PathBuf,
}

#[cfg(windows)]
fn known_folders() -> Result<KnownFolders, String> {
    Ok(KnownFolders {
        program_files: known_folder(&FOLDERID_ProgramFiles, "Program Files")?,
        program_data: known_folder(&FOLDERID_ProgramData, "ProgramData")?,
        local_app_data: known_folder(&FOLDERID_LocalAppData, "LocalAppData")?,
    })
}

#[cfg(windows)]
fn known_folder(id: &windows::core::GUID, label: &str) -> Result<PathBuf, String> {
    let path = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) }
        .map_err(|error| format!("cannot locate {label}: {error}"))?;
    let value = unsafe { path.to_string() }
        .map(PathBuf::from)
        .map_err(|error| format!("{label} path is invalid: {error}"));
    unsafe { CoTaskMemFree(Some(path.0.cast())) };
    let value = value?;
    if !value.is_absolute() {
        return Err(format!("{label} path is not absolute"));
    }
    Ok(value)
}

#[cfg(windows)]
fn text(path: &Path) -> Result<&str, String> {
    path.to_str().ok_or_else(|| "path is not Unicode".into())
}

fn usage() -> &'static str {
    "usage: FairyPamAgentSetup [repair|uninstall [--remove-user-data]]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_select_the_self_contained_install_path() {
        assert_eq!(
            parse_invocation(Vec::new()).unwrap(),
            Invocation::BootstrapInstall
        );
    }

    #[test]
    fn repair_and_uninstall_keep_the_explicit_fail_closed_contract() {
        assert!(matches!(
            parse_invocation(vec!["repair".into()]).unwrap(),
            Invocation::Maintenance { .. }
        ));
        assert!(matches!(
            parse_invocation(vec!["uninstall".into()]).unwrap(),
            Invocation::Maintenance { .. }
        ));
    }

    #[test]
    fn caller_supplied_trust_roots_are_rejected_by_the_parser() {
        for arguments in [
            vec!["install"],
            vec!["repair", "--source", "C:\\attacker"],
            vec!["uninstall", "--security-policy", "C:\\attacker.json"],
            vec!["repair", "--authorized-user-sid", "S-1-5-21-1"],
        ] {
            assert!(parse_invocation(arguments.into_iter().map(str::to_owned).collect()).is_err());
        }
    }

    #[test]
    fn installed_state_requires_exact_bound_identity() {
        let valid = br#"{"schema_version":1,"build_id":"build-1","suite_version":"0.1.0","manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","security_policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","authorized_user_sid":"S-1-5-21-1"}"#;
        assert_eq!(parse_installed_state(valid).unwrap().build_id, "build-1");
        let mut invalid: serde_json::Value = serde_json::from_slice(valid).unwrap();
        invalid["source"] = serde_json::json!("C:\\attacker");
        assert_eq!(
            parse_installed_state(&serde_json::to_vec(&invalid).unwrap()).unwrap_err(),
            "installed state fields are not exact"
        );
    }

    #[test]
    fn session_account_name_is_bound_to_the_reported_domain_and_user() {
        assert_eq!(
            session_account_name("CONTOSO", "alice").unwrap(),
            r"CONTOSO\alice"
        );
        assert!(session_account_name("CONTOSO", "").is_err());
    }

    #[test]
    fn payload_trailer_has_a_fixed_unambiguous_marker() {
        assert_eq!(PAYLOAD_MARKER_PREFIX.len(), 15);
        assert_eq!(PAYLOAD_MARKER_SUFFIX.len(), 8);
        assert_eq!(PAYLOAD_MARKER_LEN, 23);
    }

    #[test]
    fn last_valid_payload_trailer_ignores_binary_and_certificate_markers() {
        let payload = b"PK\x03\x04suite";
        let digest = format!(
            "{}{}",
            String::from_utf8_lossy(PAYLOAD_DIGEST_PREFIX),
            sha256_bytes(payload)
        );
        let mut executable = b"MZ binary .rdata FAIRYPAM-SUITE-PAYLOAD1".to_vec();
        executable.extend_from_slice(payload);
        executable.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        executable.extend_from_slice(PAYLOAD_MARKER_PREFIX);
        executable.extend_from_slice(PAYLOAD_MARKER_SUFFIX);
        executable.extend_from_slice(b"WIN_CERTIFICATE FAIRYPAM-SUITE-PAYLOAD1");

        assert_eq!(
            embedded_payload(&executable, digest.as_bytes()).unwrap(),
            payload
        );
    }

    #[test]
    fn payload_tamper_is_rejected() {
        let payload = b"PK\x03\x04suite";
        let digest = format!(
            "{}{}",
            String::from_utf8_lossy(PAYLOAD_DIGEST_PREFIX),
            sha256_bytes(payload)
        );
        let mut executable = b"MZ binary".to_vec();
        executable.extend_from_slice(payload);
        executable.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        executable.extend_from_slice(PAYLOAD_MARKER_PREFIX);
        executable.extend_from_slice(PAYLOAD_MARKER_SUFFIX);
        executable["MZ binary".len() + 4] ^= 1;

        assert_eq!(
            embedded_payload(&executable, digest.as_bytes()).unwrap_err(),
            "installer payload digest mismatch"
        );
    }

    #[test]
    fn certificate_table_must_precede_the_payload() {
        let mut executable = vec![0_u8; 512];
        executable[0..2].copy_from_slice(b"MZ");
        executable[0x3c..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
        executable[0x80..0x84].copy_from_slice(b"PE\0\0");
        executable[0x98..0x9a].copy_from_slice(&(0x20b_u16).to_le_bytes());
        let certificate = 0x98 + 112 + 4 * 8;
        executable[certificate..certificate + 4].copy_from_slice(&(400_u32).to_le_bytes());
        executable[certificate + 4..certificate + 8].copy_from_slice(&(16_u32).to_le_bytes());

        assert!(ensure_certificate_precedes_payload(&executable, 450).is_ok());
        assert_eq!(
            ensure_certificate_precedes_payload(&executable, 405).unwrap_err(),
            "installer signature must precede the embedded payload"
        );
    }

    #[test]
    fn every_mode_rejects_bootstrap_only_policy() {
        let policy = br#"{"schema_version":1,"suite_authenticode_publisher":"CN=FairyPam"}"#;
        assert!(parse_policy(policy).is_err());
    }

    #[test]
    fn packaging_contract_orders_digest_signing_overlay_and_outer_identity() {
        let script = include_str!("../../../scripts/package-windows-agent-suite.ps1");
        let digest = script.find("$payloadDigest =").unwrap();
        let patch = script.find("payload digest placeholder").unwrap();
        let sign = script.find("& $SetupSigner").unwrap();
        let append = script.find("[IO.FileMode]::Append").unwrap();
        let manifest = script.find("$manifest = New-SuiteManifest").unwrap();
        let package = script
            .find("CreateFromDirectory($stage, $packagePath")
            .unwrap();
        assert!(digest < patch && patch < sign && sign < append);
        assert!(append < manifest && manifest < package);
    }
}
