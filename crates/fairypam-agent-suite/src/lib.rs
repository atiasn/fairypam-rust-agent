//! Strict product-suite manifest and installed-layout validation.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MANIFEST_FILE: &str = "BUILD-MANIFEST.json";
pub const MANIFEST_KIND: &str = "fairypam-agent-suite";
pub const CURRENT_POINTER_FILE: &str = "current.json";
pub const ROLLBACK_PENDING_FILE: &str = "rollback-pending.json";
pub const INSTALLER_PROTOCOL_VERSION: u32 = 1;
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub const MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;

const REQUIRED_VERSIONED_EXECUTABLES: [&str; 4] = [
    "fairypam-agent.exe",
    "fairypam-agent-guardian.exe",
    "fairypam-agent-shell.exe",
    "fairypam-win32-worker.exe",
];
const REQUIRED_RUNTIME_MEMBERS: [&str; 12] = [
    "runtime/maa/THIRD-PARTY-NOTICES.md",
    "runtime/maa/active.json",
    "runtime/maa/licenses/MAA-LICENSE.md",
    "runtime/maa/maa-runtime.lock.json",
    "runtime/maa/maa-runtime.manifest.json",
    "runtime/maa/versions/5.12.3/LICENSE.md",
    "runtime/maa/versions/5.12.3/bin/MaaFramework.dll",
    "runtime/maa/versions/5.12.3/bin/MaaUtils.dll",
    "runtime/maa/versions/5.12.3/bin/MaaWin32ControlUnit.dll",
    "runtime/maa/versions/5.12.3/bin/fastdeploy_ppocr_maa.dll",
    "runtime/maa/versions/5.12.3/bin/onnxruntime_maa.dll",
    "runtime/maa/versions/5.12.3/bin/opencv_world4_maa.dll",
];
const REQUIRED_STABLE_EXECUTABLE: &str = "resources/runtime/fairypam-agent-installer.exe";
const INSTALLER_OWNED_EXECUTABLES: [&str; 2] = [
    "uninstall.exe",
    ".fairypam-installer/payload/fairypam-agent-guardian.exe",
];

pub mod windows_security {
    #[cfg(windows)]
    use super::SuiteError;

    const TRUSTED_INSTALLER_SID: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    pub fn trusted_program_files_security(sddl: &str) -> bool {
        trusted_install_owner(sddl) && !dacl_grants_untrusted_write(sddl)
    }

    fn trusted_install_owner(sddl: &str) -> bool {
        sddl.starts_with("O:BA")
            || sddl.starts_with("O:SY")
            || sddl.starts_with("O:TI")
            || sddl.starts_with(&format!("O:{TRUSTED_INSTALLER_SID}"))
    }

    fn dacl_grants_untrusted_write(sddl: &str) -> bool {
        let Some(dacl) = sddl.split_once("D:").map(|(_, dacl)| dacl) else {
            return true;
        };
        dacl.split('(').skip(1).any(|raw| {
            let ace = raw.split(')').next().unwrap_or_default();
            let fields = ace.split(';').collect::<Vec<_>>();
            if fields.len() < 6 || !fields[0].ends_with('A') {
                return false;
            }
            if matches!(fields[5], "SY" | "BA" | "CO") || fields[5] == TRUSTED_INSTALLER_SID {
                return false;
            }
            write_capable_rights(fields[2])
        })
    }

    fn write_capable_rights(rights: &str) -> bool {
        if let Some(mask) = rights.strip_prefix("0x") {
            return u32::from_str_radix(mask, 16).map_or(true, |mask| mask & 0x500D_0156 != 0);
        }
        let allowed = ["GR", "GX", "RC", "FR", "FX", "KR", "KX", "NR", "NX"];
        rights
            .as_bytes()
            .chunks_exact(2)
            .any(|right| !allowed.iter().any(|allowed| allowed.as_bytes() == right))
    }

    #[cfg(windows)]
    pub fn verify_trusted_install_entry(
        path: &std::path::Path,
        directory: bool,
    ) -> Result<(), SuiteError> {
        let metadata = path
            .symlink_metadata()
            .map_err(|_| invalid_install_security())?;
        if metadata.file_type().is_symlink()
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err(invalid_install_security());
        }
        verify_nonreparse(path)?;
        trusted_program_files_security(&security_sddl(path)?)
            .then_some(())
            .ok_or_else(invalid_install_security)
    }

    #[cfg(windows)]
    fn verify_nonreparse(path: &std::path::Path) -> Result<(), SuiteError> {
        use windows::core::HSTRING;
        use windows::Win32::Storage::FileSystem::{
            GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
        };

        let attributes =
            unsafe { GetFileAttributesW(&HSTRING::from(path.to_string_lossy().as_ref())) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        {
            return Err(invalid_install_security());
        }
        Ok(())
    }

    #[cfg(windows)]
    fn security_sddl(path: &std::path::Path) -> Result<String, SuiteError> {
        use windows::core::{HSTRING, PWSTR};
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        };

        let information = OWNER_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetNamedSecurityInfoW(
                &HSTRING::from(path.to_string_lossy().as_ref()),
                SE_FILE_OBJECT,
                information,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        if status.0 != 0 {
            return Err(invalid_install_security());
        }
        let mut text = PWSTR::null();
        let result = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                information,
                &mut text,
                None,
            )
        }
        .map_err(|_| invalid_install_security())
        .and_then(|_| unsafe { text.to_string().map_err(|_| invalid_install_security()) });
        let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
        result
    }

    #[cfg(windows)]
    fn invalid_install_security() -> SuiteError {
        SuiteError::new(
            "suite.install_security_invalid",
            "installed entry owner, DACL, or reparse state is untrusted",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberScope {
    Stable,
    Versioned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteMember {
    pub path: String,
    pub scope: MemberScope,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteManifest {
    pub schema_version: u8,
    pub kind: String,
    pub build_id: String,
    pub source_commit: String,
    pub suite_version: String,
    pub built_at: String,
    pub build_origin: String,
    pub installer_protocol: u32,
    pub members: Vec<SuiteMember>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPointer {
    pub schema_version: u8,
    pub build_id: String,
    pub suite_version: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPending {
    pub schema_version: u8,
    pub candidate: CurrentPointer,
    pub previous: CurrentPointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationHealthDecision {
    Pending,
    Promote,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSuite {
    pub pointer: CurrentPointer,
    pub manifest: SuiteManifest,
    pub version_root: PathBuf,
}

#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct SuiteError {
    code: &'static str,
    message: String,
}

impl SuiteError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

pub fn parse_manifest(bytes: &[u8]) -> Result<SuiteManifest, SuiteError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid_manifest(
            "manifest size is outside the supported range",
        ));
    }
    let manifest: SuiteManifest =
        serde_json::from_slice(bytes).map_err(|error| invalid_manifest(error.to_string()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_manifest(manifest: &SuiteManifest) -> Result<(), SuiteError> {
    if manifest.schema_version != 1 || manifest.kind != MANIFEST_KIND {
        return Err(invalid_manifest("unsupported schema_version or kind"));
    }
    if !safe_identifier(&manifest.build_id, 128) {
        return Err(invalid_manifest("build_id is invalid"));
    }
    if !matches!(manifest.source_commit.len(), 40 | 64)
        || !manifest
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_manifest("source_commit is invalid"));
    }
    Version::parse(&manifest.suite_version)
        .map_err(|_| invalid_manifest("suite_version is not semantic versioning"))?;
    if manifest.built_at.trim().is_empty()
        || manifest.build_origin.trim().is_empty()
        || manifest.installer_protocol != INSTALLER_PROTOCOL_VERSION
    {
        return Err(invalid_manifest("build provenance is incomplete"));
    }
    if manifest.members.is_empty() || manifest.members.len() > 512 {
        return Err(invalid_manifest(
            "member count is outside the supported range",
        ));
    }

    let mut paths = BTreeSet::new();
    let mut required_versioned = BTreeSet::new();
    let mut required_runtime = BTreeSet::new();
    let mut stable_helper = false;
    for member in &manifest.members {
        validate_member_path(&member.path)?;
        let folded = member.path.to_ascii_lowercase();
        if !paths.insert(folded.clone()) {
            return Err(invalid_manifest("member paths collide case-insensitively"));
        }
        if member.size_bytes == 0 || member.size_bytes > MAX_MEMBER_BYTES {
            return Err(invalid_manifest(
                "member size is outside the supported range",
            ));
        }
        if !valid_sha256(&member.sha256) {
            return Err(invalid_manifest("member SHA256 is invalid"));
        }
        if REQUIRED_RUNTIME_MEMBERS.contains(&member.path.as_str()) {
            if member.scope != MemberScope::Versioned {
                return Err(invalid_manifest("MAA runtime member must be versioned"));
            }
            required_runtime.insert(member.path.clone());
        } else if REQUIRED_VERSIONED_EXECUTABLES.contains(&folded.as_str()) {
            if member.scope != MemberScope::Versioned {
                return Err(invalid_manifest(
                    "product executable has the wrong installation scope",
                ));
            }
            required_versioned.insert(folded.clone());
        } else if folded == REQUIRED_STABLE_EXECUTABLE {
            if member.scope != MemberScope::Stable {
                return Err(invalid_manifest("installer helper must be stable"));
            }
            stable_helper = true;
        } else {
            return Err(invalid_manifest(
                "suite member is outside the exact product allowlist",
            ));
        }
    }
    if required_versioned.len() != REQUIRED_VERSIONED_EXECUTABLES.len()
        || required_runtime.len() != REQUIRED_RUNTIME_MEMBERS.len()
        || !stable_helper
    {
        return Err(invalid_manifest(
            "required production executables are incomplete",
        ));
    }
    Ok(())
}

pub fn manifest_sha256(bytes: &[u8]) -> String {
    sha256_bytes(bytes)
}

pub fn read_manifest(path: &Path) -> Result<(SuiteManifest, Vec<u8>), SuiteError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("suite.manifest_unavailable", path, error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(SuiteError::new(
            "suite.manifest_unavailable",
            format!("manifest is not a bounded regular file: {}", path.display()),
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| io_error("suite.manifest_unavailable", path, error))?;
    let manifest = parse_manifest(&bytes)?;
    Ok((manifest, bytes))
}

pub fn validate_installed_layout(
    install_root: &Path,
    version_root: &Path,
    manifest: &SuiteManifest,
) -> Result<(), SuiteError> {
    validate_manifest(manifest)?;
    let mut expected_versioned_executables = BTreeSet::new();
    for member in &manifest.members {
        let base = match member.scope {
            MemberScope::Stable => install_root,
            MemberScope::Versioned => version_root,
        };
        let path = base.join(path_from_manifest(&member.path));
        validate_file_identity(&path, member)?;
        if member.scope == MemberScope::Versioned && is_executable_member(&member.path) {
            expected_versioned_executables.insert(member.path.to_ascii_lowercase());
        }
    }
    reject_extra_executables(version_root, version_root, &expected_versioned_executables)
}

pub fn validate_active_layout(
    install_root: &Path,
    version_root: &Path,
    manifest: &SuiteManifest,
) -> Result<(), SuiteError> {
    validate_manifest(manifest)?;
    let mut expected_versioned_executables = BTreeSet::new();
    for member in &manifest.members {
        match member.scope {
            MemberScope::Stable => {
                let path = install_root.join(path_from_manifest(&member.path));
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|error| io_error("suite.member_unavailable", &path, error))?;
                if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
                    return Err(SuiteError::new(
                        "suite.member_identity_mismatch",
                        "stable installer helper is unavailable",
                    ));
                }
            }
            MemberScope::Versioned => {
                let path = version_root.join(path_from_manifest(&member.path));
                validate_file_identity(&path, member)?;
                if is_executable_member(&member.path) {
                    expected_versioned_executables.insert(member.path.to_ascii_lowercase());
                }
            }
        }
    }
    reject_extra_executables(version_root, version_root, &expected_versioned_executables)
}

pub fn validate_flat_layout(
    root: &Path,
    manifest: &SuiteManifest,
    bootstrap_helper: &Path,
) -> Result<(), SuiteError> {
    validate_manifest(manifest)?;
    for member in &manifest.members {
        validate_file_identity(&root.join(path_from_manifest(&member.path)), member)?;
    }
    reject_forbidden_executables(root, root, bootstrap_helper)
}

pub fn read_current_pointer(path: &Path) -> Result<CurrentPointer, SuiteError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("suite.pointer_invalid", path, error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(SuiteError::new(
            "suite.pointer_invalid",
            "active suite pointer is not a bounded regular file",
        ));
    }
    let bytes = fs::read(path).map_err(|error| io_error("suite.pointer_invalid", path, error))?;
    let pointer: CurrentPointer = serde_json::from_slice(&bytes)
        .map_err(|error| SuiteError::new("suite.pointer_invalid", error.to_string()))?;
    validate_current_pointer(&pointer)?;
    Ok(pointer)
}

fn validate_current_pointer(pointer: &CurrentPointer) -> Result<(), SuiteError> {
    if pointer.schema_version != 1
        || !safe_identifier(&pointer.build_id, 128)
        || Version::parse(&pointer.suite_version).is_err()
        || !valid_sha256(&pointer.manifest_sha256)
    {
        return Err(SuiteError::new(
            "suite.pointer_invalid",
            "active suite pointer fields are invalid",
        ));
    }
    Ok(())
}

pub fn parse_rollback_pending(bytes: &[u8]) -> Result<RollbackPending, SuiteError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(SuiteError::new(
            "suite.rollback_state_invalid",
            "rollback state size is invalid",
        ));
    }
    let pending: RollbackPending = serde_json::from_slice(bytes)
        .map_err(|error| SuiteError::new("suite.rollback_state_invalid", error.to_string()))?;
    validate_current_pointer(&pending.candidate)?;
    validate_current_pointer(&pending.previous)?;
    if pending.schema_version != 1 || pending.candidate == pending.previous {
        return Err(SuiteError::new(
            "suite.rollback_state_invalid",
            "rollback state fields are invalid",
        ));
    }
    Ok(pending)
}

pub fn activation_health_decision(
    candidate_is_active: bool,
    agent_failed: bool,
    health_window_elapsed: bool,
) -> ActivationHealthDecision {
    if !candidate_is_active || agent_failed {
        ActivationHealthDecision::Rollback
    } else if health_window_elapsed {
        ActivationHealthDecision::Promote
    } else {
        ActivationHealthDecision::Pending
    }
}

pub fn resolve_active_suite(install_root: &Path) -> Result<ActiveSuite, SuiteError> {
    let pointer = read_current_pointer(&install_root.join(CURRENT_POINTER_FILE))?;
    resolve_suite_pointer(install_root, pointer)
}

pub fn resolve_suite_pointer(
    install_root: &Path,
    pointer: CurrentPointer,
) -> Result<ActiveSuite, SuiteError> {
    validate_current_pointer(&pointer)?;
    let version_root = install_root.join("versions").join(&pointer.build_id);
    let (manifest, manifest_bytes) = read_manifest(&version_root.join(MANIFEST_FILE))?;
    if manifest.build_id != pointer.build_id
        || manifest.suite_version != pointer.suite_version
        || manifest_sha256(&manifest_bytes) != pointer.manifest_sha256
    {
        return Err(SuiteError::new(
            "suite.pointer_identity_mismatch",
            "active suite pointer does not match its manifest",
        ));
    }
    validate_active_layout(install_root, &version_root, &manifest)?;
    Ok(ActiveSuite {
        pointer,
        manifest,
        version_root,
    })
}

#[cfg(windows)]
pub fn read_rollback_pending(install_root: &Path) -> Result<Option<RollbackPending>, SuiteError> {
    let path = install_root.join(ROLLBACK_PENDING_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("suite.rollback_state_invalid", &path, error)),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(SuiteError::new(
            "suite.rollback_state_invalid",
            "rollback state is not a bounded regular file",
        ));
    }
    parse_rollback_pending(
        &fs::read(&path).map_err(|error| io_error("suite.rollback_state_invalid", &path, error))?,
    )
    .map(Some)
}

#[cfg(windows)]
pub fn activate_suite_pointer(
    install_root: &Path,
    pointer: &CurrentPointer,
) -> Result<(), SuiteError> {
    resolve_suite_pointer(install_root, pointer.clone())?;
    replace_json_atomic(
        &install_root.join(CURRENT_POINTER_FILE),
        &serde_json::to_vec(pointer)
            .map_err(|error| SuiteError::new("suite.pointer_invalid", error.to_string()))?,
    )
}

#[cfg(windows)]
pub fn write_rollback_pending(
    install_root: &Path,
    pending: &RollbackPending,
) -> Result<(), SuiteError> {
    let bytes = serde_json::to_vec(pending)
        .map_err(|error| SuiteError::new("suite.rollback_state_invalid", error.to_string()))?;
    parse_rollback_pending(&bytes)?;
    replace_json_atomic(&install_root.join(ROLLBACK_PENDING_FILE), &bytes)
}

#[cfg(windows)]
pub fn clear_rollback_pending(install_root: &Path) -> Result<(), SuiteError> {
    match fs::remove_file(install_root.join(ROLLBACK_PENDING_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SuiteError::new(
            "suite.rollback_state_invalid",
            error.to_string(),
        )),
    }
}

#[cfg(windows)]
fn replace_json_atomic(path: &Path, bytes: &[u8]) -> Result<(), SuiteError> {
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| io_error("suite.pointer_write_failed", &temporary, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error("suite.pointer_write_failed", &temporary, error))?;
    drop(file);
    let source = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .is_err()
    {
        let _ = fs::remove_file(&temporary);
        return Err(SuiteError::new(
            "suite.pointer_write_failed",
            "atomic pointer replacement failed",
        ));
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String, SuiteError> {
    let mut file =
        File::open(path).map_err(|error| io_error("suite.member_unavailable", path, error))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error("suite.member_unavailable", path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_file_identity(path: &Path, member: &SuiteMember) -> Result<(), SuiteError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("suite.member_unavailable", path, error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != member.size_bytes
        || sha256_file(path)? != member.sha256
    {
        return Err(SuiteError::new(
            "suite.member_identity_mismatch",
            format!("suite member does not match manifest: {}", member.path),
        ));
    }
    Ok(())
}

fn reject_extra_executables(
    root: &Path,
    directory: &Path,
    expected: &BTreeSet<String>,
) -> Result<(), SuiteError> {
    for entry in fs::read_dir(directory)
        .map_err(|error| io_error("suite.layout_invalid", directory, error))?
    {
        let entry = entry.map_err(|error| io_error("suite.layout_invalid", directory, error))?;
        let metadata = entry
            .path()
            .symlink_metadata()
            .map_err(|error| io_error("suite.layout_invalid", &entry.path(), error))?;
        if metadata.file_type().is_symlink() {
            return Err(SuiteError::new(
                "suite.layout_invalid",
                "suite layout contains a symbolic link",
            ));
        } else if metadata.is_dir() {
            reject_extra_executables(root, &entry.path(), expected)?;
        } else if metadata.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| SuiteError::new("suite.layout_invalid", "member escaped root"))?
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            if is_executable_member(&relative)
                && relative != MANIFEST_FILE.to_ascii_lowercase()
                && !expected.contains(&relative)
            {
                return Err(SuiteError::new(
                    "suite.layout_invalid",
                    format!("undeclared executable member: {relative}"),
                ));
            }
        } else {
            return Err(SuiteError::new(
                "suite.layout_invalid",
                "suite layout contains a non-file entry",
            ));
        }
    }
    Ok(())
}

fn reject_forbidden_executables(
    root: &Path,
    directory: &Path,
    bootstrap_helper: &Path,
) -> Result<(), SuiteError> {
    for entry in fs::read_dir(directory)
        .map_err(|error| io_error("suite.layout_invalid", directory, error))?
    {
        let entry = entry.map_err(|error| io_error("suite.layout_invalid", directory, error))?;
        let metadata = entry
            .path()
            .symlink_metadata()
            .map_err(|error| io_error("suite.layout_invalid", &entry.path(), error))?;
        if metadata.file_type().is_symlink() {
            return Err(SuiteError::new(
                "suite.layout_invalid",
                "suite layout contains a symbolic link",
            ));
        }
        if metadata.is_dir() {
            reject_forbidden_executables(root, &entry.path(), bootstrap_helper)?;
        } else if !metadata.is_file() {
            return Err(SuiteError::new(
                "suite.layout_invalid",
                "suite layout contains a non-file entry",
            ));
        } else {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| SuiteError::new("suite.layout_invalid", "member escaped root"))?
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            if is_executable_member(&relative)
                && !allowed_product_executable(&relative)
                && !allowed_installed_product_executable(&relative)
                && !INSTALLER_OWNED_EXECUTABLES.contains(&relative.as_str())
                && entry.path() != bootstrap_helper
            {
                return Err(SuiteError::new(
                    "suite.layout_invalid",
                    "executable member is outside the exact product allowlist",
                ));
            }
        }
    }
    Ok(())
}

fn validate_member_path(value: &str) -> Result<(), SuiteError> {
    if value.is_empty()
        || value.len() > 240
        || value.contains('\\')
        || value.contains(':')
        || value.starts_with('/')
        || value.ends_with(['.', ' '])
    {
        return Err(SuiteError::new(
            "suite.member_path_invalid",
            "suite member path is invalid",
        ));
    }
    let path = Path::new(value);
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(SuiteError::new(
            "suite.member_path_invalid",
            "suite member path is not relative and normalized",
        ));
    }
    Ok(())
}

fn path_from_manifest(value: &str) -> PathBuf {
    value.split('/').collect()
}

fn safe_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_executable_member(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [".exe", ".dll", ".msi", ".ps1", ".bat", ".cmd"]
        .iter()
        .any(|suffix| value.ends_with(suffix))
}

fn allowed_product_executable(value: &str) -> bool {
    let folded = value.to_ascii_lowercase();
    REQUIRED_VERSIONED_EXECUTABLES.contains(&folded.as_str())
        || folded == REQUIRED_STABLE_EXECUTABLE
        || REQUIRED_RUNTIME_MEMBERS
            .iter()
            .any(|member| member.eq_ignore_ascii_case(value))
}

fn allowed_installed_product_executable(value: &str) -> bool {
    let mut components = value.splitn(3, '/');
    let (Some("versions"), Some(build_id), Some(member)) =
        (components.next(), components.next(), components.next())
    else {
        return false;
    };
    safe_identifier(build_id, 128)
        && (REQUIRED_VERSIONED_EXECUTABLES.contains(&member)
            || REQUIRED_RUNTIME_MEMBERS
                .iter()
                .any(|required| required.eq_ignore_ascii_case(member)))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid_manifest(message: impl Into<String>) -> SuiteError {
    SuiteError::new("suite.manifest_invalid", message)
}

fn io_error(code: &'static str, path: &Path, error: io::Error) -> SuiteError {
    SuiteError::new(code, format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_files_acl_rejects_untrusted_owner_or_write() {
        assert!(windows_security::trusted_program_files_security(
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
        ));
        assert!(!windows_security::trusted_program_files_security(
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)"
        ));
        assert!(!windows_security::trusted_program_files_security(
            "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
    }

    #[test]
    fn activation_health_promotes_or_rolls_back_fail_closed() {
        assert_eq!(
            activation_health_decision(true, false, false),
            ActivationHealthDecision::Pending
        );
        assert_eq!(
            activation_health_decision(true, false, true),
            ActivationHealthDecision::Promote
        );
        assert_eq!(
            activation_health_decision(true, true, false),
            ActivationHealthDecision::Rollback
        );
        assert_eq!(
            activation_health_decision(false, false, false),
            ActivationHealthDecision::Rollback
        );
    }

    #[test]
    fn rollback_state_rejects_same_candidate_and_previous() {
        let pointer = CurrentPointer {
            schema_version: 1,
            build_id: "build-a".into(),
            suite_version: "0.1.12".into(),
            manifest_sha256: "a".repeat(64),
        };
        let bytes = serde_json::to_vec(&RollbackPending {
            schema_version: 1,
            candidate: pointer.clone(),
            previous: pointer,
        })
        .unwrap();
        assert_eq!(
            parse_rollback_pending(&bytes).unwrap_err().code(),
            "suite.rollback_state_invalid"
        );
    }

    fn member(path: &str, scope: MemberScope, contents: &[u8]) -> SuiteMember {
        SuiteMember {
            path: path.to_owned(),
            scope,
            sha256: sha256_bytes(contents),
            size_bytes: contents.len() as u64,
        }
    }

    fn manifest() -> SuiteManifest {
        let mut members = vec![
            member(
                "resources/runtime/fairypam-agent-installer.exe",
                MemberScope::Stable,
                b"helper",
            ),
            member("fairypam-agent.exe", MemberScope::Versioned, b"agent"),
            member(
                "fairypam-agent-guardian.exe",
                MemberScope::Versioned,
                b"guardian",
            ),
            member("fairypam-agent-shell.exe", MemberScope::Versioned, b"shell"),
            member(
                "fairypam-win32-worker.exe",
                MemberScope::Versioned,
                b"worker",
            ),
        ];
        members.extend(
            REQUIRED_RUNTIME_MEMBERS
                .iter()
                .map(|path| member(path, MemberScope::Versioned, b"runtime")),
        );
        SuiteManifest {
            schema_version: 1,
            kind: MANIFEST_KIND.to_owned(),
            build_id: "suite-1".to_owned(),
            source_commit: "a".repeat(40),
            suite_version: "1.2.3".to_owned(),
            built_at: "2026-07-25T00:00:00Z".to_owned(),
            build_origin: "github-actions".to_owned(),
            installer_protocol: INSTALLER_PROTOCOL_VERSION,
            members,
        }
    }

    fn contents(path: &str) -> &'static [u8] {
        match path {
            "resources/runtime/fairypam-agent-installer.exe" => b"helper",
            "fairypam-agent.exe" => b"agent",
            "fairypam-agent-guardian.exe" => b"guardian",
            "fairypam-agent-shell.exe" => b"shell",
            "fairypam-win32-worker.exe" => b"worker",
            _ => b"runtime",
        }
    }

    #[test]
    fn manifest_rejects_developer_cli_and_missing_product_member() {
        for forbidden in [
            "fairypam-agent-tauri-ui.exe",
            "fairypam-agentctl.exe",
            "renamed-core.exe",
            "profiles/game/renamed-core.exe",
            "profiles/game/native.dll",
            "profiles/game/setup.ps1",
            "profiles/game/extra.json",
        ] {
            let mut value = manifest();
            value
                .members
                .push(member(forbidden, MemberScope::Versioned, b"forbidden"));
            assert_eq!(
                validate_manifest(&value).unwrap_err().code(),
                "suite.manifest_invalid"
            );
        }

        let mut value = manifest();
        value
            .members
            .retain(|member| member.path != "fairypam-agent-guardian.exe");
        assert_eq!(
            validate_manifest(&value).unwrap_err().code(),
            "suite.manifest_invalid"
        );
        let mut value = manifest();
        value
            .members
            .retain(|member| member.path != "runtime/maa/active.json");
        assert_eq!(
            validate_manifest(&value).unwrap_err().code(),
            "suite.manifest_invalid"
        );
    }

    #[test]
    fn active_pointer_binds_the_exact_versioned_layout() {
        let manifest = manifest();
        let directory = std::env::temp_dir().join(format!(
            "fairypam-active-suite-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let version_root = directory.join("versions").join(&manifest.build_id);
        fs::create_dir_all(&version_root).unwrap();
        fs::create_dir_all(directory.join("resources").join("runtime")).unwrap();
        for member in &manifest.members {
            let root = match member.scope {
                MemberScope::Stable => &directory,
                MemberScope::Versioned => &version_root,
            };
            let path = root.join(path_from_manifest(&member.path));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents(&member.path)).unwrap();
        }
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(version_root.join(MANIFEST_FILE), &manifest_bytes).unwrap();
        fs::write(
            directory.join(CURRENT_POINTER_FILE),
            serde_json::to_vec(&CurrentPointer {
                schema_version: 1,
                build_id: manifest.build_id.clone(),
                suite_version: manifest.suite_version.clone(),
                manifest_sha256: manifest_sha256(&manifest_bytes),
            })
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            resolve_active_suite(&directory).unwrap().version_root,
            version_root
        );
        fs::write(
            directory.join(CURRENT_POINTER_FILE),
            serde_json::to_vec(&CurrentPointer {
                schema_version: 1,
                build_id: manifest.build_id,
                suite_version: manifest.suite_version,
                manifest_sha256: "0".repeat(64),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            resolve_active_suite(&directory).unwrap_err().code(),
            "suite.pointer_identity_mismatch"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn flat_layout_allows_only_the_running_bootstrap_helper() {
        let manifest = manifest();
        let directory = std::env::temp_dir().join(format!(
            "fairypam-flat-suite-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for member in &manifest.members {
            let path = directory.join(path_from_manifest(&member.path));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents(&member.path)).unwrap();
        }
        let bootstrap_helper = directory
            .join(".fairypam-installer/payload/resources/runtime/fairypam-agent-installer.exe");
        fs::create_dir_all(bootstrap_helper.parent().unwrap()).unwrap();
        fs::write(&bootstrap_helper, b"helper").unwrap();
        fs::write(
            directory.join(".fairypam-installer/payload/fairypam-agent-guardian.exe"),
            b"guardian",
        )
        .unwrap();
        fs::write(directory.join("uninstall.exe"), b"uninstaller").unwrap();
        let installed_version = directory.join("versions/suite-1");
        fs::create_dir_all(&installed_version).unwrap();
        for executable in REQUIRED_VERSIONED_EXECUTABLES {
            fs::write(installed_version.join(executable), b"installed").unwrap();
        }

        validate_flat_layout(&directory, &manifest, &bootstrap_helper).unwrap();
        fs::write(installed_version.join("unexpected.exe"), b"unexpected").unwrap();
        assert_eq!(
            validate_flat_layout(&directory, &manifest, &bootstrap_helper)
                .unwrap_err()
                .code(),
            "suite.layout_invalid"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
