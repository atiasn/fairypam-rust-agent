//! Strict product-suite manifest and update-package validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MANIFEST_FILE: &str = "BUILD-MANIFEST.json";
pub const MANIFEST_KIND: &str = "fairypam-agent-suite";
pub const UPDATE_PACKAGE_KIND: &str = "fairypam-agent-update";
pub const CURRENT_POINTER_FILE: &str = "current.json";
pub const INSTALLER_PROTOCOL_VERSION: u32 = 1;
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub const MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;

const REQUIRED_VERSIONED_EXECUTABLES: [&str; 3] = [
    "fairypam-agent.exe",
    "fairypam-agent-guardian.exe",
    "fairypam-agent-tauri-ui.exe",
];
const REQUIRED_STABLE_EXECUTABLE: &str = "resources/runtime/fairypam-agent-installer.exe";

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
pub struct UpdateRequest {
    pub schema_version: u8,
    pub update_id: String,
    pub source_build_id: String,
    pub target_build_id: String,
    pub suite_version: String,
    pub artifact_sha256: String,
    pub artifact_size: u64,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackage {
    pub manifest: SuiteManifest,
    pub manifest_sha256: String,
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
        if forbidden_production_member(&folded) {
            return Err(invalid_manifest(
                "developer CLI or independent updater is forbidden in the product suite",
            ));
        }
        if REQUIRED_VERSIONED_EXECUTABLES.contains(&folded.as_str()) {
            if member.scope != MemberScope::Versioned {
                return Err(invalid_manifest(
                    "product executable has the wrong installation scope",
                ));
            }
            required_versioned.insert(folded.clone());
        }
        if folded == REQUIRED_STABLE_EXECUTABLE {
            if member.scope != MemberScope::Stable {
                return Err(invalid_manifest("installer helper must be stable"));
            }
            stable_helper = true;
        }
    }
    if required_versioned.len() != REQUIRED_VERSIONED_EXECUTABLES.len() || !stable_helper {
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

pub fn validate_flat_layout(root: &Path, manifest: &SuiteManifest) -> Result<(), SuiteError> {
    validate_manifest(manifest)?;
    for member in &manifest.members {
        validate_file_identity(&root.join(path_from_manifest(&member.path)), member)?;
    }
    reject_forbidden_executables(root, root)
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
    Ok(pointer)
}

pub fn resolve_active_suite(install_root: &Path) -> Result<ActiveSuite, SuiteError> {
    let pointer = read_current_pointer(&install_root.join(CURRENT_POINTER_FILE))?;
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

pub fn validate_update_request(request: &UpdateRequest) -> Result<(), SuiteError> {
    if request.schema_version != 1
        || !safe_identifier(&request.update_id, 128)
        || !safe_identifier(&request.source_build_id, 128)
        || !safe_identifier(&request.target_build_id, 128)
        || request.source_build_id == request.target_build_id
        || Version::parse(&request.suite_version).is_err()
        || !valid_sha256(&request.artifact_sha256)
        || request.artifact_size == 0
        || request.artifact_size > MAX_PACKAGE_BYTES
        || !valid_sha256(&request.manifest_sha256)
    {
        return Err(SuiteError::new(
            "suite.update_request_invalid",
            "update request fields are invalid",
        ));
    }
    Ok(())
}

pub fn validate_update_package(
    package_path: &Path,
    expected_sha256: &str,
    expected_size: u64,
    expected_build_id: &str,
    expected_manifest_sha256: &str,
) -> Result<VerifiedPackage, SuiteError> {
    if !valid_sha256(expected_sha256)
        || !valid_sha256(expected_manifest_sha256)
        || expected_size == 0
        || expected_size > MAX_PACKAGE_BYTES
    {
        return Err(SuiteError::new(
            "suite.metadata_invalid",
            "update metadata is invalid",
        ));
    }
    let metadata = fs::symlink_metadata(package_path)
        .map_err(|error| io_error("suite.package_unavailable", package_path, error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != expected_size
        || sha256_file(package_path)? != expected_sha256
    {
        return Err(SuiteError::new(
            "suite.package_identity_mismatch",
            "update package does not match exact metadata",
        ));
    }

    let file = File::open(package_path)
        .map_err(|error| io_error("suite.package_unavailable", package_path, error))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| SuiteError::new("suite.package_invalid", error.to_string()))?;
    let mut names = BTreeSet::new();
    let mut entries = BTreeMap::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| SuiteError::new("suite.package_invalid", error.to_string()))?;
        let name = entry.name().to_owned();
        validate_member_path(&name)?;
        if entry.is_dir()
            || entry.is_symlink()
            || !names.insert(name.to_ascii_lowercase())
            || entry.size() == 0
            || entry.size() > MAX_MEMBER_BYTES
        {
            return Err(SuiteError::new(
                "suite.package_layout_invalid",
                "update package contains an invalid member",
            ));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_PACKAGE_BYTES {
            return Err(SuiteError::new(
                "suite.package_layout_invalid",
                "update package expands beyond the declared limit",
            ));
        }
        entries.insert(name, entry.size());
    }
    let mut manifest_entry = archive
        .by_name(MANIFEST_FILE)
        .map_err(|_| SuiteError::new("suite.package_layout_invalid", "manifest is missing"))?;
    if manifest_entry.size() > MAX_MANIFEST_BYTES {
        return Err(invalid_manifest("manifest is too large"));
    }
    let mut manifest_bytes = Vec::with_capacity(manifest_entry.size() as usize);
    manifest_entry
        .read_to_end(&mut manifest_bytes)
        .map_err(|error| SuiteError::new("suite.package_invalid", error.to_string()))?;
    drop(manifest_entry);
    if manifest_sha256(&manifest_bytes) != expected_manifest_sha256 {
        return Err(SuiteError::new(
            "suite.manifest_identity_mismatch",
            "package manifest hash does not match metadata",
        ));
    }
    let manifest = parse_manifest(&manifest_bytes)?;
    if manifest.build_id != expected_build_id {
        return Err(SuiteError::new(
            "suite.manifest_identity_mismatch",
            "package build id does not match metadata",
        ));
    }
    let expected_entries = manifest
        .members
        .iter()
        .filter(|member| member.scope == MemberScope::Versioned)
        .map(|member| (member.path.clone(), member.size_bytes))
        .chain(std::iter::once((
            MANIFEST_FILE.to_owned(),
            manifest_bytes.len() as u64,
        )))
        .collect::<BTreeMap<_, _>>();
    if entries != expected_entries {
        return Err(SuiteError::new(
            "suite.package_layout_invalid",
            "package members are not the exact versioned manifest set",
        ));
    }
    Ok(VerifiedPackage {
        manifest,
        manifest_sha256: expected_manifest_sha256.to_owned(),
    })
}

pub fn extract_update_package(
    package_path: &Path,
    install_root: &Path,
    destination: &Path,
    verified: &VerifiedPackage,
) -> Result<(), SuiteError> {
    match destination.symlink_metadata() {
        Ok(_) => {
            return Err(SuiteError::new(
                "suite.stage_exists",
                "update staging destination already exists",
            ));
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(io_error("suite.stage_failed", destination, error));
        }
        Err(_) => {}
    }
    fs::create_dir(destination)
        .map_err(|error| io_error("suite.stage_failed", destination, error))?;
    let result = (|| {
        let file = File::open(package_path)
            .map_err(|error| io_error("suite.package_unavailable", package_path, error))?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|error| SuiteError::new("suite.package_invalid", error.to_string()))?;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|error| SuiteError::new("suite.package_invalid", error.to_string()))?;
            let name = entry.name().to_owned();
            validate_member_path(&name)?;
            let output = destination.join(path_from_manifest(&name));
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| io_error("suite.stage_failed", parent, error))?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .map_err(|error| io_error("suite.stage_failed", &output, error))?;
            io::copy(&mut entry, &mut file)
                .and_then(|_| file.flush())
                .map_err(|error| io_error("suite.stage_failed", &output, error))?;
        }
        validate_active_layout(install_root, destination, &verified.manifest)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}

pub fn compare_versions(candidate: &str, accepted: &str) -> Result<std::cmp::Ordering, SuiteError> {
    let candidate = Version::parse(candidate)
        .map_err(|_| SuiteError::new("suite.version_invalid", "candidate version is invalid"))?;
    let accepted = Version::parse(accepted)
        .map_err(|_| SuiteError::new("suite.version_invalid", "accepted version is invalid"))?;
    Ok(candidate.cmp(&accepted))
}

#[cfg(windows)]
pub fn verify_authenticode_publisher(
    install_root: &Path,
    version_root: &Path,
    manifest: &SuiteManifest,
    allowed_publisher: &str,
    allowed_thumbprint: &str,
) -> Result<(), SuiteError> {
    if allowed_publisher.is_empty()
        || allowed_publisher.len() > 512
        || allowed_publisher.contains(['\r', '\n'])
    {
        return Err(SuiteError::new(
            "suite.publisher_invalid",
            "the compiled update publisher is unavailable",
        ));
    }
    if allowed_thumbprint.len() != 40
        || !allowed_thumbprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SuiteError::new(
            "suite.publisher_invalid",
            "the compiled update certificate pin is unavailable",
        ));
    }
    // ponytail: PowerShell exposes Windows Authenticode policy and signer
    // identity directly; use native crypto APIs only if host policy removes it.
    const SCRIPT: &str = r#"param($p) [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $s=Get-AuthenticodeSignature -LiteralPath $p; if($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate){exit 3}; [Console]::Out.Write($s.SignerCertificate.Subject+"`n"+$s.SignerCertificate.Thumbprint)"#;
    for member in manifest
        .members
        .iter()
        .filter(|member| is_executable_member(&member.path))
    {
        let path = match member.scope {
            MemberScope::Stable => install_root,
            MemberScope::Versioned => version_root,
        }
        .join(path_from_manifest(&member.path));
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                SCRIPT,
            ])
            .arg(&path)
            .output()
            .map_err(|error| io_error("suite.authenticode_unavailable", &path, error))?;
        let identity = String::from_utf8(output.stdout).map_err(|_| {
            SuiteError::new(
                "suite.authenticode_invalid",
                "publisher output is not UTF-8",
            )
        })?;
        if !authenticode_identity_matches(
            output.status.success(),
            &identity,
            allowed_publisher,
            allowed_thumbprint,
        ) {
            return Err(SuiteError::new(
                "suite.authenticode_invalid",
                format!(
                    "member is unsigned or has the wrong publisher: {}",
                    member.path
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn authenticode_identity_matches(
    status_success: bool,
    identity: &str,
    allowed_publisher: &str,
    allowed_thumbprint: &str,
) -> bool {
    identity
        .split_once('\n')
        .is_some_and(|(subject, thumbprint)| {
            status_success
                && subject == allowed_publisher
                && thumbprint.eq_ignore_ascii_case(allowed_thumbprint)
        })
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

fn reject_forbidden_executables(root: &Path, directory: &Path) -> Result<(), SuiteError> {
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
            reject_forbidden_executables(root, &entry.path())?;
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
            if forbidden_production_member(&relative) {
                return Err(SuiteError::new(
                    "suite.layout_invalid",
                    "developer CLI or independent updater is forbidden in the product layout",
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

fn forbidden_production_member(value: &str) -> bool {
    value
        .rsplit('/')
        .next()
        .is_some_and(|name| name == "fairypam-agentctl.exe" || name.contains("updater"))
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
    use std::io::Cursor;

    use super::*;

    fn member(path: &str, scope: MemberScope, contents: &[u8]) -> SuiteMember {
        SuiteMember {
            path: path.to_owned(),
            scope,
            sha256: sha256_bytes(contents),
            size_bytes: contents.len() as u64,
        }
    }

    fn manifest() -> SuiteManifest {
        SuiteManifest {
            schema_version: 1,
            kind: MANIFEST_KIND.to_owned(),
            build_id: "suite-1".to_owned(),
            source_commit: "a".repeat(40),
            suite_version: "1.2.3".to_owned(),
            built_at: "2026-07-25T00:00:00Z".to_owned(),
            build_origin: "github-actions".to_owned(),
            installer_protocol: INSTALLER_PROTOCOL_VERSION,
            members: vec![
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
                member(
                    "fairypam-agent-tauri-ui.exe",
                    MemberScope::Versioned,
                    b"gui",
                ),
                member("profiles/default.json", MemberScope::Versioned, b"profile"),
            ],
        }
    }

    fn package_bytes(manifest: &SuiteManifest, guardian: &[u8]) -> Vec<u8> {
        let manifest_bytes = serde_json::to_vec(manifest).unwrap();
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (path, contents) in [
            (MANIFEST_FILE, manifest_bytes.as_slice()),
            ("fairypam-agent.exe", b"agent".as_slice()),
            ("fairypam-agent-guardian.exe", guardian),
            ("fairypam-agent-tauri-ui.exe", b"gui".as_slice()),
            ("profiles/default.json", b"profile".as_slice()),
        ] {
            writer.start_file(path, options).unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn manifest_rejects_developer_cli_and_missing_product_member() {
        let mut value = manifest();
        value.members.push(member(
            "fairypam-agentctl.exe",
            MemberScope::Versioned,
            b"cli",
        ));
        assert_eq!(
            validate_manifest(&value).unwrap_err().code(),
            "suite.manifest_invalid"
        );

        let mut value = manifest();
        value
            .members
            .retain(|member| member.path != "fairypam-agent-guardian.exe");
        assert_eq!(
            validate_manifest(&value).unwrap_err().code(),
            "suite.manifest_invalid"
        );
    }

    #[test]
    fn update_package_requires_exact_versioned_members_and_outer_identity() {
        let manifest = manifest();
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let bytes = package_bytes(&manifest, b"guardian");
        let directory = std::env::temp_dir().join(format!(
            "fairypam-suite-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let package = directory.join("candidate.zip");
        fs::write(&package, &bytes).unwrap();
        let verified = validate_update_package(
            &package,
            &sha256_bytes(&bytes),
            bytes.len() as u64,
            "suite-1",
            &sha256_bytes(&manifest_bytes),
        )
        .unwrap();
        assert_eq!(verified.manifest.suite_version, "1.2.3");

        assert_eq!(
            validate_update_package(
                &package,
                &"0".repeat(64),
                bytes.len() as u64,
                "suite-1",
                &sha256_bytes(&manifest_bytes),
            )
            .unwrap_err()
            .code(),
            "suite.package_identity_mismatch"
        );

        let mixed = package_bytes(&manifest, b"old!!!!!");
        fs::write(&package, &mixed).unwrap();
        let verified = validate_update_package(
            &package,
            &sha256_bytes(&mixed),
            mixed.len() as u64,
            "suite-1",
            &sha256_bytes(&manifest_bytes),
        )
        .unwrap();
        let destination = directory.join("mixed.pending");
        let helper = directory
            .join("resources")
            .join("runtime")
            .join("fairypam-agent-installer.exe");
        fs::create_dir_all(helper.parent().unwrap()).unwrap();
        fs::write(helper, b"helper").unwrap();
        assert_eq!(
            extract_update_package(&package, &directory, &destination, &verified)
                .unwrap_err()
                .code(),
            "suite.member_identity_mismatch"
        );
        assert!(!destination.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn semantic_version_comparison_is_monotonic() {
        assert_eq!(
            compare_versions("1.2.4", "1.2.3").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("1.2.3-alpha.1", "1.2.3").unwrap(),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_versions("1.2.3", "1.2.3").unwrap(),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn authenticode_identity_rejects_wrong_signer() {
        let publisher = "CN=FairyPam Internal";
        let thumbprint = "0123456789abcdef0123456789abcdef01234567";
        let identity = format!("{publisher}\n{thumbprint}");
        assert!(authenticode_identity_matches(
            true, &identity, publisher, thumbprint
        ));
        assert!(!authenticode_identity_matches(
            true,
            "CN=Other\n0123456789abcdef0123456789abcdef01234567",
            publisher,
            thumbprint,
        ));
        assert!(!authenticode_identity_matches(
            true,
            &format!("{publisher}\n{}", "f".repeat(40)),
            publisher,
            thumbprint,
        ));
        assert!(!authenticode_identity_matches(
            false, &identity, publisher, thumbprint
        ));
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
        fs::create_dir_all(version_root.join("profiles")).unwrap();
        fs::create_dir_all(directory.join("resources").join("runtime")).unwrap();
        for (path, contents) in [
            (
                directory
                    .join("resources")
                    .join("runtime")
                    .join("fairypam-agent-installer.exe"),
                b"helper".as_slice(),
            ),
            (version_root.join("fairypam-agent.exe"), b"agent".as_slice()),
            (
                version_root.join("fairypam-agent-guardian.exe"),
                b"guardian".as_slice(),
            ),
            (
                version_root.join("fairypam-agent-tauri-ui.exe"),
                b"gui".as_slice(),
            ),
            (
                version_root.join("profiles").join("default.json"),
                b"profile".as_slice(),
            ),
        ] {
            fs::write(path, contents).unwrap();
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
}
