//! Fail-closed identity and transaction primitives for the Windows Agent suite.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(windows)]
use windows::Win32::Foundation::MAX_PATH;
#[cfg(windows)]
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

pub const MANIFEST_FILE: &str = "BUILD-MANIFEST.json";
pub const SUITE_SCHEMA_VERSION: u32 = 2;
pub const REQUIRED_MEMBERS: &[&str] = &[
    "FairyPamAgentSetup.exe",
    "fairypam-agent.exe",
    "fairypam-agent-guardian.exe",
    "fairypam-agent-updater.exe",
    "fairypam-agent-ui.exe",
    "fairypam-agentctl.exe",
    "protocol/fairypam-agent-v1.proto",
    "resources/install-windows-agent-suite.ps1",
    "resources/update-windows-agent-suite.ps1",
    "resources/profiles/fairypam-test-window/profile.json",
    "resources/profiles/genshin-impact/profile.json",
    "resources/test-profile-root-public-key.hex",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuiteManifest {
    pub schema_version: u32,
    pub kind: String,
    pub build_id: String,
    pub source_commit: String,
    pub public_commit: String,
    pub suite_version: String,
    pub platform: String,
    pub build_source: BuildSource,
    pub compatibility: Compatibility,
    pub members: BTreeMap<String, SuiteMember>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildSource {
    pub workflow: String,
    pub run_id: String,
    pub run_attempt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub agent_protocol_major: u16,
    pub guardian_protocol_major: u16,
    pub local_protocol_major: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuiteMember {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSuite {
    pub root: PathBuf,
    pub manifest: SuiteManifest,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TufPolicy {
    pub verifier_executable: PathBuf,
    pub verifier_authenticode_publisher: String,
    pub trusted_root: PathBuf,
    pub datastore_dir: PathBuf,
    pub metadata_url: String,
    pub targets_url: String,
    pub target_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionSecurityPolicy {
    pub suite_authenticode_publisher: String,
    pub tuf: TufPolicy,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SuiteError {
    #[error("suite.io_failed: {0}")]
    Io(String),
    #[error("suite.manifest_invalid: {0}")]
    Manifest(String),
    #[error("suite.member_invalid: {0}")]
    Member(String),
    #[error("suite.security_configuration_invalid: {0}")]
    SecurityConfiguration(String),
    #[error("suite.tuf_verification_failed: {0}")]
    Tuf(String),
    #[error("suite.authenticode_verification_failed: {0}")]
    Authenticode(String),
    #[error("suite.command_failed: {0}")]
    Command(String),
}

impl SuiteManifest {
    pub fn load_and_verify(root: &Path) -> Result<VerifiedSuite, SuiteError> {
        let root = absolute_directory(root)?;
        let manifest_path = root.join(MANIFEST_FILE);
        let raw = read_regular_file(&manifest_path, 1024 * 1024)?;
        let manifest: Self = serde_json::from_slice(&raw)
            .map_err(|error| SuiteError::Manifest(error.to_string()))?;
        manifest.validate_identity()?;
        manifest.verify_members(&root)?;
        Ok(VerifiedSuite {
            root,
            manifest,
            manifest_sha256: sha256_bytes(&raw),
        })
    }

    pub fn validate_identity(&self) -> Result<(), SuiteError> {
        if self.schema_version != SUITE_SCHEMA_VERSION
            || self.kind != "fairypam-windows-agent-suite"
            || self.platform != "windows-x64"
        {
            return Err(SuiteError::Manifest("unsupported suite identity".into()));
        }
        validate_label(&self.build_id, "build_id", 128)?;
        validate_commit(&self.source_commit, "source_commit")?;
        validate_commit(&self.public_commit, "public_commit")?;
        Version::parse(&self.suite_version)
            .map_err(|_| SuiteError::Manifest("suite_version must be semver".into()))?;
        if self.compatibility.agent_protocol_major != 1
            || self.compatibility.guardian_protocol_major != 1
            || self.compatibility.local_protocol_major != 1
        {
            return Err(SuiteError::Manifest(
                "unsupported protocol compatibility".into(),
            ));
        }
        validate_label(&self.build_source.workflow, "build_source.workflow", 128)?;
        validate_label(&self.build_source.run_id, "build_source.run_id", 64)?;
        validate_label(
            &self.build_source.run_attempt,
            "build_source.run_attempt",
            32,
        )?;
        let expected: BTreeSet<_> = REQUIRED_MEMBERS
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        let actual: BTreeSet<_> = self.members.keys().cloned().collect();
        if actual != expected {
            return Err(SuiteError::Manifest(
                "suite members are not the exact allowlist".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_members(&self, root: &Path) -> Result<(), SuiteError> {
        let mut disk = BTreeSet::new();
        collect_files(root, root, &mut disk)?;
        disk.remove(MANIFEST_FILE);
        let declared: BTreeSet<_> = self.members.keys().cloned().collect();
        if disk != declared {
            return Err(SuiteError::Member(
                "candidate contains missing or undeclared files".into(),
            ));
        }
        for (relative, expected) in &self.members {
            validate_relative_path(relative)?;
            if expected.size_bytes == 0 || !valid_sha256(&expected.sha256) {
                return Err(SuiteError::Member(format!(
                    "invalid identity for {relative}"
                )));
            }
            let path = root.join(relative);
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(SuiteError::Member(format!(
                    "member is not a regular file: {relative}"
                )));
            }
            if metadata.len() != expected.size_bytes || sha256_file(&path)? != expected.sha256 {
                return Err(SuiteError::Member(format!(
                    "member identity mismatch: {relative}"
                )));
            }
        }
        Ok(())
    }

    pub fn reject_unauthorized_downgrade(
        &self,
        current_version: &str,
        rollback_authorized: bool,
    ) -> Result<(), SuiteError> {
        let current = Version::parse(current_version)
            .map_err(|_| SuiteError::Manifest("installed version is invalid".into()))?;
        let target = Version::parse(&self.suite_version)
            .map_err(|_| SuiteError::Manifest("target version is invalid".into()))?;
        if target < current && !rollback_authorized {
            return Err(SuiteError::Manifest("unauthorized suite downgrade".into()));
        }
        Ok(())
    }
}

impl ProductionSecurityPolicy {
    pub fn validate_configuration(&self) -> Result<(), SuiteError> {
        validate_publisher(&self.suite_authenticode_publisher, "suite publisher")?;
        validate_publisher(
            &self.tuf.verifier_authenticode_publisher,
            "TUF verifier publisher",
        )?;
        if !self.tuf.verifier_executable.is_absolute()
            || !self.tuf.trusted_root.is_absolute()
            || !self.tuf.datastore_dir.is_absolute()
        {
            return Err(SuiteError::SecurityConfiguration(
                "TUF paths must be absolute".into(),
            ));
        }
        if !self.tuf.metadata_url.starts_with("https://")
            || !self.tuf.targets_url.starts_with("https://")
            || self.tuf.target_name.is_empty()
            || Path::new(&self.tuf.target_name)
                .file_name()
                .and_then(|v| v.to_str())
                != Some(self.tuf.target_name.as_str())
        {
            return Err(SuiteError::SecurityConfiguration(
                "TUF URLs must use HTTPS and target_name must be a basename".into(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SuiteError> {
        self.validate_configuration()?;
        for (path, label) in [
            (&self.tuf.verifier_executable, "TUF verifier"),
            (&self.tuf.trusted_root, "TUF root"),
        ] {
            if !path.is_file()
                || fs::symlink_metadata(path)
                    .map_err(io_error)?
                    .file_type()
                    .is_symlink()
            {
                return Err(SuiteError::SecurityConfiguration(format!(
                    "{label} must be an existing protected absolute regular file"
                )));
            }
        }
        if !self.tuf.datastore_dir.is_dir() {
            return Err(SuiteError::SecurityConfiguration(
                "TUF datastore must be an existing protected absolute directory".into(),
            ));
        }
        #[cfg(windows)]
        for path in [
            &self.tuf.verifier_executable,
            &self.tuf.trusted_root,
            &self.tuf.datastore_dir,
        ] {
            verify_protected_windows_path(path)?;
        }
        Ok(())
    }
}

/// Runs the administrator-provisioned AWS `tuftool` from a protected absolute path.
/// Tough performs signature threshold, expiry, rollback, freeze and target hash checks.
pub fn download_verified_tuf_target(
    policy: &ProductionSecurityPolicy,
    output: &Path,
) -> Result<PathBuf, SuiteError> {
    policy.validate()?;
    #[cfg(windows)]
    verify_authenticode_file(
        &policy.tuf.verifier_executable,
        &policy.tuf.verifier_authenticode_publisher,
    )?;
    if !output.is_absolute() || output.exists() {
        return Err(SuiteError::Tuf(
            "output must be a new absolute directory".into(),
        ));
    }
    fs::create_dir_all(output).map_err(io_error)?;
    let status = Command::new(&policy.tuf.verifier_executable)
        .args([
            "download",
            "--root",
            path_text(&policy.tuf.trusted_root)?,
            "-t",
            &policy.tuf.targets_url,
            "-m",
            &policy.tuf.metadata_url,
            path_text(&policy.tuf.datastore_dir)?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| SuiteError::Tuf(error.to_string()))?;
    if !status.success() {
        return Err(SuiteError::Tuf(format!("tuftool exited with {status}")));
    }
    let verified = policy.tuf.datastore_dir.join(&policy.tuf.target_name);
    if !verified.is_file()
        || fs::symlink_metadata(&verified)
            .map_err(io_error)?
            .file_type()
            .is_symlink()
    {
        return Err(SuiteError::Tuf(
            "verified target is missing or unsafe".into(),
        ));
    }
    let target = output.join(&policy.tuf.target_name);
    fs::copy(&verified, &target).map_err(io_error)?;
    Ok(target)
}

/// Uses Windows' Authenticode trust provider through the built-in PowerShell cmdlet.
pub fn verify_authenticode_suite(
    suite: &VerifiedSuite,
    policy: &ProductionSecurityPolicy,
) -> Result<(), SuiteError> {
    policy.validate()?;
    verify_authenticode_suite_publisher(suite, &policy.suite_authenticode_publisher)
}

pub fn verify_authenticode_suite_publisher(
    suite: &VerifiedSuite,
    publisher: &str,
) -> Result<(), SuiteError> {
    validate_publisher(publisher, "suite publisher")?;
    for relative in suite
        .manifest
        .members
        .keys()
        .filter(|path| path.ends_with(".exe"))
    {
        let path = suite.root.join(relative);
        verify_authenticode_file(&path, publisher).map_err(|_| {
            SuiteError::Authenticode(format!("publisher verification failed: {relative}"))
        })?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn authenticode_publisher(path: &Path) -> Result<String, SuiteError> {
    let script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$s=Get-AuthenticodeSignature -LiteralPath $args[0];if($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate){exit 9};[Console]::Out.Write($s.SignerCertificate.Subject)";
    let output = Command::new(windows_powershell()?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            path_text(path)?,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| SuiteError::Authenticode(error.to_string()))?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(SuiteError::Authenticode(
            "valid publisher identity is unavailable".into(),
        ));
    }
    let publisher = String::from_utf8(output.stdout)
        .map_err(|_| SuiteError::Authenticode("publisher identity is not UTF-8".into()))?;
    validate_publisher(&publisher, "suite publisher")?;
    Ok(publisher)
}

#[cfg(windows)]
pub fn verify_protected_windows_path(path: &Path) -> Result<(), SuiteError> {
    let script = "$i=Get-Item -Force -LiteralPath $args[0];if(($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){exit 11};$a=Get-Acl -LiteralPath $args[0];$b=@($a.Access|?{$_.AccessControlType -eq 'Allow' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' -and $_.IdentityReference.Value -match 'Everyone|Authenticated Users|\\Users$'});if($b.Count -ne 0){exit 10}";
    let status = Command::new(windows_powershell()?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            path_text(path)?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| SuiteError::SecurityConfiguration(error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(SuiteError::SecurityConfiguration(
            "security path is writable by a broad principal".into(),
        ))
    }
}

#[cfg(windows)]
fn verify_authenticode_file(path: &Path, publisher: &str) -> Result<(), SuiteError> {
    let script = "$s=Get-AuthenticodeSignature -LiteralPath $args[0]; if($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate -or $s.SignerCertificate.Subject -cne $args[1]){exit 9}";
    let status = Command::new(windows_powershell()?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            path_text(path)?,
            publisher,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| SuiteError::Authenticode(error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(SuiteError::Authenticode(
            "publisher verification failed".into(),
        ))
    }
}

#[cfg(windows)]
pub fn windows_powershell() -> Result<PathBuf, SuiteError> {
    let mut buffer = [0_u16; MAX_PATH as usize];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(SuiteError::SecurityConfiguration(
            "cannot locate Windows System32".into(),
        ));
    }
    let system = String::from_utf16(&buffer[..length]).map_err(|error| {
        SuiteError::SecurityConfiguration(format!("System32 path is invalid: {error}"))
    })?;
    let path = powershell_path_from_system_directory(Path::new(&system))?;
    let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SuiteError::SecurityConfiguration(
            "Windows PowerShell is missing or unsafe".into(),
        ));
    }
    Ok(path)
}

#[cfg(any(windows, test))]
fn powershell_path_from_system_directory(system: &Path) -> Result<PathBuf, SuiteError> {
    if !system.is_absolute() {
        return Err(SuiteError::SecurityConfiguration(
            "Windows System32 path is not absolute".into(),
        ));
    }
    Ok(system
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
}

#[cfg(not(windows))]
fn verify_authenticode_file(_path: &Path, _publisher: &str) -> Result<(), SuiteError> {
    Err(SuiteError::Authenticode(
        "Authenticode verification requires Windows".into(),
    ))
}

pub fn sha256_file(path: &Path) -> Result<String, SuiteError> {
    let mut file = fs::File::open(path).map_err(io_error)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn collect_files(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
) -> Result<(), SuiteError> {
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let metadata = entry.file_type().map_err(io_error)?;
        if metadata.is_symlink() {
            return Err(SuiteError::Member(
                "suite contains a symlink or reparse entry".into(),
            ));
        }
        if metadata.is_dir() {
            collect_files(root, &entry.path(), output)?;
        } else if metadata.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| SuiteError::Member("member escaped suite root".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            output.insert(relative);
        } else {
            return Err(SuiteError::Member("suite contains a non-file entry".into()));
        }
    }
    Ok(())
}

fn absolute_directory(path: &Path) -> Result<PathBuf, SuiteError> {
    if !path.is_absolute() {
        return Err(SuiteError::Manifest("suite root must be absolute".into()));
    }
    let path = fs::canonicalize(path).map_err(io_error)?;
    if !path.is_dir() {
        return Err(SuiteError::Manifest("suite root is not a directory".into()));
    }
    Ok(path)
}

fn read_regular_file(path: &Path, limit: u64) -> Result<Vec<u8>, SuiteError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(SuiteError::Manifest(
            "manifest is missing, unsafe or too large".into(),
        ));
    }
    fs::read(path).map_err(io_error)
}

fn validate_relative_path(value: &str) -> Result<(), SuiteError> {
    let path = Path::new(value);
    if value.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(SuiteError::Member(format!("unsafe member path: {value}")));
    }
    Ok(())
}

fn validate_label(value: &str, name: &str, max: usize) -> Result<(), SuiteError> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(SuiteError::Manifest(format!("invalid {name}")));
    }
    Ok(())
}

fn validate_commit(value: &str, name: &str) -> Result<(), SuiteError> {
    if !(40..=64).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SuiteError::Manifest(format!("invalid {name}")));
    }
    Ok(())
}

fn validate_publisher(value: &str, label: &str) -> Result<(), SuiteError> {
    let value = value.trim();
    if value.is_empty()
        || value.contains("TODO")
        || value.contains("CHANGEME")
        || !value.contains('=')
    {
        return Err(SuiteError::SecurityConfiguration(format!(
            "an exact production {label} subject is required"
        )));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn io_error(error: std::io::Error) -> SuiteError {
    SuiteError::Io(error.to_string())
}
fn path_text(path: &Path) -> Result<&str, SuiteError> {
    path.to_str()
        .ok_or_else(|| SuiteError::Command("path is not Unicode".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_policy_requires_an_independent_tuf_verifier_publisher() {
        let mut value = serde_json::json!({
            "suite_authenticode_publisher": "CN=FairyPam Suite",
            "tuf": {
                "verifier_executable": "C:/Program Files/FairyPam/tuftool.exe",
                "verifier_authenticode_publisher": "CN=AWS TUF Verifier",
                "trusted_root": "C:/ProgramData/FairyPam/root.json",
                "datastore_dir": "C:/ProgramData/FairyPam/tuf",
                "metadata_url": "https://updates.example/metadata",
                "targets_url": "https://updates.example/targets",
                "target_name": "suite.zip"
            }
        });
        let policy: ProductionSecurityPolicy = serde_json::from_value(value.clone()).unwrap();
        assert_ne!(
            policy.suite_authenticode_publisher,
            policy.tuf.verifier_authenticode_publisher
        );
        value["tuf"]
            .as_object_mut()
            .unwrap()
            .remove("verifier_authenticode_publisher");
        assert!(serde_json::from_value::<ProductionSecurityPolicy>(value).is_err());
    }

    #[test]
    fn powershell_path_is_absolute_and_beneath_system32() {
        let system = Path::new(if cfg!(windows) {
            r"C:\Windows\System32"
        } else {
            "/Windows/System32"
        });
        let path = powershell_path_from_system_directory(system).unwrap();
        assert_eq!(
            path,
            system
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        );
        assert!(powershell_path_from_system_directory(Path::new("System32")).is_err());
    }
}
