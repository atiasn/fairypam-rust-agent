use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::ZipArchive;

const DEV_ARTIFACT_CLASS: &str = "dev-automation";
const TRUSTED_DEV_REPOSITORY: &str = "atiasn/fairypam-rust-agent";
const REQUIRED_ROOT_FILES: &[&str] = &[
    "fairypam-agent.exe",
    "fairypam-agent-guardian.exe",
    "fairypam-agentctl.exe",
    "fairypam-agent-testbed.exe",
    "test-profile-root-public-key.hex",
    "dev-install.ps1",
    "dev-provision.ps1",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevArtifactReceipt {
    pub schema_version: u8,
    pub artifact_class: String,
    pub promotable: bool,
    pub source_commit: String,
    pub public_commit: String,
    pub run_id: String,
    pub run_attempt: String,
    pub build_id: String,
    pub features: Vec<String>,
    pub files: Vec<ArtifactFile>,
    pub zip_sha256: String,
    pub zip_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunIdentity {
    pub repository: String,
    pub run_id: String,
    pub run_attempt: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct DevArtifactError {
    code: &'static str,
    message: String,
}
impl DevArtifactError {
    pub const fn code(&self) -> &'static str {
        self.code
    }
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn verify_dev_artifact(
    zip: &Path,
    receipt: &DevArtifactReceipt,
    expected: &RunIdentity,
) -> Result<(), DevArtifactError> {
    if receipt.schema_version != 1
        || receipt.artifact_class != DEV_ARTIFACT_CLASS
        || receipt.promotable
    {
        return Err(DevArtifactError::new(
            "dev.artifact.promotable_invalid",
            "artifact must be schema 1 dev-automation and non-promotable",
        ));
    }
    if receipt.run_id != expected.run_id
        || receipt.run_attempt != expected.run_attempt
        || expected.repository != TRUSTED_DEV_REPOSITORY
        || !valid_run_id(&expected.run_id)
        || !valid_run_id(&expected.run_attempt)
    {
        return Err(DevArtifactError::new(
            "dev.artifact.run_mismatch",
            "receipt is not bound to the requested GitHub Actions run",
        ));
    }
    if !valid_commit(&receipt.source_commit)
        || !valid_commit(&receipt.public_commit)
        || !valid_features(&receipt.features)
    {
        return Err(DevArtifactError::new(
            "dev.artifact.metadata_invalid",
            "receipt contains invalid Dev artifact metadata",
        ));
    }
    let members = receipt_members(receipt)?;
    let bytes = fs::read(zip)
        .map_err(|error| DevArtifactError::new("dev.artifact.unavailable", error.to_string()))?;
    if bytes.len() as u64 != receipt.zip_size || sha256(&bytes) != receipt.zip_sha256 {
        return Err(DevArtifactError::new(
            "dev.artifact.hash_mismatch",
            "Dev ZIP does not match its receipt",
        ));
    }
    verify_zip_members(zip, &members)?;
    Ok(())
}

fn receipt_members(
    receipt: &DevArtifactReceipt,
) -> Result<BTreeMap<&str, &ArtifactFile>, DevArtifactError> {
    let mut members = BTreeMap::new();
    for file in &receipt.files {
        if !valid_member_path(&file.path) || !valid_hash(&file.sha256) || file.size == 0 {
            return Err(DevArtifactError::new(
                "dev.artifact.members_invalid",
                "receipt contains an unexpected or invalid Dev artifact member",
            ));
        }
        if members.insert(file.path.as_str(), file).is_some() {
            return Err(DevArtifactError::new(
                "dev.artifact.members_invalid",
                "receipt contains duplicate Dev artifact members",
            ));
        }
    }
    if members.is_empty() {
        return Err(DevArtifactError::new(
            "dev.artifact.members_invalid",
            "receipt must contain Dev artifact members",
        ));
    }
    if REQUIRED_ROOT_FILES
        .iter()
        .any(|required| !members.contains_key(required))
    {
        return Err(DevArtifactError::new(
            "dev.artifact.members_invalid",
            "receipt is missing a required Dev artifact member",
        ));
    }
    Ok(members)
}

fn verify_zip_members(
    zip: &Path,
    expected: &BTreeMap<&str, &ArtifactFile>,
) -> Result<(), DevArtifactError> {
    let file = fs::File::open(zip)
        .map_err(|error| DevArtifactError::new("dev.artifact.unavailable", error.to_string()))?;
    let mut archive = ZipArchive::new(file).map_err(|error| {
        DevArtifactError::new("dev.artifact.archive_invalid", error.to_string())
    })?;
    let mut actual = BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            DevArtifactError::new("dev.artifact.archive_invalid", error.to_string())
        })?;
        if entry.is_dir() {
            continue;
        }
        let path = entry.name();
        let Some(metadata) = expected.get(path) else {
            return Err(DevArtifactError::new(
                "dev.artifact.members_invalid",
                "ZIP contains an unexpected Dev artifact member",
            ));
        };
        if !actual.insert(path.to_owned()) {
            return Err(DevArtifactError::new(
                "dev.artifact.members_invalid",
                "ZIP contains duplicate Dev artifact members",
            ));
        }
        if entry.size() != metadata.size {
            return Err(DevArtifactError::new(
                "dev.artifact.members_invalid",
                "ZIP member size does not match its receipt",
            ));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = entry.read(&mut buffer).map_err(|error| {
                DevArtifactError::new("dev.artifact.archive_invalid", error.to_string())
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let digest = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if digest != metadata.sha256 {
            return Err(DevArtifactError::new(
                "dev.artifact.members_invalid",
                "ZIP member hash does not match its receipt",
            ));
        }
    }
    if actual.len() != expected.len() {
        return Err(DevArtifactError::new(
            "dev.artifact.members_invalid",
            "ZIP is missing a Dev artifact member required by its receipt",
        ));
    }
    Ok(())
}

fn valid_member_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains("..")
        && !path.contains("//")
        && ((path.starts_with("profiles/") && !path.ends_with('/'))
            || REQUIRED_ROOT_FILES.contains(&path))
}

fn valid_features(features: &[String]) -> bool {
    features.len() == 2
        && features.iter().any(|feature| feature == "dev-automation")
        && features.iter().any(|feature| feature == "testbed")
}

fn valid_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn replace_current_slot(
    staging: &Path,
    current: &Path,
    previous: &Path,
) -> Result<(), DevArtifactError> {
    if !staging.is_dir() {
        return Err(DevArtifactError::new(
            "dev.artifact.staging_missing",
            "staging slot is missing",
        ));
    }
    if current.exists() {
        if previous.exists() {
            fs::remove_dir_all(previous).map_err(slot_error)?;
        }
        fs::rename(current, previous).map_err(slot_error)?;
    }
    if let Err(error) = fs::rename(staging, current) {
        if previous.exists() {
            let _ = fs::rename(previous, current);
        }
        return Err(slot_error(error));
    }
    Ok(())
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn slot_error(error: std::io::Error) -> DevArtifactError {
    DevArtifactError::new("dev.artifact.slot_replace_failed", error.to_string())
}
