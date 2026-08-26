use std::collections::BTreeSet;
use std::path::{Component, Path};

use fairypam_agent_core::profile::SignatureVerifier;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MaaRuntimeError;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLock {
    pub schema_version: u32,
    pub sdk_version: String,
    pub maa_framework_rs_version: String,
    pub maa_framework_sys_version: String,
    pub architecture: String,
    pub release_tag: String,
    pub release_asset: String,
    pub release_url: String,
    pub release_sha256: String,
    pub compatibility_profile: String,
    pub minimum_agent_version: String,
    pub expected_maa_version: String,
    pub files: Vec<RuntimeFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRuntimeManifest {
    pub content: RuntimeLock,
    pub content_sha256: String,
    pub signature: String,
}

impl RuntimeLock {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MaaRuntimeError> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| MaaRuntimeError::new("maa.manifest_invalid", error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), MaaRuntimeError> {
        let mut paths = BTreeSet::new();
        let minimum_agent_version = Version::parse(&self.minimum_agent_version).map_err(|_| {
            MaaRuntimeError::new(
                "maa.manifest_invalid",
                "minimum Agent version is not semantic versioning",
            )
        })?;
        let current_agent_version = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| {
            MaaRuntimeError::new(
                "maa.runtime_incompatible",
                "current Agent version is not semantic versioning",
            )
        })?;
        let valid = self.schema_version == 1
            && self.sdk_version == "5.12.3"
            && self.maa_framework_rs_version == "1.20.0"
            && self.maa_framework_sys_version == "5.12.1"
            && self.architecture == "x86_64-pc-windows-msvc"
            && self.release_tag == "v5.12.3"
            && self.release_asset == "MAA-win-x86_64-v5.12.3.zip"
            && self.compatibility_profile == "fairypam-win32-maa-5.12-v1"
            && self.expected_maa_version == "5.12.3"
            && is_sha256(&self.release_sha256)
            && !self.files.is_empty()
            && self.files.iter().all(|file| {
                is_safe_relative_path(&file.path)
                    && is_sha256(&file.sha256)
                    && paths.insert(file.path.to_ascii_lowercase())
            });
        if !valid {
            return Err(MaaRuntimeError::new(
                "maa.manifest_invalid",
                "runtime lock does not match the frozen compatibility profile",
            ));
        }
        if current_agent_version < minimum_agent_version {
            return Err(MaaRuntimeError::new(
                "maa.runtime_incompatible",
                "runtime requires a newer FairyPam Agent",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, MaaRuntimeError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| MaaRuntimeError::new("maa.manifest_invalid", error.to_string()))?;
        Ok(hex_sha256(&bytes))
    }
}

impl SignedRuntimeManifest {
    pub fn verify(
        bytes: &[u8],
        verifier: &dyn SignatureVerifier,
    ) -> Result<RuntimeLock, MaaRuntimeError> {
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| MaaRuntimeError::new("maa.manifest_invalid", error.to_string()))?;
        envelope.content.validate()?;
        let digest = envelope.content.digest()?;
        if digest != envelope.content_sha256 {
            return Err(MaaRuntimeError::new(
                "maa.manifest_hash_mismatch",
                "runtime manifest content hash does not match",
            ));
        }
        let digest_bytes: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&envelope.content).map_err(|error| {
                MaaRuntimeError::new("maa.manifest_invalid", error.to_string())
            })?)
            .into();
        if !verifier.verify(&digest_bytes, &envelope.signature) {
            return Err(MaaRuntimeError::new(
                "maa.manifest_signature_invalid",
                "runtime manifest signature is invalid",
            ));
        }
        Ok(envelope.content)
    }
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}
