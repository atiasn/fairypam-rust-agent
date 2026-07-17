use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path};

use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AgentError;

const ALLOWED_PROFILE_EXTENSIONS: &[&str] = &["json"];
const NORMALIZED_SCALE_PPM: u32 = 1_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileEnvelope {
    pub content: ProfileContent,
    pub content_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileContent {
    pub schema_version: u32,
    pub profile: Profile,
    #[serde(default)]
    pub files: Vec<ProfileFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub version: String,
    pub display_name: String,
    pub target: TargetRules,
    pub capture_sources: Vec<CaptureSource>,
    pub actions: BTreeMap<String, ActionDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetRules {
    pub process_names: Vec<String>,
    pub process_path_sha256: Vec<String>,
    pub window_classes: Vec<String>,
    pub title_patterns: Vec<String>,
    #[serde(default)]
    pub require_elevated: bool,
    pub minimum_client_width: u32,
    pub minimum_client_height: u32,
    pub minimum_dpi: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaptureSource {
    pub id: String,
    pub region: CaptureRegion,
    pub maximum_fps: u32,
    pub encodings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureRegion {
    FullClient,
    NormalizedRoi {
        x_ppm: u32,
        y_ppm: u32,
        width_ppm: u32,
        height_ppm: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionDefinition {
    Hold { scan_code: u16 },
    Pulse { scan_code: u16 },
    RelativeMouse { maximum_delta: i32 },
    ClientPointClick { button: ClientPointButton },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientPointButton {
    Left,
    Right,
    Middle,
}

pub trait SignatureVerifier: Send + Sync {
    fn verify(&self, digest: &[u8; 32], signature: &str) -> bool;
}

#[derive(Clone, Debug)]
pub struct Ed25519SignatureVerifier {
    key: VerifyingKey,
}

impl Ed25519SignatureVerifier {
    pub fn from_public_key_hex(value: &str) -> Result<Self, AgentError> {
        let bytes = decode_fixed_hex::<32>(value).ok_or_else(|| {
            AgentError::new(
                "profile.root_key_invalid",
                "Profile root public key must be exactly 32 bytes of hex",
            )
        })?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|error| AgentError::new("profile.root_key_invalid", error.to_string()))?;
        Ok(Self { key })
    }
}

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(&self, digest: &[u8; 32], signature: &str) -> bool {
        let Some(bytes) = decode_fixed_hex::<64>(signature) else {
            return false;
        };
        self.key
            .verify_strict(digest, &Signature::from_bytes(&bytes))
            .is_ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProfile {
    content: ProfileContent,
    content_sha256: String,
}

impl VerifiedProfile {
    pub const fn profile(&self) -> &Profile {
        &self.content.profile
    }

    pub fn files(&self) -> &[ProfileFile] {
        &self.content.files
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }
}

pub fn profile_content_sha256(content: &ProfileContent) -> Result<String, AgentError> {
    Ok(hex_digest(&profile_content_digest(content)?))
}

pub fn verify_profile(
    bytes: &[u8],
    verifier: &dyn SignatureVerifier,
) -> Result<VerifiedProfile, AgentError> {
    let envelope: ProfileEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        AgentError::new(
            "profile.schema_invalid",
            format!("profile envelope is not valid strict JSON: {error}"),
        )
    })?;
    let digest = profile_content_digest(&envelope.content)?;
    let actual_hash = hex_digest(&digest);
    if envelope.content_sha256 != actual_hash {
        return Err(AgentError::new(
            "profile.hash_mismatch",
            "profile content hash does not match the signed envelope",
        ));
    }
    if envelope.signature.is_empty() || !verifier.verify(&digest, &envelope.signature) {
        return Err(AgentError::new(
            "profile.signature_invalid",
            "profile signature is missing or invalid",
        ));
    }
    validate_content(&envelope.content)?;
    Ok(VerifiedProfile {
        content: envelope.content,
        content_sha256: actual_hash,
    })
}

fn profile_content_digest(content: &ProfileContent) -> Result<[u8; 32], AgentError> {
    let canonical = serde_json::to_vec(content).map_err(|error| {
        AgentError::new(
            "profile.schema_invalid",
            format!("profile content cannot be canonicalized: {error}"),
        )
    })?;
    Ok(Sha256::digest(canonical).into())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_content(content: &ProfileContent) -> Result<(), AgentError> {
    if content.schema_version != 1 {
        return Err(AgentError::new(
            "profile.schema_invalid",
            "unsupported profile schema version",
        ));
    }
    validate_profile_identity(&content.profile)?;
    validate_files(&content.files)?;
    validate_target_rules(&content.profile.target)?;
    validate_capture_sources(&content.profile.capture_sources)?;
    validate_actions(&content.profile.actions)
}

fn validate_profile_identity(profile: &Profile) -> Result<(), AgentError> {
    let id_is_valid = !profile.id.is_empty()
        && profile
            .id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !id_is_valid
        || profile.display_name.trim().is_empty()
        || Version::parse(&profile.version).is_err()
    {
        return Err(AgentError::new(
            "profile.schema_invalid",
            "profile id, display name, or semantic version is invalid",
        ));
    }
    Ok(())
}

fn validate_files(files: &[ProfileFile]) -> Result<(), AgentError> {
    for file in files {
        let path = Path::new(&file.path);
        let path_is_relative = !path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_) | Component::CurDir));
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase);
        if !extension
            .as_deref()
            .is_some_and(|value| ALLOWED_PROFILE_EXTENSIONS.contains(&value))
        {
            return Err(AgentError::new(
                "profile.executable_content",
                format!("profile file extension is not allowed: {}", file.path),
            ));
        }
        if !path_is_relative || !is_sha256(&file.sha256) {
            return Err(AgentError::new(
                "profile.schema_invalid",
                "profile file path or hash is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_target_rules(target: &TargetRules) -> Result<(), AgentError> {
    let dimensions_are_valid = target.minimum_client_width > 0
        && target.minimum_client_height > 0
        && target.minimum_dpi >= 72;
    if target.process_names.is_empty()
        || target.process_path_sha256.is_empty()
        || target.window_classes.is_empty()
        || target.title_patterns.is_empty()
        || !all_non_empty(&target.process_names)
        || !all_non_empty(&target.window_classes)
        || !all_non_empty(&target.title_patterns)
        || !target
            .process_path_sha256
            .iter()
            .all(|value| is_sha256(value))
        || !dimensions_are_valid
    {
        return Err(AgentError::new(
            "profile.target_rules_invalid",
            "profile must define exact process, path, class, title, size, and DPI rules",
        ));
    }
    Ok(())
}

fn validate_capture_sources(sources: &[CaptureSource]) -> Result<(), AgentError> {
    let mut ids = HashSet::new();
    let valid = !sources.is_empty()
        && sources.iter().all(|source| {
            !source.id.is_empty()
                && ids.insert(source.id.as_str())
                && (1..=120).contains(&source.maximum_fps)
                && !source.encodings.is_empty()
                && source
                    .encodings
                    .iter()
                    .all(|encoding| matches!(encoding.as_str(), "jpeg" | "png"))
                && capture_region_is_valid(&source.region)
        });
    if !valid {
        return Err(AgentError::new(
            "profile.capture_invalid",
            "capture sources must be unique and use bounded supported encodings",
        ));
    }
    Ok(())
}

fn validate_actions(actions: &BTreeMap<String, ActionDefinition>) -> Result<(), AgentError> {
    let valid = !actions.is_empty()
        && actions.iter().all(|(id, definition)| {
            let id_is_valid = !id.is_empty()
                && id.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                });
            let definition_is_valid = match definition {
                ActionDefinition::Hold { scan_code } | ActionDefinition::Pulse { scan_code } => {
                    *scan_code > 0
                }
                ActionDefinition::RelativeMouse { maximum_delta } => {
                    (1..=2_000).contains(maximum_delta)
                }
                ActionDefinition::ClientPointClick { .. } => true,
            };
            id_is_valid && definition_is_valid
        });
    if !valid {
        return Err(AgentError::new(
            "profile.action_invalid",
            "profile action map contains an invalid semantic action",
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(output)
}

fn all_non_empty(values: &[String]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
}

fn capture_region_is_valid(region: &CaptureRegion) -> bool {
    match region {
        CaptureRegion::FullClient => true,
        CaptureRegion::NormalizedRoi {
            x_ppm,
            y_ppm,
            width_ppm,
            height_ppm,
        } => {
            *width_ppm > 0
                && *height_ppm > 0
                && x_ppm
                    .checked_add(*width_ppm)
                    .is_some_and(|right| right <= NORMALIZED_SCALE_PPM)
                && y_ppm
                    .checked_add(*height_ppm)
                    .is_some_and(|bottom| bottom <= NORMALIZED_SCALE_PPM)
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn ed25519_verifier_accepts_only_strict_hex_signature() {
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let public_hex = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let verifier = Ed25519SignatureVerifier::from_public_key_hex(&public_hex).unwrap();
        let digest = [3_u8; 32];
        let signature = signing
            .sign(&digest)
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert!(verifier.verify(&digest, &signature));
        assert!(!verifier.verify(&[4_u8; 32], &signature));
        assert!(!verifier.verify(&digest, "not-hex"));
    }

    #[test]
    fn ed25519_root_requires_exact_public_key_length() {
        let error = Ed25519SignatureVerifier::from_public_key_hex("00").unwrap_err();

        assert_eq!(error.code(), "profile.root_key_invalid");
    }
}
