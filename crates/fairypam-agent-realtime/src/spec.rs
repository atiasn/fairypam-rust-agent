use std::collections::BTreeSet;

use fairypam_agent_core::profile::SignatureVerifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::program::MUSIC_AUTOPLAY_PROGRAM_ID;
use crate::RealtimeError;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RealtimeProgramEnvelope {
    pub content: RealtimeProgramSpec,
    pub content_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RealtimeProgramSpec {
    pub id: String,
    pub schema_version: u32,
    pub kind: String,
    pub engine: String,
    pub required_client_size: ClientSize,
    pub sample_interval_us: u32,
    pub event_freshness_us: u32,
    pub lanes: Vec<LaneSpec>,
    pub safety: SafetySpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientSize {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaneSpec {
    pub action_id: String,
    pub x_ppm: u32,
    pub y_ppm: u32,
    pub channel: String,
    pub press_below: u8,
    pub release_at_or_above: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafetySpec {
    pub require_foreground: bool,
    pub reject_local_input: bool,
    pub target_revalidate_ms: u32,
    pub maximum_queue_depth: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRealtimeSpec {
    content: RealtimeProgramSpec,
    digest: String,
}

impl VerifiedRealtimeSpec {
    pub fn verify(bytes: &[u8], verifier: &dyn SignatureVerifier) -> Result<Self, RealtimeError> {
        let envelope: RealtimeProgramEnvelope = serde_json::from_slice(bytes)
            .map_err(|error| RealtimeError::new("realtime.spec_invalid", error.to_string()))?;
        validate(&envelope.content)?;
        let canonical = serde_json::to_vec(&envelope.content)
            .map_err(|error| RealtimeError::new("realtime.spec_invalid", error.to_string()))?;
        let digest_bytes: [u8; 32] = Sha256::digest(&canonical).into();
        let digest = digest_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if envelope.content_sha256 != digest {
            return Err(RealtimeError::new(
                "realtime.spec_hash_mismatch",
                "realtime spec content hash does not match",
            ));
        }
        if !verifier.verify(&digest_bytes, &envelope.signature) {
            return Err(RealtimeError::new(
                "realtime.spec_signature_invalid",
                "realtime spec signature is invalid",
            ));
        }
        Ok(Self {
            content: envelope.content,
            digest,
        })
    }

    pub const fn spec(&self) -> &RealtimeProgramSpec {
        &self.content
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn validate(spec: &RealtimeProgramSpec) -> Result<(), RealtimeError> {
    let mut actions = BTreeSet::new();
    let valid = spec.id == MUSIC_AUTOPLAY_PROGRAM_ID
        && spec.schema_version == 1
        && spec.kind == "pixel-threshold-key-state"
        && spec.engine == "independent-six-lane"
        && spec.required_client_size.width == 1_920
        && spec.required_client_size.height == 1_080
        && spec.sample_interval_us == 5_000
        && spec.event_freshness_us == 80_000
        && spec.lanes.len() == 6
        && spec.lanes.iter().all(|lane| {
            !lane.action_id.is_empty()
                && actions.insert(&lane.action_id)
                && lane.x_ppm <= 1_000_000
                && lane.y_ppm <= 1_000_000
                && lane.channel == "blue"
                && lane.press_below == lane.release_at_or_above
        })
        && spec.safety.require_foreground
        && spec.safety.reject_local_input
        && spec.safety.target_revalidate_ms == 250
        && spec.safety.maximum_queue_depth == 32;
    if !valid {
        return Err(RealtimeError::new(
            "realtime.spec_invalid",
            "spec is outside the installed music program policy",
        ));
    }
    Ok(())
}
