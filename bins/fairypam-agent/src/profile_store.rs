use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fairypam_agent_core::profile::{verify_profile, SignatureVerifier, VerifiedProfile};
use fairypam_agent_core::AgentError;

#[derive(Clone, Debug, Default)]
pub struct ProfileStore {
    profiles: BTreeMap<String, VerifiedProfile>,
}

impl ProfileStore {
    pub fn load(root: &Path, verifier: &dyn SignatureVerifier) -> Result<Self, AgentError> {
        Self::load_with_optional_empty(root, verifier, false)
    }

    /// Loads the signed Profile store while allowing an enrolled Agent to stay
    /// online before Profiles have been delivered. Any present Profile remains
    /// subject to the same strict layout and signature verification as `load`.
    pub fn load_optional(
        root: &Path,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Self, AgentError> {
        Self::load_with_optional_empty(root, verifier, true)
    }

    fn load_with_optional_empty(
        root: &Path,
        verifier: &dyn SignatureVerifier,
        optional_empty: bool,
    ) -> Result<Self, AgentError> {
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if optional_empty && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(AgentError::new(
                    "profile.store_unavailable",
                    format!("cannot read Profile directory {}: {error}", root.display()),
                ))
            }
        };
        let mut paths = entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| AgentError::new("profile.store_unavailable", error.to_string()))?;
        paths.sort();

        let mut profiles = BTreeMap::new();
        for path in paths {
            let profile_path = installed_profile_path(&path)?;
            let bytes = fs::read(&profile_path).map_err(|error| {
                AgentError::new(
                    "profile.store_unavailable",
                    format!("cannot read {}: {error}", profile_path.display()),
                )
            })?;
            let verified = verify_profile(&bytes, verifier)?;
            let profile_id = verified.profile().id.clone();
            if profiles.insert(profile_id.clone(), verified).is_some() {
                return Err(AgentError::new(
                    "profile.duplicate",
                    format!("Profile id is installed more than once: {profile_id}"),
                ));
            }
        }
        if profiles.is_empty() && !optional_empty {
            return Err(AgentError::new(
                "profile.store_empty",
                "Profile directory contains no installed profiles",
            ));
        }
        Ok(Self { profiles })
    }

    pub fn get(&self, profile_id: &str) -> Result<&VerifiedProfile, AgentError> {
        self.profiles.get(profile_id).ok_or_else(|| {
            AgentError::new(
                "profile.not_installed",
                format!("Profile is not installed: {profile_id}"),
            )
        })
    }

    pub fn ids(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }

    pub fn installed(&self) -> impl Iterator<Item = &VerifiedProfile> {
        self.profiles.values()
    }

    pub fn from_verified_profiles(
        profiles: impl IntoIterator<Item = VerifiedProfile>,
    ) -> Result<Self, AgentError> {
        let mut installed = BTreeMap::new();
        for profile in profiles {
            let profile_id = profile.profile().id.clone();
            if installed.insert(profile_id.clone(), profile).is_some() {
                return Err(AgentError::new(
                    "profile.duplicate",
                    format!("Profile id is installed more than once: {profile_id}"),
                ));
            }
        }
        if installed.is_empty() {
            return Err(AgentError::new(
                "profile.store_empty",
                "Profile store contains no verified profiles",
            ));
        }
        Ok(Self {
            profiles: installed,
        })
    }
}

fn installed_profile_path(path: &Path) -> Result<PathBuf, AgentError> {
    if path.is_dir() {
        let profile = path.join("profile.json");
        if profile.is_file() {
            return Ok(profile);
        }
    } else if path.is_file() && path.file_name().is_some_and(|name| name == "profile.json") {
        return Ok(path.to_path_buf());
    }
    Err(AgentError::new(
        "profile.store_layout_invalid",
        format!(
            "Profile store entries must be directories containing profile.json: {}",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{Signer, SigningKey};
    use fairypam_agent_core::profile::{
        profile_content_sha256, ActionDefinition, CaptureRegion, CaptureSource,
        Ed25519SignatureVerifier, Profile, ProfileContent, ProfileEnvelope, TargetRules,
    };

    use super::*;

    fn signed_profile(id: &str, signing: &SigningKey) -> Vec<u8> {
        let content = ProfileContent {
            schema_version: 1,
            profile: Profile {
                id: id.into(),
                version: "1.0.0".into(),
                display_name: id.into(),
                target: TargetRules {
                    process_names: vec![format!("{id}.exe")],
                    process_path_sha256: vec!["11".repeat(32)],
                    window_classes: vec!["FairyPamTestWindow".into()],
                    title_patterns: vec!["FairyPam Test *".into()],
                    require_elevated: false,
                    minimum_client_width: 640,
                    minimum_client_height: 360,
                    minimum_dpi: 96,
                },
                capture_sources: vec![CaptureSource {
                    id: "client".into(),
                    region: CaptureRegion::FullClient,
                    maximum_fps: 10,
                    encodings: vec!["jpeg".into()],
                }],
                actions: BTreeMap::from([(
                    "move.forward".into(),
                    ActionDefinition::Hold { scan_code: 17 },
                )]),
            },
            files: Vec::new(),
        };
        let digest_hex = profile_content_sha256(&content).unwrap();
        let mut digest = [0_u8; 32];
        for (index, chunk) in digest_hex.as_bytes().chunks_exact(2).enumerate() {
            digest[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        let signature = signing
            .sign(&digest)
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        serde_json::to_vec(&ProfileEnvelope {
            content,
            content_sha256: digest_hex,
            signature,
        })
        .unwrap()
    }

    fn temp_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fairypam-profile-store-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn loads_verified_profiles_in_stable_id_order() {
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let public_hex = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = temp_root();
        for id in ["testbed", "genshin-impact"] {
            let directory = root.join(id);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("profile.json"), signed_profile(id, &signing)).unwrap();
        }

        let store = ProfileStore::load(
            &root,
            &Ed25519SignatureVerifier::from_public_key_hex(&public_hex).unwrap(),
        )
        .unwrap();

        assert_eq!(store.ids(), vec!["genshin-impact", "testbed"]);
        assert_eq!(store.get("testbed").unwrap().profile().id, "testbed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unknown_store_entries_instead_of_ignoring_them() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("README.txt"), "unexpected").unwrap();
        struct Reject;
        impl SignatureVerifier for Reject {
            fn verify(&self, _digest: &[u8; 32], _signature: &str) -> bool {
                false
            }
        }

        let error = ProfileStore::load(&root, &Reject).unwrap_err();

        assert_eq!(error.code(), "profile.store_layout_invalid");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn optional_store_allows_missing_profiles_but_keeps_the_strict_loader() {
        let root = temp_root();
        struct Reject;
        impl SignatureVerifier for Reject {
            fn verify(&self, _digest: &[u8; 32], _signature: &str) -> bool {
                false
            }
        }

        assert!(ProfileStore::load_optional(&root, &Reject)
            .unwrap()
            .ids()
            .is_empty());
        assert_eq!(
            ProfileStore::load(&root, &Reject).unwrap_err().code(),
            "profile.store_unavailable"
        );
    }
}
