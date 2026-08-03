use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fairypam_agent_core::profile::{verify_profile, Ed25519SignatureVerifier};
use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v2;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::profile_store::ProfileStore;

const MAX_PROFILE_BYTES: usize = 256 * 1024;
const MAX_CATALOG_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogManifest {
    catalog_version: u64,
    catalog_digest: String,
    source_commit: String,
    profiles: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    profile_id: String,
    profile_version: String,
    content_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogPointer {
    generation: String,
}

#[derive(Clone, Debug)]
struct Candidate {
    manifest: CatalogManifest,
    profiles: ProfileStore,
    files: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Debug)]
pub struct ActiveCatalog {
    pub version: u64,
    pub digest: String,
    pub profiles: ProfileStore,
}

#[derive(Clone, Debug)]
pub struct ProfileCatalogStore {
    root: PathBuf,
    verifier: Ed25519SignatureVerifier,
    active: Option<ActiveCatalog>,
    pending: Option<Candidate>,
}

impl ProfileCatalogStore {
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub fn open(root: PathBuf, verifier: Ed25519SignatureVerifier) -> Self {
        let active = load_active(&root, &verifier).ok().flatten();
        let store = Self {
            root,
            verifier,
            active,
            pending: None,
        };
        if let Err(error) = store.cleanup_inactive() {
            tracing::warn!(code = "profile.cleanup_failed", error_code = error.code());
        }
        store
    }

    pub fn active(&self) -> Option<&ActiveCatalog> {
        self.active.as_ref()
    }

    pub fn pending_identity(&self) -> Option<(u64, &str)> {
        self.pending.as_ref().map(|pending| {
            (
                pending.manifest.catalog_version,
                pending.manifest.catalog_digest.as_str(),
            )
        })
    }

    pub fn stage(&mut self, catalog: &v2::ProfileCatalog) -> Result<bool, AgentError> {
        let candidate = validate_catalog(catalog, &self.verifier, self.active.as_ref())?;
        if self.active.as_ref().is_some_and(|active| {
            active.version == candidate.manifest.catalog_version
                && active.digest == candidate.manifest.catalog_digest
        }) {
            return Ok(false);
        }
        if let Some(pending) = &self.pending {
            if candidate.manifest.catalog_version < pending.manifest.catalog_version
                || (candidate.manifest.catalog_version == pending.manifest.catalog_version
                    && candidate.manifest.catalog_digest != pending.manifest.catalog_digest)
            {
                return Err(invalid("profile_catalog.version_stale"));
            }
            if candidate.manifest.catalog_version == pending.manifest.catalog_version {
                return Ok(true);
            }
        }
        ensure_root(&self.root)?;
        let generation = generation_name(&candidate.manifest);
        let directory = generations_root(&self.root).join(&generation);
        if directory.exists() {
            remove_private_directory(&directory)?;
        }
        create_private_directory(&directory)?;
        let result = (|| {
            let profiles_root = directory.join("profiles");
            create_private_directory(&profiles_root)?;
            for (profile_id, bytes) in &candidate.files {
                let profile_root = profiles_root.join(profile_id);
                create_private_directory(&profile_root)?;
                write_private(&profile_root.join("profile.json"), bytes)?;
            }
            write_private(
                &directory.join("catalog.json"),
                &serde_json::to_vec(&candidate.manifest).map_err(persistence_error)?,
            )?;
            load_generation(&directory, &self.verifier).map(|_| ())
        })();
        if result.is_err() {
            let _ = remove_private_directory(&directory);
            return result.map(|_| false);
        }
        self.pending = Some(candidate);
        Ok(true)
    }

    pub fn activate(&mut self) -> Result<ActiveCatalog, AgentError> {
        let pending = self.pending.as_ref().ok_or_else(|| {
            AgentError::new(
                "profile_catalog.not_pending",
                "no Profile Catalog is pending",
            )
        })?;
        ensure_root(&self.root)?;
        let generation = generation_name(&pending.manifest);
        let temporary = self.root.join(format!(
            "current-{}-{}.tmp",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(persistence_error)?
                .as_nanos()
        ));
        write_private(
            &temporary,
            &serde_json::to_vec(&CatalogPointer { generation }).map_err(persistence_error)?,
        )?;
        replace_private(&temporary, &self.root.join("current.json"))?;
        let active = ActiveCatalog {
            version: pending.manifest.catalog_version,
            digest: pending.manifest.catalog_digest.clone(),
            profiles: pending.profiles.clone(),
        };
        self.active = Some(active.clone());
        self.pending = None;
        if let Err(error) = self.cleanup_inactive() {
            tracing::warn!(code = "profile.cleanup_failed", error_code = error.code());
        }
        Ok(active)
    }

    pub fn cleanup_inactive(&self) -> Result<(), AgentError> {
        if !self.root.exists() {
            return Ok(());
        }
        let active = self
            .active
            .as_ref()
            .map(|active| format!("c-{}-{}", active.version, active.digest));
        for entry in fs::read_dir(&self.root).map_err(persistence_error)? {
            let entry = entry.map_err(persistence_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("current-") && name.ends_with(".tmp") {
                remove_private_file(&entry.path())?;
            }
        }
        if self.active.is_none() && self.root.join("current.json").exists() {
            return Ok(());
        }
        for entry in fs::read_dir(generations_root(&self.root)).map_err(persistence_error)? {
            let entry = entry.map_err(persistence_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("c-") && active.as_deref() != Some(&name) {
                remove_private_directory(&entry.path())?;
            }
        }
        Ok(())
    }
}

fn validate_catalog(
    catalog: &v2::ProfileCatalog,
    verifier: &Ed25519SignatureVerifier,
    active: Option<&ActiveCatalog>,
) -> Result<Candidate, AgentError> {
    if catalog.catalog_version == 0
        || !lower_hex(&catalog.catalog_digest, 64)
        || !lower_hex(&catalog.source_commit, 40)
        || catalog.profiles.is_empty()
    {
        return Err(invalid("profile_catalog.schema_invalid"));
    }
    if let Some(active) = active {
        if catalog.catalog_version < active.version
            || (catalog.catalog_version == active.version
                && catalog.catalog_digest != active.digest)
        {
            return Err(invalid("profile_catalog.version_stale"));
        }
    }
    let mut total = 0_usize;
    let mut files = Vec::with_capacity(catalog.profiles.len());
    let mut verified = Vec::with_capacity(catalog.profiles.len());
    let mut entries = BTreeMap::new();
    if catalog
        .profiles
        .windows(2)
        .any(|pair| pair[0].profile_id >= pair[1].profile_id)
    {
        return Err(invalid("profile_catalog.profile_order_invalid"));
    }
    for value in &catalog.profiles {
        total = total.saturating_add(value.profile_json.len());
        if value.profile_json.is_empty()
            || value.profile_json.len() > MAX_PROFILE_BYTES
            || total > MAX_CATALOG_BYTES
        {
            return Err(invalid("profile_catalog.size_exceeded"));
        }
        let profile = verify_profile(&value.profile_json, verifier)?;
        if !profile.files().is_empty()
            || value.profile_id != profile.profile().id
            || value.profile_version != profile.profile().version
            || value.content_digest != profile.content_sha256()
            || Version::parse(&value.profile_version).is_err()
        {
            return Err(invalid("profile_catalog.profile_mismatch"));
        }
        let entry = CatalogEntry {
            profile_id: value.profile_id.clone(),
            profile_version: value.profile_version.clone(),
            content_digest: value.content_digest.clone(),
        };
        if entries.insert(value.profile_id.clone(), entry).is_some() {
            return Err(invalid("profile_catalog.profile_duplicate"));
        }
        files.push((value.profile_id.clone(), value.profile_json.clone()));
        verified.push(profile);
    }
    if let Some(active) = active {
        if active
            .profiles
            .ids()
            .iter()
            .any(|profile_id| !entries.contains_key(profile_id))
        {
            return Err(invalid("profile_catalog.profile_removed"));
        }
        for entry in entries.values() {
            let Ok(previous) = active.profiles.get(&entry.profile_id) else {
                continue;
            };
            let previous_version = Version::parse(&previous.profile().version)
                .map_err(|_| invalid("profile_catalog.persistence_invalid"))?;
            let next_version = Version::parse(&entry.profile_version)
                .map_err(|_| invalid("profile_catalog.profile_mismatch"))?;
            if next_version < previous_version
                || (next_version == previous_version
                    && entry.content_digest != previous.content_sha256())
            {
                return Err(invalid("profile_catalog.profile_version_stale"));
            }
        }
    }
    let identity = entries.values().fold(Vec::new(), |mut bytes, entry| {
        bytes.extend_from_slice(entry.profile_id.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(entry.profile_version.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(entry.content_digest.as_bytes());
        bytes.push(b'\n');
        bytes
    });
    let digest = format!("{:x}", Sha256::digest(identity));
    if digest != catalog.catalog_digest {
        return Err(invalid("profile_catalog.digest_mismatch"));
    }
    Ok(Candidate {
        manifest: CatalogManifest {
            catalog_version: catalog.catalog_version,
            catalog_digest: catalog.catalog_digest.clone(),
            source_commit: catalog.source_commit.clone(),
            profiles: entries.into_values().collect(),
        },
        profiles: ProfileStore::from_verified_profiles(verified)?,
        files,
    })
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn load_active(
    root: &Path,
    verifier: &Ed25519SignatureVerifier,
) -> Result<Option<ActiveCatalog>, AgentError> {
    ensure_root(root)?;
    let pointer_path = root.join("current.json");
    if !pointer_path.exists() {
        return Ok(None);
    }
    let pointer: CatalogPointer = serde_json::from_slice(&read_private(&pointer_path, 4096)?)
        .map_err(|_| invalid("profile_catalog.pointer_invalid"))?;
    if !pointer.generation.starts_with("c-") || pointer.generation.contains(['/', '\\']) {
        return Err(invalid("profile_catalog.pointer_invalid"));
    }
    let candidate = load_generation(&generations_root(root).join(&pointer.generation), verifier)?;
    if generation_name(&candidate.manifest) != pointer.generation {
        return Err(invalid("profile_catalog.pointer_invalid"));
    }
    Ok(Some(ActiveCatalog {
        version: candidate.manifest.catalog_version,
        digest: candidate.manifest.catalog_digest,
        profiles: candidate.profiles,
    }))
}

fn load_generation(
    directory: &Path,
    verifier: &Ed25519SignatureVerifier,
) -> Result<Candidate, AgentError> {
    verify_private_directory(directory)?;
    let manifest: CatalogManifest = serde_json::from_slice(&read_private(
        &directory.join("catalog.json"),
        MAX_CATALOG_BYTES,
    )?)
    .map_err(|_| invalid("profile_catalog.persistence_invalid"))?;
    let profiles = manifest
        .profiles
        .iter()
        .map(|entry| {
            read_private(
                &directory
                    .join("profiles")
                    .join(&entry.profile_id)
                    .join("profile.json"),
                MAX_PROFILE_BYTES,
            )
            .map(|bytes| v2::ProfileCatalogProfile {
                profile_id: entry.profile_id.clone(),
                profile_version: entry.profile_version.clone(),
                content_digest: entry.content_digest.clone(),
                profile_json: bytes,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_catalog(
        &v2::ProfileCatalog {
            catalog_version: manifest.catalog_version,
            catalog_digest: manifest.catalog_digest.clone(),
            source_commit: manifest.source_commit.clone(),
            profiles,
        },
        verifier,
        None,
    )
}

fn generation_name(manifest: &CatalogManifest) -> String {
    format!("c-{}-{}", manifest.catalog_version, manifest.catalog_digest)
}

fn generations_root(root: &Path) -> PathBuf {
    root.join("generations")
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(code: &'static str) -> AgentError {
    AgentError::new(code, "Profile Catalog is invalid")
}

fn persistence_error(error: impl std::fmt::Display) -> AgentError {
    AgentError::new("profile_catalog.persistence_failed", error.to_string())
}

#[cfg(windows)]
fn ensure_root(root: &Path) -> Result<(), AgentError> {
    crate::enrollment::ensure_private_directory(root)?;
    let generations = generations_root(root);
    if generations.exists() {
        verify_private_directory(&generations)
    } else {
        create_private_directory(&generations)
    }
}

#[cfg(not(windows))]
fn ensure_root(root: &Path) -> Result<(), AgentError> {
    fs::create_dir_all(generations_root(root)).map_err(persistence_error)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> Result<(), AgentError> {
    crate::enrollment::create_private_directory(path)
}

#[cfg(not(windows))]
fn create_private_directory(path: &Path) -> Result<(), AgentError> {
    fs::create_dir(path).map_err(persistence_error)
}

#[cfg(windows)]
fn verify_private_directory(path: &Path) -> Result<(), AgentError> {
    crate::enrollment::verify_private_directory(path)
}

#[cfg(not(windows))]
fn verify_private_directory(path: &Path) -> Result<(), AgentError> {
    path.is_dir()
        .then_some(())
        .ok_or_else(|| persistence_error("directory is unavailable"))
}

#[cfg(windows)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    crate::enrollment::write_private(path, bytes)
}

#[cfg(not(windows))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(persistence_error)?;
    file.write_all(bytes).map_err(persistence_error)?;
    file.sync_all().map_err(persistence_error)
}

#[cfg(windows)]
fn replace_private(source: &Path, destination: &Path) -> Result<(), AgentError> {
    crate::enrollment::replace_private(source, destination)
}

#[cfg(not(windows))]
fn replace_private(source: &Path, destination: &Path) -> Result<(), AgentError> {
    fs::rename(source, destination).map_err(persistence_error)
}

fn read_private(path: &Path, maximum: usize) -> Result<Vec<u8>, AgentError> {
    #[cfg(windows)]
    let mut file = crate::enrollment::open_private_read(path)?;
    #[cfg(not(windows))]
    let mut file = fs::File::open(path).map_err(persistence_error)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(persistence_error)?;
    if bytes.len() > maximum {
        return Err(invalid("profile_catalog.size_exceeded"));
    }
    #[cfg(windows)]
    crate::enrollment::verify_private_file(path)?;
    Ok(bytes)
}

#[cfg(windows)]
fn remove_private_file(path: &Path) -> Result<(), AgentError> {
    crate::enrollment::verify_private_file(path)?;
    fs::remove_file(path).map_err(persistence_error)
}

#[cfg(not(windows))]
fn remove_private_file(path: &Path) -> Result<(), AgentError> {
    fs::remove_file(path).map_err(persistence_error)
}

fn remove_private_directory(path: &Path) -> Result<(), AgentError> {
    verify_private_directory(path)?;
    fs::remove_dir_all(path).map_err(persistence_error)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::{Signer, SigningKey};
    use fairypam_agent_core::profile::{
        profile_content_sha256, ActionDefinition, CaptureRegion, CaptureSource, Profile,
        ProfileContent, ProfileEnvelope, TargetRules,
    };

    use super::*;

    #[test]
    fn stages_activates_reloads_and_rejects_downgrade() {
        let root = std::env::temp_dir().join(format!(
            "fairypam-profile-catalog-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let signing = SigningKey::from_bytes(&[7; 32]);
        let verifier = Ed25519SignatureVerifier::from_public_key_hex(
            &signing
                .verifying_key()
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        let mut store = ProfileCatalogStore::open(root.clone(), verifier.clone());
        let profile = signed_profile("profile-a", "1.0.0", &signing);
        let mut current_catalog = catalog(2, profile.clone());
        assert!(store.stage(&current_catalog).unwrap());
        assert_eq!(store.activate().unwrap().version, 2);
        assert_eq!(
            ProfileCatalogStore::open(root.clone(), verifier.clone())
                .active()
                .unwrap()
                .version,
            2
        );
        current_catalog.catalog_version = 1;
        assert_eq!(
            store.stage(&current_catalog).unwrap_err().code(),
            "profile_catalog.version_stale"
        );
        let downgraded_profile = catalog(3, signed_profile("profile-a", "0.9.0", &signing));
        assert_eq!(
            store.stage(&downgraded_profile).unwrap_err().code(),
            "profile_catalog.profile_version_stale"
        );
        let removed_profile = catalog(3, signed_profile("profile-b", "1.0.0", &signing));
        assert_eq!(
            store.stage(&removed_profile).unwrap_err().code(),
            "profile_catalog.profile_removed"
        );
        let pending_newer = catalog(4, profile.clone());
        let pending_older = catalog(3, profile);
        assert!(store.stage(&pending_newer).unwrap());
        assert_eq!(
            store.stage(&pending_older).unwrap_err().code(),
            "profile_catalog.version_stale"
        );
        assert_eq!(store.pending_identity().unwrap().0, 4);
        let generation = generation_name(&CatalogManifest {
            catalog_version: 2,
            catalog_digest: store.active().unwrap().digest.clone(),
            source_commit: "a".repeat(40),
            profiles: Vec::new(),
        });
        let generation_root = generations_root(&root).join(generation);
        fs::write(generation_root.join("catalog.json"), b"invalid").unwrap();
        assert!(ProfileCatalogStore::open(root.clone(), verifier.clone())
            .active()
            .is_none());
        assert!(generation_root.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn signed_profile(id: &str, version: &str, signing: &SigningKey) -> Vec<u8> {
        let content = ProfileContent {
            schema_version: 1,
            profile: Profile {
                id: id.into(),
                version: version.into(),
                display_name: id.into(),
                target: TargetRules {
                    process_names: vec![format!("{id}.exe")],
                    process_path_sha256: vec!["11".repeat(32)],
                    window_classes: vec!["GameWindow".into()],
                    title_patterns: vec!["Game".into()],
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
        let digest = profile_content_sha256(&content).unwrap();
        let digest_bytes: [u8; 32] = std::array::from_fn(|index| {
            u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).unwrap()
        });
        serde_json::to_vec(&ProfileEnvelope {
            content,
            content_sha256: digest,
            signature: signing
                .sign(&digest_bytes)
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        })
        .unwrap()
    }

    fn catalog(version: u64, profile_json: Vec<u8>) -> v2::ProfileCatalog {
        let envelope: ProfileEnvelope = serde_json::from_slice(&profile_json).unwrap();
        let profile_id = envelope.content.profile.id;
        let profile_version = envelope.content.profile.version;
        let content_digest = envelope.content_sha256;
        let identity = format!("{profile_id}\0{profile_version}\0{content_digest}\n");
        v2::ProfileCatalog {
            catalog_version: version,
            catalog_digest: format!("{:x}", Sha256::digest(identity)),
            source_commit: "a".repeat(40),
            profiles: vec![v2::ProfileCatalogProfile {
                profile_id,
                profile_version,
                content_digest,
                profile_json,
            }],
        }
    }
}
