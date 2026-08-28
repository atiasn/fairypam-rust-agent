use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fairypam_agent_core::profile::Ed25519SignatureVerifier;

use crate::runtime_discovery::discover_active;
use crate::runtime_manifest::{hex_sha256, RuntimeLock, SignedRuntimeManifest};
use crate::MaaRuntimeError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRuntime {
    pub version: String,
    pub root: PathBuf,
    pub framework_dll: PathBuf,
}

pub fn verify_active_runtime(
    root: &Path,
    public_key: &str,
) -> Result<VerifiedRuntime, MaaRuntimeError> {
    let verifier = Ed25519SignatureVerifier::from_public_key_hex(public_key)
        .map_err(|error| MaaRuntimeError::new(error.code(), error.to_string()))?;
    let lock = RuntimeLock::from_slice(&fs::read(root.join("maa-runtime.lock.json"))?)?;
    let signed = SignedRuntimeManifest::verify(
        &fs::read(root.join("maa-runtime.manifest.json"))?,
        &verifier,
    )?;
    if signed != lock {
        return Err(MaaRuntimeError::new(
            "maa.manifest_lock_mismatch",
            "signed runtime manifest does not match the installed lock",
        ));
    }
    let (active, version_root) = discover_active(root)?;
    if active.active_version != signed.sdk_version {
        return Err(MaaRuntimeError::new(
            "maa.active_version_mismatch",
            "active runtime does not match the signed manifest",
        ));
    }
    verify_runtime(&version_root, &signed)
}

pub fn verify_runtime(
    version_root: &Path,
    manifest: &RuntimeLock,
) -> Result<VerifiedRuntime, MaaRuntimeError> {
    manifest.validate()?;
    let expected_dlls = manifest
        .files
        .iter()
        .filter(|file| file.path.to_ascii_lowercase().ends_with(".dll"))
        .map(|file| file.path.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let actual_dlls = list_dlls(version_root)?;
    if actual_dlls != expected_dlls {
        return Err(MaaRuntimeError::new(
            "maa.runtime_file_set_mismatch",
            "runtime DLL set does not match the signed manifest",
        ));
    }
    for file in &manifest.files {
        let path = version_root.join(&file.path);
        let bytes = fs::read(&path).map_err(|error| {
            MaaRuntimeError::new(
                "maa.runtime_file_missing",
                format!("{}: {error}", file.path),
            )
        })?;
        if hex_sha256(&bytes) != file.sha256.to_ascii_lowercase() {
            return Err(MaaRuntimeError::new(
                "maa.runtime_hash_mismatch",
                format!("runtime file hash mismatch: {}", file.path),
            ));
        }
    }
    let framework_dll = version_root.join("bin/MaaFramework.dll");
    if !framework_dll.is_file() {
        return Err(MaaRuntimeError::new(
            "maa.runtime_file_missing",
            "MaaFramework.dll is missing",
        ));
    }
    Ok(VerifiedRuntime {
        version: manifest.sdk_version.clone(),
        root: version_root.to_path_buf(),
        framework_dll,
    })
}

fn list_dlls(root: &Path) -> Result<BTreeSet<String>, MaaRuntimeError> {
    let bin = root.join("bin");
    let mut values = BTreeSet::new();
    for entry in fs::read_dir(&bin)
        .map_err(|error| MaaRuntimeError::new("maa.runtime_file_missing", error.to_string()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("dll"))
        {
            values.insert(
                format!("bin/{}", entry.file_name().to_string_lossy()).to_ascii_lowercase(),
            );
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn active_runtime_rejects_a_signed_manifest_that_differs_from_the_lock() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bytes = fs::read(manifest_dir.join("../../../runtime/maa/maa-runtime.lock.json"))
            .or_else(|_| fs::read(manifest_dir.join("../../runtime/maa/maa-runtime.lock.json")))
            .unwrap();
        let signed_lock = RuntimeLock::from_slice(&bytes).unwrap();
        let signing = SigningKey::from_bytes(&[7; 32]);
        let content = serde_json::to_vec(&signed_lock).unwrap();
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let signed = SignedRuntimeManifest {
            content: signed_lock.clone(),
            content_sha256: hex_sha256(&content),
            signature: signing
                .sign(&digest)
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        };
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("maa-runtime.manifest.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        let mut installed_lock = signed_lock;
        installed_lock.release_sha256 = "0".repeat(64);
        fs::write(
            root.path().join("maa-runtime.lock.json"),
            serde_json::to_vec(&installed_lock).unwrap(),
        )
        .unwrap();
        let public_key = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let error = verify_active_runtime(root.path(), &public_key).unwrap_err();

        assert_eq!(error.code(), "maa.manifest_lock_mismatch");
    }
}
