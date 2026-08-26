use std::fs;

use fairypam_agent_core::profile::SignatureVerifier;
use fairypam_agent_maa::runtime_discovery::discover_active;
use fairypam_agent_maa::runtime_manifest::{RuntimeFile, RuntimeLock, SignedRuntimeManifest};
use fairypam_agent_maa::runtime_switch::{activate, rollback};
use fairypam_agent_maa::runtime_verify::{verify_runtime, VerifiedRuntime};
use sha2::{Digest, Sha256};

fn lock() -> RuntimeLock {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let bytes = fs::read(manifest_dir.join("../../../runtime/maa/maa-runtime.lock.json"))
        .or_else(|_| fs::read(manifest_dir.join("../../runtime/maa/maa-runtime.lock.json")))
        .unwrap();
    RuntimeLock::from_slice(&bytes).unwrap()
}

#[test]
fn checked_in_runtime_lock_is_strict_and_pinned() {
    let lock = lock();
    assert_eq!(lock.sdk_version, "5.12.3");
    assert_eq!(lock.maa_framework_rs_version, "1.20.0");
    assert_eq!(lock.maa_framework_sys_version, "5.12.1");
    assert_eq!(lock.files.len(), 7);
}

#[test]
fn runtime_lock_rejects_unknown_profile_and_newer_agent_requirement() {
    let mut value = lock();
    value.compatibility_profile = "unknown".into();
    assert_eq!(value.validate().unwrap_err().code(), "maa.manifest_invalid");

    let mut value = lock();
    value.minimum_agent_version = "0.1.13".into();
    assert_eq!(
        value.validate().unwrap_err().code(),
        "maa.runtime_incompatible"
    );
}

#[test]
fn runtime_verification_rejects_hashes_and_extra_dlls() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("bin")).unwrap();
    let mut lock = lock();
    lock.files = vec![file("bin/MaaFramework.dll", b"framework")];
    fs::write(root.path().join("bin/MaaFramework.dll"), b"framework").unwrap();
    assert!(verify_runtime(root.path(), &lock).is_ok());

    fs::write(root.path().join("bin/foreign.dll"), b"foreign").unwrap();
    assert_eq!(
        verify_runtime(root.path(), &lock).unwrap_err().code(),
        "maa.runtime_file_set_mismatch"
    );
    fs::remove_file(root.path().join("bin/foreign.dll")).unwrap();
    fs::write(root.path().join("bin/MaaFramework.dll"), b"tampered").unwrap();
    assert_eq!(
        verify_runtime(root.path(), &lock).unwrap_err().code(),
        "maa.runtime_hash_mismatch"
    );
}

#[test]
fn side_by_side_activation_and_rollback_keep_one_previous_version() {
    let root = tempfile::tempdir().unwrap();
    for version in ["5.12.2", "5.12.3"] {
        fs::create_dir_all(root.path().join("versions").join(version).join("bin")).unwrap();
        activate(
            root.path(),
            &VerifiedRuntime {
                version: version.into(),
                root: root.path().join("versions").join(version),
                framework_dll: root
                    .path()
                    .join("versions")
                    .join(version)
                    .join("bin/MaaFramework.dll"),
            },
        )
        .unwrap();
    }
    let active = discover_active(root.path()).unwrap().0;
    assert_eq!(active.active_version, "5.12.3");
    assert_eq!(active.previous_stable_version.as_deref(), Some("5.12.2"));

    let active = rollback(root.path()).unwrap();
    assert_eq!(active.active_version, "5.12.2");
    assert_eq!(active.previous_stable_version.as_deref(), Some("5.12.3"));
}

#[test]
fn signed_manifest_is_required_before_install() {
    struct AcceptDigest([u8; 32]);
    impl SignatureVerifier for AcceptDigest {
        fn verify(&self, digest: &[u8; 32], signature: &str) -> bool {
            digest == &self.0 && signature == "test-signature"
        }
    }

    let content = lock();
    let bytes = serde_json::to_vec(&content).unwrap();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let envelope = SignedRuntimeManifest {
        content,
        content_sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        signature: "test-signature".into(),
    };
    assert_eq!(
        SignedRuntimeManifest::verify(
            &serde_json::to_vec(&envelope).unwrap(),
            &AcceptDigest(digest),
        )
        .unwrap()
        .sdk_version,
        "5.12.3"
    );
}

fn file(path: &str, bytes: &[u8]) -> RuntimeFile {
    RuntimeFile {
        path: path.into(),
        sha256: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}
