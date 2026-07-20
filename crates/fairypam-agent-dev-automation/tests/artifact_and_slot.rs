use fairypam_agent_dev_automation::{
    replace_current_slot, verify_dev_artifact, ArtifactFile, DevArtifactReceipt, RunIdentity,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};
use zip::{write::SimpleFileOptions, ZipWriter};
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn receipt(bytes: &[u8], promotable: bool) -> DevArtifactReceipt {
    DevArtifactReceipt {
        schema_version: 1,
        artifact_class: "dev-automation".into(),
        promotable,
        source_commit: "a".repeat(40),
        public_commit: "b".repeat(40),
        run_id: "1".into(),
        run_attempt: "1".into(),
        build_id: "dev-1".into(),
        features: vec!["dev-automation".into(), "testbed".into()],
        files: vec![ArtifactFile {
            path: "fairypam-agent.exe".into(),
            sha256: "0".repeat(64),
            size: 1,
        }],
        zip_sha256: hash(bytes),
        zip_size: bytes.len() as u64,
    }
}
#[test]
fn receipt_and_slot_are_fail_closed() {
    let root = std::env::temp_dir().join(format!(
        "fairypam-dev-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let zip = root.join("dev.zip");
    fs::write(&zip, b"zip").unwrap();
    let run = RunIdentity {
        repository: "atiasn/fairypam-rust-agent".into(),
        run_id: "1".into(),
        run_attempt: "1".into(),
    };
    assert_eq!(
        verify_dev_artifact(&zip, &receipt(b"zip", true), &run)
            .unwrap_err()
            .code(),
        "dev.artifact.promotable_invalid"
    );
    let mut bad = receipt(b"zip", false);
    bad.files[0].path = "extra.exe".into();
    assert_eq!(
        verify_dev_artifact(&zip, &bad, &run).unwrap_err().code(),
        "dev.artifact.members_invalid"
    );
    let current = root.join("current");
    let previous = root.join("previous");
    let staging = root.join("staging");
    fs::create_dir_all(&current).unwrap();
    fs::write(current.join("build"), "old").unwrap();
    fs::create_dir_all(&staging).unwrap();
    fs::write(staging.join("build"), "new").unwrap();
    replace_current_slot(&staging, &current, &previous).unwrap();
    assert_eq!(fs::read_to_string(current.join("build")).unwrap(), "new");
    assert_eq!(fs::read_to_string(previous.join("build")).unwrap(), "old");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_zip_must_match_every_receipt_member() {
    let root = std::env::temp_dir().join(format!(
        "fairypam-dev-zip-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let zip = root.join("dev.zip");
    let file = fs::File::create(&zip).unwrap();
    let mut archive = ZipWriter::new(file);
    let payloads: [(&str, &[u8]); 7] = [
        ("fairypam-agent.exe", b"agent"),
        ("fairypam-agent-guardian.exe", b"guardian"),
        ("fairypam-agentctl.exe", b"agentctl"),
        ("fairypam-agent-testbed.exe", b"testbed"),
        ("test-profile-root-public-key.hex", b"key"),
        ("dev-install.ps1", b"install"),
        ("dev-provision.ps1", b"provision"),
    ];
    for (path, payload) in payloads {
        archive
            .start_file(path, SimpleFileOptions::default())
            .unwrap();
        archive.write_all(payload).unwrap();
    }
    archive.finish().unwrap();
    let bytes = fs::read(&zip).unwrap();
    let mut valid = receipt(&bytes, false);
    valid.files = payloads
        .iter()
        .map(|(path, payload)| ArtifactFile {
            path: (*path).into(),
            sha256: hash(payload),
            size: payload.len() as u64,
        })
        .collect();
    let run = RunIdentity {
        repository: "atiasn/fairypam-rust-agent".into(),
        run_id: "1".into(),
        run_attempt: "1".into(),
    };
    verify_dev_artifact(&zip, &valid, &run).unwrap();
    valid.files[0].sha256 = hash(b"tampered");
    assert_eq!(
        verify_dev_artifact(&zip, &valid, &run).unwrap_err().code(),
        "dev.artifact.members_invalid"
    );
    fs::remove_dir_all(root).unwrap();
}
