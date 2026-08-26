use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use fairypam_agent_maa::runtime_manifest::{RuntimeLock, SignedRuntimeManifest};
use sha2::{Digest, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("maa.runtime_sign_failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (lock, manifest, public_key) = arguments(std::env::args_os().skip(1))?;
    let mut seed = String::new();
    std::io::stdin()
        .take(129)
        .read_to_string(&mut seed)
        .map_err(|error| error.to_string())?;
    let signing = SigningKey::from_bytes(&decode_seed(seed.trim())?);
    let lock = RuntimeLock::from_slice(&std::fs::read(lock).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    write_new(&manifest, &signed_bytes(lock, &signing)?)?;
    write_new(
        &public_key,
        &hex(&signing.verifying_key().to_bytes()).into_bytes(),
    )
}

fn arguments(
    values: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let values = values.collect::<Vec<_>>();
    if values.len() != 6 {
        return Err("expected --lock, --manifest, and --public-key-output".into());
    }
    let value = |name: &str| {
        values
            .chunks_exact(2)
            .find(|pair| pair[0] == name)
            .map(|pair| PathBuf::from(&pair[1]))
            .ok_or_else(|| format!("missing {name}"))
    };
    Ok((
        value("--lock")?,
        value("--manifest")?,
        value("--public-key-output")?,
    ))
}

fn signed_bytes(lock: RuntimeLock, signing: &SigningKey) -> Result<Vec<u8>, String> {
    let content = serde_json::to_vec(&lock).map_err(|error| error.to_string())?;
    let digest: [u8; 32] = Sha256::digest(&content).into();
    let envelope = SignedRuntimeManifest {
        content: lock,
        content_sha256: hex(&digest),
        signature: hex(&signing.sign(&digest).to_bytes()),
    };
    let mut bytes = serde_json::to_vec_pretty(&envelope).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_seed(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("signing seed must be exactly 64 hexadecimal characters".into());
    }
    let mut seed = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        seed[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|error| error.to_string())?,
            16,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(seed)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use fairypam_agent_core::profile::Ed25519SignatureVerifier;

    use super::*;

    #[test]
    fn generated_manifest_verifies_with_the_exported_public_key() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(manifest_dir.join("../../../runtime/maa/maa-runtime.lock.json"))
            .or_else(|_| {
                std::fs::read(manifest_dir.join("../../runtime/maa/maa-runtime.lock.json"))
            })
            .unwrap();
        let lock = RuntimeLock::from_slice(&bytes).unwrap();
        let signing = SigningKey::from_bytes(&[7; 32]);
        let bytes = signed_bytes(lock.clone(), &signing).unwrap();
        let verifier = Ed25519SignatureVerifier::from_public_key_hex(&hex(&signing
            .verifying_key()
            .to_bytes()))
        .unwrap();

        assert_eq!(
            SignedRuntimeManifest::verify(&bytes, &verifier).unwrap(),
            lock
        );
    }
}
