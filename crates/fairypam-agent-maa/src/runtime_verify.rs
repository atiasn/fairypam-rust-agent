use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::runtime_manifest::{hex_sha256, RuntimeLock};
use crate::MaaRuntimeError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRuntime {
    pub version: String,
    pub root: PathBuf,
    pub framework_dll: PathBuf,
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
