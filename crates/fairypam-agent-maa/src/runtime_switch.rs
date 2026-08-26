use std::fs;
use std::path::Path;

use crate::runtime_discovery::{safe_version, ActiveRuntime};
use crate::runtime_verify::VerifiedRuntime;
use crate::MaaRuntimeError;

pub fn activate(root: &Path, runtime: &VerifiedRuntime) -> Result<ActiveRuntime, MaaRuntimeError> {
    if !safe_version(&runtime.version)
        || runtime.root != root.join("versions").join(&runtime.version)
    {
        return Err(MaaRuntimeError::new(
            "maa.activation_invalid",
            "verified runtime is outside the side-by-side versions directory",
        ));
    }
    let previous = read_active(root).ok().map(|value| value.active_version);
    let active = ActiveRuntime {
        schema_version: 1,
        active_version: runtime.version.clone(),
        previous_stable_version: previous.filter(|value| value != &runtime.version),
    };
    write_active(root, &active)?;
    Ok(active)
}

pub fn rollback(root: &Path) -> Result<ActiveRuntime, MaaRuntimeError> {
    let current = read_active(root)?;
    let previous = current.previous_stable_version.ok_or_else(|| {
        MaaRuntimeError::new(
            "maa.rollback_unavailable",
            "no previous stable runtime exists",
        )
    })?;
    if !root.join("versions").join(&previous).is_dir() {
        return Err(MaaRuntimeError::new(
            "maa.rollback_unavailable",
            "previous stable runtime directory is missing",
        ));
    }
    let active = ActiveRuntime {
        schema_version: 1,
        active_version: previous,
        previous_stable_version: Some(current.active_version),
    };
    write_active(root, &active)?;
    Ok(active)
}

fn read_active(root: &Path) -> Result<ActiveRuntime, MaaRuntimeError> {
    serde_json::from_slice(&fs::read(root.join("active.json"))?)
        .map_err(|error| MaaRuntimeError::new("maa.active_invalid", error.to_string()))
}

fn write_active(root: &Path, active: &ActiveRuntime) -> Result<(), MaaRuntimeError> {
    fs::create_dir_all(root)?;
    let target = root.join("active.json");
    let staged = root.join("active.json.new");
    fs::write(
        &staged,
        serde_json::to_vec_pretty(active)
            .map_err(|error| MaaRuntimeError::new("maa.active_invalid", error.to_string()))?,
    )?;
    replace_file(&staged, &target)
}

#[cfg(not(windows))]
fn replace_file(staged: &Path, target: &Path) -> Result<(), MaaRuntimeError> {
    fs::rename(staged, target).map_err(Into::into)
}

#[cfg(windows)]
fn replace_file(staged: &Path, target: &Path) -> Result<(), MaaRuntimeError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{ReplaceFileW, REPLACE_FILE_FLAGS};

    if !target.exists() {
        return fs::rename(staged, target).map_err(Into::into);
    }
    let staged = staged
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    unsafe {
        ReplaceFileW(
            PCWSTR(target.as_ptr()),
            PCWSTR(staged.as_ptr()),
            PCWSTR::null(),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
        .map_err(|error| MaaRuntimeError::new("maa.activation_failed", error.to_string()))
    }
}
