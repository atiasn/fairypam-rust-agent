use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::MaaRuntimeError;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveRuntime {
    pub schema_version: u32,
    pub active_version: String,
    pub previous_stable_version: Option<String>,
}

pub fn discover_active(root: &Path) -> Result<(ActiveRuntime, PathBuf), MaaRuntimeError> {
    let active: ActiveRuntime = serde_json::from_slice(&fs::read(root.join("active.json"))?)
        .map_err(|error| MaaRuntimeError::new("maa.active_invalid", error.to_string()))?;
    if active.schema_version != 1 || !safe_version(&active.active_version) {
        return Err(MaaRuntimeError::new(
            "maa.active_invalid",
            "active runtime pointer is invalid",
        ));
    }
    Ok((
        active.clone(),
        root.join("versions").join(active.active_version),
    ))
}

pub(crate) fn safe_version(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}
