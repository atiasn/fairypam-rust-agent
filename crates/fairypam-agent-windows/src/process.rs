use sha2::{Digest, Sha256};

/// Produces a stable Windows path identity without accepting filesystem aliases.
pub fn normalize_process_path(path: &str) -> Option<String> {
    let trimmed = path.trim().trim_matches('"').replace('/', "\\");
    let normalized = if let Some(unc) = trimmed.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        trimmed
            .strip_prefix(r"\\?\")
            .unwrap_or(&trimmed)
            .to_string()
    };
    let trimmed = normalized.as_str();
    if trimmed.is_empty() || !trimmed.contains('\\') {
        return None;
    }
    Some(trimmed.to_lowercase())
}

pub fn normalized_process_path_sha256(path: &str) -> Option<[u8; 32]> {
    let normalized = normalize_process_path(path)?;
    Some(Sha256::digest(normalized.as_bytes()).into())
}

pub fn process_path_is_within(path: &str, root: &str) -> bool {
    let (Some(path), Some(root)) = (normalize_process_path(path), normalize_process_path(root))
    else {
        return false;
    };
    let root = root.trim_end_matches('\\');
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

#[cfg(windows)]
pub fn matching_process_ids(
    executable: &std::path::Path,
) -> Result<Vec<u32>, fairypam_agent_core::AgentError> {
    use windows::Win32::Foundation::{GetLastError, ERROR_NO_MORE_FILES};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let expected =
        normalized_process_path_sha256(&executable.to_string_lossy()).ok_or_else(|| {
            fairypam_agent_core::AgentError::new(
                "target_invalid",
                "trusted executable path cannot be normalized",
            )
        })?;
    let expected_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            fairypam_agent_core::AgentError::new(
                "target_invalid",
                "trusted executable has no valid file name",
            )
        })?;
    let snapshot = OwnedHandle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|error| {
            fairypam_agent_core::AgentError::new("target.enumeration_failed", error.to_string())
        })?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe { Process32FirstW(snapshot.0, &mut entry) }.map_err(|error| {
        fairypam_agent_core::AgentError::new("target.enumeration_failed", error.to_string())
    })?;
    let mut matches = Vec::new();
    loop {
        let name_end = entry
            .szExeFile
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..name_end]);
        if entry.th32ProcessID != 0 && name.eq_ignore_ascii_case(expected_name) {
            if query_process_path(entry.th32ProcessID)?
                .and_then(|path| normalized_process_path_sha256(&path))
                == Some(expected)
            {
                matches.push(entry.th32ProcessID);
            }
        }
        if let Err(error) = unsafe { Process32NextW(snapshot.0, &mut entry) } {
            if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(fairypam_agent_core::AgentError::new(
                "target.enumeration_failed",
                error.to_string(),
            ));
        }
    }
    matches.sort_unstable();
    matches.dedup();
    Ok(matches)
}

#[cfg(windows)]
pub fn process_matches_executable(
    process_id: u32,
    executable: &std::path::Path,
) -> Result<bool, fairypam_agent_core::AgentError> {
    let expected =
        normalized_process_path_sha256(&executable.to_string_lossy()).ok_or_else(|| {
            fairypam_agent_core::AgentError::new(
                "target_invalid",
                "trusted executable path cannot be normalized",
            )
        })?;
    Ok(
        query_process_path(process_id)?.and_then(|path| normalized_process_path_sha256(&path))
            == Some(expected),
    )
}

#[cfg(windows)]
fn query_process_path(process_id: u32) -> Result<Option<String>, fairypam_agent_core::AgentError> {
    use windows::core::{HRESULT, PWSTR};
    use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let process = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
    {
        Ok(process) => OwnedHandle(process),
        Err(error) if error.code() == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) => {
            return Ok(None);
        }
        Err(error) => {
            return Err(fairypam_agent_core::AgentError::new(
                "target.identity_unknown",
                error.to_string(),
            ));
        }
    };
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|error| {
        fairypam_agent_core::AgentError::new("target.identity_unknown", error.to_string())
    })?;
    String::from_utf16(&buffer[..length as usize])
        .map(Some)
        .map_err(|_| {
            fairypam_agent_core::AgentError::new(
                "target.identity_unknown",
                "target executable path is not valid UTF-16",
            )
        })
}

#[cfg(windows)]
struct OwnedHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_and_regular_paths_share_one_identity() {
        assert_eq!(
            normalized_process_path_sha256(r"\\?\C:\Games\Testbed.exe"),
            normalized_process_path_sha256(r"c:/games/testbed.exe")
        );
    }

    #[test]
    fn basename_is_not_a_process_path_identity() {
        assert_eq!(normalized_process_path_sha256("testbed.exe"), None);
    }

    #[test]
    fn extended_unc_path_shares_the_regular_unc_identity() {
        assert_eq!(
            normalized_process_path_sha256(r"\\?\UNC\server\share\Testbed.exe"),
            normalized_process_path_sha256(r"\\server\share\testbed.exe")
        );
    }

    #[test]
    fn protected_root_match_has_a_component_boundary() {
        assert!(process_path_is_within(
            r"C:\Program Files\FairyPam\fairypam-agent.exe",
            r"c:\program files"
        ));
        assert!(!process_path_is_within(
            r"C:\Program Files-Evil\FairyPam\fairypam-agent.exe",
            r"C:\Program Files"
        ));
    }
}
