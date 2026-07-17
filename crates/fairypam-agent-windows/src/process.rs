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
}
