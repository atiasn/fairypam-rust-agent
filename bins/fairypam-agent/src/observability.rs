#![cfg_attr(not(windows), allow(dead_code))]

use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use fairypam_agent_core::AgentError;
use fairypam_agent_local_protocol::LogLevel;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::profile_store::ProfileStore;

const MAX_LOG_BYTES: u64 = 256 * 1024;
const MAX_LOG_FILES: u8 = 3;
const LOG_FILE: &str = "agent.log";

pub struct FixedLog {
    root: PathBuf,
}

impl FixedLog {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, AgentError> {
        let root = root.into();
        let metadata = root.symlink_metadata().map_err(log_root_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(log_root_unavailable());
        }
        Ok(Self { root })
    }

    pub fn append(&self, level: LogLevel, message: &str) -> Result<(), AgentError> {
        let record = AgentLogRecord::new(level, redact_log_line(message));
        let line = serde_json::to_string(&json!({
            "level": log_level_name(&record.level),
            "message": record.message,
        }))
        .map_err(|_| AgentError::new("local.log_write_failed", "Agent log cannot be encoded"))?;
        self.rotate_if_needed(line.len() as u64 + 1)?;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(0))
            .and_then(|mut file| writeln!(file, "{line}"))
            .map_err(|_| AgentError::new("local.log_write_failed", "Agent log cannot be persisted"))
    }

    pub fn tail(&self, lines: u16, level: &LogLevel) -> Result<Value, AgentError> {
        let mut records = Vec::new();
        for index in (0..MAX_LOG_FILES).rev() {
            let path = self.path(index);
            let Ok(file) = fs::File::open(&path) else {
                continue;
            };
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let value = serde_json::from_str::<Value>(&line).ok();
                let Some(value) = value else { continue };
                let Some(level) = value
                    .get("level")
                    .and_then(Value::as_str)
                    .and_then(parse_log_level)
                else {
                    continue;
                };
                let Some(message) = value.get("message").and_then(Value::as_str) else {
                    continue;
                };
                records.push(AgentLogRecord::new(level, message));
            }
        }
        Ok(log_tail_json(&records, lines, level))
    }

    fn rotate_if_needed(&self, incoming: u64) -> Result<(), AgentError> {
        let current = self.path(0);
        let size = current
            .metadata()
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if size.saturating_add(incoming) <= MAX_LOG_BYTES {
            return Ok(());
        }
        for index in (1..MAX_LOG_FILES).rev() {
            let source = self.path(index);
            let target = self.path(index + 1);
            if source.exists() {
                let _ = fs::remove_file(&target);
                fs::rename(source, target).map_err(|_| log_root_unavailable())?;
            }
        }
        if current.exists() {
            fs::rename(current, self.path(1)).map_err(|_| log_root_unavailable())?;
        }
        Ok(())
    }

    fn path(&self, index: u8) -> PathBuf {
        match index {
            0 => self.root.join(LOG_FILE),
            _ => self.root.join(format!("{LOG_FILE}.{index}")),
        }
    }
}

#[cfg(windows)]
pub fn production_log() -> Result<FixedLog, AgentError> {
    let root = PathBuf::from(r"C:\ProgramData\FairyPam\Agent\logs");
    crate::enrollment::ensure_private_directory(&root)?;
    FixedLog::open(root)
}

fn log_root_error(_: std::io::Error) -> AgentError {
    log_root_unavailable()
}

fn log_root_unavailable() -> AgentError {
    AgentError::new(
        "local.log_root_unavailable",
        "protected Agent log directory is unavailable",
    )
}

#[derive(Clone, Debug)]
pub struct AgentLogRecord {
    pub level: LogLevel,
    pub message: String,
}

impl AgentLogRecord {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
        }
    }
}

pub fn redact_log_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if [
        "token",
        "password",
        "secret",
        "private_key",
        "client_key",
        "certificate",
        "api_key",
        "registration_code",
    ]
    .into_iter()
    .any(|marker| lower.contains(marker))
        || lower.contains("bearer ")
        || lower.contains("-----begin ")
        || contains_jwt(line)
        || contains_absolute_path(line)
    {
        "[redacted agent log content]".to_owned()
    } else {
        line.chars().take(512).collect()
    }
}

pub fn log_tail_json(records: &[AgentLogRecord], lines: u16, level: &LogLevel) -> Value {
    let entries = records
        .iter()
        .rev()
        .filter(|record| includes_level(level, &record.level))
        .take(usize::from(lines))
        .map(|record| {
            json!({
                "level": log_level_name(&record.level),
                "message": redact_log_line(&record.message),
            })
        })
        .collect::<Vec<_>>();
    json!({"entries": entries})
}

pub fn scan_installed_games(profiles: &ProfileStore) -> Result<Value, AgentError> {
    let entries = registry_entries()?;
    Ok(json!({"games": scan_entries(&entries, profiles)}))
}

#[derive(Default)]
struct RegistryEntry {
    source: RegistrySource,
    display_name: Option<String>,
    display_version: Option<String>,
    install_location: Option<String>,
    uninstall_string: Option<String>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum RegistrySource {
    #[default]
    Machine,
    #[cfg(test)]
    CurrentUser,
}

struct KnownGame {
    game_id: &'static str,
    display_name: &'static str,
    game_dir: &'static str,
    process_name: &'static str,
}

const KNOWN_GAMES: &[KnownGame] = &[
    KnownGame {
        game_id: "hk4e_cn",
        display_name: "原神",
        game_dir: "Genshin Impact Game",
        process_name: "YuanShen.exe",
    },
    KnownGame {
        game_id: "hkrpg_cn",
        display_name: "崩坏：星穹铁道",
        game_dir: "Star Rail Game",
        process_name: "StarRail.exe",
    },
    KnownGame {
        game_id: "nap_cn",
        display_name: "绝区零",
        game_dir: "ZenlessZoneZero Game",
        process_name: "ZZZ.exe",
    },
];

fn scan_entries(entries: &[RegistryEntry], profiles: &ProfileStore) -> Vec<Value> {
    let mut seen = HashSet::new();
    entries
        .iter()
        .filter_map(|entry| {
            if entry.source != RegistrySource::Machine {
                return None;
            }
            let game_id = entry
                .uninstall_string
                .as_deref()
                .and_then(extract_game_id)?;
            let known = KNOWN_GAMES.iter().find(|game| game.game_id == game_id)?;
            let root = entry.install_location.as_deref().unwrap_or_default();
            let dedupe_key = format!("{game_id}:{}", root.to_ascii_lowercase());
            if !seen.insert(dedupe_key.clone()) {
                return None;
            }
            let executable = Path::new(root)
                .join("games")
                .join(known.game_dir)
                .join(known.process_name);
            let installed = trusted_executable(&executable);
            let version = installed
                .then(|| game_version(Path::new(root), &executable))
                .flatten()
                .or_else(|| entry.display_version.clone());
            Some(json!({
                "discovery_id": stable_discovery_id(&dedupe_key),
                "name": entry.display_name.as_deref().unwrap_or(known.display_name),
                "version": version,
                "installed": installed,
                "supported": installed && profile_supports_process(profiles, known.process_name),
            }))
        })
        .collect()
}

fn profile_supports_process(profiles: &ProfileStore, process_name: &str) -> bool {
    profiles.ids().iter().any(|profile_id| {
        profiles.get(profile_id).is_ok_and(|profile| {
            profile
                .profile()
                .target
                .process_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(process_name))
        })
    })
}

fn trusted_executable(executable: &Path) -> bool {
    if !executable.is_absolute()
        || !matches!(executable.extension(), Some(extension) if extension == "exe")
        || executable.to_string_lossy().starts_with(r"\\")
    {
        return false;
    }
    for component in executable.ancestors() {
        let Ok(metadata) = component.symlink_metadata() else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
    }
    executable.is_file()
}

fn game_version(launcher_dir: &Path, executable: &Path) -> Option<String> {
    [Some(launcher_dir), executable.parent()]
        .into_iter()
        .flatten()
        .filter_map(|directory| std::fs::read_to_string(directory.join("config.ini")).ok())
        .filter_map(|content| ini_value(&content, "game_version"))
        .next()
}

fn ini_value(content: &str, wanted_key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let (key, value) = line.trim().split_once('=')?;
        if key.trim().eq_ignore_ascii_case(wanted_key) {
            let value = value.trim().trim_matches('"');
            (!value.is_empty()).then(|| value.to_owned())
        } else {
            None
        }
    })
}

fn extract_game_id(uninstall: &str) -> Option<&str> {
    let (_, tail) = uninstall.split_once("--uninstall_game=")?;
    let game_id = tail.split_whitespace().next()?.trim_matches('"');
    (!game_id.is_empty()).then_some(game_id)
}

fn stable_discovery_id(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("mihoyo:{digest}")
}

fn includes_level(requested: &LogLevel, actual: &LogLevel) -> bool {
    log_level_rank(actual) <= log_level_rank(requested)
}

fn log_level_rank(level: &LogLevel) -> u8 {
    match level {
        LogLevel::Error => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
    }
}

fn log_level_name(level: &LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
    }
}

fn parse_log_level(value: &str) -> Option<LogLevel> {
    match value {
        "error" => Some(LogLevel::Error),
        "warn" => Some(LogLevel::Warn),
        "info" => Some(LogLevel::Info),
        _ => None,
    }
}

fn contains_absolute_path(value: &str) -> bool {
    value.contains(r"\\")
        || value.contains('/')
        || value
            .as_bytes()
            .windows(3)
            .any(|bytes| bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
}

fn contains_jwt(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '.')
        .any(|compact| {
            let mut segments = compact.split('.');
            let Some(header) = segments.next() else {
                return false;
            };
            let Some(payload) = segments.next() else {
                return false;
            };
            let Some(signature) = segments.next() else {
                return false;
            };
            segments.next().is_none()
                && header.starts_with("eyJ")
                && !payload.is_empty()
                && signature.len() >= 16
        })
}

#[cfg(windows)]
fn registry_entries() -> Result<Vec<RegistryEntry>, AgentError> {
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS},
            System::Registry::{
                RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY,
                HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_EXPAND_SZ,
                REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
            },
        },
    };

    const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    struct OwnedKey(HKEY);

    impl Drop for OwnedKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn open_key(parent: HKEY, name: &str, access: REG_SAM_FLAGS) -> Result<OwnedKey, u32> {
        let name = wide(name);
        let mut key = HKEY(std::ptr::null_mut());
        let status =
            unsafe { RegOpenKeyExW(parent, PCWSTR(name.as_ptr()), None, access, &mut key) };
        status.is_ok().then_some(OwnedKey(key)).ok_or(status.0)
    }

    fn string_value(key: HKEY, name: &str) -> Option<String> {
        let name = wide(name);
        let mut kind = REG_VALUE_TYPE(0);
        let mut bytes = 0;
        let status = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut bytes),
            )
        };
        if !status.is_ok()
            || !matches!(kind, REG_SZ | REG_EXPAND_SZ)
            || bytes == 0
            || bytes % 2 != 0
        {
            return None;
        }
        let mut value = vec![0_u16; bytes as usize / 2];
        let status = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                None,
                Some(value.as_mut_ptr().cast()),
                Some(&mut bytes),
            )
        };
        if !status.is_ok() || bytes % 2 != 0 || bytes as usize / 2 > value.len() {
            return None;
        }
        value.truncate(bytes as usize / 2);
        if value.last() == Some(&0) {
            value.pop();
        }
        String::from_utf16(&value).ok()
    }

    fn entries_in_view(access: REG_SAM_FLAGS) -> Result<Option<Vec<RegistryEntry>>, AgentError> {
        let uninstall = match open_key(HKEY_LOCAL_MACHINE, UNINSTALL_KEY, KEY_READ | access) {
            Ok(key) => key,
            Err(code) if code == ERROR_FILE_NOT_FOUND.0 => return Ok(None),
            Err(_) => {
                return Err(AgentError::new(
                    "game.discovery_unavailable",
                    "MiHoYo discovery is unavailable",
                ));
            }
        };
        let mut entries = Vec::new();
        for index in 0.. {
            let mut name = vec![0_u16; 256];
            let mut length = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    uninstall.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if !status.is_ok() || length as usize > name.len() {
                return Err(AgentError::new(
                    "game.discovery_unavailable",
                    "MiHoYo discovery is unavailable",
                ));
            }
            let Ok(name) = String::from_utf16(&name[..length as usize]) else {
                continue;
            };
            let Ok(key) = open_key(uninstall.0, &name, KEY_READ | access) else {
                continue;
            };
            entries.push(RegistryEntry {
                source: RegistrySource::Machine,
                display_name: string_value(key.0, "DisplayName"),
                display_version: string_value(key.0, "DisplayVersion"),
                install_location: string_value(key.0, "InstallLocation"),
                uninstall_string: string_value(key.0, "UninstallString"),
            });
        }
        Ok(Some(entries))
    }

    let mut entries = Vec::new();
    let mut opened = false;
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        if let Some(view_entries) = entries_in_view(view)? {
            opened = true;
            entries.extend(view_entries);
        }
    }
    opened.then_some(entries).ok_or_else(|| {
        AgentError::new(
            "game.discovery_unavailable",
            "MiHoYo discovery is unavailable",
        )
    })
}

#[cfg(not(windows))]
fn registry_entries() -> Result<Vec<RegistryEntry>, AgentError> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fairypam_agent_core::profile::{
        profile_content_sha256, verify_profile, ActionDefinition, CaptureRegion, CaptureSource,
        Profile, ProfileContent, ProfileEnvelope, SignatureVerifier, TargetRules,
    };

    use super::*;

    struct TestRoot;

    impl SignatureVerifier for TestRoot {
        fn verify(&self, _digest: &[u8; 32], signature: &str) -> bool {
            signature == "test-signature"
        }
    }

    fn signed_profile_for(process_name: &str) -> ProfileStore {
        let content = ProfileContent {
            schema_version: 1,
            profile: Profile {
                id: "profile-a".into(),
                version: "1.0.0".into(),
                display_name: "Profile A".into(),
                target: TargetRules {
                    process_names: vec![process_name.into()],
                    process_path_sha256: vec!["aa".repeat(32)],
                    window_classes: vec!["GameWindow".into()],
                    title_patterns: vec!["Game".into()],
                    require_elevated: false,
                    minimum_client_width: 1,
                    minimum_client_height: 1,
                    minimum_dpi: 96,
                },
                capture_sources: vec![CaptureSource {
                    id: "client".into(),
                    region: CaptureRegion::FullClient,
                    maximum_fps: 1,
                    encodings: vec!["jpeg".into()],
                }],
                actions: BTreeMap::from([(
                    "movement.forward".into(),
                    ActionDefinition::Hold { scan_code: 17 },
                )]),
            },
            files: Vec::new(),
        };
        let content_sha256 = profile_content_sha256(&content).unwrap();
        let verified = verify_profile(
            &serde_json::to_vec(&ProfileEnvelope {
                content,
                content_sha256,
                signature: "test-signature".into(),
            })
            .unwrap(),
            &TestRoot,
        )
        .unwrap();
        ProfileStore::from_verified_profiles([verified]).unwrap()
    }

    #[test]
    fn discovery_id_is_stable_and_does_not_expose_the_install_path() {
        let temporary = std::env::temp_dir();
        #[cfg(unix)]
        let temporary =
            std::fs::canonicalize(temporary).expect("temporary directory is canonicalizable");
        let root = temporary.join(format!("fairypam-discovery-{}", std::process::id()));
        let executable = root
            .join("games")
            .join("Genshin Impact Game")
            .join("YuanShen.exe");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, []).unwrap();
        std::fs::write(root.join("config.ini"), "game_version = 5.8.0\n").unwrap();
        let entries = [RegistryEntry {
            source: RegistrySource::Machine,
            display_name: Some("HoYoPlay".into()),
            display_version: Some("launcher-version".into()),
            install_location: Some(root.display().to_string()),
            uninstall_string: Some("uninstall.exe --uninstall_game=hk4e_cn".into()),
        }];
        let games = scan_entries(&entries, &ProfileStore::default());
        let first = games.first().expect("known game is discovered");
        assert_eq!(
            first["discovery_id"],
            stable_discovery_id(&format!(
                "hk4e_cn:{}",
                root.display().to_string().to_ascii_lowercase()
            ))
        );
        assert_eq!(first["version"], "5.8.0");
        assert_eq!(first["installed"], true);
        assert_eq!(first["supported"], false);
        assert!(!first.to_string().contains(root.to_string_lossy().as_ref()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn game_support_requires_a_verified_profile_process_mapping() {
        let profiles = signed_profile_for("YuanShen.exe");

        assert!(profile_supports_process(&profiles, "yuanshen.exe"));
        assert!(!profile_supports_process(&profiles, "StarRail.exe"));
    }

    #[test]
    fn fixed_log_tail_redacts_credentials_and_paths() {
        let tail = log_tail_json(
            &[AgentLogRecord::new(
                LogLevel::Info,
                r"connected token=secret C:\\ProgramData\\FairyPam\\agent.pem",
            )],
            20,
            &LogLevel::Info,
        );
        assert_eq!(
            tail["entries"][0]["message"],
            "[redacted agent log content]"
        );
        assert!(!tail.to_string().contains("secret"));
        assert!(!tail.to_string().contains("ProgramData"));
    }

    #[test]
    fn persistent_log_redacts_and_rotates_within_a_fixed_bound() {
        let root = std::env::temp_dir().join(format!(
            "fairypam-fixed-log-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let log = FixedLog::open(&root).unwrap();
        log.append(LogLevel::Info, "token=must-not-appear").unwrap();
        assert_eq!(
            log.tail(10, &LogLevel::Info).unwrap()["entries"][0]["message"],
            "[redacted agent log content]"
        );

        std::fs::write(root.join(LOG_FILE), vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();
        log.append(LogLevel::Info, "rotation check").unwrap();
        assert!(root.join(LOG_FILE).is_file());
        assert!(root.join(format!("{LOG_FILE}.1")).is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixed_log_tail_redacts_bearer_jwt_pem_and_registration_code() {
        let pem_marker = ["-----BEGIN", "PRIVATE", "KEY-----"].join(" ");
        for secret in [
            "Authorization: Bearer super-secret",
            "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.0123456789abcdef",
            pem_marker.as_str(),
            "registration_code=one-time-code",
        ] {
            assert_eq!(redact_log_line(secret), "[redacted agent log content]");
        }
    }

    #[test]
    fn current_user_and_reparse_entries_never_become_discoverable() {
        let user_entries = [RegistryEntry {
            source: RegistrySource::CurrentUser,
            display_name: Some("HoYoPlay".into()),
            display_version: None,
            install_location: Some(r"C:\\attacker".into()),
            uninstall_string: Some("uninstall.exe --uninstall_game=hk4e_cn".into()),
        }];
        assert!(scan_entries(&user_entries, &ProfileStore::default()).is_empty());

        let root = std::env::temp_dir().join(format!("fairypam-reparse-{}", std::process::id()));
        let target = root.join("target");
        #[cfg(unix)]
        let link = root.join("link");
        std::fs::create_dir_all(target.join("games/Genshin Impact Game")).unwrap();
        std::fs::write(target.join("games/Genshin Impact Game/YuanShen.exe"), []).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(unix)]
        assert!(!trusted_executable(
            &link.join("games/Genshin Impact Game/YuanShen.exe")
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
