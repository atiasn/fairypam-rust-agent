//! Local read-only HoYoverse / miHoYo game discovery.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryHive {
    Machine,
    User,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MihoyoRegistryEntry {
    pub source_hive: RegistryHive,
    pub display_name: Option<String>,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    pub display_icon: Option<PathBuf>,
    pub uninstall_string: Option<String>,
    pub game_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MihoyoGameInstall {
    pub discovery_id: String,
    pub profile_id: Option<String>,
    pub display_name: String,
    pub registry: MihoyoRegistryEntry,
    pub launch_path: Option<PathBuf>,
    pub game_dir: Option<PathBuf>,
    pub game_version: Option<String>,
    pub channel: Option<String>,
    pub sub_channel: Option<String>,
    pub cps: Option<String>,
    pub exists_on_disk: bool,
    pub supported: bool,
    pub last_scanned_at: Option<DateTime<Utc>>,
    pub scan_status: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KnownGame {
    game_id: &'static str,
    profile_id: &'static str,
    display_name: &'static str,
    game_dir: &'static str,
    process_name: &'static str,
    supported: bool,
}

const KNOWN_GAMES: &[KnownGame] = &[
    KnownGame {
        game_id: "hk4e_cn",
        profile_id: "genshin",
        display_name: "原神",
        game_dir: "Genshin Impact Game",
        process_name: "YuanShen.exe",
        supported: true,
    },
    KnownGame {
        game_id: "hkrpg_cn",
        profile_id: "star_rail",
        display_name: "崩坏：星穹铁道",
        game_dir: "Star Rail Game",
        process_name: "StarRail.exe",
        supported: false,
    },
    KnownGame {
        game_id: "nap_cn",
        profile_id: "zzz",
        display_name: "绝区零",
        game_dir: "ZenlessZoneZero Game",
        process_name: "ZZZ.exe",
        supported: false,
    },
];

pub fn discover_mihoyo_games() -> Result<Vec<MihoyoGameInstall>> {
    let scanned_at = Some(Utc::now());
    discover_from_entries(read_registry_entries()?, scanned_at)
}

pub(crate) fn discover_from_entries(
    entries: Vec<MihoyoRegistryEntry>,
    scanned_at: Option<DateTime<Utc>>,
) -> Result<Vec<MihoyoGameInstall>> {
    let mut seen = HashSet::new();
    let mut installs = Vec::new();
    for mut entry in entries.into_iter().filter(is_mihoyo_entry) {
        entry.game_id = entry
            .game_id
            .take()
            .or_else(|| entry.uninstall_string.as_deref().and_then(extract_game_id));
        if entry
            .game_id
            .as_deref()
            .and_then(known_game_by_id)
            .is_none()
        {
            continue;
        }
        let key = dedupe_key(&entry);
        if !seen.insert(key) {
            continue;
        }

        installs.push(build_install(entry, scanned_at)?);
    }
    Ok(installs)
}

pub(crate) fn extract_game_id(uninstall_string: &str) -> Option<String> {
    let (_, rest) = uninstall_string.split_once("--uninstall_game=")?;
    let id = rest.split_whitespace().next()?.trim_matches('"').trim();
    (!id.is_empty()).then(|| id.to_string())
}

pub fn is_trusted_elevated_install(game: &MihoyoGameInstall) -> bool {
    let roots = ["ProgramFiles", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    is_trusted_elevated_install_with_roots(game, &roots)
}

fn is_trusted_elevated_install_with_roots(game: &MihoyoGameInstall, roots: &[PathBuf]) -> bool {
    game.registry.source_hive == RegistryHive::Machine
        && game
            .launch_path
            .as_deref()
            .is_some_and(|path| is_path_under_protected_roots(path, roots))
}

fn is_path_under_protected_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let path = normalize_path_for_compare(path);
    roots.iter().any(|root| {
        let root = normalize_path_for_compare(root);
        !root.is_empty()
            && path
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn normalize_path_for_compare(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn build_install(
    entry: MihoyoRegistryEntry,
    scanned_at: Option<DateTime<Utc>>,
) -> Result<MihoyoGameInstall> {
    let known = entry.game_id.as_deref().and_then(known_game_by_id);
    let launch_path = known.and_then(|game| {
        entry
            .install_location
            .as_ref()
            .map(|root| derive_launch_path(root, game))
    });
    let game_dir = launch_path
        .as_ref()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let exists_on_disk = launch_path.as_ref().is_some_and(|path| path.exists());
    let metadata = read_metadata(entry.install_location.as_deref(), game_dir.as_deref());
    let display_name = entry
        .display_name
        .clone()
        .or_else(|| known.map(|game| game.display_name.to_string()))
        .unwrap_or_else(|| "HoYoverse".to_string());
    let discovery_id = discovery_id(&entry);

    Ok(MihoyoGameInstall {
        discovery_id,
        profile_id: known.map(|game| game.profile_id.to_string()),
        display_name,
        registry: entry,
        launch_path,
        game_dir,
        game_version: metadata.get("game_version").cloned(),
        channel: metadata.get("channel").cloned(),
        sub_channel: metadata.get("sub_channel").cloned(),
        cps: metadata.get("cps").cloned(),
        exists_on_disk,
        supported: known.is_some_and(|game| game.supported),
        last_scanned_at: scanned_at,
        scan_status: Some("ok".to_string()),
        error: None,
    })
}

fn known_game_by_id(game_id: &str) -> Option<&'static KnownGame> {
    KNOWN_GAMES.iter().find(|game| game.game_id == game_id)
}

fn derive_launch_path(root: &Path, game: &KnownGame) -> PathBuf {
    root.join("games")
        .join(game.game_dir)
        .join(game.process_name)
}

fn read_metadata(launcher_dir: Option<&Path>, game_dir: Option<&Path>) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    for path in [launcher_dir, game_dir]
        .into_iter()
        .flatten()
        .map(|dir| dir.join("config.ini"))
    {
        if let Ok(content) = std::fs::read_to_string(path) {
            metadata.extend(parse_ini_metadata(&content));
        }
    }
    metadata
}

pub(crate) fn parse_ini_metadata(content: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in content.lines().map(str::trim) {
        if line.is_empty() || matches!(line.chars().next(), Some('#' | ';' | '[')) {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "game_version" | "channel" | "sub_channel" | "cps"
        ) {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                values.insert(key, value.to_string());
            }
        }
    }
    values
}

fn is_mihoyo_entry(entry: &MihoyoRegistryEntry) -> bool {
    if entry.game_id.is_some()
        || entry
            .uninstall_string
            .as_deref()
            .is_some_and(|value| value.contains("--uninstall_game="))
    {
        return true;
    }

    [
        entry.display_name.as_deref(),
        entry.publisher.as_deref(),
        entry
            .install_location
            .as_ref()
            .and_then(|path| path.to_str()),
        entry.display_icon.as_ref().and_then(|path| path.to_str()),
        entry.uninstall_string.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| {
        let lower = value.to_ascii_lowercase();
        lower.contains("mihoyo") || lower.contains("hoyo") || lower.contains("hoyoplay")
    })
}

fn dedupe_key(entry: &MihoyoRegistryEntry) -> String {
    format!(
        "{}|{}|{}",
        entry.display_name.as_deref().unwrap_or_default(),
        entry.uninstall_string.as_deref().unwrap_or_default(),
        entry
            .install_location
            .as_ref()
            .and_then(|path| path.to_str())
            .unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn discovery_id(entry: &MihoyoRegistryEntry) -> String {
    let game_id = entry.game_id.as_deref().unwrap_or("launcher");
    let install = entry
        .install_location
        .as_ref()
        .and_then(|path| path.to_str())
        .unwrap_or_default();
    format!("{game_id}:{}", install.to_ascii_lowercase())
}

#[cfg(not(target_os = "windows"))]
fn read_registry_entries() -> Result<Vec<MihoyoRegistryEntry>> {
    Ok(Vec::new())
}

#[cfg(target_os = "windows")]
fn read_registry_entries() -> Result<Vec<MihoyoRegistryEntry>> {
    let mut entries = Vec::new();
    for (root, reg_view) in [
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            Some("/reg:64"),
        ),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            Some("/reg:32"),
        ),
        (
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            None,
        ),
    ] {
        entries.extend(query_registry_view(root, reg_view)?);
    }
    Ok(entries)
}

#[cfg(target_os = "windows")]
fn query_registry_view(root: &str, reg_view: Option<&str>) -> Result<Vec<MihoyoRegistryEntry>> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut command = std::process::Command::new("reg");
    command.args(["query", root, "/s"]);
    if let Some(reg_view) = reg_view {
        command.arg(reg_view);
    }

    let output = match command.creation_flags(CREATE_NO_WINDOW).output() {
        Ok(output) if reg_query_output_is_usable(output.status.success(), &output.stdout) => output,
        Ok(_) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let source_hive = if root.starts_with("HKLM") {
        RegistryHive::Machine
    } else {
        RegistryHive::User
    };
    Ok(parse_reg_query_output(&decode_reg_stdout(&output.stdout))
        .into_iter()
        .map(|mut entry| {
            entry.source_hive = source_hive;
            entry
        })
        .collect())
}

#[cfg(any(target_os = "windows", test))]
fn reg_query_output_is_usable(status_success: bool, stdout: &[u8]) -> bool {
    status_success || !stdout.is_empty()
}

#[cfg(target_os = "windows")]
fn decode_reg_stdout(bytes: &[u8]) -> String {
    if let Some(text) = decode_utf16le_stdout(bytes) {
        return text;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }

    use windows::Win32::Globalization::{
        MultiByteToWideChar, CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS,
    };

    unsafe {
        let flags = MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0);
        let len = MultiByteToWideChar(CP_OEMCP, flags, bytes, None);
        if len <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }

        let mut wide = vec![0u16; len as usize];
        let written = MultiByteToWideChar(CP_OEMCP, flags, bytes, Some(&mut wide));
        if written <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }

        String::from_utf16_lossy(&wide[..written as usize])
    }
}

#[cfg(all(not(target_os = "windows"), test))]
fn decode_reg_stdout(bytes: &[u8]) -> String {
    if let Some(text) = decode_utf16le_stdout(bytes) {
        return text;
    }
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(any(target_os = "windows", test))]
fn decode_utf16le_stdout(bytes: &[u8]) -> Option<String> {
    let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }

    let sample_pairs = bytes.chunks_exact(2).take(64).count().max(1);
    let ascii_nul_pairs = bytes
        .chunks_exact(2)
        .take(64)
        .filter(|pair| pair[0].is_ascii() && pair[1] == 0)
        .count();
    if ascii_nul_pairs * 2 < sample_pairs {
        return None;
    }

    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

#[cfg(any(target_os = "windows", test))]
fn parse_reg_query_output(output: &str) -> Vec<MihoyoRegistryEntry> {
    let mut entries = Vec::new();
    let mut current = MihoyoRegistryEntry::default();
    let mut has_values = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("HKEY_")
            || trimmed.starts_with("HKLM\\")
            || trimmed.starts_with("HKCU\\")
        {
            if has_values {
                entries.push(current);
                current = MihoyoRegistryEntry::default();
                has_values = false;
            }
            continue;
        }

        let Some((name, value)) = parse_reg_value_line(trimmed) else {
            continue;
        };
        has_values = true;
        match name {
            "DisplayName" => current.display_name = Some(value),
            "DisplayVersion" => current.display_version = Some(value),
            "Publisher" => current.publisher = Some(value),
            "InstallLocation" => current.install_location = Some(PathBuf::from(value)),
            "DisplayIcon" => current.display_icon = Some(PathBuf::from(value)),
            "UninstallString" => current.uninstall_string = Some(value),
            _ => {}
        }
    }
    if has_values {
        entries.push(current);
    }
    entries
}

#[cfg(any(target_os = "windows", test))]
fn parse_reg_value_line(line: &str) -> Option<(&str, String)> {
    let type_start = line.find("REG_")?;
    let name = line[..type_start].trim();
    let after_type = &line[type_start..];
    let value_start = after_type.find(char::is_whitespace)?;
    let value = after_type[value_start..].trim();
    (!name.is_empty()).then(|| (name, value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn entry(game_id: Option<&str>, root: &str) -> MihoyoRegistryEntry {
        MihoyoRegistryEntry {
            source_hive: RegistryHive::Machine,
            display_name: Some("HoYoPlay".to_string()),
            display_version: Some("1.2.3".to_string()),
            publisher: Some("miHoYo".to_string()),
            install_location: Some(PathBuf::from(root)),
            display_icon: None,
            uninstall_string: game_id
                .map(|id| format!(r#""C:\HoYoPlay\uninstall.exe" --uninstall_game={id} --foo"#)),
            game_id: None,
        }
    }

    #[test]
    fn elevated_self_test_rejects_user_hive_and_unprotected_paths() {
        let base =
            std::env::temp_dir().join(format!("fairypam-discovery-trust-{}", std::process::id()));
        let protected_root = base.join("Program Files");
        let protected_exe = protected_root.join("miHoYo").join("YuanShen.exe");
        let outside_exe = base.join("Downloads").join("YuanShen.exe");
        std::fs::create_dir_all(protected_exe.parent().unwrap()).unwrap();
        std::fs::create_dir_all(outside_exe.parent().unwrap()).unwrap();
        std::fs::write(&protected_exe, b"test").unwrap();
        std::fs::write(&outside_exe, b"test").unwrap();

        let mut install = MihoyoGameInstall {
            registry: entry(Some("hk4e_cn"), protected_root.to_str().unwrap()),
            launch_path: Some(protected_exe),
            supported: true,
            exists_on_disk: true,
            ..Default::default()
        };
        assert!(is_trusted_elevated_install_with_roots(
            &install,
            std::slice::from_ref(&protected_root)
        ));

        install.registry.source_hive = RegistryHive::User;
        assert!(!is_trusted_elevated_install_with_roots(
            &install,
            std::slice::from_ref(&protected_root)
        ));
        install.registry.source_hive = RegistryHive::Machine;
        install.launch_path = Some(outside_exe);
        assert!(!is_trusted_elevated_install_with_roots(
            &install,
            std::slice::from_ref(&protected_root)
        ));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn game_id_extraction_handles_quotes_and_tail_args() {
        assert_eq!(
            extract_game_id(r#""C:\HoYoPlay\uninstall.exe" --uninstall_game="hk4e_cn" --foo"#)
                .as_deref(),
            Some("hk4e_cn")
        );
        assert_eq!(extract_game_id(r"C:\HoYoPlay\uninstall.exe"), None);
    }

    #[test]
    fn discovery_filters_dedupes_and_maps_known_games() {
        let scanned_at = Utc.with_ymd_and_hms(2026, 7, 4, 0, 0, 0).single();
        let installs = discover_from_entries(
            vec![
                entry(Some("hk4e_cn"), r"C:\Program Files\miHoYo Launcher"),
                entry(Some("hk4e_cn"), r"C:\Program Files\miHoYo Launcher"),
                entry(None, r"C:\Program Files\miHoYo Launcher"),
                MihoyoRegistryEntry {
                    display_name: Some("Other App".to_string()),
                    ..Default::default()
                },
            ],
            scanned_at,
        )
        .unwrap();

        assert_eq!(installs.len(), 1);
        let install = &installs[0];
        assert_eq!(install.profile_id.as_deref(), Some("genshin"));
        assert!(install.supported);
        assert_eq!(install.last_scanned_at, scanned_at);
        let launch_path = install.launch_path.as_ref().unwrap();
        assert_eq!(
            launch_path.file_name().and_then(|name| name.to_str()),
            Some("YuanShen.exe")
        );
        assert!(launch_path
            .to_string_lossy()
            .contains("Genshin Impact Game"));
    }

    #[test]
    fn unsupported_games_are_discovered_but_not_operable() {
        let installs =
            discover_from_entries(vec![entry(Some("hkrpg_cn"), r"C:\HoYoPlay")], None).unwrap();
        assert_eq!(installs[0].profile_id.as_deref(), Some("star_rail"));
        assert!(!installs[0].supported);
        assert!(!(installs[0].supported && installs[0].exists_on_disk));
    }

    #[test]
    fn unknown_game_is_not_listed_as_discovered_game() {
        let installs =
            discover_from_entries(vec![entry(Some("unknown_cn"), r"C:\HoYoPlay")], None).unwrap();
        assert!(installs.is_empty());
    }

    #[test]
    fn ini_metadata_ignores_missing_or_bad_lines() {
        let values = parse_ini_metadata(
            r#"
            [General]
            game_version = 5.7.0
            channel=1
            sub_channel = "3"
            cps =
            invalid
            "#,
        );
        assert_eq!(
            values.get("game_version").map(String::as_str),
            Some("5.7.0")
        );
        assert_eq!(values.get("channel").map(String::as_str), Some("1"));
        assert_eq!(values.get("sub_channel").map(String::as_str), Some("3"));
        assert!(!values.contains_key("cps"));
    }

    #[test]
    fn registry_query_uses_partial_stdout_even_when_exit_code_fails() {
        assert!(reg_query_output_is_usable(
            false,
            b"HKEY_LOCAL_MACHINE\\..."
        ));
        assert!(!reg_query_output_is_usable(false, b""));
    }

    #[test]
    fn registry_stdout_keeps_utf8_chinese() {
        assert_eq!(decode_reg_stdout("原神".as_bytes()), "原神");
    }

    #[test]
    fn registry_stdout_decodes_utf16le_before_utf8() {
        let text = "HKEY_LOCAL_MACHINE\\x\r\n    DisplayName    REG_SZ    原神\r\n";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();

        let decoded = decode_reg_stdout(&bytes);
        let entries = parse_reg_query_output(&decoded);

        assert_eq!(entries[0].display_name.as_deref(), Some("原神"));
    }
}
