//! Agent configuration loading and saving.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Hub connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    /// Hub WebSocket URL, for example ws://192.168.1.100:8000/ws.
    pub ws_url: String,
    /// Agent API key.
    pub api_key: String,
}

/// General agent settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Display name shown to the Hub.
    pub name: String,
    /// Log level: trace / debug / info / warn / error.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_auto_update() -> bool {
    true
}

fn default_auto_start() -> bool {
    false
}

fn default_command_timeout_s() -> u64 {
    60
}

fn default_launch_allowlist() -> Vec<String> {
    Vec::new()
}

/// Agent runtime settings persisted in local config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Whether auto-update is enabled.
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    /// Whether the agent should start on login.
    #[serde(default = "default_auto_start")]
    pub auto_start: bool,
    /// Default timeout for Hub commands, in seconds.
    #[serde(default = "default_command_timeout_s")]
    pub command_timeout_s: u64,
    /// Remote launch allowlist.
    #[serde(default = "default_launch_allowlist")]
    pub launch_allowlist: Vec<String>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            auto_update: default_auto_update(),
            auto_start: default_auto_start(),
            command_timeout_s: default_command_timeout_s(),
            launch_allowlist: default_launch_allowlist(),
        }
    }
}

/// Screen capture settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Target display index.
    #[serde(default)]
    pub target_display: u32,
    /// Capture frame rate.
    #[serde(default = "default_fps")]
    pub fps: u32,
    /// JPEG quality in the range 1-100.
    #[serde(default = "default_quality")]
    pub jpeg_quality: u8,
    /// Encoder name, such as media_foundation or gdi.
    #[serde(default = "default_encoder")]
    pub encoder: String,
}

/// Optional local override for a supported HoYoverse game profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GameProfileOverride {
    #[serde(default)]
    pub executable_path: Option<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub window_title: Option<String>,
    #[serde(default)]
    pub window_class: Option<String>,
}

fn default_game_profiles() -> HashMap<String, GameProfileOverride> {
    HashMap::new()
}

fn default_fps() -> u32 {
    30
}

fn default_quality() -> u8 {
    90
}

fn default_encoder() -> String {
    "media_foundation".to_string()
}

/// Top-level agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub hub: HubConfig,
    pub agent: AgentConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub capture: CaptureConfig,
    #[serde(default = "default_game_profiles")]
    pub game_profiles: HashMap<String, GameProfileOverride>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            hub: HubConfig {
                ws_url: "ws://127.0.0.1:8000/ws".to_string(),
                api_key: String::new(),
            },
            agent: AgentConfig {
                name: "FairyPam Agent".to_string(),
                log_level: default_log_level(),
            },
            runtime: RuntimeConfig::default(),
            capture: CaptureConfig {
                target_display: 0,
                fps: default_fps(),
                jpeg_quality: default_quality(),
                encoder: default_encoder(),
            },
            game_profiles: default_game_profiles(),
        }
    }
}

/// Load configuration from a YAML file.
pub fn load_config(path: impl AsRef<Path>) -> anyhow::Result<AppConfig> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read config file: {}", path.as_ref().display()))?;
    let content = content.trim_start_matches('\u{feff}');

    let config: AppConfig =
        serde_yaml::from_str(content).with_context(|| "invalid config file format")?;

    Ok(config)
}

/// Save configuration to a YAML file.
pub fn save_config(path: impl AsRef<Path>, config: &AppConfig) -> anyhow::Result<()> {
    let content =
        serde_yaml::to_string(config).with_context(|| "failed to serialize configuration")?;

    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory: {}", parent.display())
            })?;
        }
    }

    std::fs::write(path.as_ref(), content)
        .with_context(|| format!("failed to write config file: {}", path.as_ref().display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-config-load-test-{}",
            std::process::id()
        ));
        let path = dir.join("config.yaml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            "hub:\n  ws_url: \"ws://192.168.1.100:8000/ws\"\n  api_key: \"test\"\n\nagent:\n  name: \"我的游戏PC\"\n  log_level: \"info\"\n\ncapture:\n  fps: 30\n  target_display: 0\n  jpeg_quality: 90\n  encoder: \"media_foundation\"\n",
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.hub.ws_url, "ws://192.168.1.100:8000/ws");
        assert_eq!(config.agent.name, "我的游戏PC");
        assert_eq!(config.capture.fps, 30);
        assert_eq!(config.runtime, RuntimeConfig::default());
        assert!(config.game_profiles.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_missing_config_file() {
        let result = load_config("nonexistent.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_config_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("fairypam-agent-config-test-{}", std::process::id()));
        let path = dir.join("config.yaml");
        let config = AppConfig::default();

        save_config(&path, &config).unwrap();
        let loaded = load_config(&path).unwrap();

        assert_eq!(loaded.hub.ws_url, config.hub.ws_url);
        assert_eq!(loaded.agent.name, config.agent.name);
        assert_eq!(loaded.capture.fps, config.capture.fps);
        assert_eq!(loaded.runtime, config.runtime);
        assert_eq!(loaded.game_profiles, config.game_profiles);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_config_accepts_utf8_bom() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-bom-config-test-{}",
            std::process::id()
        ));
        let path = dir.join("config.yaml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            "\u{feff}hub:\n  ws_url: \"ws://127.0.0.1:8000/ws\"\n  api_key: \"test\"\n\nagent:\n  name: \"cleiagent\"\n\ncapture:\n  fps: 30\n",
        )
        .unwrap();

        let loaded = load_config(&path).unwrap();

        assert_eq!(loaded.hub.ws_url, "ws://127.0.0.1:8000/ws");
        assert_eq!(loaded.agent.name, "cleiagent");
        assert_eq!(loaded.capture.fps, 30);
        assert_eq!(loaded.runtime, RuntimeConfig::default());
        assert!(loaded.game_profiles.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_config_roundtrip_and_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-runtime-test-{}",
            std::process::id()
        ));
        let path = dir.join("config.yaml");
        let mut config = AppConfig::default();
        config.runtime.auto_update = false;
        config.runtime.auto_start = true;
        config.runtime.command_timeout_s = 123;
        config.runtime.launch_allowlist = vec!["tool.exe".into()];

        save_config(&path, &config).unwrap();
        let loaded = load_config(&path).unwrap();

        assert_eq!(loaded.runtime, config.runtime);

        let legacy_yaml = "hub:\n  ws_url: \"ws://127.0.0.1:8000/ws\"\n  api_key: \"test\"\n\nagent:\n  name: \"legacy\"\n  log_level: \"info\"\n\ncapture:\n  fps: 30\n";
        std::fs::write(&path, legacy_yaml).unwrap();
        let legacy_loaded = load_config(&path).unwrap();

        assert_eq!(legacy_loaded.runtime, RuntimeConfig::default());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn game_profile_override_roundtrip_and_legacy_default() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-profile-config-test-{}",
            std::process::id()
        ));
        let path = dir.join("config.yaml");
        let mut config = AppConfig::default();
        config.game_profiles.insert(
            "genshin".into(),
            GameProfileOverride {
                executable_path: Some(r"D:\Games\YuanShen.exe".into()),
                working_dir: Some(r"D:\Games".into()),
                process_name: Some("YuanShen.exe".into()),
                window_title: Some("原神".into()),
                window_class: Some("UnityWndClass".into()),
            },
        );

        save_config(&path, &config).unwrap();
        let loaded = load_config(&path).unwrap();

        assert_eq!(loaded.game_profiles, config.game_profiles);

        let legacy_yaml = "hub:\n  ws_url: \"ws://127.0.0.1:8000/ws\"\n  api_key: \"test\"\n\nagent:\n  name: \"legacy\"\n\ncapture:\n  fps: 30\n";
        std::fs::write(&path, legacy_yaml).unwrap();
        let legacy_loaded = load_config(&path).unwrap();

        assert!(legacy_loaded.game_profiles.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }
}
