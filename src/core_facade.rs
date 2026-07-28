use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::capture::{CapturedFrame, ScreenCapture};
use crate::config::{self, AppConfig};
use crate::input::InputController;
use crate::mihoyo_discovery::{self, MihoyoGameInstall};
use crate::process::{process_privilege_level, PrivilegeLevel, ProcessManager};
use crate::protocol::InputFrame;
use crate::runtime_controller::{RuntimeController, RuntimePhase, RuntimeRunner, RuntimeStartSpec};
use crate::target_operation;
use crate::window::TargetWindow;

const LOG_TAIL_BYTES: usize = 200_000;

pub struct CoreFacade {
    config_path: PathBuf,
    log_path: PathBuf,
    auto_start_executable: Option<PathBuf>,
    runtime: RuntimeController,
}

impl CoreFacade {
    pub fn new(
        config_path: impl Into<PathBuf>,
        log_path: impl Into<PathBuf>,
        runner: RuntimeRunner,
    ) -> Self {
        Self::new_with_auto_start_executable(config_path, log_path, None, runner)
    }

    pub fn new_with_auto_start_executable(
        config_path: impl Into<PathBuf>,
        log_path: impl Into<PathBuf>,
        auto_start_executable: Option<PathBuf>,
        runner: RuntimeRunner,
    ) -> Self {
        Self {
            config_path: config_path.into(),
            log_path: log_path.into(),
            auto_start_executable,
            runtime: RuntimeController::new(runner),
        }
    }

    pub fn load_config(&self) -> Result<AppConfig> {
        config::load_config(&self.config_path)
    }

    pub fn save_config(&self, config: &AppConfig) -> Result<()> {
        validate_config(config)?;
        config::save_config(&self.config_path, config)
    }

    pub fn validate_config(&self, config: &AppConfig) -> Vec<String> {
        validate_config(config)
            .err()
            .into_iter()
            .map(|err| err.to_string())
            .collect()
    }

    pub fn runtime_phase(&self) -> RuntimePhase {
        self.runtime.phase()
    }

    pub fn runtime_status(&self) -> String {
        self.runtime.status_text()
    }

    pub fn can_start_runtime(&self) -> bool {
        self.runtime.can_start()
    }

    pub fn can_stop_runtime(&self) -> bool {
        self.runtime.can_stop()
    }

    pub fn can_restart_runtime(&self) -> bool {
        self.runtime.can_restart()
    }

    pub fn start_runtime(&mut self, app_config: AppConfig) -> Result<()> {
        self.runtime.start(RuntimeStartSpec {
            app_config,
            config_path: self.config_path.clone(),
            log_path: self.log_path.clone(),
            auto_start_executable: self.auto_start_executable.clone(),
        })
    }

    pub fn stop_runtime(&mut self) {
        self.runtime.request_stop();
    }

    pub fn shutdown_runtime_and_wait(&mut self) {
        self.runtime.shutdown_and_wait();
    }

    pub fn restart_runtime(&mut self, app_config: AppConfig) -> Result<()> {
        self.runtime.request_restart(RuntimeStartSpec {
            app_config,
            config_path: self.config_path.clone(),
            log_path: self.log_path.clone(),
            auto_start_executable: self.auto_start_executable.clone(),
        })
    }

    pub fn poll_runtime(&mut self) {
        self.runtime.poll();
    }

    pub fn log_tail(&self) -> Result<String> {
        read_redacted_log_tail(&self.log_path)
    }

    pub fn scan_mihoyo_games(&self) -> Result<Vec<MihoyoGameInstall>> {
        mihoyo_discovery::discover_mihoyo_games()
    }
}

pub fn validate_config(config: &AppConfig) -> Result<()> {
    if config.hub.ws_url.trim().is_empty() {
        anyhow::bail!("Hub URL 不能为空");
    }
    if config.agent.name.trim().is_empty() {
        anyhow::bail!("Agent 名称不能为空");
    }
    if !(1..=100).contains(&config.capture.jpeg_quality) {
        anyhow::bail!("JPEG 质量必须在 1..=100");
    }
    if config.capture.encoder.trim().is_empty() {
        anyhow::bail!("Encoder 不能为空");
    }
    Ok(())
}

pub fn read_redacted_log_tail(path: &Path) -> Result<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len() as usize;
    let read_size = file_size.min(LOG_TAIL_BYTES);
    if read_size == 0 {
        return Ok(String::new());
    }
    file.seek(SeekFrom::Start((file_size - read_size) as u64))?;
    let mut buffer = vec![0u8; read_size];
    file.read_exact(&mut buffer)?;
    Ok(redact_sensitive_text(&String::from_utf8_lossy(&buffer)))
}

pub fn redact_sensitive_text(text: &str) -> String {
    text.lines()
        .map(redact_sensitive_line)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn discovery_self_test_target(game: &MihoyoGameInstall) -> Option<SelfTestTarget> {
    if !game.supported || !game.exists_on_disk {
        return None;
    }
    Some(SelfTestTarget {
        profile_id: game.profile_id.clone()?,
        executable: game.launch_path.as_ref()?.display().to_string(),
        working_dir: game.game_dir.as_ref()?.display().to_string(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTestTarget {
    pub profile_id: String,
    pub executable: String,
    pub working_dir: String,
}

pub struct SelfTestSession {
    process: ProcessManager,
    input: InputController,
    pid: Option<u32>,
    input_seq: u64,
}

impl SelfTestSession {
    pub fn new(
        profile_overrides: &std::collections::HashMap<String, config::GameProfileOverride>,
    ) -> Result<Self> {
        Ok(Self {
            process: ProcessManager::with_profile_overrides(profile_overrides)?,
            input: InputController::new(),
            pid: None,
            input_seq: 0,
        })
    }

    pub fn launch(&mut self, target: &SelfTestTarget, args: &[String]) -> Result<SelfTestLaunch> {
        let pid = self.process.launch_game(
            &target.profile_id,
            &target.executable,
            args,
            Some(&target.working_dir),
        )?;
        self.pid = Some(pid);
        let binding = self.process.active_binding_or_refresh()?;
        let window = target_operation::target_window_from_binding(&binding);
        let privilege = process_privilege_level(window.pid).unwrap_or(PrivilegeLevel::Unknown);
        Ok(SelfTestLaunch {
            pid,
            window,
            privilege,
        })
    }

    pub fn capture(&mut self, capture_config: &config::CaptureConfig) -> Result<CapturedFrame> {
        let capture = ScreenCapture::new(capture_config)?;
        let (_, frame) = target_operation::capture_active_target(&mut self.process, &capture)?;
        Ok(frame)
    }

    pub fn send_input(&mut self, mut frame: InputFrame) -> Result<TargetWindow> {
        self.input_seq += 1;
        frame.seq = self.input_seq;
        let binding = target_operation::send_input_to_active_target(
            &mut self.process,
            &mut self.input,
            &frame,
        )?;
        Ok(target_operation::target_window_from_binding(&binding))
    }

    pub fn release_input(&mut self) -> Result<()> {
        self.input.emergency_stop()
    }

    pub fn close(&mut self, force: bool) -> Result<()> {
        target_operation::close_active_target(&mut self.process, force)?;
        self.pid = None;
        Ok(())
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
}

#[derive(Debug)]
pub struct SelfTestLaunch {
    pub pid: u32,
    pub window: TargetWindow,
    pub privilege: PrivilegeLevel,
}

fn redact_sensitive_line(line: &str) -> String {
    let mut redacted = line.to_string();
    for key in ["api_key", "token", "jwt", "secret", "password"] {
        redacted = redact_field_value(&redacted, key);
    }
    redacted
}

fn redact_field_value(text: &str, key: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut remaining = text;

    while let Some(index) = remaining.find(key) {
        let (prefix, rest) = remaining.split_at(index);
        output.push_str(prefix);
        let after_key = &rest[key.len()..];
        let Some((separator, tail)) = after_key
            .chars()
            .next()
            .map(|ch| (ch, &after_key[ch.len_utf8()..]))
        else {
            output.push_str(key);
            return output;
        };

        if matches!(separator, ':' | '=' | ' ' | '\t') {
            output.push_str(key);
            output.push(separator);
            output.push_str("***");
            return output;
        }

        output.push_str(key);
        output.push(separator);
        remaining = tail;
    }

    output.push_str(remaining);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_sensitive_text_masks_api_keys() {
        let text = redact_sensitive_text("api_key=fp_agent_secret\nok=true");
        assert!(text.contains("api_key=***"));
        assert!(text.contains("ok=true"));
        assert!(!text.contains("fp_agent_secret"));
    }

    #[test]
    fn validate_config_rejects_empty_hub() {
        let mut config = AppConfig::default();
        config.hub.ws_url.clear();

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validate_config_accepts_disabled_capture() {
        let mut config = AppConfig::default();
        config.capture.fps = 0;

        assert!(validate_config(&config).is_ok());
    }
}
