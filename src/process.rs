//! Game process manager.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;
#[cfg(any(target_os = "windows", test))]
use std::path::PathBuf;
use tracing::{info, warn};

use crate::config::GameProfileOverride;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivilegeLevel {
    Unknown,
    Standard,
    Elevated,
}

/// Normalizes a launch target or allowlist entry to a lowercase executable name.
///
/// Empty strings return `None`; file paths are reduced to basename.
pub fn normalize_executable_name(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }

    trimmed
        .rsplit(['\\', '/'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase)
}

/// Returns whether a remote launch target is allowed by the local allowlist.
///
/// Empty allowlist is conservative and denies remote launch.
pub fn is_launch_allowed(executable: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }

    let Some(executable_name) = normalize_executable_name(executable) else {
        return false;
    };

    allowlist
        .iter()
        .filter_map(|entry| normalize_executable_name(entry))
        .any(|entry| entry == executable_name)
}

/// Normalizes a launch path by trimming whitespace and wrapping quotes.
///
/// Unlike `normalize_executable_name`, this keeps the full path intact.
fn normalize_launch_path(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GameProfile {
    pub(crate) profile_id: String,
    pub(crate) display_name: String,
    pub(crate) hyp_internal_id: String,
    pub(crate) process_name: String,
    pub(crate) window_title: String,
    pub(crate) window_class: String,
    pub(crate) pattern_key: String,
    pub(crate) executable_path: Option<String>,
    pub(crate) working_dir: Option<String>,
    aliases: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TargetBinding {
    pub profile_id: Option<String>,
    pub resolved_executable: String,
    pub process_name: String,
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    pub class_name: Option<String>,
    pub rect: crate::window::WindowRect,
}

impl TargetBinding {
    fn from_window(
        profile_id: Option<String>,
        resolved_executable: String,
        process_name: String,
        window: crate::window::TargetWindow,
    ) -> Self {
        Self {
            profile_id,
            resolved_executable,
            process_name,
            hwnd: window.hwnd,
            pid: window.pid,
            title: window.title,
            class_name: window.class_name,
            rect: window.rect,
        }
    }
}

fn profile(
    profile_id: &str,
    display_name: &str,
    hyp_internal_id: &str,
    process_name: &str,
    window: (&str, &str, &str),
    aliases: &[&str],
) -> GameProfile {
    GameProfile {
        profile_id: profile_id.into(),
        display_name: display_name.into(),
        hyp_internal_id: hyp_internal_id.into(),
        process_name: process_name.into(),
        window_title: window.0.into(),
        window_class: window.1.into(),
        pattern_key: window.2.into(),
        executable_path: None,
        working_dir: None,
        aliases: aliases.iter().map(|value| (*value).into()).collect(),
    }
}

pub(crate) fn default_game_profiles() -> HashMap<String, GameProfile> {
    [
        profile(
            "genshin",
            "原神",
            "hk4e_cn",
            "YuanShen.exe",
            ("原神", "UnityWndClass", "Genshin Impact Game"),
            &["yuanshen.exe", "genshinimpact.exe"],
        ),
        profile(
            "star_rail",
            "崩坏：星穹铁道",
            "hkrpg_cn",
            "StarRail.exe",
            ("崩坏：星穹铁道", "UnityWndClass", "Star Rail////Game"),
            &["starrail.exe"],
        ),
        profile(
            "zzz",
            "绝区零",
            "nap_cn",
            "ZZZ.exe",
            ("绝区零", "UnityWndClass", "ZenlessZoneZero Game"),
            &["zzz.exe", "zenlesszonezero.exe"],
        ),
    ]
    .into_iter()
    .map(|profile| (profile.profile_id.clone(), profile))
    .collect()
}

pub(crate) fn profiles_with_overrides(
    overrides: &HashMap<String, GameProfileOverride>,
) -> Result<HashMap<String, GameProfile>> {
    let mut profiles = default_game_profiles();
    for (profile_id, update) in overrides {
        let Some(profile) = profiles.get_mut(profile_id) else {
            anyhow::bail!("unsupported game profile: {profile_id}");
        };
        if let Some(value) = update
            .process_name
            .as_deref()
            .and_then(normalize_launch_path)
        {
            profile.process_name = value;
        }
        if let Some(value) = update
            .window_title
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            profile.window_title = value.to_string();
        }
        if let Some(value) = update
            .window_class
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            profile.window_class = value.to_string();
        }
        profile.executable_path = update
            .executable_path
            .as_deref()
            .and_then(normalize_launch_path);
        profile.working_dir = update
            .working_dir
            .as_deref()
            .and_then(normalize_launch_path);
        if let Some(name) = normalize_executable_name(&profile.process_name) {
            if !profile.aliases.contains(&name) {
                profile.aliases.push(name);
            }
        }
    }
    Ok(profiles)
}

pub(crate) fn known_game_for_executable(executable: &str) -> Option<GameProfile> {
    let executable_name = normalize_executable_name(executable);
    let executable_lower = executable.to_ascii_lowercase().replace('/', "\\");
    default_game_profiles().into_values().find(|game| {
        executable_name
            .as_deref()
            .is_some_and(|name| game.aliases.iter().any(|alias| alias == name))
            || executable_lower
                .contains(&game.pattern_key.to_ascii_lowercase().replace("////", "\\"))
    })
}

fn profile_for_launch(
    profiles: &HashMap<String, GameProfile>,
    game_id: &str,
    executable: &str,
) -> Option<GameProfile> {
    if let Some(profile) = profiles.get(game_id) {
        return Some(profile.clone());
    }

    let executable_name = normalize_executable_name(executable);
    let executable_lower = executable.to_ascii_lowercase().replace('/', "\\");
    profiles
        .values()
        .find(|game| {
            executable_name
                .as_deref()
                .is_some_and(|name| game.aliases.iter().any(|alias| alias == name))
                || executable_lower
                    .contains(&game.pattern_key.to_ascii_lowercase().replace("////", "\\"))
        })
        .cloned()
}

fn with_explicit_profile_executable(mut profile: GameProfile, executable: &str) -> GameProfile {
    if profile.executable_path.is_none() && executable.contains(['\\', '/']) {
        profile.executable_path = Some(executable.to_string());
    }
    profile
}

#[cfg(any(target_os = "windows", test))]
fn extract_hyp_install_path(content: &str, internal_id: &str) -> Option<String> {
    let start = content.find(internal_id)?;
    let json_start = content[start..].find('{')? + start;
    let json = json_object_at(content, json_start)?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    value
        .get("installPath")
        .and_then(|path| path.as_str())
        .filter(|path| !path.trim().is_empty())
        .map(ToString::to_string)
}

#[cfg(any(target_os = "windows", test))]
fn json_object_at(content: &str, start: usize) -> Option<String> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in content[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(content[start..=start + offset].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn hyp_game_data_path() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(r"miHoYo\HYP\1_1\data\gamedata.dat")
}

#[cfg(target_os = "windows")]
fn resolve_hyp_game_executable(game: &GameProfile) -> Result<Option<PathBuf>> {
    let data_path = hyp_game_data_path();
    if !data_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&data_path)
        .with_context(|| format!("failed to read HYP game data: {}", data_path.display()))?;
    let Some(install_path) = extract_hyp_install_path(&content, &game.hyp_internal_id) else {
        return Ok(None);
    };
    Ok(Some(profile_executable_from_install_path(
        &install_path,
        &game.process_name,
    )))
}

#[cfg(any(target_os = "windows", test))]
fn profile_executable_from_install_path(install_path: &str, process_name: &str) -> PathBuf {
    PathBuf::from(install_path).join(process_name)
}

fn missing_profile_executable_message(game: &GameProfile) -> String {
    format!(
        "profile {} needs executable_path or HYP installPath",
        game.profile_id
    )
}

#[cfg(any(target_os = "windows", test))]
fn validate_profile_executable_path(game: &GameProfile, path: &Path) -> Result<String> {
    if path.exists() {
        return Ok(path.display().to_string());
    }
    anyhow::bail!(
        "profile {} resolved executable does not exist: {}",
        game.profile_id,
        path.display()
    )
}

#[cfg(target_os = "windows")]
fn resolve_profile_executable(game: &GameProfile) -> Result<String> {
    if let Some(path) = &game.executable_path {
        return Ok(path.clone());
    }

    match resolve_hyp_game_executable(game)? {
        Some(path) if path.exists() => {
            info!(
                "resolved HoYoverse launch target from HYP config: {}",
                game.process_name
            );
            Ok(path.display().to_string())
        }
        Some(path) => validate_profile_executable_path(game, &path),
        None => anyhow::bail!("{}", missing_profile_executable_message(game)),
    }
}

#[cfg(not(target_os = "windows"))]
fn resolve_profile_executable(game: &GameProfile) -> Result<String> {
    game.executable_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{}", missing_profile_executable_message(game)))
}

#[cfg(target_os = "windows")]
pub fn current_process_privilege_level() -> PrivilegeLevel {
    unsafe {
        use windows::Win32::UI::Shell::IsUserAnAdmin;

        if IsUserAnAdmin().as_bool() {
            PrivilegeLevel::Elevated
        } else {
            PrivilegeLevel::Standard
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn current_process_privilege_level() -> PrivilegeLevel {
    PrivilegeLevel::Unknown
}

#[cfg(target_os = "windows")]
pub fn process_privilege_level(pid: u32) -> Result<PrivilegeLevel> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .with_context(|| format!("打开 PID {pid} 失败，无法检查权限"))?;
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token)
            .with_context(|| format!("打开 PID {pid} 的访问令牌失败"))?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .with_context(|| format!("读取 PID {pid} 的权限信息失败"))?;

        let _ = CloseHandle(token);
        let _ = CloseHandle(process);

        Ok(if elevation.TokenIsElevated != 0 {
            PrivilegeLevel::Elevated
        } else {
            PrivilegeLevel::Standard
        })
    }
}

#[cfg(not(target_os = "windows"))]
pub fn process_privilege_level(pid: u32) -> Result<PrivilegeLevel> {
    let _ = pid;
    Ok(PrivilegeLevel::Unknown)
}

#[cfg(target_os = "windows")]
pub fn relaunch_with_runas(
    executable: &Path,
    parameters: &str,
    working_dir: Option<&Path>,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(value: &Path) -> Vec<u16> {
        value.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn wide_str(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    unsafe {
        let operation = wide_str("runas");
        let file = wide(executable);
        let params = wide_str(parameters);
        let dir = working_dir.map(wide);
        let directory = dir
            .as_ref()
            .map(|value| PCWSTR(value.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let result = ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(params.as_ptr()),
            directory,
            SW_SHOWNORMAL,
        );

        if (result.0 as isize) <= 32 {
            anyhow::bail!("UAC 重启请求失败，ShellExecuteW 返回 {}", result.0 as isize);
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn relaunch_with_runas(
    executable: &Path,
    parameters: &str,
    working_dir: Option<&Path>,
) -> Result<()> {
    let _ = (executable, parameters, working_dir);
    anyhow::bail!("管理员重启仅支持 Windows")
}

pub(crate) fn executable_process_names(executable: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    let Some(executable_name) = normalize_executable_name(executable) else {
        return names;
    };

    if let Some(game) = known_game_for_executable(executable) {
        for alias in game.aliases {
            names.insert((*alias).to_string());
        }
    }
    names.insert(executable_name);
    names
}

pub(crate) fn uses_extended_window_wait(executable: &str) -> bool {
    known_game_for_executable(executable).is_some()
}

/// Manages the currently launched game process.
pub struct ProcessManager {
    active_pid: Option<u32>,
    active_kill_pid: Option<u32>,
    active_executable: Option<String>,
    active_binding: Option<TargetBinding>,
    profiles: HashMap<String, GameProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProcessExit {
    pub process_id: u32,
    pub executable: String,
    pub event: String,
    pub exit_code: Option<i32>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            active_pid: None,
            active_kill_pid: None,
            active_executable: None,
            active_binding: None,
            profiles: default_game_profiles(),
        }
    }

    pub fn with_profile_overrides(
        overrides: &HashMap<String, GameProfileOverride>,
    ) -> Result<Self> {
        Ok(Self {
            profiles: profiles_with_overrides(overrides)?,
            ..Self::new()
        })
    }

    pub fn launch(
        &mut self,
        executable: &str,
        args: &[String],
        working_dir: Option<&str>,
    ) -> Result<u32> {
        self.launch_game("", executable, args, working_dir)
    }

    pub fn launch_game(
        &mut self,
        game_id: &str,
        executable: &str,
        args: &[String],
        working_dir: Option<&str>,
    ) -> Result<u32> {
        let requested_executable =
            normalize_launch_path(executable).unwrap_or_else(|| executable.trim().to_string());
        let profile = profile_for_launch(&self.profiles, game_id, &requested_executable)
            .map(|profile| with_explicit_profile_executable(profile, &requested_executable));
        let mut executable = match profile.as_ref() {
            Some(profile) => resolve_profile_executable(profile)?,
            None => requested_executable.clone(),
        };
        let working_dir = working_dir.and_then(normalize_launch_path).or_else(|| {
            profile
                .as_ref()
                .and_then(|profile| profile.working_dir.clone())
        });
        executable = resolve_launch_target_executable(
            &requested_executable,
            executable,
            working_dir.as_deref(),
        );
        info!("launch process: {} {:?}", executable, args);
        #[cfg(target_os = "windows")]
        let existing_pids = matching_process_ids(&executable).unwrap_or_default();

        let mut cmd = std::process::Command::new(&executable);
        cmd.args(args);
        if let Some(dir) = working_dir.as_deref() {
            cmd.current_dir(dir);
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x00000010);
        }

        let child = cmd.spawn()?;
        let pid = child.id();
        #[cfg(target_os = "windows")]
        let kill_pid = resolve_launched_process_pid(pid, &executable, &existing_pids);
        #[cfg(not(target_os = "windows"))]
        let kill_pid = pid;

        let process_name = profile
            .as_ref()
            .map(|profile| profile.process_name.clone())
            .or_else(|| normalize_executable_name(&executable))
            .unwrap_or_else(|| executable.clone());
        let binding = match crate::window::find_target_window(kill_pid, Some(&executable)) {
            Ok(window) => Some(TargetBinding::from_window(
                profile.as_ref().map(|profile| profile.profile_id.clone()),
                executable.clone(),
                process_name,
                window,
            )),
            Err(err) if profile.is_some() => {
                cleanup_failed_profile_launch(pid, kill_pid, &executable).with_context(|| {
                    format!("target window not ready after launch: {err}; cleanup failed")
                })?;
                anyhow::bail!("target window not ready after launch: {err}")
            }
            Err(_) => None,
        };

        self.active_pid = Some(pid);
        self.active_executable = Some(executable.to_string());
        self.active_kill_pid = Some(kill_pid);
        self.active_binding = binding;
        info!("process launched: PID={}, kill_pid={}", pid, kill_pid);
        Ok(pid)
    }

    pub fn kill(&mut self, pid: Option<u32>, force: bool) -> Result<()> {
        let target_pid = self
            .active_binding
            .as_ref()
            .map(|binding| binding.pid)
            .or_else(|| select_kill_pid(pid, self.active_pid, self.active_kill_pid))
            .ok_or_else(|| anyhow::anyhow!("无活跃进程"))?;
        let executable = self.active_executable.clone();
        #[cfg(target_os = "windows")]
        let target_pid = executable
            .as_deref()
            .map(|executable| resolve_current_process_pid(target_pid, executable))
            .transpose()?
            .unwrap_or(target_pid);

        info!("kill process: PID={}, force={}", target_pid, force);

        if force {
            force_kill_pid(target_pid, executable.as_deref())?;
        } else if let Some(binding) = &self.active_binding {
            let window = crate::window::TargetWindow {
                hwnd: binding.hwnd,
                pid: binding.pid,
                title: binding.title.clone(),
                class_name: binding.class_name.clone(),
                rect: binding.rect.clone(),
            };
            crate::window::post_close(&window)
                .with_context(|| format!("向 PID {} 的窗口发送 WM_CLOSE 失败", window.pid))?;
            if !crate::window::wait_for_window_closed(
                window.hwnd,
                std::time::Duration::from_secs(3),
                std::time::Duration::from_millis(100),
            ) {
                anyhow::bail!("已发送 WM_CLOSE，但 PID {} 的窗口仍未关闭", window.pid);
            }
        } else {
            graceful_close_pid(target_pid, executable.as_deref()).or_else(|err| {
                warn!("graceful close failed for PID {target_pid}: {err}; terminating exact PID");
                force_kill_pid(target_pid, executable.as_deref())
            })?;
        }

        self.active_pid = None;
        self.active_kill_pid = None;
        self.active_executable = None;
        self.active_binding = None;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn active_pid(&self) -> Option<u32> {
        self.active_pid
    }

    #[allow(dead_code)]
    pub fn active_target(&self) -> Option<(u32, String)> {
        if let Some(binding) = &self.active_binding {
            return Some((binding.pid, binding.resolved_executable.clone()));
        }
        Some((
            self.active_kill_pid.or(self.active_pid)?,
            self.active_executable.clone()?,
        ))
    }

    pub(crate) fn active_binding_or_refresh(&mut self) -> Result<TargetBinding> {
        if let Some(binding) = &self.active_binding {
            if crate::window::window_exists(binding.hwnd) {
                if let Ok(window) = crate::window::refresh_window_by_hwnd(binding.hwnd) {
                    if refreshed_window_matches_binding(binding, &window) {
                        let refreshed = TargetBinding::from_window(
                            binding.profile_id.clone(),
                            binding.resolved_executable.clone(),
                            binding.process_name.clone(),
                            window,
                        );
                        self.active_binding = Some(refreshed.clone());
                        return Ok(refreshed);
                    }
                }
            }
        }

        let previous_binding = self.active_binding.clone();
        let (pid, executable) = self
            .active_target()
            .ok_or_else(|| anyhow::anyhow!("target-window-not-found: no active target"))?;
        let window = crate::window::find_target_window(pid, Some(&executable))
            .with_context(|| "target-window-not-found")?;
        let refreshed =
            binding_from_rediscovered_window(previous_binding.as_ref(), executable, window);
        self.active_binding = Some(refreshed.clone());
        Ok(refreshed)
    }

    pub fn take_exit_event(&mut self) -> Option<ActiveProcessExit> {
        #[cfg(target_os = "windows")]
        if let Some(binding) = &self.active_binding {
            if !crate::window::window_exists(binding.hwnd) {
                let exit = ActiveProcessExit {
                    process_id: binding.pid,
                    executable: binding.resolved_executable.clone(),
                    event: "process_exited".to_string(),
                    exit_code: None,
                };
                warn!(
                    "active target window disappeared: pid={} exe={}",
                    binding.pid, binding.resolved_executable
                );
                self.clear_active_target();
                return Some(exit);
            }
        }

        let (pid, executable) = self.active_target()?;
        if process_exists(pid) {
            return None;
        }

        self.clear_active_target();

        Some(ActiveProcessExit {
            process_id: pid,
            executable,
            event: "process_exited".to_string(),
            exit_code: None,
        })
    }

    fn clear_active_target(&mut self) {
        self.active_pid = None;
        self.active_kill_pid = None;
        self.active_executable = None;
        self.active_binding = None;
    }
}

fn resolve_launch_target_executable(
    requested_executable: &str,
    resolved_executable: String,
    working_dir: Option<&str>,
) -> String {
    if Path::new(&resolved_executable).exists() {
        return resolved_executable;
    }

    let requested_path = Path::new(requested_executable);
    let file_name = requested_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned);
    let Some(file_name) = file_name.filter(|name| !name.is_empty()) else {
        return resolved_executable;
    };

    let Some(working_dir) = working_dir.and_then(normalize_launch_path) else {
        return resolved_executable;
    };

    let candidate = Path::new(&working_dir).join(file_name);
    if candidate.exists() {
        return candidate
            .to_str()
            .map_or_else(|| resolved_executable.clone(), ToString::to_string);
    }

    resolved_executable
}

fn binding_from_rediscovered_window(
    previous: Option<&TargetBinding>,
    executable: String,
    window: crate::window::TargetWindow,
) -> TargetBinding {
    let profile_id = previous.and_then(|binding| binding.profile_id.clone());
    let process_name = previous
        .map(|binding| binding.process_name.clone())
        .unwrap_or_else(|| {
            normalize_executable_name(&executable).unwrap_or_else(|| executable.clone())
        });
    TargetBinding::from_window(profile_id, executable, process_name, window)
}

fn refreshed_window_matches_binding(
    binding: &TargetBinding,
    window: &crate::window::TargetWindow,
) -> bool {
    if window.pid != binding.pid {
        return false;
    }
    if binding.profile_id.is_none() {
        return true;
    }

    let title_matches = window.title == binding.title;
    let class_matches = match (&binding.class_name, &window.class_name) {
        (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
        (None, None) => true,
        _ => false,
    };
    title_matches && class_matches
}

fn select_kill_pid(
    requested_pid: Option<u32>,
    active_pid: Option<u32>,
    active_kill_pid: Option<u32>,
) -> Option<u32> {
    match (requested_pid, active_pid, active_kill_pid) {
        (Some(requested), Some(active), Some(kill_pid)) if requested == active => Some(kill_pid),
        (None, _, Some(kill_pid)) => Some(kill_pid),
        (Some(requested), _, _) => Some(requested),
        (_, Some(active), _) => Some(active),
        _ => None,
    }
}

#[cfg(any(target_os = "windows", test))]
fn cleanup_pids_after_failed_profile_launch(launcher_pid: u32, kill_pid: u32) -> Vec<u32> {
    let mut pids = vec![kill_pid];
    if launcher_pid != kill_pid {
        pids.push(launcher_pid);
    }
    pids
}

#[cfg(target_os = "windows")]
fn cleanup_failed_profile_launch(launcher_pid: u32, kill_pid: u32, executable: &str) -> Result<()> {
    for pid in cleanup_pids_after_failed_profile_launch(launcher_pid, kill_pid) {
        if process_exists(pid) {
            warn!("cleaning launched process after window discovery failure: PID={pid}");
            force_kill_pid(pid, Some(executable))?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn cleanup_failed_profile_launch(launcher_pid: u32, kill_pid: u32, executable: &str) -> Result<()> {
    let _ = (launcher_pid, kill_pid, executable);
    Ok(())
}

#[cfg(target_os = "windows")]
fn graceful_close_pid(pid: u32, executable: Option<&str>) -> Result<()> {
    use std::time::Duration;

    let window = crate::window::find_target_window(pid, executable)
        .with_context(|| format!("未找到 PID {pid} 的可见目标窗口，无法执行温和关闭"))?;
    crate::window::post_close(&window)
        .with_context(|| format!("向 PID {} 的窗口发送 WM_CLOSE 失败", window.pid))?;

    if crate::window::wait_for_window_closed(
        window.hwnd,
        Duration::from_secs(3),
        Duration::from_millis(100),
    ) {
        if process_exists(window.pid) {
            warn!(
                "window closed but PID {} is still alive; terminating exact PID",
                window.pid
            );
            terminate_pid(window.pid)?;
        }
        Ok(())
    } else {
        anyhow::bail!("已发送 WM_CLOSE，但 PID {} 的窗口仍未关闭", window.pid)
    }
}

#[cfg(not(target_os = "windows"))]
fn graceful_close_pid(pid: u32, executable: Option<&str>) -> Result<()> {
    let _ = (pid, executable);
    anyhow::bail!("进程温和关闭仅支持 Windows")
}

#[cfg(target_os = "windows")]
fn force_kill_pid(pid: u32, executable: Option<&str>) -> Result<()> {
    let _ = executable;
    terminate_pid(pid)
}

#[cfg(target_os = "windows")]
fn resolve_launched_process_pid(
    launcher_pid: u32,
    executable: &str,
    existing_pids: &HashSet<u32>,
) -> u32 {
    let started = std::time::Instant::now();
    let timeout = if uses_extended_window_wait(executable) {
        std::time::Duration::from_secs(30)
    } else {
        std::time::Duration::from_secs(5)
    };

    while started.elapsed() <= timeout {
        if let Ok(pids) = matching_process_ids(executable) {
            let new_pids: Vec<u32> = pids.difference(existing_pids).copied().collect();
            for pid in &new_pids {
                if let Ok(window) = crate::window::find_target_window(*pid, Some(executable)) {
                    return window.pid;
                }
            }
            if new_pids.len() == 1 {
                return new_pids[0];
            }
            if new_pids.contains(&launcher_pid) {
                return launcher_pid;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    launcher_pid
}

#[cfg(target_os = "windows")]
fn resolve_current_process_pid(pid: u32, executable: &str) -> Result<u32> {
    if let Ok(window) = crate::window::find_target_window(pid, Some(executable)) {
        return Ok(window.pid);
    }

    let pids = matching_process_ids(executable)?;
    if pids.contains(&pid) {
        return Ok(pid);
    }
    if pids.len() == 1 {
        return Ok(*pids.iter().next().expect("checked len"));
    }
    Ok(pid)
}

#[cfg(target_os = "windows")]
fn matching_process_ids(executable: &str) -> Result<HashSet<u32>> {
    let target_names = executable_process_names(executable);
    if target_names.is_empty() {
        return Ok(HashSet::new());
    }

    unsafe {
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            anyhow::bail!("CreateToolhelp32Snapshot returned invalid handle");
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut pids = HashSet::new();
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if target_names.contains(&process_entry_name(&entry).to_ascii_lowercase()) {
                    pids.insert(entry.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        Ok(pids)
    }
}

#[cfg(target_os = "windows")]
fn process_entry_name(
    entry: &windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W,
) -> String {
    let len = entry
        .szExeFile
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..len])
}

#[cfg(target_os = "windows")]
fn process_exists(pid: u32) -> bool {
    unsafe {
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return false;
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return false;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = false;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    found = true;
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        found
    }
}

#[cfg(not(target_os = "windows"))]
fn process_exists(pid: u32) -> bool {
    let _ = pid;
    true
}

#[cfg(target_os = "windows")]
fn terminate_pid(pid: u32) -> Result<()> {
    unsafe {
        use windows::Win32::Foundation::{CloseHandle, WAIT_FAILED, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
            PROCESS_TERMINATE,
        };

        let handle = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid)
            .with_context(|| format!("打开 PID {pid} 失败，无法强制终止"))?;
        TerminateProcess(handle, 1).with_context(|| format!("强制终止 PID {pid} 失败"))?;
        let wait_result = WaitForSingleObject(handle, 5_000);
        let _ = CloseHandle(handle);
        if wait_result == WAIT_TIMEOUT || wait_result == WAIT_FAILED {
            anyhow::bail!("强制终止 PID {pid} 后等待退出超时")
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn force_kill_pid(pid: u32, executable: Option<&str>) -> Result<()> {
    let _ = (pid, executable);
    anyhow::bail!("进程强制终止仅支持 Windows")
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_manager_new_has_no_active_pid() {
        let pm = ProcessManager::new();
        assert!(pm.active_pid().is_none());
    }

    #[test]
    fn kill_without_active_pid_returns_error() {
        let mut pm = ProcessManager::new();
        assert!(pm.kill(None, false).is_err());
    }

    #[test]
    fn active_target_returns_resolved_window_pid() {
        let pm = ProcessManager {
            active_pid: Some(8228),
            active_kill_pid: Some(6540),
            active_executable: Some("notepad.exe".to_string()),
            active_binding: None,
            profiles: default_game_profiles(),
        };

        assert_eq!(pm.active_target(), Some((6540, "notepad.exe".to_string())));
    }

    #[test]
    fn take_exit_event_ignores_missing_active_target() {
        let mut pm = ProcessManager::new();

        assert_eq!(pm.take_exit_event(), None);
    }

    #[test]
    fn take_exit_event_ignores_alive_active_target() {
        let mut pm = ProcessManager {
            active_pid: Some(std::process::id()),
            active_kill_pid: None,
            active_executable: Some("fairypam-agent-test".to_string()),
            active_binding: None,
            profiles: default_game_profiles(),
        };

        assert_eq!(pm.take_exit_event(), None);
        assert_eq!(
            pm.active_target(),
            Some((std::process::id(), "fairypam-agent-test".to_string()))
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn take_exit_event_reports_exited_active_target() {
        let missing_pid = u32::MAX;
        let mut pm = ProcessManager {
            active_pid: Some(missing_pid),
            active_kill_pid: None,
            active_executable: Some("missing-game.exe".to_string()),
            active_binding: None,
            profiles: default_game_profiles(),
        };

        let exit = pm.take_exit_event().expect("missing pid should exit");

        assert_eq!(exit.process_id, missing_pid);
        assert_eq!(exit.executable, "missing-game.exe");
        assert_eq!(exit.event, "process_exited");
        assert_eq!(pm.active_target(), None);
    }

    #[test]
    fn kill_target_prefers_resolved_window_pid_for_active_launcher_pid() {
        assert_eq!(
            select_kill_pid(Some(8228), Some(8228), Some(6540)),
            Some(6540)
        );
        assert_eq!(select_kill_pid(None, Some(8228), Some(6540)), Some(6540));
        assert_eq!(
            select_kill_pid(Some(7777), Some(8228), Some(6540)),
            Some(7777)
        );
    }

    #[test]
    fn failed_profile_launch_cleanup_includes_resolved_and_launcher_pid() {
        assert_eq!(
            cleanup_pids_after_failed_profile_launch(8228, 6540),
            vec![6540, 8228]
        );
        assert_eq!(
            cleanup_pids_after_failed_profile_launch(8228, 8228),
            vec![8228]
        );
    }

    #[test]
    fn empty_launch_allowlist_rejects_remote_launch() {
        assert!(!is_launch_allowed("C:\\Games\\Game.exe", &[]));
    }

    #[test]
    fn launch_allowlist_accepts_exact_path_or_basename() {
        let allowlist = vec![
            "C:\\Games\\Allowed\\Allowed.exe".to_string(),
            "Launcher.exe".to_string(),
        ];

        assert!(is_launch_allowed(
            "C:\\Games\\Allowed\\Allowed.exe",
            &allowlist
        ));
        assert!(is_launch_allowed("D:\\Other\\Launcher.exe", &allowlist));
        assert!(!is_launch_allowed("D:\\Other\\Blocked.exe", &allowlist));
    }

    #[test]
    fn normalize_executable_name_uses_basename_and_casefolds() {
        assert_eq!(
            normalize_executable_name(r#"C:\Games\Foo\Bar.EXE"#),
            Some("bar.exe".into())
        );
        assert_eq!(
            normalize_executable_name(r#"  "C:\Games\Foo\Bar.EXE"  "#),
            Some("bar.exe".into())
        );
        assert_eq!(normalize_executable_name("   "), None);
    }

    #[test]
    fn normalize_launch_path_strips_wrapping_quotes_and_whitespace() {
        assert_eq!(
            normalize_launch_path(r#"  "C:\Program Files\Game\Game.exe"  "#),
            Some(r#"C:\Program Files\Game\Game.exe"#.into())
        );
        assert_eq!(normalize_launch_path("   \"\"   "), None);
    }

    #[test]
    fn launch_target_executable_falls_back_to_workdir_basename_when_resolved_missing() {
        let root =
            std::env::temp_dir().join(format!("fairypam-launch-fallback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let fallback_exe = root.join("YuanShen.exe");
        std::fs::write(&fallback_exe, b"1").unwrap();

        let requested = "YuanShen.exe";
        let resolved =
            resolve_launch_target_executable(requested, "missing.exe".to_string(), root.to_str());
        assert_eq!(resolved, fallback_exe.to_str().unwrap());

        let abs_resolved = resolve_launch_target_executable(
            requested,
            fallback_exe.to_str().unwrap().to_string(),
            None,
        );
        assert_eq!(abs_resolved, fallback_exe.to_str().unwrap().to_string());

        let _ = std::fs::remove_file(&fallback_exe);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hoyoverse_aliases_match_regional_game_processes() {
        let genshin_names = executable_process_names(r"C:\Games\YuanShen.exe");
        assert!(genshin_names.contains("yuanshen.exe"));
        assert!(genshin_names.contains("genshinimpact.exe"));

        let star_rail_names = executable_process_names(r"C:\Games\StarRail.exe");
        assert!(star_rail_names.contains("starrail.exe"));

        let zzz_names = executable_process_names(r"C:\Games\ZenlessZoneZero.exe");
        assert!(zzz_names.contains("zzz.exe"));
        assert!(zzz_names.contains("zenlesszonezero.exe"));
    }

    #[test]
    fn known_game_mapping_contains_window_contract() {
        let genshin = known_game_for_executable(r"C:\Games\YuanShen.exe").expect("genshin");
        assert_eq!(genshin.hyp_internal_id, "hk4e_cn");
        assert_eq!(genshin.process_name, "YuanShen.exe");
        assert_eq!(genshin.window_title, "原神");
        assert_eq!(genshin.window_class, "UnityWndClass");

        let zzz = known_game_for_executable(r"C:\Games\ZenlessZoneZero.exe").expect("zzz");
        assert_eq!(zzz.hyp_internal_id, "nap_cn");
        assert_eq!(zzz.process_name, "ZZZ.exe");
    }

    #[test]
    fn profile_defaults_and_overrides_are_minimal_and_strict() {
        let defaults = default_game_profiles();
        assert!(["genshin", "star_rail", "zzz"]
            .iter()
            .all(|profile_id| defaults.contains_key(*profile_id)));
        assert!(defaults
            .values()
            .all(|profile| profile.executable_path.is_none()));

        let mut overrides = HashMap::new();
        overrides.insert(
            "genshin".to_string(),
            GameProfileOverride {
                executable_path: Some(r#" "C:\Games\YuanShen.exe" "#.to_string()),
                window_title: Some("原神".to_string()),
                ..Default::default()
            },
        );
        let profiles = profiles_with_overrides(&overrides).expect("override accepted");
        assert_eq!(
            profiles
                .get("genshin")
                .and_then(|profile| profile.executable_path.as_deref()),
            Some(r"C:\Games\YuanShen.exe")
        );

        overrides.insert("unknown".to_string(), GameProfileOverride::default());
        assert!(profiles_with_overrides(&overrides)
            .unwrap_err()
            .to_string()
            .contains("unsupported game profile"));
    }

    #[test]
    fn profile_missing_path_error_is_explicit() {
        let genshin = default_game_profiles().remove("genshin").expect("genshin");

        assert!(missing_profile_executable_message(&genshin)
            .contains("needs executable_path or HYP installPath"));
    }

    #[test]
    fn explicit_hoyoverse_path_becomes_profile_executable_override() {
        let profile = profile_for_launch(
            &default_game_profiles(),
            "",
            r"C:\Program Files\miHoYo Launcher\games\Genshin Impact Game\YuanShen.exe",
        )
        .expect("genshin profile");
        let profile = with_explicit_profile_executable(
            profile,
            r"C:\Program Files\miHoYo Launcher\games\Genshin Impact Game\YuanShen.exe",
        );

        assert_eq!(
            profile.executable_path.as_deref(),
            Some(r"C:\Program Files\miHoYo Launcher\games\Genshin Impact Game\YuanShen.exe")
        );
    }

    #[test]
    fn hyp_game_data_extracts_install_path() {
        let content = r#"noise hk4e_cn ignored {"installPath":"C:\\Games\\Genshin Impact Game","version":""} tail"#;

        assert_eq!(
            extract_hyp_install_path(content, "hk4e_cn"),
            Some(r"C:\Games\Genshin Impact Game".to_string())
        );
        assert_eq!(extract_hyp_install_path(content, "missing"), None);
    }

    #[test]
    fn hyp_install_path_is_joined_and_missing_executable_is_rejected() {
        let genshin = default_game_profiles().remove("genshin").expect("genshin");
        let path = profile_executable_from_install_path(
            r"C:\Games\Genshin Impact Game",
            &genshin.process_name,
        );

        assert_eq!(
            path,
            PathBuf::from(r"C:\Games\Genshin Impact Game").join("YuanShen.exe")
        );
        assert!(validate_profile_executable_path(
            &genshin,
            &PathBuf::from(r"Z:\FairyPam\missing\YuanShen.exe")
        )
        .unwrap_err()
        .to_string()
        .contains("resolved executable does not exist"));
    }

    #[test]
    fn refreshed_profile_binding_requires_same_pid_title_and_class() {
        let binding = TargetBinding {
            profile_id: Some("genshin".to_string()),
            resolved_executable: r"C:\Games\YuanShen.exe".to_string(),
            process_name: "YuanShen.exe".to_string(),
            hwnd: 10,
            pid: 42,
            title: "原神".to_string(),
            class_name: Some("UnityWndClass".to_string()),
            rect: crate::window::WindowRect {
                left: 0,
                top: 0,
                right: 100,
                bottom: 100,
            },
        };
        let mut window = crate::window::TargetWindow {
            hwnd: 10,
            pid: 42,
            title: "原神".to_string(),
            class_name: Some("UnityWndClass".to_string()),
            rect: binding.rect.clone(),
        };

        assert!(refreshed_window_matches_binding(&binding, &window));
        window.title = "Other Unity".to_string();
        assert!(!refreshed_window_matches_binding(&binding, &window));
        window.title = "原神".to_string();
        window.pid = 99;
        assert!(!refreshed_window_matches_binding(&binding, &window));
    }

    #[test]
    fn ordinary_binding_refresh_accepts_same_pid_without_title_contract() {
        let binding = TargetBinding {
            profile_id: None,
            resolved_executable: "tool.exe".to_string(),
            process_name: "tool.exe".to_string(),
            hwnd: 10,
            pid: 42,
            title: "Tool".to_string(),
            class_name: None,
            rect: crate::window::WindowRect {
                left: 0,
                top: 0,
                right: 100,
                bottom: 100,
            },
        };
        let window = crate::window::TargetWindow {
            hwnd: 10,
            pid: 42,
            title: "Tool changed".to_string(),
            class_name: None,
            rect: binding.rect.clone(),
        };

        assert!(refreshed_window_matches_binding(&binding, &window));
    }

    #[test]
    fn rediscovered_profile_binding_keeps_profile_contract() {
        let previous = TargetBinding {
            profile_id: Some("genshin".to_string()),
            resolved_executable: r"C:\Games\YuanShen.exe".to_string(),
            process_name: "YuanShen.exe".to_string(),
            hwnd: 10,
            pid: 42,
            title: "原神".to_string(),
            class_name: Some("UnityWndClass".to_string()),
            rect: crate::window::WindowRect {
                left: 0,
                top: 0,
                right: 100,
                bottom: 100,
            },
        };
        let window = crate::window::TargetWindow {
            hwnd: 11,
            pid: 42,
            title: "原神".to_string(),
            class_name: Some("UnityWndClass".to_string()),
            rect: previous.rect.clone(),
        };

        let refreshed = binding_from_rediscovered_window(
            Some(&previous),
            previous.resolved_executable.clone(),
            window,
        );

        assert_eq!(refreshed.profile_id.as_deref(), Some("genshin"));
        assert_eq!(refreshed.process_name, "YuanShen.exe");
        assert_eq!(refreshed.hwnd, 11);
    }

    #[test]
    fn hoyoverse_targets_use_extended_window_wait() {
        assert!(uses_extended_window_wait(r"C:\Games\YuanShen.exe"));
        assert!(uses_extended_window_wait(r"C:\Games\StarRail.exe"));
        assert!(uses_extended_window_wait(r"C:\Games\ZZZ.exe"));
        assert!(!uses_extended_window_wait("notepad.exe"));
    }

    #[test]
    fn allowlist_ignores_quotes_and_duplicate_entries() {
        let allowlist = vec![
            r#"  "C:\Games\Foo\Bar.EXE"  "#.to_string(),
            "bar.exe".to_string(),
            "BAR.EXE".to_string(),
        ];

        assert!(is_launch_allowed("D:\\Other\\Bar.exe", &allowlist));
        assert!(!is_launch_allowed("D:\\Other\\Baz.exe", &allowlist));
    }
}
