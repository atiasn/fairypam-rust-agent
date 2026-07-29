#[cfg(windows)]
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    dto::{
        ClosedGameDto, ConnectionStatusDto, EnvironmentCheckDto, InputResultDto, InstalledGamesDto,
        LaunchedGameDto, LogTailDto, OverviewDto, PreviewDto, RegistrationStatusDto,
        SupportStatusDto,
    },
    local_gateway::{ProductionGateway, UiCommandError},
};
use tauri::State;

type CommandResult<T> = Result<T, UiCommandError>;

#[cfg(windows)]
const HUB_OBSERVATION_LIMIT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const HUB_OBSERVATION_ATTEMPTS: u8 = 20;
#[cfg(windows)]
const HUB_OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(windows)]
#[tauri::command]
pub async fn get_overview(state: State<'_, ProductionGateway>) -> CommandResult<OverviewDto> {
    state.overview().await
}

#[tauri::command]
pub async fn get_connection_status(
    state: State<'_, ProductionGateway>,
) -> CommandResult<ConnectionStatusDto> {
    state.connection_status().await
}

#[tauri::command]
pub async fn run_environment_check(
    state: State<'_, ProductionGateway>,
) -> CommandResult<EnvironmentCheckDto> {
    state.environment_check().await
}

#[tauri::command]
pub async fn get_log_tail(
    lines: u16,
    level: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<LogTailDto> {
    let level = match level.as_str() {
        "error" => fairypam_agent::runtime_api::LogLevel::Error,
        "warn" => fairypam_agent::runtime_api::LogLevel::Warn,
        "info" => fairypam_agent::runtime_api::LogLevel::Info,
        _ => {
            return Err(UiCommandError::unavailable(
                "local.command.invalid_argument",
                "level must be error, warn, or info",
            ))
        }
    };
    if !(1..=200).contains(&lines) {
        return Err(UiCommandError::unavailable(
            "local.command.invalid_argument",
            "lines must be within 1..=200",
        ));
    }
    state.log_tail(lines, level).await
}

#[tauri::command]
pub async fn scan_installed_games(
    state: State<'_, ProductionGateway>,
) -> CommandResult<InstalledGamesDto> {
    state.installed_games().await
}

#[tauri::command]
pub async fn launch_game(
    profile_id: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<LaunchedGameDto> {
    if profile_id.is_empty()
        || profile_id.len() > 64
        || !profile_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(UiCommandError::unavailable(
            "local.command.invalid_argument",
            "profile_id is invalid",
        ));
    }
    state.launch_game(profile_id).await
}

#[tauri::command]
pub async fn close_game(state: State<'_, ProductionGateway>) -> CommandResult<ClosedGameDto> {
    state.close_game().await
}

#[tauri::command]
pub async fn capture_preview(state: State<'_, ProductionGateway>) -> CommandResult<PreviewDto> {
    state.capture_preview().await
}

#[tauri::command]
pub async fn input_probe(
    action: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<InputResultDto> {
    match action.as_str() {
        "move_forward" => state.input_key_pulse(17, false).await,
        "quick_use" => state.input_key_pulse(44, false).await,
        "mouse_left" => state.input_mouse_click(1).await,
        _ => Err(UiCommandError::unavailable(
            "local.command.invalid_argument",
            "input action is invalid",
        )),
    }
}

#[tauri::command]
pub async fn register_hub(
    hub_address: String,
    registration_code: String,
    state: State<'_, ProductionGateway>,
) -> CommandResult<RegistrationStatusDto> {
    state.register_hub(hub_address, registration_code).await
}

#[tauri::command]
pub async fn ensure_local_agent(
    state: State<'_, ProductionGateway>,
) -> CommandResult<SupportStatusDto> {
    ensure_local_agent_owned(&state).await
}

pub(crate) async fn ensure_local_agent_owned(
    state: &ProductionGateway,
) -> CommandResult<SupportStatusDto> {
    #[cfg(windows)]
    {
        let _lifecycle = state.acquire_lifecycle()?;
        observe_hub(state).await
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Err(UiCommandError::unavailable(
            "local.transport.platform_unsupported",
            "FairyPam Agent startup requires Windows",
        ))
    }
}

pub(crate) async fn shutdown_local_agent_for_exit(state: &ProductionGateway) -> CommandResult<()> {
    #[cfg(windows)]
    {
        let _lifecycle = state.acquire_lifecycle()?;
        state.shutdown_agent().await
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Ok(())
    }
}

#[cfg(windows)]
async fn observe_hub(state: &ProductionGateway) -> CommandResult<SupportStatusDto> {
    let deadline = Instant::now() + HUB_OBSERVATION_LIMIT;
    for attempt in 0..HUB_OBSERVATION_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let status = match state
            .connection_status_with_timeout(remaining.min(Duration::from_secs(1)))
            .await
        {
            Ok(status) => status,
            Err(error) => return Err(error),
        };
        if status.control.eq_ignore_ascii_case("connected")
            && status.frame.eq_ignore_ascii_case("connected")
        {
            return Ok(SupportStatusDto {
                status: "ready".into(),
            });
        }
        if status.recovery_code == "runtime.not_registered" {
            return Ok(SupportStatusDto {
                status: "agent_ready".into(),
            });
        }
        if attempt + 1 < HUB_OBSERVATION_ATTEMPTS {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(HUB_OBSERVATION_INTERVAL.min(remaining)).await;
        }
    }
    Ok(SupportStatusDto {
        status: "hub_wait_timeout".into(),
    })
}

#[cfg(windows)]
pub(crate) fn verify_active_gui() -> CommandResult<()> {
    active_gui_paths().map(|_| ())
}

#[cfg(windows)]
fn active_gui_paths() -> CommandResult<(PathBuf, PathBuf)> {
    let gui = std::env::current_exe().map_err(|_| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let version_root = gui.parent().map(|path| path.to_path_buf()).ok_or_else(|| {
        UiCommandError::unavailable("startup.agent_unavailable", "FairyPam Agent is unavailable")
    })?;
    let versions = version_root.parent().ok_or_else(untrusted_install_root)?;
    if versions.file_name().and_then(|name| name.to_str()) != Some("versions") {
        return Err(untrusted_install_root());
    }
    let install_root = versions.parent().ok_or_else(untrusted_install_root)?;
    let pointer = install_root.join(fairypam_agent_suite::CURRENT_POINTER_FILE);
    for path in [&gui, &pointer] {
        install_security::verify_protected_program_files_path(path)?;
    }
    let active = fairypam_agent_suite::resolve_active_suite(install_root)
        .map_err(|_| untrusted_install_root())?;
    let actual = std::fs::canonicalize(&version_root).map_err(|_| untrusted_install_root())?;
    let expected =
        std::fs::canonicalize(&active.version_root).map_err(|_| untrusted_install_root())?;
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(UiCommandError::unavailable(
            "startup.inactive_suite",
            "FairyPam must be started from the active installed version",
        ));
    }
    Ok((gui, version_root))
}

#[cfg(windows)]
fn untrusted_install_root() -> UiCommandError {
    UiCommandError::unavailable(
        "startup.install_root_untrusted",
        "FairyPam must be installed under Program Files before requesting administrator access",
    )
}

#[cfg(windows)]
mod install_security {
    use std::{fs, path::Path};

    use windows::{
        core::{GUID, HSTRING},
        Win32::{
            Foundation::{CloseHandle, ERROR_ACCESS_DENIED},
            Storage::FileSystem::{
                CreateFileW, GetFileAttributesW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
                FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
                FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, FILE_WRITE_DATA, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING,
                WRITE_DAC, WRITE_OWNER,
            },
            System::Com::CoTaskMemFree,
            UI::Shell::{
                FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath,
                KF_FLAG_DEFAULT,
            },
        },
    };

    use super::{untrusted_install_root, CommandResult};

    pub(super) fn verify_protected_program_files_path(path: &Path) -> CommandResult<()> {
        for root in [FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86]
            .iter()
            .filter_map(|folder| known_folder_path(folder).ok())
            .map(std::path::PathBuf::from)
        {
            if protected_install_path(path, &root)? {
                return Ok(());
            }
        }
        Err(untrusted_install_root())
    }

    fn protected_install_path(path: &Path, root: &Path) -> CommandResult<bool> {
        if has_reparse_component(root) || has_reparse_component(path) {
            return Ok(false);
        }
        let (Ok(final_root), Ok(final_path)) = (fs::canonicalize(root), fs::canonicalize(path))
        else {
            return Ok(false);
        };
        if !fs::metadata(&final_path).is_ok_and(|metadata| metadata.is_file()) {
            return Ok(false);
        }
        Ok(path_is_within(&final_path, &final_root)
            && protected_install_chain(&final_root, &final_path)?)
    }

    fn protected_install_chain(root: &Path, target: &Path) -> CommandResult<bool> {
        let Ok(relative) = target.strip_prefix(root) else {
            return Ok(false);
        };
        let mut current = root.to_path_buf();
        if path_is_writable(&current)? {
            return Ok(false);
        }
        for component in relative {
            current.push(component);
            if has_reparse_component(&current) || path_is_writable(&current)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn path_is_within(path: &Path, root: &Path) -> bool {
        let path = path.to_string_lossy().replace('/', "\\").to_lowercase();
        let root = root
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase();
        path == root
            || path
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('\\'))
    }

    fn has_reparse_component(path: &Path) -> bool {
        let mut current = std::path::PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            if !matches!(component, std::path::Component::Normal(_)) {
                continue;
            }
            let attributes =
                unsafe { GetFileAttributesW(&HSTRING::from(current.to_string_lossy().as_ref())) };
            if attributes == INVALID_FILE_ATTRIBUTES
                || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            {
                return true;
            }
        }
        false
    }

    fn path_is_writable(path: &Path) -> CommandResult<bool> {
        let Ok(metadata) = fs::metadata(path) else {
            return Ok(true);
        };
        let (access, flags) = if metadata.is_dir() {
            (
                [
                    DELETE.0,
                    FILE_ADD_FILE.0,
                    FILE_ADD_SUBDIRECTORY.0,
                    FILE_DELETE_CHILD.0,
                    WRITE_DAC.0,
                    WRITE_OWNER.0,
                ],
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        } else {
            (
                [
                    DELETE.0,
                    FILE_WRITE_DATA.0,
                    FILE_APPEND_DATA.0,
                    WRITE_DAC.0,
                    WRITE_OWNER.0,
                    0,
                ],
                FILE_ATTRIBUTE_NORMAL,
            )
        };
        for access in access.into_iter().filter(|access| *access != 0) {
            let handle = unsafe {
                CreateFileW(
                    &HSTRING::from(path.to_string_lossy().as_ref()),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    flags,
                    None,
                )
            };
            match handle {
                Ok(handle) => {
                    let _ = unsafe { CloseHandle(handle) };
                    return Ok(true);
                }
                Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
                Err(_) => return Err(untrusted_install_root()),
            }
        }
        Ok(false)
    }

    fn known_folder_path(folder: &GUID) -> CommandResult<String> {
        let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None) }
            .map_err(|_| untrusted_install_root())?;
        let result = unsafe { path.to_string() }.map_err(|_| untrusted_install_root());
        unsafe { CoTaskMemFree(Some(path.0.cast())) };
        result
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::time::Duration;

    #[cfg(windows)]
    use super::{HUB_OBSERVATION_ATTEMPTS, HUB_OBSERVATION_INTERVAL, HUB_OBSERVATION_LIMIT};

    #[cfg(windows)]
    #[test]
    fn hub_observation_budget_is_bounded() {
        assert_eq!(HUB_OBSERVATION_ATTEMPTS, 20);
        assert_eq!(HUB_OBSERVATION_INTERVAL, Duration::from_secs(1));
        assert_eq!(HUB_OBSERVATION_LIMIT, Duration::from_secs(20));
    }
}
