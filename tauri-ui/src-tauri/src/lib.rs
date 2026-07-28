use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use fairypam_agent::agent_runtime::in_process_runtime_runner;
use fairypam_agent::config::AppConfig;
use fairypam_agent::core_facade::{
    discovery_self_test_target, CoreFacade, SelfTestSession, SelfTestTarget,
};
use fairypam_agent::mihoyo_discovery::{is_trusted_elevated_install, MihoyoGameInstall};
use fairypam_agent::protocol::{InputFrame, MouseButtons, MouseState};
use fairypam_agent::runtime_controller::RuntimePhase;
use fairypam_agent::window::{TargetWindow, WindowRect};
use serde::Serialize;
use tauri::Manager;

struct AppState {
    facade: Mutex<CoreFacade>,
    config_path: PathBuf,
    log_path: PathBuf,
    startup_error: Option<String>,
    self_test: Mutex<Option<SelfTestSession>>,
    self_test_window: Mutex<Option<TargetWindowDto>>,
}

#[derive(Serialize)]
struct RuntimeStatusDto {
    phase: String,
    label: String,
    message: String,
    can_start: bool,
    can_stop: bool,
    can_restart: bool,
}

#[derive(Serialize)]
struct DashboardState {
    agent_name: String,
    hub_url: String,
    runtime: RuntimeStatusDto,
    fps: u32,
    encoder: String,
    config_path: String,
    log_path: String,
    cli_preview: String,
}

#[derive(Serialize)]
struct GameCandidateDto {
    discovery_id: String,
    display_name: String,
    display_version: Option<String>,
    launch_path: Option<String>,
    supported: bool,
    exists_on_disk: bool,
    status: String,
    self_test_target: Option<SelfTestTargetDto>,
}

#[derive(Clone, Serialize)]
struct SelfTestTargetDto {
    profile_id: String,
    executable: String,
    working_dir: String,
}

#[derive(Clone, Serialize)]
struct WindowRectDto {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[derive(Clone, Serialize)]
struct TargetWindowDto {
    pid: u32,
    title: String,
    class_name: Option<String>,
    rect: WindowRectDto,
}

#[derive(Serialize)]
struct SelfTestLaunchDto {
    pid: u32,
    window: TargetWindowDto,
    privilege: String,
}

#[derive(Serialize)]
struct SelfTestCaptureDto {
    width: u32,
    height: u32,
    bytes: usize,
    jpeg: Vec<u8>,
}

pub fn run() -> tauri::Result<()> {
    let paths = resolve_agent_paths();
    let auto_start_executable =
        std::env::var_os("FAIRYPAM_AGENT_RUNTIME_EXECUTABLE").map(PathBuf::from);
    let startup_error = ensure_log_file(&paths.log_path)
        .err()
        .map(|err| format!("初始化日志失败：{} ({err})", paths.log_path.display()));
    let app = tauri::Builder::default()
        .manage(AppState {
            facade: Mutex::new(CoreFacade::new_with_auto_start_executable(
                paths.config_path.clone(),
                paths.log_path.clone(),
                auto_start_executable,
                in_process_runtime_runner,
            )),
            config_path: paths.config_path,
            log_path: paths.log_path,
            startup_error,
            self_test: Mutex::new(None),
            self_test_window: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            load_dashboard_state,
            load_config,
            save_config,
            runtime_status,
            start_runtime,
            stop_runtime,
            restart_runtime,
            read_log_tail,
            scan_local_games,
            self_test_launch,
            self_test_capture,
            self_test_input,
            self_test_close,
        ])
        .build(tauri::generate_context!())?;
    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            let state = app_handle.state::<AppState>();
            shutdown_app_state(state.inner());
        }
    });
    Ok(())
}

#[tauri::command]
fn load_dashboard_state(state: tauri::State<'_, AppState>) -> Result<DashboardState, String> {
    if let Some(error) = &state.startup_error {
        return Err(error.clone());
    }
    let facade = state.facade.lock().map_err(|err| err.to_string())?;
    let config = facade.load_config().unwrap_or_default();
    let config_path = state.config_path.display().to_string();
    let log_path = state.log_path.display().to_string();
    Ok(DashboardState {
        agent_name: config.agent.name,
        hub_url: config.hub.ws_url,
        runtime: runtime_status_from_facade(&facade),
        fps: config.capture.fps,
        encoder: config.capture.encoder,
        config_path: config_path.clone(),
        log_path: log_path.clone(),
        cli_preview: format!(
            "fairypam-agent --run --config \"{config_path}\" --log-file \"{log_path}\""
        ),
    })
}

#[tauri::command]
fn load_config(state: tauri::State<'_, AppState>) -> Result<AppConfig, String> {
    state
        .facade
        .lock()
        .map_err(|err| err.to_string())?
        .load_config()
        .map_err(|err| format!("读取配置失败：{} ({err})", state.config_path.display()))
}

#[tauri::command]
fn save_config(state: tauri::State<'_, AppState>, config: AppConfig) -> Result<AppConfig, String> {
    let facade = state.facade.lock().map_err(|err| err.to_string())?;
    facade.save_config(&config).map_err(|err| err.to_string())?;
    Ok(config)
}

#[tauri::command]
fn runtime_status(state: tauri::State<'_, AppState>) -> Result<RuntimeStatusDto, String> {
    let mut facade = state.facade.lock().map_err(|err| err.to_string())?;
    facade.poll_runtime();
    Ok(runtime_status_from_facade(&facade))
}

#[tauri::command]
fn start_runtime(state: tauri::State<'_, AppState>) -> Result<RuntimeStatusDto, String> {
    let mut facade = state.facade.lock().map_err(|err| err.to_string())?;
    let config = facade.load_config().map_err(|err| err.to_string())?;
    facade
        .start_runtime(config)
        .map_err(|err| err.to_string())?;
    facade.poll_runtime();
    Ok(runtime_status_from_facade(&facade))
}

#[tauri::command]
fn stop_runtime(state: tauri::State<'_, AppState>) -> Result<RuntimeStatusDto, String> {
    let mut facade = state.facade.lock().map_err(|err| err.to_string())?;
    facade.stop_runtime();
    facade.poll_runtime();
    Ok(runtime_status_from_facade(&facade))
}

#[tauri::command]
fn restart_runtime(state: tauri::State<'_, AppState>) -> Result<RuntimeStatusDto, String> {
    let mut facade = state.facade.lock().map_err(|err| err.to_string())?;
    let config = facade.load_config().map_err(|err| err.to_string())?;
    facade
        .restart_runtime(config)
        .map_err(|err| err.to_string())?;
    facade.poll_runtime();
    Ok(runtime_status_from_facade(&facade))
}

#[tauri::command]
fn read_log_tail(
    state: tauri::State<'_, AppState>,
    filter: Option<String>,
) -> Result<String, String> {
    if !state.log_path.exists() {
        return Ok(format!("日志文件尚未创建：{}", state.log_path.display()));
    }
    let facade = state.facade.lock().map_err(|err| err.to_string())?;
    let text = facade.log_tail().map_err(|err| err.to_string())?;
    let Some(filter) = filter
        .map(|value| value.to_lowercase())
        .filter(|value| !value.is_empty())
    else {
        return Ok(text);
    };
    Ok(text
        .lines()
        .filter(|line| line.to_lowercase().contains(&filter))
        .collect::<Vec<_>>()
        .join("\n"))
}

struct AgentPaths {
    config_path: PathBuf,
    log_path: PathBuf,
}

fn resolve_agent_paths() -> AgentPaths {
    let config_path = std::env::var_os("FAIRYPAM_AGENT_CONFIG_PATH")
        .map(PathBuf::from)
        .or_else(|| find_upwards("config.yaml"))
        .unwrap_or_else(|| PathBuf::from("config.yaml"));
    let log_path = std::env::var_os("FAIRYPAM_AGENT_LOG_PATH").map(PathBuf::from);
    let root = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    AgentPaths {
        config_path,
        log_path: log_path.unwrap_or_else(|| root.join("logs").join("agent.log")),
    }
}

fn find_upwards(file_name: &str) -> Option<PathBuf> {
    let starts = [
        std::env::current_dir().ok(),
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf)),
    ];

    starts
        .into_iter()
        .flatten()
        .flat_map(|start| start.ancestors().map(Path::to_path_buf).collect::<Vec<_>>())
        .map(|dir| dir.join(file_name))
        .find(|path| path.is_file())
}

fn ensure_log_file(path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    writeln!(file, "[{now}] Tauri GUI started")
}

fn shutdown_app_state(state: &AppState) {
    {
        let mut facade = lock_recover(&state.facade);
        facade.stop_runtime();
    }
    let release_error = {
        let mut session = lock_recover(&state.self_test);
        let release_error = session.as_mut().and_then(|session| {
            release_input_with_retry(|| session.release_input().map_err(|err| err.to_string()))
                .err()
        });
        *session = None;
        release_error
    };
    if let Some(error) = release_error {
        let _ = fairypam_agent::agent_runtime::append_log_line(
            &state.log_path,
            &format!("Tauri exit input release failed after 2 attempts: {error}"),
        );
    }
    {
        let mut window = lock_recover(&state.self_test_window);
        *window = None;
    }
    {
        let mut facade = lock_recover(&state.facade);
        facade.shutdown_runtime_and_wait();
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn release_input_with_retry<F>(mut release: F) -> Result<(), String>
where
    F: FnMut() -> Result<(), String>,
{
    let mut last_error = None;
    for _ in 0..2 {
        match release() {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "input release failed".to_string()))
}

async fn run_blocking<T, F>(operation: &'static str, task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|err| format!("{operation}任务失败：{err}"))?
}

#[tauri::command]
async fn scan_local_games(app: tauri::AppHandle) -> Result<Vec<GameCandidateDto>, String> {
    run_blocking("扫描本机游戏", move || {
        let state = app.state::<AppState>();
        let facade = state.facade.lock().map_err(|err| err.to_string())?;
        facade
            .scan_mihoyo_games()
            .map_err(|err| err.to_string())
            .map(|games| games.into_iter().map(game_candidate_dto).collect())
    })
    .await
}

fn game_candidate_dto(game: MihoyoGameInstall) -> GameCandidateDto {
    let trusted = is_trusted_elevated_install(&game);
    let target = trusted.then(|| discovery_self_test_target(&game)).flatten();
    let status = if game.supported && game.exists_on_disk && !trusted {
        "已发现，但当前安装来源或位置不可用于自检".to_string()
    } else {
        game.scan_status.clone().unwrap_or_else(|| "ok".to_string())
    };

    GameCandidateDto {
        discovery_id: game.discovery_id,
        display_name: game.display_name,
        display_version: game.registry.display_version,
        launch_path: game.launch_path.map(|path| path.display().to_string()),
        supported: game.supported,
        exists_on_disk: game.exists_on_disk,
        status,
        self_test_target: target.map(self_test_target_dto),
    }
}

fn resolve_self_test_target(
    games: &[MihoyoGameInstall],
    discovery_id: &str,
) -> Result<SelfTestTarget, String> {
    games
        .iter()
        .find(|game| game.discovery_id == discovery_id)
        .filter(|game| is_trusted_elevated_install(game))
        .and_then(discovery_self_test_target)
        .ok_or_else(|| "自检目标不可用或已过期，请重新扫描".to_string())
}

#[tauri::command]
async fn self_test_launch(
    app: tauri::AppHandle,
    discovery_id: String,
) -> Result<SelfTestLaunchDto, String> {
    run_blocking("启动自检", move || {
        let state = app.state::<AppState>();
        let (config, target) = {
            let facade = state.facade.lock().map_err(|err| err.to_string())?;
            let games = facade
                .scan_mihoyo_games()
                .map_err(|err| format!("扫描本机游戏失败：{err}"))?;
            let target = resolve_self_test_target(&games, &discovery_id)?;
            let config = facade
                .load_config()
                .map_err(|err| format!("读取配置失败：{} ({err})", state.config_path.display()))?;
            (config, target)
        };
        let mut session =
            SelfTestSession::new(&config.game_profiles).map_err(|err| err.to_string())?;
        let launch = session
            .launch(&target, &[])
            .map_err(|err| err.to_string())?;
        let window = target_window_dto(launch.window);
        *state.self_test.lock().map_err(|err| err.to_string())? = Some(session);
        *state
            .self_test_window
            .lock()
            .map_err(|err| err.to_string())? = Some(window.clone());
        Ok(SelfTestLaunchDto {
            pid: launch.pid,
            window,
            privilege: format!("{:?}", launch.privilege),
        })
    })
    .await
}

#[tauri::command]
async fn self_test_capture(app: tauri::AppHandle) -> Result<SelfTestCaptureDto, String> {
    run_blocking("自检截图", move || {
        let state = app.state::<AppState>();
        let config = state
            .facade
            .lock()
            .map_err(|err| err.to_string())?
            .load_config()
            .map_err(|err| format!("读取配置失败：{} ({err})", state.config_path.display()))?;
        let mut session = state.self_test.lock().map_err(|err| err.to_string())?;
        let session = session.as_mut().ok_or("没有正在运行的自检目标")?;
        let frame = session
            .capture(&config.capture)
            .map_err(|err| err.to_string())?;
        Ok(SelfTestCaptureDto {
            width: frame.width,
            height: frame.height,
            bytes: frame.jpeg.len(),
            jpeg: frame.jpeg,
        })
    })
    .await
}

#[tauri::command]
async fn self_test_input(app: tauri::AppHandle, action: String) -> Result<TargetWindowDto, String> {
    run_blocking("自检输入", move || {
        let state = app.state::<AppState>();
        let mut session = state.self_test.lock().map_err(|err| err.to_string())?;
        let session = session.as_mut().ok_or("没有正在运行的自检目标")?;
        if action == "release_all" {
            session.release_input().map_err(|err| err.to_string())?;
            return state
                .self_test_window
                .lock()
                .map_err(|err| err.to_string())?
                .clone()
                .ok_or_else(|| "尚未绑定自检窗口".to_string());
        }

        let window = state
            .self_test_window
            .lock()
            .map_err(|err| err.to_string())?
            .clone()
            .ok_or("尚未绑定自检窗口")?;
        let x = window.rect.left + (window.rect.right - window.rect.left) / 2;
        let y = window.rect.top + (window.rect.bottom - window.rect.top) / 2;

        let window = match action.as_str() {
            "move_center" => send_input(session, x, y, None, None)?,
            "click_left" => {
                send_input(session, x, y, Some("down"), None)?;
                send_input(session, x, y, Some("up"), None)?
            }
            "tap_space" => {
                send_input(session, x, y, None, Some(("space", "down")))?;
                send_input(session, x, y, None, Some(("space", "up")))?
            }
            "tap_esc" => {
                send_input(session, x, y, None, Some(("esc", "down")))?;
                send_input(session, x, y, None, Some(("esc", "up")))?
            }
            _ => return Err(format!("未知自检动作：{action}")),
        };
        *state
            .self_test_window
            .lock()
            .map_err(|err| err.to_string())? = Some(window.clone());
        Ok(window)
    })
    .await
}

#[tauri::command]
async fn self_test_close(app: tauri::AppHandle) -> Result<(), String> {
    run_blocking("关闭自检", move || {
        let state = app.state::<AppState>();
        let mut session = state.self_test.lock().map_err(|err| err.to_string())?;
        session
            .as_mut()
            .ok_or("没有正在运行的自检目标")?
            .close(true)
            .map_err(|err| err.to_string())?;
        *session = None;
        *state
            .self_test_window
            .lock()
            .map_err(|err| err.to_string())? = None;
        Ok(())
    })
    .await
}

fn send_input(
    session: &mut SelfTestSession,
    x: i32,
    y: i32,
    left_button: Option<&str>,
    key: Option<(&str, &str)>,
) -> Result<TargetWindowDto, String> {
    let mut keyboard = HashMap::new();
    if let Some((name, state)) = key {
        keyboard.insert(name.to_string(), state.to_string());
    }
    let window = session
        .send_input(InputFrame {
            session_id: "tauri-self-test".to_string(),
            game_id: "genshin".to_string(),
            seq: 0,
            keyboard,
            mouse: MouseState {
                x,
                y,
                buttons: MouseButtons {
                    left: left_button.unwrap_or("up").to_string(),
                    right: "up".to_string(),
                    middle: "up".to_string(),
                },
                scroll_delta: 0,
            },
            gamepad: None,
        })
        .map_err(|err| err.to_string())?;
    Ok(target_window_dto(window))
}

fn runtime_status_from_facade(facade: &CoreFacade) -> RuntimeStatusDto {
    let phase = facade.runtime_phase();
    RuntimeStatusDto {
        phase: phase_key(phase).to_string(),
        label: phase.label().to_string(),
        message: facade.runtime_status(),
        can_start: facade.can_start_runtime(),
        can_stop: facade.can_stop_runtime(),
        can_restart: facade.can_restart_runtime(),
    }
}

fn phase_key(phase: RuntimePhase) -> &'static str {
    match phase {
        RuntimePhase::Stopped => "stopped",
        RuntimePhase::Starting => "starting",
        RuntimePhase::Running => "running",
        RuntimePhase::Stopping => "stopping",
        RuntimePhase::Error => "error",
    }
}

fn self_test_target_dto(target: SelfTestTarget) -> SelfTestTargetDto {
    SelfTestTargetDto {
        profile_id: target.profile_id,
        executable: target.executable,
        working_dir: target.working_dir,
    }
}

fn target_window_dto(window: TargetWindow) -> TargetWindowDto {
    TargetWindowDto {
        pid: window.pid,
        title: window.title,
        class_name: window.class_name,
        rect: window_rect_dto(window.rect),
    }
}

fn window_rect_dto(rect: WindowRect) -> WindowRectDto {
    WindowRectDto {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::panic::AssertUnwindSafe;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Mutex, PoisonError};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use anyhow::Result;
    use fairypam_agent::config::AppConfig;
    use fairypam_agent::core_facade::{CoreFacade, SelfTestSession};
    use fairypam_agent::mihoyo_discovery::{MihoyoGameInstall, RegistryHive};
    use fairypam_agent::runtime_controller::{RuntimePhase, RuntimeStartSpec, RuntimeStatusUpdate};
    use tokio::sync::watch;

    use super::{
        game_candidate_dto, release_input_with_retry, resolve_self_test_target, shutdown_app_state,
        AppState,
    };

    fn game(id: &str) -> MihoyoGameInstall {
        MihoyoGameInstall {
            discovery_id: id.to_string(),
            registry: fairypam_agent::mihoyo_discovery::MihoyoRegistryEntry {
                source_hive: RegistryHive::Machine,
                ..Default::default()
            },
            supported: true,
            exists_on_disk: true,
            profile_id: Some("genshin".to_string()),
            launch_path: Some("C:/games/YuanShen.exe".into()),
            game_dir: Some("C:/games".into()),
            ..Default::default()
        }
    }

    #[test]
    fn self_test_target_resolution_rejects_untrusted_discovery_items() {
        let root = std::env::temp_dir().join(format!(
            "fairypam-tauri-protected-root-{}",
            std::process::id()
        ));
        let game_dir = root.join("miHoYo").join("Genshin Impact Game");
        let launch_path = game_dir.join("YuanShen.exe");
        std::fs::create_dir_all(&game_dir).unwrap();
        std::fs::write(&launch_path, b"test").unwrap();
        let old_program_files = std::env::var_os("ProgramFiles");
        std::env::set_var("ProgramFiles", &root);

        let mut valid = game("current");
        valid.launch_path = Some(launch_path);
        valid.game_dir = Some(game_dir);
        assert_eq!(
            resolve_self_test_target(std::slice::from_ref(&valid), "current").unwrap(),
            fairypam_agent::core_facade::discovery_self_test_target(&valid).unwrap()
        );
        assert!(resolve_self_test_target(std::slice::from_ref(&valid), "forged").is_err());

        let mut unsupported = valid.clone();
        unsupported.supported = false;
        assert!(resolve_self_test_target(&[unsupported], "current").is_err());

        let mut missing = valid.clone();
        missing.exists_on_disk = false;
        assert!(resolve_self_test_target(&[missing], "current").is_err());

        let mut forged = valid.clone();
        forged.registry.source_hive = RegistryHive::User;
        assert!(resolve_self_test_target(&[forged], "current").is_err());

        let mut targetless = valid;
        targetless.game_dir = None;
        assert!(resolve_self_test_target(&[targetless], "current").is_err());

        if let Some(value) = old_program_files {
            std::env::set_var("ProgramFiles", value);
        } else {
            std::env::remove_var("ProgramFiles");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn untrusted_scan_item_does_not_advertise_self_test_capability() {
        let mut forged = game("forged");
        forged.registry.source_hive = RegistryHive::User;

        let candidate = game_candidate_dto(forged);

        assert!(candidate.self_test_target.is_none());
        assert_eq!(candidate.status, "已发现，但当前安装来源或位置不可用于自检");
    }

    #[test]
    fn runtime_status_exposes_controller_capabilities() {
        let facade = CoreFacade::new(
            "config.yaml",
            "agent.log",
            fairypam_agent::agent_runtime::in_process_runtime_runner,
        );
        let status = super::runtime_status_from_facade(&facade);

        assert!(status.can_start);
        assert!(!status.can_stop);
        assert!(status.can_restart);
    }

    #[test]
    fn app_shutdown_joins_runtime_and_clears_self_test_state() {
        static JOINED: AtomicBool = AtomicBool::new(false);

        fn waiting_runner(
            _spec: RuntimeStartSpec,
            mut stop_rx: watch::Receiver<bool>,
            _status_tx: mpsc::Sender<RuntimeStatusUpdate>,
        ) -> Result<JoinHandle<()>> {
            Ok(std::thread::spawn(move || {
                while !*stop_rx.borrow() {
                    if stop_rx.has_changed().unwrap_or(true) {
                        let _ = stop_rx.borrow_and_update();
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                JOINED.store(true, Ordering::SeqCst);
            }))
        }

        JOINED.store(false, Ordering::SeqCst);
        let state = AppState {
            facade: Mutex::new(CoreFacade::new("config.yaml", "agent.log", waiting_runner)),
            config_path: PathBuf::from("config.yaml"),
            log_path: PathBuf::from("agent.log"),
            startup_error: None,
            self_test: Mutex::new(Some(SelfTestSession::new(&HashMap::new()).unwrap())),
            self_test_window: Mutex::new(None),
        };
        state
            .facade
            .lock()
            .unwrap()
            .start_runtime(AppConfig::default())
            .unwrap();

        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = state.facade.lock().unwrap();
            panic!("poison facade");
        }));
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = state.self_test.lock().unwrap();
            panic!("poison self-test");
        }));
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = state.self_test_window.lock().unwrap();
            panic!("poison window");
        }));

        shutdown_app_state(&state);

        assert!(JOINED.load(Ordering::SeqCst));
        assert_eq!(
            state
                .facade
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .runtime_phase(),
            RuntimePhase::Stopped
        );
        assert!(state
            .self_test
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none());
        assert!(state
            .self_test_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none());
    }

    #[test]
    fn input_release_retry_is_bounded() {
        let mut attempts = 0;
        let result = release_input_with_retry(|| {
            attempts += 1;
            Err("release failed".to_string())
        });

        assert!(result.is_err());
        assert_eq!(attempts, 2);
    }
}
