//! Shared in-process FairyPam Agent runtime.

use std::collections::HashSet;
use std::future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{mpsc as std_mpsc, Arc};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::{AbortHandle, JoinHandle};
use tracing::{error, info, warn};

use crate::input::InputController;
use crate::process::{
    is_launch_allowed, normalize_executable_name, resolve_discovered_game_launch, ProcessManager,
    TargetBinding,
};
use crate::protocol::{
    AgentMessage, GameKillAck, GameLaunchAck, HubMessage, InputFrameAck, SystemInfo,
};
use crate::runtime_controller::{RuntimeStartSpec, RuntimeStatusUpdate};
use crate::system::SystemMonitor;
use crate::ws_client::{OutboundWriter, WsClient};
use crate::{
    config, environment_check,
    launch_to_ready::{LaunchToReadyEngine, ProductionLaunchToReadyOps},
    mihoyo_discovery, protocol, system, target_operation,
};

use crate::capture::ScreenCapture;

const RECONNECT_BASE_DELAY_MS: u64 = 1_000;
const RECONNECT_MAX_DELAY_MS: u64 = 30_000;

enum AgentEvent {
    InputFrame(protocol::InputFrame),
    InputFrameResume(protocol::InputFrameResume),
    GameLaunch(protocol::GameLaunch),
    GameKill(protocol::GameKill),
    SettingsUpdate(protocol::SettingsUpdate),
    GameDiscoveryRequest(protocol::GameDiscoveryRequest),
    EnvironmentCheckStart(protocol::EnvironmentCheckStart),
    EnvironmentCheckCancel(protocol::EnvironmentCheckCancel),
    TaskRunStart(protocol::TaskRunStart),
    TaskRunCancel(protocol::TaskRunCancel),
    TaskRunClick(protocol::TaskRunClick),
    TaskRunTerminal(protocol::TaskRunTerminal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EnvironmentCheckIdentity {
    task_run_id: String,
    trace_id: String,
    session_id: String,
    connection_id: uuid::Uuid,
}

type ActiveEnvironmentCheck = Arc<Mutex<Option<(EnvironmentCheckIdentity, Arc<AtomicBool>)>>>;

#[derive(Clone, Debug)]
struct PendingTaskRunStart {
    task_run_id: String,
    trace_id: String,
    session_id: String,
    connection_id: uuid::Uuid,
    phase: Arc<AtomicU8>,
}

impl PendingTaskRunStart {
    const PENDING: u8 = 0;
    const STARTING: u8 = 1;
    const CANCELLED: u8 = 2;

    fn from_start(start: &protocol::TaskRunStart) -> Self {
        Self {
            task_run_id: start.task_run_id.clone(),
            trace_id: start.trace_id.clone(),
            session_id: start.session_id.clone(),
            connection_id: start.connection_id,
            phase: Arc::new(AtomicU8::new(Self::PENDING)),
        }
    }

    fn matches_cancel(&self, cancel: &protocol::TaskRunCancel) -> bool {
        self.task_run_id == cancel.task_run_id
            && self.trace_id == cancel.trace_id
            && self.session_id == cancel.session_id
            && self.connection_id == cancel.connection_id
    }

    fn matches_start(&self, start: &protocol::TaskRunStart) -> bool {
        self.task_run_id == start.task_run_id
            && self.trace_id == start.trace_id
            && self.session_id == start.session_id
            && self.connection_id == start.connection_id
    }

    fn matches_terminal(&self, terminal: &protocol::TaskRunTerminal) -> bool {
        self.task_run_id == terminal.task_run_id
            && self.trace_id == terminal.trace_id
            && self.session_id == terminal.session_id
            && self.connection_id == terminal.connection_id
    }

    fn is_cancelled(&self) -> bool {
        self.phase.load(Ordering::Acquire) == Self::CANCELLED
    }

    fn claim_start(&self) -> bool {
        self.phase
            .compare_exchange(
                Self::PENDING,
                Self::STARTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn cancel_before_start(&self) -> bool {
        self.phase
            .compare_exchange(
                Self::PENDING,
                Self::CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn is_starting(&self) -> bool {
        self.phase.load(Ordering::Acquire) == Self::STARTING
    }
}

type PendingTaskRunStartSlot = Arc<Mutex<Option<PendingTaskRunStart>>>;

async fn cancel_pending_task_run_start(
    pending: &PendingTaskRunStartSlot,
    cancel: &protocol::TaskRunCancel,
) -> bool {
    let pending = pending.lock().await;
    let Some(pending) = pending
        .as_ref()
        .filter(|pending| pending.matches_cancel(cancel))
    else {
        return false;
    };
    pending.cancel_before_start()
}

async fn clear_pending_task_run_start(
    pending: &PendingTaskRunStartSlot,
    start: &protocol::TaskRunStart,
) {
    let mut pending = pending.lock().await;
    if pending
        .as_ref()
        .is_some_and(|pending| pending.matches_start(start) && !pending.is_cancelled())
    {
        *pending = None;
    }
}

async fn consume_cancelled_pending_task_run_start(
    pending: &PendingTaskRunStartSlot,
    terminal: &protocol::TaskRunTerminal,
) -> bool {
    let mut pending = pending.lock().await;
    if pending
        .as_ref()
        .is_some_and(|pending| pending.is_cancelled() && pending.matches_terminal(terminal))
    {
        *pending = None;
        true
    } else {
        false
    }
}

async fn clear_pending_task_run_start_on_disconnect(pending: &PendingTaskRunStartSlot) {
    *pending.lock().await = None;
}

async fn activate_pending_task_run_start(
    pending: &PendingTaskRunStartSlot,
    start: &protocol::TaskRunStart,
    state: &Arc<Mutex<AgentRuntimeState>>,
) -> bool {
    let mut pending = pending.lock().await;
    if pending
        .as_ref()
        .is_some_and(|pending| pending.matches_start(start) && pending.is_starting())
    {
        state
            .lock()
            .await
            .start_session(start.session_id.clone(), "genshin".into());
        *pending = None;
        true
    } else {
        false
    }
}

fn task_run_failure(task_run_id: String, trace_id: String, session_id: String) -> HubMessage {
    HubMessage::TaskRunResult(protocol::TaskRunResult {
        task_run_id,
        trace_id,
        session_id,
        status: "failed".into(),
        result: serde_json::json!({}),
        steps: vec![],
        error_code: Some("launch_to_ready_failed".into()),
        error_message: Some("launch-to-ready execution failed".into()),
    })
}

async fn enqueue_task_run_terminal(outbound: &OutboundWriter, message: HubMessage) -> Result<()> {
    outbound
        .send_control(message)
        .await
        .context("task-run terminal enqueue failed")
}

async fn enqueue_task_run_cleanup_receipt(
    outbound: &OutboundWriter,
    receipt: protocol::TaskRunCleanupReceipt,
) -> Result<()> {
    enqueue_task_run_terminal(outbound, HubMessage::TaskRunCleanupReceipt(receipt))
        .await
        .context("task-run cleanup receipt enqueue failed")
}

fn dispatch_task_run_start<F>(
    exit_tx: mpsc::UnboundedSender<ConnectionTaskExit>,
    abort_handles: &mut Vec<AbortHandle>,
    future: F,
) where
    F: future::Future<Output = Result<()>> + Send + 'static,
{
    monitor_connection_task(
        ConnectionTaskName::LaunchToReadyStart,
        false,
        exit_tx,
        abort_handles,
        tokio::spawn(future),
    );
}

fn dispatch_task_run_start_event<F, Fut>(
    event: AgentEvent,
    exit_tx: mpsc::UnboundedSender<ConnectionTaskExit>,
    abort_handles: &mut Vec<AbortHandle>,
    outbound: OutboundWriter,
    execute: F,
) where
    F: FnOnce(protocol::TaskRunStart) -> Fut + Send + 'static,
    Fut: future::Future<Output = Result<()>> + Send + 'static,
{
    let AgentEvent::TaskRunStart(start) = event else {
        unreachable!("task-run start dispatcher requires TaskRunStart")
    };
    info!(task_run_id = %start.task_run_id, trace_id = %start.trace_id, "task-run start received");
    dispatch_task_run_start(exit_tx, abort_handles, async move {
        match execute(start.clone()).await {
            Ok(()) => {
                info!(task_run_id = %start.task_run_id, trace_id = %start.trace_id, "task-run start activated");
            }
            Err(_) => {
                warn!(task_run_id = %start.task_run_id, trace_id = %start.trace_id, "task-run start failed");
                if let Err(err) = enqueue_task_run_terminal(
                    &outbound,
                    task_run_failure(
                        start.task_run_id.clone(),
                        start.trace_id.clone(),
                        start.session_id.clone(),
                    ),
                )
                .await
                {
                    error!(task_run_id = %start.task_run_id, trace_id = %start.trace_id, error = %err, "task-run terminal enqueue failed");
                    return Err(err);
                }
                info!(task_run_id = %start.task_run_id, trace_id = %start.trace_id, "task-run failure result enqueued");
            }
        }
        Ok(())
    });
}

fn environment_check_failure(
    command: &protocol::EnvironmentCheckStart,
    error_code: &str,
    error_message: &str,
) -> HubMessage {
    HubMessage::EnvironmentCheckResult(protocol::EnvironmentCheckResult {
        task_run_id: command.task_run_id.clone(),
        trace_id: command.trace_id.clone(),
        session_id: command.session_id.clone(),
        status: "failed".into(),
        result: serde_json::json!({}),
        steps: vec![],
        error_code: Some(error_code.to_string()),
        error_message: Some(error_message.to_string()),
    })
}

fn environment_check_cancel_matches(
    identity: &EnvironmentCheckIdentity,
    cancel: &protocol::EnvironmentCheckCancel,
) -> bool {
    identity.task_run_id == cancel.task_run_id
        && identity.trace_id == cancel.trace_id
        && cancel
            .session_id
            .as_deref()
            .is_none_or(|session_id| identity.session_id == session_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionTaskName {
    Recv,
    Heartbeat,
    LaunchToReadyStart,
    LaunchToReadyTick,
    #[cfg(any(target_os = "windows", test))]
    Capture,
    Writer,
}

#[derive(Debug)]
struct ConnectionTaskExit {
    task: ConnectionTaskName,
    reason: String,
    critical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionRunResult {
    Stopped,
    Reconnect { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconnectPlan {
    attempt: u32,
    delay: Duration,
    last_error: String,
}

#[derive(Debug, Default, Clone)]
pub struct AgentRuntimeContext {
    pub auto_start_executable: Option<PathBuf>,
    pub config_path: PathBuf,
    pub log_path: PathBuf,
}

#[derive(Debug, Default)]
struct AgentRuntimeState {
    connection_id: uuid::Uuid,
    auto_update: bool,
    auto_start: bool,
    command_timeout_s: u64,
    launch_allowlist: Vec<String>,
    active_session: Option<ActiveSession>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionKind {
    Game,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSession {
    session_id: String,
    game_id: Option<String>,
    kind: SessionKind,
    last_seq: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum InputGateDecision {
    Accepted,
    Rejected(String),
}

#[cfg(any(target_os = "windows", test))]
fn should_start_capture(capture: &config::CaptureConfig) -> bool {
    capture.fps > 0
}

fn clamp_command_timeout_s(value: u64) -> u64 {
    value.clamp(10, 600)
}

const CANONICAL_GAME_SLUGS: [&str; 3] = ["genshin", "star-rail", "zenless"];

fn game_discovery_result_from_result(
    request_id: String,
    result: Result<Vec<mihoyo_discovery::MihoyoGameInstall>>,
) -> protocol::GameDiscoveryResult {
    match result {
        Ok(games) => protocol::GameDiscoveryResult {
            request_id,
            status: "ready".to_string(),
            error: None,
            games: canonical_game_discovery_items(&games),
        },
        Err(_) => protocol::GameDiscoveryResult {
            request_id,
            status: "failed".to_string(),
            error: Some("discovery_failed".to_string()),
            games: canonical_game_discovery_items(&[]),
        },
    }
}

async fn collect_game_process_events(
    runtime_state: &Arc<Mutex<AgentRuntimeState>>,
    proc_mgr: &Arc<Mutex<ProcessManager>>,
) -> Vec<protocol::GameProcessEvent> {
    let current_session = runtime_state.lock().await.current_game_session();
    let Some((session_id, game_id)) = current_session else {
        return vec![];
    };

    let exit_event = proc_mgr.lock().await.take_exit_event();
    let Some(exit) = exit_event else {
        return vec![];
    };

    runtime_state.lock().await.finish_session(&session_id);
    vec![protocol::GameProcessEvent {
        session_id,
        game_id,
        executable: exit.executable,
        event: exit.event,
        process_id: exit.process_id,
        exit_code: exit.exit_code,
        extra: Default::default(),
    }]
}

fn canonical_game_discovery_items(
    games: &[mihoyo_discovery::MihoyoGameInstall],
) -> Vec<protocol::GameDiscoveryItem> {
    CANONICAL_GAME_SLUGS
        .iter()
        .map(|slug| {
            let game = games.iter().find(|game| {
                game.profile_id.as_deref() == Some(*slug) && game.supported && game.exists_on_disk
            });
            protocol::GameDiscoveryItem {
                game_slug: (*slug).to_string(),
                discovered: game.is_some(),
                discovery_source: game.map(|_| "registry".to_string()),
                last_discovered_at: game
                    .and_then(|game| game.last_scanned_at)
                    .map(|time| time.to_rfc3339()),
                error: None,
            }
        })
        .collect()
}

async fn send_game_discovery_result(outbound: OutboundWriter, request_id: String) -> Result<()> {
    let result = match tokio::task::spawn_blocking(mihoyo_discovery::discover_mihoyo_games).await {
        Ok(result) => result,
        Err(err) => Err(anyhow::anyhow!("discovery task failed: {err}")),
    };
    let result = game_discovery_result_from_result(request_id, result);
    outbound
        .try_send_control(HubMessage::GameDiscoveryResult(result))
        .context("game discovery result enqueue failed")
}

async fn cleanup_local_runtime(
    input_ctrl: &Arc<Mutex<InputController>>,
    runtime_state: &Arc<Mutex<AgentRuntimeState>>,
    log_context: &str,
) -> bool {
    let emergency_stop_ok = {
        let mut ctrl = input_ctrl.lock().await;
        match ctrl.emergency_stop() {
            Ok(()) => true,
            Err(e) => {
                error!("{log_context} emergency_stop failed: {e}");
                false
            }
        }
    };
    runtime_state.lock().await.clear_session();
    emergency_stop_ok
}

fn disconnect_launch_to_ready_with_ops<O: crate::launch_to_ready::LaunchToReadyOps>(
    engine: &mut LaunchToReadyEngine,
    ops: &mut O,
    reason: &str,
) -> Option<protocol::TaskRunCleanupReceipt> {
    if engine.disconnect(ops).is_err() {
        warn!("launch-to-ready cleanup failed during {reason}");
    }
    engine.take_cleanup_receipt()
}

async fn disconnect_launch_to_ready(
    engine: &Arc<Mutex<LaunchToReadyEngine>>,
    process: &Arc<Mutex<ProcessManager>>,
    input: &Arc<Mutex<InputController>>,
    owned: &Arc<Mutex<Option<TargetBinding>>>,
    capture: &ScreenCapture,
    outbound: &OutboundWriter,
    reason: &str,
) {
    let receipt = {
        let mut engine = engine.lock().await;
        let mut process = process.lock().await;
        let mut input = input.lock().await;
        let mut owned = owned.lock().await;
        let mut ops = ProductionLaunchToReadyOps {
            process: &mut process,
            input: &mut input,
            capture,
            owned: &mut owned,
        };
        disconnect_launch_to_ready_with_ops(&mut engine, &mut ops, reason)
    };
    if let Some(receipt) = receipt {
        if let Err(err) = enqueue_task_run_cleanup_receipt(outbound, receipt).await {
            warn!("launch-to-ready cleanup receipt enqueue failed during {reason}: {err}");
        }
    }
}

struct LaunchToReadyResources<'a> {
    engine: &'a Arc<Mutex<LaunchToReadyEngine>>,
    process: &'a Arc<Mutex<ProcessManager>>,
    owned: &'a Arc<Mutex<Option<TargetBinding>>>,
    capture: &'a ScreenCapture,
    outbound: &'a OutboundWriter,
}

async fn fail_connection_after_control_enqueue_error_with_cleanup<Cleanup>(
    cancel_tx: &watch::Sender<bool>,
    abort_handles: &[AbortHandle],
    input_ctrl: &Arc<Mutex<InputController>>,
    runtime_state: &Arc<Mutex<AgentRuntimeState>>,
    operation: &str,
    err: anyhow::Error,
    launch_cleanup: Cleanup,
) -> ConnectionRunResult
where
    Cleanup: future::Future<Output = ()>,
{
    let reason = format!("{operation} control enqueue failed: {err}");
    warn!("{reason}");
    cancel_connection(cancel_tx, &reason);
    abort_connection_tasks(abort_handles);
    launch_cleanup.await;
    cleanup_local_runtime(input_ctrl, runtime_state, operation).await;
    ConnectionRunResult::Reconnect { reason }
}

async fn fail_connection_after_control_enqueue_error(
    cancel_tx: &watch::Sender<bool>,
    abort_handles: &[AbortHandle],
    input_ctrl: &Arc<Mutex<InputController>>,
    runtime_state: &Arc<Mutex<AgentRuntimeState>>,
    launch: &LaunchToReadyResources<'_>,
    operation: &str,
    err: anyhow::Error,
) -> ConnectionRunResult {
    fail_connection_after_control_enqueue_error_with_cleanup(
        cancel_tx,
        abort_handles,
        input_ctrl,
        runtime_state,
        operation,
        err,
        disconnect_launch_to_ready(
            launch.engine,
            launch.process,
            input_ctrl,
            launch.owned,
            launch.capture,
            launch.outbound,
            operation,
        ),
    )
    .await
}

#[cfg(any(target_os = "windows", test))]
fn process_name_for_log(executable: &str) -> String {
    executable
        .rsplit(['\\', '/'])
        .find(|part| !part.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn monitor_connection_task(
    task: ConnectionTaskName,
    critical: bool,
    exit_tx: mpsc::UnboundedSender<ConnectionTaskExit>,
    abort_handles: &mut Vec<AbortHandle>,
    handle: JoinHandle<Result<()>>,
) {
    abort_handles.push(handle.abort_handle());
    tokio::spawn(async move {
        let exit = match handle.await {
            Ok(Ok(())) if critical => ConnectionTaskExit {
                task,
                reason: "critical task completed unexpectedly".to_string(),
                critical,
            },
            Ok(Ok(())) => return,
            Ok(Err(err)) => ConnectionTaskExit {
                task,
                reason: err.to_string(),
                critical,
            },
            Err(err) if err.is_cancelled() => return,
            Err(err) => ConnectionTaskExit {
                task,
                reason: err.to_string(),
                critical,
            },
        };
        let _ = exit_tx.send(exit);
    });
}

fn spawn_connection_task<F>(
    task: ConnectionTaskName,
    critical: bool,
    exit_tx: mpsc::UnboundedSender<ConnectionTaskExit>,
    abort_handles: &mut Vec<AbortHandle>,
    future: F,
) where
    F: future::Future<Output = Result<()>> + Send + 'static,
{
    monitor_connection_task(task, critical, exit_tx, abort_handles, tokio::spawn(future));
}

fn cancel_connection(cancel_tx: &watch::Sender<bool>, reason: &str) {
    warn!("connection lifecycle cancelling: {reason}");
    let _ = cancel_tx.send(true);
}

fn abort_connection_tasks(abort_handles: &[AbortHandle]) {
    for handle in abort_handles {
        handle.abort();
    }
}

async fn cancel_active_environment_check(active: &ActiveEnvironmentCheck, reason: &str) {
    let active_check = {
        let active = active.lock().await;
        active
            .as_ref()
            .map(|(identity, flag)| (identity.task_run_id.clone(), flag.clone()))
    };
    if let Some((task_run_id, flag)) = active_check {
        warn!("environment check cancel requested: task_run_id={task_run_id}, reason={reason}");
        flag.store(true, Ordering::Relaxed);
    }
}

fn handle_connection_task_exit(cancel_tx: &watch::Sender<bool>, exit: &ConnectionTaskExit) -> bool {
    warn!(
        "connection task exited: task={:?}, critical={}, reason={}",
        exit.task, exit.critical, exit.reason
    );
    if exit.critical || exit.task == ConnectionTaskName::LaunchToReadyStart {
        cancel_connection(cancel_tx, &format!("{:?}: {}", exit.task, exit.reason));
        return true;
    }
    false
}

fn reconnect_backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(5);
    let multiplier = 1_u64 << shift;
    let delay_ms = RECONNECT_BASE_DELAY_MS
        .saturating_mul(multiplier)
        .min(RECONNECT_MAX_DELAY_MS);
    Duration::from_millis(delay_ms)
}

fn reconnect_plan(attempt: u32, last_error: impl Into<String>) -> ReconnectPlan {
    ReconnectPlan {
        attempt,
        delay: reconnect_backoff_delay(attempt),
        last_error: last_error.into(),
    }
}

fn publish_runtime_starting(runtime_status_tx: Option<&std_mpsc::Sender<RuntimeStatusUpdate>>) {
    if let Some(tx) = runtime_status_tx {
        let _ = tx.send(RuntimeStatusUpdate::Starting);
    }
}

fn prepare_reconnect(
    attempt: u32,
    last_error: impl Into<String>,
    runtime_status_tx: Option<&std_mpsc::Sender<RuntimeStatusUpdate>>,
) -> ReconnectPlan {
    publish_runtime_starting(runtime_status_tx);
    reconnect_plan(attempt, last_error)
}

#[cfg(test)]
fn reconnect_plan_for_result(attempt: u32, result: &ConnectionRunResult) -> Option<ReconnectPlan> {
    match result {
        ConnectionRunResult::Stopped => None,
        ConnectionRunResult::Reconnect { reason } => Some(reconnect_plan(attempt, reason.clone())),
    }
}

fn runtime_stop_requested(shutdown: &Option<watch::Receiver<bool>>) -> bool {
    shutdown.as_ref().is_some_and(|rx| *rx.borrow())
}

async fn wait_for_reconnect_backoff(
    delay: Duration,
    shutdown: &mut Option<watch::Receiver<bool>>,
) -> bool {
    if runtime_stop_requested(shutdown) {
        return false;
    }

    let shutdown_fut = async {
        if let Some(rx) = shutdown.as_mut() {
            let _ = rx.changed().await;
        } else {
            future::pending::<()>().await;
        }
    };

    tokio::select! {
        _ = tokio::time::sleep(delay) => true,
        _ = shutdown_fut => false,
    }
}

fn absolute_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}
fn normalize_launch_allowlist(allowlist: &[String]) -> Vec<String> {
    const FORBIDDEN_LAUNCH_EXECUTABLES: [&str; 2] = ["calc.exe", "notepad.exe"];
    let forbidden: HashSet<&str> = FORBIDDEN_LAUNCH_EXECUTABLES.iter().copied().collect();

    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for entry in allowlist {
        let Some(name) = normalize_executable_name(entry) else {
            continue;
        };

        if forbidden.contains(name.as_str()) || seen.contains(&name) {
            continue;
        }

        seen.insert(name.clone());
        normalized.push(name);
    }

    normalized
}

#[cfg(any(target_os = "windows", test))]
fn build_auto_start_command_line(context: &AgentRuntimeContext) -> Result<String> {
    let executable = context
        .auto_start_executable
        .as_ref()
        .context("auto_start requires the fairypam-agent executable")?;
    let install_dir = executable
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    Ok(format!(
        "cmd.exe /c cd /d \"{}\" && \"{}\" {} --config \"{}\" --log-file \"{}\"",
        install_dir.display(),
        executable.display(),
        "--run",
        context.config_path.display(),
        context.log_path.display()
    ))
}

fn persist_runtime_config(config_path: &Path, runtime: config::RuntimeConfig) -> Result<()> {
    let mut app_config = config::load_config(config_path)?;
    app_config.runtime = runtime;
    config::save_config(config_path, &app_config)
}

pub fn build_runtime_context(config_path: &Path, log_path: &Path) -> Result<AgentRuntimeContext> {
    let current_dir = std::env::current_dir().context("failed to get current directory")?;
    Ok(AgentRuntimeContext {
        auto_start_executable: Some(
            std::env::current_exe().context("failed to locate current executable")?,
        ),
        config_path: absolute_path(&current_dir, config_path),
        log_path: absolute_path(&current_dir, log_path),
    })
}

impl AgentRuntimeState {
    fn from_welcome(welcome: &protocol::HubWelcome) -> Self {
        let mut state = Self {
            connection_id: welcome.connection_id,
            ..Self::default()
        };
        state.apply_hub_config(&welcome.config);
        state
    }

    fn apply_hub_config(&mut self, config: &protocol::HubAgentConfig) {
        self.auto_update = config.auto_update;
        self.auto_start = config.auto_start;
        self.command_timeout_s = clamp_command_timeout_s(config.command_timeout_s);
        self.launch_allowlist = normalize_launch_allowlist(&config.launch_allowlist);
    }

    fn validate_game_launch(&self, launch: &protocol::GameLaunch) -> Result<()> {
        if launch.connection_id != self.connection_id {
            anyhow::bail!("game launch rejected: stale connection");
        }
        if self.active_session.is_some() {
            anyhow::bail!("game launch rejected: active session exists");
        }
        Ok(())
    }

    fn validate_resolved_launch(&self, executable: &str) -> Result<()> {
        if is_launch_allowed(executable, &self.launch_allowlist) {
            Ok(())
        } else if self.launch_allowlist.is_empty() {
            anyhow::bail!("launch rejected: empty launch allowlist");
        } else {
            anyhow::bail!("launch rejected: executable not in allowlist")
        }
    }

    fn apply_settings_update(&mut self, update: &protocol::SettingsUpdate) {
        if let Some(auto_update) = update.auto_update {
            self.auto_update = auto_update;
        }

        if let Some(auto_start) = update.auto_start {
            self.auto_start = auto_start;
        }

        if let Some(command_timeout_s) = update.command_timeout_s {
            self.command_timeout_s = clamp_command_timeout_s(command_timeout_s);
        }

        if let Some(allowlist) = &update.launch_allowlist {
            self.launch_allowlist = normalize_launch_allowlist(allowlist);
        }
    }

    fn runtime_config(&self) -> config::RuntimeConfig {
        config::RuntimeConfig {
            auto_update: self.auto_update,
            auto_start: self.auto_start,
            command_timeout_s: self.command_timeout_s,
            launch_allowlist: normalize_launch_allowlist(&self.launch_allowlist),
        }
    }

    fn effective_command_timeout(&self) -> Duration {
        Duration::from_secs(clamp_command_timeout_s(self.command_timeout_s))
    }

    fn start_session(&mut self, session_id: String, game_id: String) {
        self.active_session = Some(ActiveSession {
            session_id,
            game_id: Some(game_id),
            kind: SessionKind::Game,
            last_seq: None,
        });
    }

    fn start_manual_session(&mut self, session_id: String) {
        self.active_session = Some(ActiveSession {
            session_id,
            game_id: None,
            kind: SessionKind::Manual,
            last_seq: None,
        });
    }

    fn current_game_session(&self) -> Option<(String, String)> {
        let session = self.active_session.as_ref()?;
        if session.kind != SessionKind::Game {
            return None;
        }
        Some((session.session_id.clone(), session.game_id.clone()?))
    }

    fn finish_session(&mut self, session_id: &str) {
        if self
            .active_session
            .as_ref()
            .is_some_and(|session| session.session_id == session_id)
        {
            self.active_session = None;
        }
    }

    fn clear_session(&mut self) {
        self.active_session = None;
    }

    fn accept_input_frame(&mut self, session_id: &str, seq: u64) -> InputGateDecision {
        let is_manual = session_id.starts_with("manual-");
        if self.active_session.is_none() {
            if is_manual {
                self.start_manual_session(session_id.to_string());
            } else {
                return InputGateDecision::Rejected("no_active_session".into());
            }
        }

        let Some(session) = self.active_session.as_mut() else {
            return InputGateDecision::Rejected("no_active_session".into());
        };

        if session.kind == SessionKind::Game && is_manual {
            return InputGateDecision::Rejected("manual_session_rejected".into());
        }

        if session.kind == SessionKind::Manual && !is_manual {
            return InputGateDecision::Rejected("manual_session_rejected".into());
        }

        if session.session_id != session_id {
            return InputGateDecision::Rejected("session_mismatch".into());
        }

        if session.last_seq.is_some_and(|last_seq| seq <= last_seq) {
            return InputGateDecision::Rejected("non_monotonic_seq".into());
        }

        session.last_seq = Some(seq);
        InputGateDecision::Accepted
    }
}

#[cfg(target_os = "windows")]
fn sync_auto_start_setting(enabled: bool, context: &AgentRuntimeContext) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const VALUE_NAME: &str = "FairyPam Agent";
    let command_line = enabled
        .then(|| build_auto_start_command_line(context))
        .transpose()?;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    unsafe {
        let subkey = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
        let value_name = wide(VALUE_NAME);
        let mut key = windows::Win32::System::Registry::HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        );
        if status != ERROR_SUCCESS {
            anyhow::bail!("failed to open HKCU Run key: {:?}", status);
        }

        let result = if enabled {
            let command_line = command_line.as_deref().expect("checked above");
            let mut data = Vec::with_capacity((command_line.encode_utf16().count() + 1) * 2);
            for unit in command_line.encode_utf16().chain(Some(0)) {
                data.extend_from_slice(&unit.to_le_bytes());
            }
            RegSetValueExW(key, PCWSTR(value_name.as_ptr()), 0, REG_SZ, Some(&data))
        } else {
            RegDeleteValueW(key, PCWSTR(value_name.as_ptr()))
        };

        let close_status = RegCloseKey(key);
        if close_status != ERROR_SUCCESS {
            warn!("failed to close HKCU Run key cleanly: {:?}", close_status);
        }

        if result != ERROR_SUCCESS && (enabled || result != ERROR_FILE_NOT_FOUND) {
            anyhow::bail!("auto_start registry update failed: {:?}", result);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn sync_auto_start_setting(enabled: bool, context: &AgentRuntimeContext) -> Result<()> {
    let _ = enabled;
    let _ = context;
    Ok(())
}

pub async fn run_agent(
    app_config: config::AppConfig,
    runtime_context: AgentRuntimeContext,
    mut shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    runtime_status_tx: Option<std_mpsc::Sender<RuntimeStatusUpdate>>,
    safe_smoke: bool,
) -> Result<()> {
    let log_path = runtime_context.log_path.clone();
    append_log_line(
        &log_path,
        &format!("FairyPam Agent starting: {}", app_config.agent.name),
    )?;
    append_log_line(&log_path, &format!("Hub URL: {}", app_config.hub.ws_url))?;

    info!("FairyPam Agent starting: {}", app_config.agent.name);
    info!("Hub URL: {}", app_config.hub.ws_url);

    let mut reconnect_attempt = 0_u32;
    publish_runtime_starting(runtime_status_tx.as_ref());
    loop {
        if runtime_stop_requested(&shutdown) {
            warn!("runtime stop requested before connection attempt");
            return Ok(());
        }
        let connection_result = if safe_smoke {
            run_safe_smoke_connection(&app_config, &mut shutdown).await
        } else {
            run_agent_connection(
                app_config.clone(),
                runtime_context.clone(),
                &mut shutdown,
                runtime_status_tx.as_ref(),
            )
            .await
        };

        let reconnect_reason = match connection_result {
            Ok(ConnectionRunResult::Stopped) => return Ok(()),
            Ok(ConnectionRunResult::Reconnect { reason }) => reason,
            Err(err) => err.to_string(),
        };

        reconnect_attempt = reconnect_attempt.saturating_add(1);
        let plan = prepare_reconnect(
            reconnect_attempt,
            reconnect_reason,
            runtime_status_tx.as_ref(),
        );
        warn!(
            "agent connection will reconnect: attempt={}, backoff_ms={}, last_error={}",
            plan.attempt,
            plan.delay.as_millis(),
            plan.last_error
        );

        if !wait_for_reconnect_backoff(plan.delay, &mut shutdown).await {
            warn!("runtime stop requested during reconnect backoff");
            return Ok(());
        }
    }
}

fn connection_system_info() -> SystemInfo {
    let sys_metrics = SystemMonitor::new().collect().unwrap_or_default();

    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);

    SystemInfo {
        hostname: system::hostname(),
        os_name: std::env::consts::OS.to_string(),
        os_version: String::new(),
        os_build: String::new(),
        os_arch: std::env::consts::ARCH.to_string(),
        net_version: String::new(),
        timezone: String::new(),
        locale: String::new(),
        last_boot_time: String::new(),
        cpu_name: system::cpu_name(),
        cpu_cores,
        cpu_threads: cpu_cores,
        memory_total_gb: sys_metrics.memory_total_gb,
        disks: vec![],
        network_adapters: vec![],
        displays: vec![],
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

async fn run_safe_smoke_connection(
    app_config: &config::AppConfig,
    shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<ConnectionRunResult> {
    let connect_fut = WsClient::connect(
        &app_config.hub.ws_url,
        &app_config.hub.api_key,
        &app_config.agent.name,
        connection_system_info(),
    );
    let shutdown_fut = async {
        if let Some(rx) = shutdown.as_mut() {
            let _ = rx.changed().await;
        } else {
            future::pending::<()>().await;
        }
    };
    let (ws, _) = tokio::select! {
        _ = shutdown_fut => return Ok(ConnectionRunResult::Stopped),
        result = connect_fut => result?,
    };
    let (mut writer, mut reader) = ws.into_split();
    let heartbeat_sys = SystemMonitor::new();
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = async {
                if let Some(rx) = shutdown.as_mut() {
                    let _ = rx.changed().await;
                } else {
                    future::pending::<()>().await;
                }
            } => return Ok(ConnectionRunResult::Stopped),
            _ = interval.tick() => {
                let metrics = heartbeat_sys.collect().unwrap_or_default();
                writer.send_json(&HubMessage::Heartbeat(protocol::Heartbeat {
                    cpu_usage: metrics.cpu_usage,
                    memory_available_gb: metrics.memory_available_gb,
                    active_processes: metrics.active_processes,
                    game_process_events: vec![],
                })).await?;
            }
            message = reader.recv_json() => match message? {
                AgentMessage::HubWelcome(_) | AgentMessage::HeartbeatAck(_) => {}
                AgentMessage::Error(error) => {
                    error!("safe smoke Hub error: {} - {}", error.code, error.message);
                }
                _ => warn!("safe smoke ignored unsupported Hub message"),
            },
        }
    }
}

async fn run_agent_connection(
    app_config: config::AppConfig,
    runtime_context: AgentRuntimeContext,
    shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>,
    runtime_status_tx: Option<&std_mpsc::Sender<RuntimeStatusUpdate>>,
) -> Result<ConnectionRunResult> {
    let connect_fut = WsClient::connect(
        &app_config.hub.ws_url,
        &app_config.hub.api_key,
        &app_config.agent.name,
        connection_system_info(),
    );
    let shutdown_fut = async {
        if let Some(rx) = shutdown.as_mut() {
            let _ = rx.changed().await;
        } else {
            future::pending::<()>().await;
        }
    };
    let (ws, welcome) = tokio::select! {
        _ = shutdown_fut => {
            warn!("runtime stop requested during connection attempt");
            return Ok(ConnectionRunResult::Stopped);
        }
        result = connect_fut => result?,
    };

    let runtime_state = Arc::new(Mutex::new(AgentRuntimeState::from_welcome(&welcome)));
    {
        let auto_start = runtime_state.lock().await.auto_start;
        if let Err(e) = sync_auto_start_setting(auto_start, &runtime_context) {
            error!("auto_start sync failed: {e}");
        }
    }
    {
        let runtime_config = runtime_state.lock().await.runtime_config();
        if let Err(e) = persist_runtime_config(&runtime_context.config_path, runtime_config) {
            error!("runtime config persist failed: {e}");
        }
    }

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(32);
    let (ws_writer, mut ws_reader) = ws.into_split();

    let input_ctrl = Arc::new(Mutex::new(InputController::new()));
    let proc_mgr = Arc::new(Mutex::new(ProcessManager::with_profile_overrides(
        &app_config.game_profiles,
    )?));
    let launch_engine = Arc::new(Mutex::new(LaunchToReadyEngine::new()));
    let launch_owned = Arc::new(Mutex::new(Option::<TargetBinding>::None));
    let launch_capture = Arc::new(ScreenCapture::new(&app_config.capture)?);
    let pending_task_run_start: PendingTaskRunStartSlot = Arc::new(Mutex::new(None));
    let active_environment_check: ActiveEnvironmentCheck = Arc::new(Mutex::new(None));
    let (outbound, writer_task) = OutboundWriter::spawn(ws_writer);
    let (connection_cancel_tx, _) = watch::channel(false);
    let (task_exit_tx, mut task_exit_rx) = mpsc::unbounded_channel::<ConnectionTaskExit>();
    let mut connection_task_aborts = Vec::new();
    monitor_connection_task(
        ConnectionTaskName::Writer,
        true,
        task_exit_tx.clone(),
        &mut connection_task_aborts,
        writer_task,
    );

    let recv_tx = tx.clone();
    let mut recv_cancel = connection_cancel_tx.subscribe();
    spawn_connection_task(
        ConnectionTaskName::Recv,
        true,
        task_exit_tx.clone(),
        &mut connection_task_aborts,
        async move {
            loop {
                let msg = tokio::select! {
                    _ = recv_cancel.changed() => return Ok(()),
                    result = ws_reader.recv_json() => result.context("message receive failed")?,
                };
                match msg {
                    AgentMessage::InputFrame(frame) => {
                        recv_tx
                            .send(AgentEvent::InputFrame(frame))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::SettingsUpdate(update) => {
                        recv_tx
                            .send(AgentEvent::SettingsUpdate(update))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::GameDiscoveryRequest(request) => {
                        recv_tx
                            .send(AgentEvent::GameDiscoveryRequest(request))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::GameLaunch(launch) => {
                        recv_tx
                            .send(AgentEvent::GameLaunch(launch))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::GameKill(kill) => {
                        recv_tx
                            .send(AgentEvent::GameKill(kill))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::EnvironmentCheckStart(command) => {
                        recv_tx
                            .send(AgentEvent::EnvironmentCheckStart(command))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::EnvironmentCheckCancel(cancel) => {
                        recv_tx
                            .send(AgentEvent::EnvironmentCheckCancel(cancel))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::TaskRunClick(click) => {
                        recv_tx
                            .send(AgentEvent::TaskRunClick(click))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::TaskRunStart(start) => {
                        recv_tx
                            .send(AgentEvent::TaskRunStart(start))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::TaskRunCancel(cancel) => {
                        recv_tx
                            .send(AgentEvent::TaskRunCancel(cancel))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::TaskRunTerminal(terminal) => {
                        recv_tx
                            .send(AgentEvent::TaskRunTerminal(terminal))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::PauseAI(pause) => {
                        info!("pause_ai received: session={}", pause.session_id);
                    }
                    AgentMessage::ResumeAI(resume) => {
                        info!("resume_ai received: session={}", resume.session_id);
                    }
                    AgentMessage::InputFrameResume(resume) => {
                        recv_tx
                            .send(AgentEvent::InputFrameResume(resume))
                            .await
                            .context("agent event channel closed")?;
                    }
                    AgentMessage::HubWelcome(_) => {
                        info!("duplicate hub_welcome ignored");
                    }
                    AgentMessage::HeartbeatAck(_) => {}
                    AgentMessage::Error(e) => {
                        error!("Hub error: {} - {}", e.code, e.message);
                    }
                }
            }
        },
    );

    let heartbeat_outbound = outbound.clone();
    let heartbeat_sys = SystemMonitor::new();
    let heartbeat_runtime_state = runtime_state.clone();
    let heartbeat_proc_mgr = proc_mgr.clone();
    let mut heartbeat_cancel = connection_cancel_tx.subscribe();
    spawn_connection_task(
        ConnectionTaskName::Heartbeat,
        true,
        task_exit_tx.clone(),
        &mut connection_task_aborts,
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = heartbeat_cancel.changed() => return Ok(()),
                    _ = interval.tick() => {}
                }
                let metrics = heartbeat_sys.collect().unwrap_or_default();
                let game_process_events =
                    collect_game_process_events(&heartbeat_runtime_state, &heartbeat_proc_mgr)
                        .await;
                let heartbeat = HubMessage::Heartbeat(protocol::Heartbeat {
                    cpu_usage: metrics.cpu_usage,
                    memory_available_gb: metrics.memory_available_gb,
                    active_processes: metrics.active_processes,
                    game_process_events,
                });
                if let Err(e) = heartbeat_outbound.try_send_control(heartbeat) {
                    anyhow::bail!("heartbeat enqueue failed: {e}");
                }
            }
        },
    );

    let tick_outbound = outbound.clone();
    let tick_engine = launch_engine.clone();
    let tick_process = proc_mgr.clone();
    let tick_input = input_ctrl.clone();
    let tick_owned = launch_owned.clone();
    let tick_capture = launch_capture.clone();
    let tick_state = runtime_state.clone();
    let mut tick_cancel = connection_cancel_tx.subscribe();
    let tick_ms = (1000 / app_config.capture.fps.max(1)).max(1) as u64;
    spawn_connection_task(
        ConnectionTaskName::LaunchToReadyTick,
        true,
        task_exit_tx.clone(),
        &mut connection_task_aborts,
        async move {
            let mut interval = tokio::time::interval(Duration::from_millis(tick_ms));
            loop {
                tokio::select! { _ = tick_cancel.changed() => return Ok(()), _ = interval.tick() => {} }
                let tick = {
                    let mut engine = tick_engine.lock().await;
                    if let Some((task_run_id, trace_id, session_id)) = engine.active_identity() {
                        let mut process = tick_process.lock().await;
                        let mut input = tick_input.lock().await;
                        let mut owned = tick_owned.lock().await;
                        let mut ops = ProductionLaunchToReadyOps {
                            process: &mut process,
                            input: &mut input,
                            capture: &tick_capture,
                            owned: &mut owned,
                        };
                        let result = match engine.tick(std::time::Instant::now(), &mut ops) {
                            Ok(result) => Ok(result),
                            Err(_) => {
                                let _ = engine.disconnect(&mut ops);
                                Err(())
                            }
                        };
                        let receipt = engine.take_cleanup_receipt();
                        Some((task_run_id, trace_id, session_id, result, receipt))
                    } else {
                        None
                    }
                };
                let Some((task_run_id, trace_id, session_id, result, receipt)) = tick else {
                    continue;
                };
                if let Some(receipt) = receipt {
                    enqueue_task_run_cleanup_receipt(&tick_outbound, receipt).await?;
                }
                match result {
                    Ok(Some(frame)) => {
                        let first_frame = frame.frame_seq == 0;
                        let task_run_id = frame.task_run_id.clone();
                        let trace_id = frame.trace_id.clone();
                        tick_outbound.try_send_control(HubMessage::TaskRunFrame(frame))?;
                        if first_frame {
                            info!(task_run_id, trace_id, "task-run first frame enqueued");
                        }
                    }
                    Ok(None) => {
                        tick_state.lock().await.finish_session(&session_id);
                        warn!(task_run_id, trace_id, "task-run deadline reached");
                        enqueue_task_run_terminal(
                            &tick_outbound,
                            task_run_failure(task_run_id, trace_id, session_id),
                        )
                        .await?;
                    }
                    Err(()) => {
                        tick_state.lock().await.finish_session(&session_id);
                        warn!(task_run_id, trace_id, "task-run tick failed");
                        enqueue_task_run_terminal(
                            &tick_outbound,
                            task_run_failure(task_run_id, trace_id, session_id),
                        )
                        .await?;
                    }
                }
            }
        },
    );

    #[cfg(target_os = "windows")]
    {
        let capture_config = app_config.capture.clone();
        if should_start_capture(&capture_config) {
            let capture_outbound = outbound.clone();
            let capture_proc_mgr = proc_mgr.clone();
            let mut capture_cancel = connection_cancel_tx.subscribe();
            spawn_connection_task(
                ConnectionTaskName::Capture,
                false,
                task_exit_tx.clone(),
                &mut connection_task_aborts,
                async move {
                    let capture = match ScreenCapture::new(&capture_config) {
                        Ok(capture) => capture,
                        Err(e) => {
                            anyhow::bail!("screen capture init failed: {e}");
                        }
                    };

                    let frame_interval_ms = (1000 / capture_config.fps.max(1)).max(1) as u64;
                    let mut interval =
                        tokio::time::interval(std::time::Duration::from_millis(frame_interval_ms));
                    let mut last_target: Option<(u32, String)> = None;
                    let mut sent_frames: u64 = 0;
                    loop {
                        tokio::select! {
                            _ = capture_cancel.changed() => return Ok(()),
                            _ = interval.tick() => {}
                        }
                        let captured = {
                            let mut pm = capture_proc_mgr.lock().await;
                            target_operation::capture_active_target(&mut pm, &capture)
                        };
                        let (binding, frame) = match captured {
                            Ok(value) => value,
                            Err(e) => {
                                if last_target.take().is_some() {
                                    info!("capture target cleared");
                                }
                                warn!("target_capture_miss err={e}");
                                continue;
                            }
                        };
                        let pid = binding.pid;
                        let process_name = process_name_for_log(&binding.resolved_executable);
                        if last_target.as_ref() != Some(&(pid, process_name.clone())) {
                            info!(
                                "capture target active: pid={} process_name={}",
                                pid, process_name
                            );
                            last_target = Some((pid, process_name.clone()));
                            sent_frames = 0;
                        }
                        let frame = frame.jpeg;

                        let frame_size = frame.len();
                        if let Err(e) = capture_outbound.send_video(frame) {
                            anyhow::bail!("video frame queue failed: {e}");
                        }
                        sent_frames += 1;
                        if sent_frames == 1 || sent_frames.is_multiple_of(90) {
                            info!(
                                "video frame queued: pid={} process_name={} bytes={} count={} dropped={}",
                                pid,
                                process_name,
                                frame_size,
                                sent_frames,
                                capture_outbound.dropped_video_frames()
                            );
                        }
                    }
                },
            );
        } else {
            info!("screen capture disabled because capture.fps=0");
        }
    }

    info!("Agent ready; waiting for commands");
    if let Some(tx) = runtime_status_tx {
        let _ = tx.send(RuntimeStatusUpdate::Running);
    }

    let launch_resources = LaunchToReadyResources {
        engine: &launch_engine,
        process: &proc_mgr,
        owned: &launch_owned,
        capture: launch_capture.as_ref(),
        outbound: &outbound,
    };

    loop {
        let shutdown_fut = async {
            if let Some(rx) = shutdown.as_mut() {
                let _ = rx.changed().await;
            } else {
                future::pending::<()>().await;
            }
        };

        tokio::select! {
            _ = shutdown_fut => {
                warn!("runtime stop requested");
                cancel_connection(&connection_cancel_tx, "runtime stop requested");
                cancel_active_environment_check(&active_environment_check, "runtime stop requested").await;
                abort_connection_tasks(&connection_task_aborts);
                disconnect_launch_to_ready(&launch_engine, &proc_mgr, &input_ctrl, &launch_owned, &launch_capture, &outbound, "runtime stop").await;
                {
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) = ctrl.emergency_stop() {
                        error!("runtime stop emergency_stop failed: {e}");
                    }
                }
                runtime_state.lock().await.clear_session();
                clear_pending_task_run_start_on_disconnect(&pending_task_run_start).await;
                return Ok(ConnectionRunResult::Stopped);
            }
            maybe_exit = task_exit_rx.recv() => match maybe_exit {
                Some(exit) => {
                    let reconnect_reason = format!("{:?}: {}", exit.task, exit.reason);
                    if handle_connection_task_exit(&connection_cancel_tx, &exit) {
                        cancel_active_environment_check(&active_environment_check, &reconnect_reason).await;
                        abort_connection_tasks(&connection_task_aborts);
                        disconnect_launch_to_ready(&launch_engine, &proc_mgr, &input_ctrl, &launch_owned, &launch_capture, &outbound, "critical task exit").await;
                        {
                            let mut ctrl = input_ctrl.lock().await;
                            if let Err(e) = ctrl.emergency_stop() {
                                error!("task exit emergency_stop failed: {e}");
                            }
                        }
                        runtime_state.lock().await.clear_session();
                        clear_pending_task_run_start_on_disconnect(&pending_task_run_start).await;
                        return Ok(ConnectionRunResult::Reconnect {
                            reason: reconnect_reason,
                        });
                    }
                }
                None => {
                    warn!("connection task exit channel closed");
                    cancel_connection(&connection_cancel_tx, "connection task exit channel closed");
                    cancel_active_environment_check(
                        &active_environment_check,
                        "connection task exit channel closed",
                    )
                    .await;
                    abort_connection_tasks(&connection_task_aborts);
                    disconnect_launch_to_ready(&launch_engine, &proc_mgr, &input_ctrl, &launch_owned, &launch_capture, &outbound, "task exit channel close").await;
                    {
                        let mut ctrl = input_ctrl.lock().await;
                        if let Err(e) = ctrl.emergency_stop() {
                            error!("task exit channel emergency_stop failed: {e}");
                        }
                    }
                    runtime_state.lock().await.clear_session();
                    clear_pending_task_run_start_on_disconnect(&pending_task_run_start).await;
                    return Ok(ConnectionRunResult::Reconnect {
                        reason: "connection task exit channel closed".to_string(),
                    });
                }
            },
            maybe_event = rx.recv() => match maybe_event {
                Some(event) => match event {
            AgentEvent::InputFrame(frame) => {
                let session_id = frame.session_id.clone();
                let seq = frame.seq;

                {
                    let mut state = runtime_state.lock().await;
                    match state.accept_input_frame(&session_id, seq) {
                        InputGateDecision::Accepted => {}
                        InputGateDecision::Rejected(reason) => {
                            warn!(
                                "input_frame rejected: reason={}, seq={}, has_active_session={}",
                                reason,
                                seq,
                                state.active_session.is_some()
                            );
                            continue;
                        }
                    }
                }

                #[cfg(target_os = "windows")]
                {
                    let mut pm = proc_mgr.lock().await;
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) =
                        target_operation::send_input_to_active_target(&mut pm, &mut ctrl, &frame)
                    {
                        warn!("input_frame rejected before injection: {e}");
                        continue;
                    }
                }

                #[cfg(not(target_os = "windows"))]
                {
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) = ctrl.apply_frame(&frame) {
                        error!("input injection failed: {e}");
                        continue;
                    }
                }

                info!(
                    "input_frame accepted; sending InputFrameAck: session_id={}, seq={}",
                    session_id, seq
                );

                let ack = InputFrameAck { session_id, seq };
                if let Err(e) = outbound.try_send_control(HubMessage::InputFrameAck(ack)) {
                    return Ok(fail_connection_after_control_enqueue_error(
                        &connection_cancel_tx,
                        &connection_task_aborts,
                        &input_ctrl,
                        &runtime_state,
                        &launch_resources,
                        "input_frame_ack",
                        e,
                    )
                    .await);
                }
            }
            AgentEvent::InputFrameResume(resume) => {
                info!("input_frame_resume received: seq={}", resume.seq);
                let frame = protocol::InputFrame {
                    session_id: resume.session_id,
                    game_id: String::new(),
                    seq: resume.seq,
                    keyboard: resume.keyboard,
                    mouse: resume.mouse,
                    gamepad: None,
                };
                let session_id = frame.session_id.clone();
                let seq = frame.seq;

                {
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) = ctrl.emergency_stop() {
                        error!("input_frame_resume emergency_stop failed: {e}");
                        continue;
                    }
                }

                {
                    let mut state = runtime_state.lock().await;
                    match state.accept_input_frame(&session_id, seq) {
                        InputGateDecision::Accepted => {}
                        InputGateDecision::Rejected(reason) => {
                            warn!(
                                "input_frame_resume rejected: reason={}, seq={}, has_active_session={}",
                                reason,
                                seq,
                                state.active_session.is_some()
                            );
                            continue;
                        }
                    }
                }

                #[cfg(target_os = "windows")]
                {
                    let mut pm = proc_mgr.lock().await;
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) =
                        target_operation::send_input_to_active_target(&mut pm, &mut ctrl, &frame)
                    {
                        warn!("input_frame_resume rejected before injection: {e}");
                        continue;
                    }
                }

                #[cfg(not(target_os = "windows"))]
                {
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) = ctrl.apply_frame(&frame) {
                        error!("input_frame_resume injection failed: {e}");
                        continue;
                    }
                }

                info!(
                    "input_frame_resume accepted; sending InputFrameAck: session_id={}, seq={}",
                    session_id, seq
                );

                let ack = InputFrameAck { session_id, seq };
                if let Err(e) = outbound.try_send_control(HubMessage::InputFrameAck(ack)) {
                    return Ok(fail_connection_after_control_enqueue_error(
                        &connection_cancel_tx,
                        &connection_task_aborts,
                        &input_ctrl,
                        &runtime_state,
                        &launch_resources,
                        "input_frame_resume_ack",
                        e,
                    )
                    .await);
                }
            }
            AgentEvent::GameLaunch(launch) => {
                info!("game_launch received");
                if let Err(e) = runtime_state.lock().await.validate_game_launch(&launch) {
                    warn!("game_launch rejected: {e}");
                    let ack = GameLaunchAck {
                        session_id: launch.session_id.to_string(),
                        process_id: 0,
                        success: false,
                        error: Some(e.to_string()),
                    };
                    if let Err(e) = outbound.try_send_control(HubMessage::GameLaunchAck(ack)) {
                        return Ok(fail_connection_after_control_enqueue_error(
                            &connection_cancel_tx,
                            &connection_task_aborts,
                            &input_ctrl,
                            &runtime_state,
                            &launch_resources,
                            "game_launch_reject_ack",
                            e,
                        )
                        .await);
                    }
                    continue;
                }

                let command_timeout = {
                    let state = runtime_state.lock().await;
                    state.effective_command_timeout()
                };

                let result = tokio::time::timeout(command_timeout, async {
                    let mut pm = proc_mgr.lock().await;
                    let (executable, working_dir) = pm.resolve_canonical_game_launch(&launch.game_slug)?;
                    {
                        let state = runtime_state.lock().await;
                        state.validate_game_launch(&launch)?;
                        state.validate_resolved_launch(&executable)?;
                    }
                    pm.launch_game(
                        &launch.game_slug,
                        &executable,
                        &[],
                        working_dir.as_deref(),
                    )
                })
                .await;

                let ack = match result {
                    Ok(Ok(pid)) => GameLaunchAck {
                        session_id: launch.session_id.to_string(),
                        process_id: pid,
                        success: true,
                        error: None,
                    },
                    Ok(Err(_)) => {
                        error!("game launch failed");
                        GameLaunchAck {
                            session_id: launch.session_id.to_string(),
                            process_id: 0,
                            success: false,
                            error: Some("local game launch failed".to_string()),
                        }
                    }
                    Err(_) => {
                        warn!("game launch timed out after {}s", command_timeout.as_secs());
                        GameLaunchAck {
                            session_id: launch.session_id.to_string(),
                            process_id: 0,
                            success: false,
                            error: Some(format!(
                                "game launch timed out after {}s",
                                command_timeout.as_secs()
                            )),
                        }
                    }
                };

                if ack.success {
                    runtime_state
                        .lock()
                        .await
                        .start_session(ack.session_id.clone(), launch.game_slug.clone());
                }

                if let Err(e) = outbound.try_send_control(HubMessage::GameLaunchAck(ack)) {
                    return Ok(fail_connection_after_control_enqueue_error(
                        &connection_cancel_tx,
                        &connection_task_aborts,
                        &input_ctrl,
                        &runtime_state,
                        &launch_resources,
                        "game_launch_ack",
                        e,
                    )
                    .await);
                }
            }
            AgentEvent::GameKill(kill) => {
                {
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) = ctrl.emergency_stop() {
                        error!("game_kill emergency_stop failed: {e}");
                    }
                }

                let command_timeout = {
                    let state = runtime_state.lock().await;
                    state.effective_command_timeout()
                };

                let result = tokio::time::timeout(command_timeout, async {
                    let mut pm = proc_mgr.lock().await;
                    target_operation::close_active_target(&mut pm, kill.force)
                })
                .await;

                let ack = match result {
                    Ok(Ok(())) => GameKillAck {
                        session_id: kill.session_id,
                        success: true,
                        exit_code: Some(0),
                        error: None,
                    },
                    Ok(Err(e)) => {
                        error!("game kill failed: {e}");
                        GameKillAck {
                            session_id: kill.session_id.clone(),
                            success: false,
                            exit_code: None,
                            error: Some(e.to_string()),
                        }
                    }
                    Err(_) => {
                        warn!("game kill timed out after {}s", command_timeout.as_secs());
                        GameKillAck {
                            session_id: kill.session_id.clone(),
                            success: false,
                            exit_code: None,
                            error: Some(format!(
                                "game kill timed out after {}s",
                                command_timeout.as_secs()
                            )),
                        }
                    }
                };

                if ack.success {
                    runtime_state.lock().await.finish_session(&ack.session_id);
                }

                if let Err(e) = outbound.try_send_control(HubMessage::GameKillAck(ack)) {
                    return Ok(fail_connection_after_control_enqueue_error(
                        &connection_cancel_tx,
                        &connection_task_aborts,
                        &input_ctrl,
                        &runtime_state,
                        &launch_resources,
                        "game_kill_ack",
                        e,
                    )
                    .await);
                }
            }
            AgentEvent::SettingsUpdate(update) => {
                let runtime_config = {
                    let mut state = runtime_state.lock().await;
                    state.apply_settings_update(&update);
                    info!(
                        "settings_update applied: auto_update={}, auto_start={}, command_timeout_s={}, launch_allowlist_len={}",
                        state.auto_update,
                        state.auto_start,
                        state.command_timeout_s,
                        state.launch_allowlist.len()
                    );
                    state.runtime_config()
                };

                if let Err(e) = persist_runtime_config(&runtime_context.config_path, runtime_config)
                {
                    error!("runtime config persist failed: {e}");
                }

                let auto_start = { runtime_state.lock().await.auto_start };
                if let Err(e) = sync_auto_start_setting(auto_start, &runtime_context) {
                    error!("auto_start sync failed: {e}");
                }
            }
            AgentEvent::GameDiscoveryRequest(request) => {
                info!("game_discovery_request received");
                if let Err(e) =
                    send_game_discovery_result(outbound.clone(), request.request_id).await
                {
                    return Ok(fail_connection_after_control_enqueue_error(
                        &connection_cancel_tx,
                        &connection_task_aborts,
                        &input_ctrl,
                        &runtime_state,
                        &launch_resources,
                        "game_discovery_result",
                        e,
                    )
                    .await);
                }
            }
            AgentEvent::EnvironmentCheckStart(command) => {
                info!("environment_check_start received: task_run_id={}", command.task_run_id);
                let (executable, working_dir) = match resolve_discovered_game_launch(&command.game_slug) {
                    Ok(target) => target,
                    Err(_) => {
                        let _ = outbound.try_send_control(environment_check_failure(
                            &command,
                            "game_not_available",
                            "local game target unavailable",
                        ));
                        continue;
                    }
                };
                if runtime_state
                    .lock()
                    .await
                    .validate_resolved_launch(&executable)
                    .is_err()
                {
                    let _ = outbound.try_send_control(environment_check_failure(
                        &command,
                        "launch_rejected",
                        "local game target rejected",
                    ));
                    continue;
                }
                let command = command.with_local_target(executable, working_dir);
                let identity = EnvironmentCheckIdentity {
                    task_run_id: command.task_run_id.clone(),
                    trace_id: command.trace_id.clone(),
                    session_id: command.session_id.clone(),
                    connection_id: command.connection_id,
                };
                let cancel_flag = Arc::new(AtomicBool::new(false));
                {
                    let mut active = active_environment_check.lock().await;
                    if active.is_some() {
                        let _ = outbound.try_send_control(environment_check_failure(
                            &command,
                            "environment_check_busy",
                            "environment check already running",
                        ));
                        continue;
                    }
                    *active = Some((identity.clone(), cancel_flag.clone()));
                }
                let task_proc_mgr = proc_mgr.clone();
                let task_input_ctrl = input_ctrl.clone();
                let task_outbound = outbound.clone();
                let task_active_environment_check = active_environment_check.clone();
                let task_identity = identity.clone();
                let capture_config = app_config.capture.clone();
                let launch_allowlist = runtime_state.lock().await.launch_allowlist.clone();
                tokio::spawn(async move {
                    let (steps, final_result) = {
                        let mut pm = task_proc_mgr.lock().await;
                        let mut input = task_input_ctrl.lock().await;
                        let mut ops = environment_check::AgentEnvironmentCheckOps {
                            process: &mut pm,
                            input: &mut input,
                            capture_config: &capture_config,
                            launch_allowlist: &launch_allowlist,
                        };
                        environment_check::run_environment_check(&command, &mut ops, &cancel_flag)
                    };
                    for step in steps {
                        if let Err(e) = task_outbound.try_send_control(HubMessage::EnvironmentCheckStepResult(step)) {
                            error!("environment check step result enqueue failed: {e}");
                            break;
                        }
                    }
                    if let Err(e) = task_outbound.try_send_control(HubMessage::EnvironmentCheckResult(final_result)) {
                        error!("environment check final result enqueue failed: {e}");
                    }
                    let mut active = task_active_environment_check.lock().await;
                    if active
                        .as_ref()
                        .is_some_and(|(active_identity, _)| active_identity == &task_identity)
                    {
                        *active = None;
                    }
                });
            }
            AgentEvent::EnvironmentCheckCancel(cancel) => {
                info!("environment_check_cancel received: task_run_id={}", cancel.task_run_id);
                let cancel_flag = {
                    let active = active_environment_check.lock().await;
                    active.as_ref().and_then(|(identity, flag)| {
                        environment_check_cancel_matches(identity, &cancel).then(|| flag.clone())
                    })
                };
                if let Some(flag) = cancel_flag {
                    flag.store(true, Ordering::Relaxed);
                    let mut ctrl = input_ctrl.lock().await;
                    if let Err(e) = ctrl.emergency_stop() {
                        error!("environment check cancel emergency_stop failed: {e}");
                    }
                }
            }
            event @ AgentEvent::TaskRunStart(_) => {
                let start = match &event {
                    AgentEvent::TaskRunStart(start) => start,
                    _ => unreachable!(),
                };
                let pending_start = PendingTaskRunStart::from_start(start);
                let reserved = {
                    let mut pending = pending_task_run_start.lock().await;
                    if pending.is_some() {
                        false
                    } else {
                        *pending = Some(pending_start.clone());
                        true
                    }
                };
                let start_state = runtime_state.clone();
                let start_engine = launch_engine.clone();
                let start_process = proc_mgr.clone();
                let start_input = input_ctrl.clone();
                let start_owned = launch_owned.clone();
                let start_capture = launch_capture.clone();
                let start_pending = pending_task_run_start.clone();
                let start_outbound = outbound.clone();
                dispatch_task_run_start_event(
                    event,
                    task_exit_tx.clone(),
                    &mut connection_task_aborts,
                    outbound.clone(),
                    move |start| async move {
                        if !reserved {
                            anyhow::bail!("launch-to-ready executor busy");
                        }
                        if pending_start.is_cancelled() {
                            clear_pending_task_run_start(&start_pending, &start).await;
                            return Ok(());
                        }
                        let (executable, working_dir) = {
                            let process = start_process.lock().await;
                            process.resolve_canonical_game_launch(&start.game_slug)?
                        };
                        let allowed = start_state
                            .lock()
                            .await
                            .validate_resolved_launch(&executable);
                        if allowed.is_err() {
                            clear_pending_task_run_start(&start_pending, &start).await;
                            return if pending_start.is_cancelled() {
                                Ok(())
                            } else {
                                allowed
                            };
                        }
                        let start = start.with_local_target(executable, working_dir);
                        let start_result = {
                            let mut engine = start_engine.lock().await;
                            let mut process = start_process.lock().await;
                            let mut input = start_input.lock().await;
                            let mut owned = start_owned.lock().await;
                            let mut ops = ProductionLaunchToReadyOps {
                                process: &mut process,
                                input: &mut input,
                                capture: &start_capture,
                                owned: &mut owned,
                            };
                            if !pending_start.claim_start() {
                                None
                            } else {
                                let result =
                                    engine.start(start.clone(), std::time::Instant::now(), &mut ops);
                                let result = if result.is_ok()
                                    && !activate_pending_task_run_start(
                                        &start_pending,
                                        &start,
                                        &start_state,
                                    )
                                    .await
                                {
                                    engine.cancel(
                                        &protocol::TaskRunCancel {
                                            message_type: "task_run_cancel".into(),
                                            task_run_id: start.task_run_id.clone(),
                                            trace_id: start.trace_id.clone(),
                                            session_id: start.session_id.clone(),
                                            connection_id: start.connection_id,
                                        },
                                        &mut ops,
                                    )
                                } else {
                                    result
                                };
                                Some((result, engine.take_cleanup_receipt()))
                            }
                        };
                        let Some((result, receipt)) = start_result else {
                            clear_pending_task_run_start(&start_pending, &start).await;
                            return Ok(());
                        };
                        if let Some(receipt) = receipt {
                            enqueue_task_run_cleanup_receipt(&start_outbound, receipt).await?;
                        }
                        if let Err(error) = result {
                            clear_pending_task_run_start(&start_pending, &start).await;
                            return if pending_start.is_cancelled() {
                                Ok(())
                            } else {
                                Err(error)
                            };
                        }
                        Ok(())
                    },
                );
            }
            AgentEvent::TaskRunCancel(cancel) => {
                if cancel_pending_task_run_start(&pending_task_run_start, &cancel).await {
                    continue;
                }
                let (result, receipt) = {
                    let mut engine = launch_engine.lock().await;
                    let mut process = proc_mgr.lock().await;
                    let mut input = input_ctrl.lock().await;
                    let mut owned = launch_owned.lock().await;
                    let mut ops = ProductionLaunchToReadyOps { process: &mut process, input: &mut input, capture: &launch_capture, owned: &mut owned };
                    let result = engine.cancel(&cancel, &mut ops);
                    (result, engine.take_cleanup_receipt())
                };
                if let Some(receipt) = receipt {
                    if let Err(e) = enqueue_task_run_cleanup_receipt(&outbound, receipt).await { return Ok(fail_connection_after_control_enqueue_error(&connection_cancel_tx, &connection_task_aborts, &input_ctrl, &runtime_state, &launch_resources, "task_run_cancel_cleanup", e).await); }
                }
                if result.is_ok() { runtime_state.lock().await.finish_session(&cancel.session_id); }
                else if let Err(e) = enqueue_task_run_terminal(&outbound, task_run_failure(cancel.task_run_id, cancel.trace_id, cancel.session_id)).await { return Ok(fail_connection_after_control_enqueue_error(&connection_cancel_tx, &connection_task_aborts, &input_ctrl, &runtime_state, &launch_resources, "task_run_cancel", e).await); }
            }
            AgentEvent::TaskRunClick(click) => {
                let (result, receipt) = {
                    let mut engine = launch_engine.lock().await;
                    let mut process = proc_mgr.lock().await;
                    let mut input = input_ctrl.lock().await;
                    let mut owned = launch_owned.lock().await;
                    let mut ops = ProductionLaunchToReadyOps { process: &mut process, input: &mut input, capture: &launch_capture, owned: &mut owned };
                    let result = engine.click(&click, &mut ops);
                    (result, engine.take_cleanup_receipt())
                };
                if let Some(receipt) = receipt {
                    if let Err(e) = enqueue_task_run_cleanup_receipt(&outbound, receipt).await { return Ok(fail_connection_after_control_enqueue_error(&connection_cancel_tx, &connection_task_aborts, &input_ctrl, &runtime_state, &launch_resources, "task_run_click_cleanup", e).await); }
                }
                if result.is_err() { if let Err(e) = enqueue_task_run_terminal(&outbound, task_run_failure(click.task_run_id, click.trace_id, click.session_id)).await { return Ok(fail_connection_after_control_enqueue_error(&connection_cancel_tx, &connection_task_aborts, &input_ctrl, &runtime_state, &launch_resources, "task_run_click", e).await); } }
            }
            AgentEvent::TaskRunTerminal(terminal) => {
                if consume_cancelled_pending_task_run_start(&pending_task_run_start, &terminal).await {
                    continue;
                }
                let (result, receipt) = {
                    let mut engine = launch_engine.lock().await;
                    let mut process = proc_mgr.lock().await;
                    let mut input = input_ctrl.lock().await;
                    let mut owned = launch_owned.lock().await;
                    let mut ops = ProductionLaunchToReadyOps { process: &mut process, input: &mut input, capture: &launch_capture, owned: &mut owned };
                    let result = engine.terminal(&terminal, &mut ops);
                    (result, engine.take_cleanup_receipt())
                };
                let keep = result.is_ok()
                    && receipt.as_ref().is_some_and(|receipt| {
                        receipt.owned_cleanup == protocol::OwnedCleanup::NotRequired
                    });
                if let Some(receipt) = receipt {
                    if let Err(e) = enqueue_task_run_cleanup_receipt(&outbound, receipt).await { return Ok(fail_connection_after_control_enqueue_error(&connection_cancel_tx, &connection_task_aborts, &input_ctrl, &runtime_state, &launch_resources, "task_run_terminal_cleanup", e).await); }
                }
                if result.is_ok() { if !keep { runtime_state.lock().await.finish_session(&terminal.session_id); } }
                else if let Err(e) = enqueue_task_run_terminal(&outbound, task_run_failure(terminal.task_run_id, terminal.trace_id, terminal.session_id)).await { return Ok(fail_connection_after_control_enqueue_error(&connection_cancel_tx, &connection_task_aborts, &input_ctrl, &runtime_state, &launch_resources, "task_run_terminal", e).await); }
            }
                },
                None => {
                    warn!("agent event channel closed");
                    cancel_connection(&connection_cancel_tx, "agent event channel closed");
                    cancel_active_environment_check(&active_environment_check, "agent event channel closed").await;
                    abort_connection_tasks(&connection_task_aborts);
                    disconnect_launch_to_ready(&launch_engine, &proc_mgr, &input_ctrl, &launch_owned, &launch_capture, &outbound, "agent event channel close").await;
                    {
                        let mut ctrl = input_ctrl.lock().await;
                        if let Err(e) = ctrl.emergency_stop() {
                            error!("agent event channel emergency_stop failed: {e}");
                        }
                    }
                    runtime_state.lock().await.clear_session();
                    clear_pending_task_run_start_on_disconnect(&pending_task_run_start).await;
                    return Ok(ConnectionRunResult::Reconnect {
                        reason: "agent event channel closed".to_string(),
                    });
                }
            }
        }
    }
}
pub fn append_log_line(log_path: &Path, message: &str) -> Result<()> {
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log directory: {}", parent.display()))?;
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("failed to open log file: {}", log_path.display()))?;

    writeln!(file, "{} {}", chrono::Local::now().to_rfc3339(), message)
        .with_context(|| format!("failed to write log file: {}", log_path.display()))?;
    Ok(())
}

pub fn in_process_runtime_runner(
    spec: RuntimeStartSpec,
    stop_rx: watch::Receiver<bool>,
    status_tx: std_mpsc::Sender<RuntimeStatusUpdate>,
) -> Result<std::thread::JoinHandle<()>> {
    Ok(std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to create Agent runtime")?;
            let context = AgentRuntimeContext {
                auto_start_executable: spec.auto_start_executable,
                config_path: spec.config_path,
                log_path: spec.log_path,
            };
            runtime.block_on(run_agent(
                spec.app_config,
                context,
                Some(stop_rx),
                Some(status_tx.clone()),
                false,
            ))
        })();
        let _ = status_tx.send(RuntimeStatusUpdate::Stopped(
            result.map_err(|err| err.to_string()),
        ));
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LaunchCleanupFakeOps {
        binding: TargetBinding,
        release_count: usize,
        close_count: usize,
        force_close_count: usize,
        fail_release: bool,
        fail_close: bool,
        fail_force_close: bool,
    }

    impl LaunchCleanupFakeOps {
        fn new() -> Self {
            Self {
                binding: TargetBinding {
                    profile_id: Some("genshin".into()),
                    resolved_executable: "YuanShen.exe".into(),
                    process_name: "YuanShen.exe".into(),
                    hwnd: 1,
                    pid: 2,
                    title: "Genshin".into(),
                    class_name: Some("UnityWndClass".into()),
                    rect: crate::window::WindowRect {
                        left: 0,
                        top: 0,
                        right: 100,
                        bottom: 100,
                    },
                },
                release_count: 0,
                close_count: 0,
                force_close_count: 0,
                fail_release: false,
                fail_close: false,
                fail_force_close: false,
            }
        }
    }

    impl crate::launch_to_ready::LaunchToReadyOps for LaunchCleanupFakeOps {
        fn launch_and_bind(
            &mut self,
            _start: &protocol::TaskRunStart,
        ) -> Result<crate::launch_to_ready::LaunchedTarget> {
            Ok(crate::launch_to_ready::LaunchedTarget {
                binding: self.binding.clone(),
                client_version: "test".into(),
            })
        }

        fn capture_target(&mut self) -> Result<crate::launch_to_ready::CapturedTarget> {
            anyhow::bail!("capture is not used by cleanup")
        }

        fn click_target(
            &mut self,
            _binding: &TargetBinding,
            _source_width: u32,
            _source_height: u32,
            _x: u32,
            _y: u32,
        ) -> Result<()> {
            anyhow::bail!("click is not used by cleanup")
        }

        fn release_input(&mut self) -> Result<()> {
            self.release_count += 1;
            if self.fail_release {
                anyhow::bail!("fake release failure")
            }
            Ok(())
        }

        fn close_owned_process(&mut self) -> Result<()> {
            self.close_count += 1;
            if self.fail_close {
                anyhow::bail!("fake close failure")
            }
            Ok(())
        }

        fn force_close_owned_process(&mut self) -> Result<()> {
            self.force_close_count += 1;
            if self.fail_force_close {
                anyhow::bail!("fake force-close failure")
            }
            Ok(())
        }
    }

    #[test]
    fn environment_check_cancel_requires_current_task_trace_and_session() {
        let identity = EnvironmentCheckIdentity {
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            session_id: "session-a".into(),
            connection_id: uuid::Uuid::nil(),
        };
        let current = protocol::EnvironmentCheckCancel {
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            session_id: Some("session-a".into()),
        };
        let stale_trace = protocol::EnvironmentCheckCancel {
            trace_id: "trace-old".into(),
            ..current.clone()
        };
        let stale_session = protocol::EnvironmentCheckCancel {
            session_id: Some("session-old".into()),
            ..current.clone()
        };

        assert!(environment_check_cancel_matches(&identity, &current));
        assert!(!environment_check_cancel_matches(&identity, &stale_trace));
        assert!(!environment_check_cancel_matches(&identity, &stale_session));
    }

    #[test]
    fn environment_check_failure_is_pathless() {
        let command = protocol::EnvironmentCheckStart {
            _message_type: "environment_check_start".into(),
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            connection_id: uuid::Uuid::nil(),
            game_slug: "genshin".into(),
            session_id: "session-a".into(),
            timeout_s: 10,
            force_close_on_cleanup: false,
            resolved_executable: Some(r"C:\\private\\YuanShen.exe".into()),
            resolved_working_dir: Some(r"C:\\private".into()),
        };

        let wire = serde_json::to_string(&environment_check_failure(
            &command,
            "game_not_available",
            "local game target unavailable",
        ))
        .unwrap();
        assert!(!wire.contains("private"));
        assert!(!wire.contains("executable_path"));
        assert!(!wire.contains("working_dir"));
    }

    #[test]
    fn auto_start_command_requires_explicit_agent_executable() {
        let mut context = AgentRuntimeContext {
            auto_start_executable: None,
            config_path: PathBuf::from("config.yaml"),
            log_path: PathBuf::from("agent.log"),
        };
        assert!(build_auto_start_command_line(&context).is_err());

        context.auto_start_executable = Some(PathBuf::from("fairypam-agent.exe"));
        let command = build_auto_start_command_line(&context).unwrap();
        assert!(command.contains("fairypam-agent.exe"));
        assert!(command.contains("--run"));
    }

    fn game_launch(connection_id: uuid::Uuid) -> protocol::GameLaunch {
        protocol::GameLaunch {
            message_type: "game_launch".into(),
            session_id: uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            trace_id: "trace-a".into(),
            game_slug: "genshin".into(),
            connection_id,
        }
    }

    fn hub_welcome(connection_id: uuid::Uuid) -> protocol::HubWelcome {
        protocol::HubWelcome {
            protocol_version: 3,
            agent_id: "agent-a".into(),
            connection_id,
            agent_name_effective: "agent-a".into(),
            config: protocol::HubAgentConfig {
                heartbeat_interval_s: 10,
                command_timeout_s: 60,
                auto_update: false,
                auto_start: false,
                launch_allowlist: vec!["yuanshen.exe".into()],
            },
            accepted_capabilities: vec![],
        }
    }

    fn task_run_start() -> protocol::TaskRunStart {
        protocol::TaskRunStart {
            message_type: "task_run_start".into(),
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            session_id: "session-a".into(),
            connection_id: uuid::Uuid::nil(),
            game_slug: "genshin".into(),
            template_id: "genshin/launch-to-ready".into(),
            template_version: "v1".into(),
            params: serde_json::json!({}),
            timeout_s: 30,
            resolved_executable: Some("YuanShen.exe".into()),
            resolved_working_dir: None,
        }
    }

    fn task_run_cancel() -> protocol::TaskRunCancel {
        protocol::TaskRunCancel {
            message_type: "task_run_cancel".into(),
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            session_id: "session-a".into(),
            connection_id: uuid::Uuid::nil(),
        }
    }

    fn terminal(outcome: &str) -> protocol::TaskRunTerminal {
        protocol::TaskRunTerminal {
            message_type: "task_run_terminal".into(),
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            session_id: "session-a".into(),
            connection_id: uuid::Uuid::nil(),
            outcome: outcome.into(),
        }
    }

    #[tokio::test]
    async fn pending_task_run_start_accepts_matching_cancel_before_engine_registration() {
        let pending = Arc::new(Mutex::new(Some(PendingTaskRunStart::from_start(
            &task_run_start(),
        ))));

        assert!(cancel_pending_task_run_start(&pending, &task_run_cancel()).await);
        assert!(pending
            .lock()
            .await
            .as_ref()
            .is_some_and(PendingTaskRunStart::is_cancelled));
    }

    #[tokio::test]
    async fn pending_task_run_start_rejects_mismatched_cancel_identity() {
        let pending = Arc::new(Mutex::new(Some(PendingTaskRunStart::from_start(
            &task_run_start(),
        ))));
        let cancels = [
            protocol::TaskRunCancel {
                task_run_id: "task-other".into(),
                ..task_run_cancel()
            },
            protocol::TaskRunCancel {
                trace_id: "trace-other".into(),
                ..task_run_cancel()
            },
            protocol::TaskRunCancel {
                session_id: "session-other".into(),
                ..task_run_cancel()
            },
            protocol::TaskRunCancel {
                connection_id: uuid::Uuid::new_v4(),
                ..task_run_cancel()
            },
        ];

        for cancel in cancels {
            assert!(!cancel_pending_task_run_start(&pending, &cancel).await);
        }
        assert!(!pending
            .lock()
            .await
            .as_ref()
            .is_some_and(PendingTaskRunStart::is_cancelled));
    }

    #[tokio::test]
    async fn pending_task_run_start_cancel_during_start_defers_to_engine_cleanup() {
        let start = task_run_start();
        let pending = Arc::new(Mutex::new(Some(PendingTaskRunStart::from_start(&start))));
        let state = Arc::new(Mutex::new(AgentRuntimeState::default()));
        let reservation = pending.lock().await.as_ref().cloned().unwrap();

        assert!(reservation.claim_start());
        assert!(!cancel_pending_task_run_start(&pending, &task_run_cancel()).await);
        assert!(activate_pending_task_run_start(&pending, &start, &state).await);
        assert!(state.lock().await.active_session.is_some());
        state.lock().await.finish_session(&start.session_id);
        assert!(state.lock().await.active_session.is_none());
        assert!(pending.lock().await.is_none());
    }

    #[tokio::test]
    async fn cancelled_pending_start_consumes_matching_terminal_once() {
        let start = task_run_start();
        let pending = Arc::new(Mutex::new(Some(PendingTaskRunStart::from_start(&start))));

        assert!(cancel_pending_task_run_start(&pending, &task_run_cancel()).await);
        assert!(consume_cancelled_pending_task_run_start(&pending, &terminal("canceled")).await);
        assert!(!consume_cancelled_pending_task_run_start(&pending, &terminal("canceled")).await);
        assert!(pending.lock().await.is_none());
    }

    #[tokio::test]
    async fn cancelled_pending_start_rejects_mismatched_terminal_and_clears_on_disconnect() {
        let start = task_run_start();
        let pending = Arc::new(Mutex::new(Some(PendingTaskRunStart::from_start(&start))));
        let mut mismatch = terminal("canceled");
        mismatch.trace_id = "trace-other".into();

        assert!(cancel_pending_task_run_start(&pending, &task_run_cancel()).await);
        assert!(!consume_cancelled_pending_task_run_start(&pending, &mismatch).await);
        assert!(pending.lock().await.is_some());
        clear_pending_task_run_start_on_disconnect(&pending).await;
        assert!(pending.lock().await.is_none());
    }

    #[tokio::test]
    async fn critical_connection_task_exit_cancels_lifecycle() {
        let (exit_tx, mut exit_rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut abort_handles = Vec::new();

        spawn_connection_task(
            ConnectionTaskName::Writer,
            true,
            exit_tx,
            &mut abort_handles,
            async { anyhow::bail!("writer failed") },
        );

        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(exit.task, ConnectionTaskName::Writer);
        assert!(exit.critical);
        assert!(exit.reason.contains("writer failed"));
        assert!(handle_connection_task_exit(&cancel_tx, &exit));
        assert!(*cancel_rx.borrow());
        abort_connection_tasks(&abort_handles);
    }

    #[tokio::test]
    async fn critical_connection_task_success_still_cancels_lifecycle() {
        let (exit_tx, mut exit_rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut abort_handles = Vec::new();

        spawn_connection_task(
            ConnectionTaskName::Recv,
            true,
            exit_tx,
            &mut abort_handles,
            async { Ok(()) },
        );

        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(exit.task, ConnectionTaskName::Recv);
        assert!(exit.critical);
        assert!(exit.reason.contains("completed unexpectedly"));
        assert!(handle_connection_task_exit(&cancel_tx, &exit));
        assert!(*cancel_rx.borrow());
        abort_connection_tasks(&abort_handles);
    }

    #[tokio::test]
    async fn task_run_start_production_dispatcher_keeps_cancel_control_path_responsive() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (exit_tx, _exit_rx) = mpsc::unbounded_channel();
        let mut abort_handles = Vec::new();

        dispatch_task_run_start_event(
            AgentEvent::TaskRunStart(task_run_start()),
            exit_tx,
            &mut abort_handles,
            OutboundWriter::closed_for_test(),
            |_start| async move {
                let _ = entered_tx.send(());
                let _ = release_rx.await;
                Ok(())
            },
        );

        entered_rx.await.unwrap();
        let (control_tx, mut control_rx) = mpsc::channel(1);
        control_tx
            .send(AgentEvent::TaskRunCancel(protocol::TaskRunCancel {
                message_type: "task_run_cancel".into(),
                task_run_id: "task-a".into(),
                trace_id: "trace-a".into(),
                session_id: "session-a".into(),
                connection_id: uuid::Uuid::nil(),
            }))
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(50), control_rx.recv())
                .await
                .unwrap(),
            Some(AgentEvent::TaskRunCancel(_))
        ));

        let _ = release_tx.send(());
    }

    #[tokio::test]
    async fn task_run_start_production_dispatcher_rejects_duplicate_active_owner() {
        let active = Arc::new(AtomicBool::new(false));
        let (first_entered_tx, first_entered_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel::<()>();
        let (duplicate_tx, duplicate_rx) = tokio::sync::oneshot::channel();
        let (exit_tx, mut exit_rx) = mpsc::unbounded_channel();
        let mut abort_handles = Vec::new();

        let first_active = active.clone();
        dispatch_task_run_start_event(
            AgentEvent::TaskRunStart(task_run_start()),
            exit_tx.clone(),
            &mut abort_handles,
            OutboundWriter::closed_for_test(),
            move |_start| async move {
                if first_active.swap(true, Ordering::SeqCst) {
                    anyhow::bail!("duplicate task-run start");
                }
                let _ = first_entered_tx.send(());
                let _ = release_first_rx.await;
                Ok(())
            },
        );
        first_entered_rx.await.unwrap();

        let second_active = active.clone();
        dispatch_task_run_start_event(
            AgentEvent::TaskRunStart(task_run_start()),
            exit_tx,
            &mut abort_handles,
            OutboundWriter::closed_for_test(),
            move |_start| async move {
                if second_active.swap(true, Ordering::SeqCst) {
                    let _ = duplicate_tx.send(());
                    anyhow::bail!("duplicate task-run start");
                }
                Ok(())
            },
        );
        tokio::time::timeout(Duration::from_secs(1), duplicate_rx)
            .await
            .unwrap()
            .unwrap();
        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exit.task, ConnectionTaskName::LaunchToReadyStart);
        assert!(exit.reason.contains("task-run terminal enqueue failed"));

        abort_connection_tasks(&abort_handles);
        drop(release_first_tx);
    }

    #[tokio::test]
    async fn task_run_start_production_dispatcher_aborts_pending_start_on_disconnect() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (completed_tx, mut completed_rx) = mpsc::channel(1);
        let (exit_tx, _exit_rx) = mpsc::unbounded_channel();
        let mut abort_handles = Vec::new();

        dispatch_task_run_start_event(
            AgentEvent::TaskRunStart(task_run_start()),
            exit_tx,
            &mut abort_handles,
            OutboundWriter::closed_for_test(),
            |_start| async move {
                let _ = entered_tx.send(());
                let _ = release_rx.await;
                let _ = completed_tx.send(()).await;
                Ok(())
            },
        );
        entered_rx.await.unwrap();

        abort_connection_tasks(&abort_handles);
        tokio::task::yield_now().await;
        let _ = release_tx.send(());
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(50), completed_rx.recv())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn task_run_start_production_terminal_enqueue_failure_reconnects() {
        let (exit_tx, mut exit_rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut abort_handles = Vec::new();

        dispatch_task_run_start_event(
            AgentEvent::TaskRunStart(task_run_start()),
            exit_tx,
            &mut abort_handles,
            OutboundWriter::closed_for_test(),
            |_start| async { anyhow::bail!("start failed") },
        );

        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(exit.task, ConnectionTaskName::LaunchToReadyStart);
        assert!(exit.reason.contains("task-run terminal enqueue failed"));
        assert!(handle_connection_task_exit(&cancel_tx, &exit));
        assert!(*cancel_rx.borrow());
    }

    #[test]
    fn noncritical_capture_exit_does_not_cancel_lifecycle() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let exit = ConnectionTaskExit {
            task: ConnectionTaskName::Capture,
            reason: "screen capture init failed".into(),
            critical: false,
        };

        assert!(!handle_connection_task_exit(&cancel_tx, &exit));
        assert!(!*cancel_rx.borrow());
    }

    #[test]
    fn disconnect_result_plans_bounded_exponential_reconnect() {
        let result = ConnectionRunResult::Reconnect {
            reason: "Recv: WebSocket connection closed".to_string(),
        };

        let first = reconnect_plan_for_result(1, &result).unwrap();
        assert_eq!(first.attempt, 1);
        assert_eq!(first.delay, Duration::from_secs(1));
        assert_eq!(first.last_error, "Recv: WebSocket connection closed");

        let capped = reconnect_plan_for_result(10, &result).unwrap();
        assert_eq!(capped.attempt, 10);
        assert_eq!(capped.delay, Duration::from_secs(30));
    }

    #[test]
    fn reconnect_is_published_before_backoff_begins() {
        let (status_tx, status_rx) = std_mpsc::channel();
        status_tx.send(RuntimeStatusUpdate::Running).unwrap();

        let plan = prepare_reconnect(1, "hub disconnected", Some(&status_tx));

        assert!(matches!(
            status_rx.recv().unwrap(),
            RuntimeStatusUpdate::Running
        ));
        assert!(matches!(
            status_rx.recv().unwrap(),
            RuntimeStatusUpdate::Starting
        ));
        assert_eq!(plan.attempt, 1);
    }

    #[test]
    fn user_stop_result_does_not_plan_reconnect() {
        assert!(reconnect_plan_for_result(1, &ConnectionRunResult::Stopped).is_none());
    }

    #[tokio::test]
    async fn full_control_queue_after_input_cleanup_returns_reconnect_without_waiting() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let input_ctrl = Arc::new(Mutex::new(InputController::new()));
        let runtime_state = Arc::new(Mutex::new(AgentRuntimeState::default()));
        runtime_state
            .lock()
            .await
            .start_manual_session("manual-local".into());
        let pending_task = tokio::spawn(async { future::pending::<Result<()>>().await });
        let abort_handles = vec![pending_task.abort_handle()];

        let result = tokio::time::timeout(
            Duration::from_millis(50),
            fail_connection_after_control_enqueue_error_with_cleanup(
                &cancel_tx,
                &abort_handles,
                &input_ctrl,
                &runtime_state,
                "input_frame_ack",
                anyhow::anyhow!("outbound control queue full"),
                async {},
            ),
        )
        .await
        .unwrap();

        assert!(matches!(
            result,
            ConnectionRunResult::Reconnect { ref reason }
                if reason.contains("outbound control queue full")
        ));
        assert!(*cancel_rx.borrow());
        assert!(runtime_state.lock().await.active_session.is_none());

        let _ = pending_task.await;
    }

    #[tokio::test]
    async fn closed_control_writer_cleans_active_launch_before_reconnect_and_can_retry() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let input_ctrl = Arc::new(Mutex::new(InputController::new()));
        let runtime_state = Arc::new(Mutex::new(AgentRuntimeState::default()));
        runtime_state
            .lock()
            .await
            .start_session("session-a".into(), "genshin".into());

        let engine = Arc::new(Mutex::new(LaunchToReadyEngine::new()));
        let ops = Arc::new(Mutex::new(LaunchCleanupFakeOps::new()));
        {
            let mut engine = engine.lock().await;
            let mut ops = ops.lock().await;
            engine
                .start(task_run_start(), std::time::Instant::now(), &mut *ops)
                .unwrap();
            ops.fail_release = true;
            ops.fail_close = true;
            ops.fail_force_close = true;
        }

        let cleanup_engine = engine.clone();
        let cleanup_ops = ops.clone();
        let result = fail_connection_after_control_enqueue_error_with_cleanup(
            &cancel_tx,
            &[],
            &input_ctrl,
            &runtime_state,
            "task_run_terminal",
            anyhow::anyhow!("outbound control writer closed"),
            async move {
                let mut engine = cleanup_engine.lock().await;
                let mut ops = cleanup_ops.lock().await;
                let _ =
                    disconnect_launch_to_ready_with_ops(&mut engine, &mut *ops, "closed writer");
            },
        )
        .await;

        assert!(matches!(result, ConnectionRunResult::Reconnect { .. }));
        assert!(*cancel_rx.borrow());
        assert!(runtime_state.lock().await.active_session.is_none());
        {
            let ops = ops.lock().await;
            assert_eq!(
                (ops.release_count, ops.close_count, ops.force_close_count),
                (2, 2, 1)
            );
        }
        assert!(engine.lock().await.active_identity().is_some());

        {
            let mut ops = ops.lock().await;
            ops.fail_release = false;
            ops.fail_close = false;
            ops.fail_force_close = false;
        }
        {
            let mut engine = engine.lock().await;
            let mut ops = ops.lock().await;
            let _ = disconnect_launch_to_ready_with_ops(&mut engine, &mut *ops, "retry");
            let _ = disconnect_launch_to_ready_with_ops(&mut engine, &mut *ops, "repeat");
            assert!(engine.active_identity().is_none());
            assert_eq!(
                (ops.release_count, ops.close_count, ops.force_close_count),
                (3, 3, 1)
            );
        }
    }

    #[tokio::test]
    async fn cleanup_receipt_enqueue_failure_does_not_mask_completed_local_cleanup() {
        let mut engine = LaunchToReadyEngine::new();
        let mut ops = LaunchCleanupFakeOps::new();
        engine
            .start(task_run_start(), std::time::Instant::now(), &mut ops)
            .unwrap();
        engine.cancel(&task_run_cancel(), &mut ops).unwrap();
        let receipt = engine.take_cleanup_receipt().expect("cleanup receipt");

        assert!(
            enqueue_task_run_cleanup_receipt(&OutboundWriter::closed_for_test(), receipt)
                .await
                .is_err()
        );
        assert_eq!((ops.release_count, ops.close_count), (1, 1));
        assert!(engine.active_identity().is_none());
    }

    #[test]
    fn process_name_for_log_strips_local_paths() {
        let process_name =
            process_name_for_log(r"C:\Users\clei\AppData\Local\Game\GenshinImpact.exe");

        assert_eq!(process_name, "GenshinImpact.exe");
        assert!(!process_name.contains("Users"));
        assert!(!process_name.contains('\\'));
    }

    #[test]
    fn allowlist_accepts_matching_filename_case_insensitive() {
        let state = AgentRuntimeState {
            connection_id: uuid::Uuid::nil(),
            auto_update: false,
            auto_start: false,
            command_timeout_s: 60,
            launch_allowlist: vec!["GenshinImpact.exe".into()],
            active_session: None,
        };
        assert!(state
            .validate_resolved_launch("C:\\Games\\GenshinImpact.exe")
            .is_ok());
        assert!(state.validate_resolved_launch("genshinimpact.exe").is_ok());
    }

    #[test]
    fn game_discovery_result_always_has_three_redacted_canonical_games() {
        let genshin = mihoyo_discovery::MihoyoGameInstall {
            profile_id: Some("genshin".to_string()),
            launch_path: Some(PathBuf::from(r"C:\private\YuanShen.exe")),
            exists_on_disk: true,
            supported: true,
            ..Default::default()
        };
        let result =
            game_discovery_result_from_result("req-canonical".to_string(), Ok(vec![genshin]));

        assert_eq!(result.request_id, "req-canonical");
        assert_eq!(result.status, "ready");
        assert_eq!(
            result
                .games
                .iter()
                .map(|game| game.game_slug.as_str())
                .collect::<Vec<_>>(),
            ["genshin", "star-rail", "zenless"]
        );
        assert!(result.games[0].discovered);
        assert!(result.games[1..].iter().all(|game| !game.discovered));
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains(r"C:\private"));
        assert!(!json.contains("executable_path"));
        assert!(!json.contains("working_dir"));

        let failed = game_discovery_result_from_result(
            "req-failed".to_string(),
            Err(anyhow::anyhow!(r"scan failed at C:\private")),
        );
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.error.as_deref(), Some("discovery_failed"));
        assert_eq!(failed.games.len(), 3);
    }

    #[test]
    fn allowlist_rejects_empty_list_conservatively() {
        let state = AgentRuntimeState::default();
        assert!(state.validate_resolved_launch("calc.exe").is_err());
    }

    #[test]
    fn allowlist_rejects_non_matching_executable() {
        let state = AgentRuntimeState {
            connection_id: uuid::Uuid::nil(),
            auto_update: false,
            auto_start: false,
            command_timeout_s: 60,
            launch_allowlist: vec!["calc.exe".into()],
            active_session: None,
        };

        assert!(state.validate_resolved_launch("notepad.exe").is_err());
    }

    #[test]
    fn canonical_game_launch_requires_current_connection_and_no_active_owner() {
        let connection_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap();
        let mut state = AgentRuntimeState {
            connection_id,
            ..Default::default()
        };
        let launch = game_launch(connection_id);

        assert!(state.validate_game_launch(&launch).is_ok());
        assert!(state
            .validate_game_launch(&game_launch(uuid::Uuid::nil()))
            .is_err());

        state.start_session("other-session".into(), "genshin".into());
        assert!(state.validate_game_launch(&launch).is_err());
    }

    #[test]
    fn reconnect_replaces_the_trusted_game_launch_connection() {
        let first = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap();
        let second = uuid::Uuid::parse_str("660e8400-e29b-41d4-a716-446655440002").unwrap();
        let first_state = AgentRuntimeState::from_welcome(&hub_welcome(first));
        let second_state = AgentRuntimeState::from_welcome(&hub_welcome(second));

        assert!(first_state
            .validate_game_launch(&game_launch(first))
            .is_ok());
        assert!(second_state
            .validate_game_launch(&game_launch(first))
            .is_err());
        assert!(second_state
            .validate_game_launch(&game_launch(second))
            .is_ok());
    }

    #[test]
    fn input_gate_requires_active_session() {
        let mut state = AgentRuntimeState::default();

        assert_eq!(
            state.accept_input_frame("session-a", 1),
            InputGateDecision::Rejected("no_active_session".into())
        );
    }

    #[test]
    fn manual_session_bootstraps_first_frame() {
        let mut state = AgentRuntimeState::default();

        assert_eq!(
            state.accept_input_frame("manual-local", 1),
            InputGateDecision::Accepted
        );
        assert_eq!(
            state.active_session.as_ref().unwrap().kind,
            SessionKind::Manual
        );
        assert_eq!(state.active_session.as_ref().unwrap().last_seq, Some(1));
    }

    #[test]
    fn manual_frame_is_rejected_when_game_session_exists() {
        let mut state = AgentRuntimeState::default();
        state.start_session("session-a".into(), "game-a".into());

        assert_eq!(
            state.accept_input_frame("manual-local", 1),
            InputGateDecision::Rejected("manual_session_rejected".into())
        );
    }

    #[test]
    fn input_gate_accepts_current_session_and_advances_seq() {
        let mut state = AgentRuntimeState::default();
        state.start_session("session-a".into(), "game-a".into());

        assert_eq!(
            state.accept_input_frame("session-a", 1),
            InputGateDecision::Accepted
        );
        assert_eq!(state.active_session.unwrap().last_seq, Some(1));
    }

    #[test]
    fn input_gate_accepts_zero_as_first_seq() {
        let mut state = AgentRuntimeState::default();
        state.start_session("session-a".into(), "game-a".into());

        assert_eq!(
            state.accept_input_frame("session-a", 0),
            InputGateDecision::Accepted
        );
        assert_eq!(state.active_session.unwrap().last_seq, Some(0));
    }

    #[test]
    fn input_gate_rejects_repeat_and_rollback_seq() {
        let mut state = AgentRuntimeState::default();
        state.start_session("session-a".into(), "game-a".into());

        assert_eq!(
            state.accept_input_frame("session-a", 7),
            InputGateDecision::Accepted
        );
        assert_eq!(
            state.accept_input_frame("session-a", 7),
            InputGateDecision::Rejected("non_monotonic_seq".into())
        );
        assert_eq!(
            state.accept_input_frame("session-a", 6),
            InputGateDecision::Rejected("non_monotonic_seq".into())
        );
    }

    #[test]
    fn input_gate_rejects_non_current_session_without_advancing_seq() {
        let mut state = AgentRuntimeState::default();
        state.start_session("session-a".into(), "game-a".into());

        assert_eq!(
            state.accept_input_frame("session-a", 3),
            InputGateDecision::Accepted
        );
        assert_eq!(
            state.accept_input_frame("session-b", 4),
            InputGateDecision::Rejected("session_mismatch".into())
        );
        assert_eq!(state.active_session.unwrap().last_seq, Some(3));
    }

    #[test]
    fn game_launch_overrides_manual_session() {
        let mut state = AgentRuntimeState::default();
        state.start_manual_session("manual-local".into());
        state.start_session("session-a".into(), "game-a".into());

        assert_eq!(
            state.active_session.as_ref().unwrap().kind,
            SessionKind::Game
        );
        assert_eq!(
            state.active_session.as_ref().unwrap().session_id,
            "session-a"
        );
    }

    #[test]
    fn current_game_session_only_reports_game_sessions_with_game_id() {
        let mut state = AgentRuntimeState::default();
        assert_eq!(state.current_game_session(), None);

        state.start_manual_session("manual-local".into());
        assert_eq!(state.current_game_session(), None);

        state.start_session("session-a".into(), "genshin".into());
        assert_eq!(
            state.current_game_session(),
            Some(("session-a".into(), "genshin".into()))
        );
    }

    #[test]
    fn finishing_current_session_clears_session_state() {
        let mut state = AgentRuntimeState::default();
        state.start_session("session-a".into(), "game-a".into());

        state.finish_session("session-a");

        assert!(state.active_session.is_none());
    }

    #[test]
    fn settings_update_refreshes_allowlist_only_when_present() {
        let mut state = AgentRuntimeState::default();
        state.apply_settings_update(&protocol::SettingsUpdate {
            auto_update: Some(true),
            auto_start: Some(true),
            command_timeout_s: Some(120),
            launch_allowlist: Some(vec!["calc.exe".into(), "yuanshen.exe".into()]),
            extra: Default::default(),
        });
        assert_eq!(state.launch_allowlist, vec!["yuanshen.exe".to_string()]);
        assert!(state.auto_update);
        assert!(state.auto_start);
        assert_eq!(state.command_timeout_s, 120);

        state.apply_settings_update(&protocol::SettingsUpdate {
            auto_update: None,
            auto_start: None,
            command_timeout_s: None,
            launch_allowlist: None,
            extra: Default::default(),
        });
        assert_eq!(state.launch_allowlist, vec!["yuanshen.exe".to_string()]);
        assert!(state.auto_update);
        assert!(state.auto_start);
        assert_eq!(state.command_timeout_s, 120);
    }

    #[test]
    fn settings_update_clamps_command_timeout() {
        let mut state = AgentRuntimeState::default();
        state.apply_settings_update(&protocol::SettingsUpdate {
            auto_update: None,
            auto_start: None,
            command_timeout_s: Some(0),
            launch_allowlist: None,
            extra: Default::default(),
        });
        assert_eq!(state.command_timeout_s, 10);

        state.apply_settings_update(&protocol::SettingsUpdate {
            auto_update: None,
            auto_start: None,
            command_timeout_s: Some(9_999),
            launch_allowlist: None,
            extra: Default::default(),
        });
        assert_eq!(state.command_timeout_s, 600);
    }

    #[test]
    fn persist_runtime_config_updates_only_runtime() {
        let dir = std::env::temp_dir().join(format!(
            "fairypam-agent-persist-runtime-{}",
            std::process::id()
        ));
        let path = dir.join("config.yaml");
        let mut app_config = config::AppConfig::default();
        app_config.hub.ws_url = "ws://127.0.0.1:8000/ws".into();
        app_config.hub.api_key = "secret-key".into();
        app_config.agent.name = "Agent A".into();
        app_config.capture.fps = 12;
        config::save_config(&path, &app_config).unwrap();

        persist_runtime_config(
            &path,
            config::RuntimeConfig {
                auto_update: false,
                auto_start: true,
                command_timeout_s: 120,
                launch_allowlist: vec!["yuanshen.exe".into()],
            },
        )
        .unwrap();

        let loaded = config::load_config(&path).unwrap();
        assert_eq!(loaded.hub.ws_url, "ws://127.0.0.1:8000/ws");
        assert_eq!(loaded.hub.api_key, "secret-key");
        assert_eq!(loaded.agent.name, "Agent A");
        assert_eq!(loaded.capture.fps, 12);
        assert_eq!(
            loaded.runtime,
            config::RuntimeConfig {
                auto_update: false,
                auto_start: true,
                command_timeout_s: 120,
                launch_allowlist: vec!["yuanshen.exe".into()],
            }
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn capture_fps_zero_disables_capture_task() {
        let mut capture = config::CaptureConfig {
            target_display: 0,
            fps: 0,
            jpeg_quality: 90,
            encoder: "media_foundation".into(),
        };

        assert!(!should_start_capture(&capture));

        capture.fps = 1;
        assert!(should_start_capture(&capture));
    }

    #[test]
    fn effective_command_timeout_is_clamped_to_safe_bounds() {
        let mut state = AgentRuntimeState {
            command_timeout_s: 0,
            ..Default::default()
        };
        assert_eq!(state.effective_command_timeout(), Duration::from_secs(10));

        state.command_timeout_s = 900;
        assert_eq!(state.effective_command_timeout(), Duration::from_secs(600));
    }

    #[test]
    fn apply_hub_config_replaces_runtime_state() {
        let mut state = AgentRuntimeState::default();
        state.apply_hub_config(&protocol::HubAgentConfig {
            heartbeat_interval_s: 10,
            command_timeout_s: 45,
            auto_update: true,
            auto_start: false,
            launch_allowlist: vec!["calc.exe".into(), "genshinimpact.exe".into()],
        });

        assert!(state.auto_update);
        assert!(!state.auto_start);
        assert_eq!(state.command_timeout_s, 45);
        assert_eq!(
            state.launch_allowlist,
            vec!["genshinimpact.exe".to_string()]
        );
    }
}
