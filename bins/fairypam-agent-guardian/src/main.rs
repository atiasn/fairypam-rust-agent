#[cfg(any(windows, test))]
use std::io::Write;
#[cfg(windows)]
use std::sync::mpsc;
#[cfg(any(windows, test))]
use std::time::Duration;
use std::time::Instant;

use fairypam_agent_guardian::monitor::{GuardianMonitor, ReleaseDriver};
#[cfg(any(windows, test))]
use fairypam_agent_guardian_protocol::encode_response;
#[cfg(windows)]
use fairypam_agent_guardian_protocol::{decode_request, read_bounded_frame};
use fairypam_agent_guardian_protocol::{
    GuardianRequest, GuardianResponse, PhysicalHold, ReleaseReason,
};
#[cfg(windows)]
use fairypam_agent_protocol::{connect_local_agent_pipe, SecureLocalPipeListener};

fn main() {
    let result = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [argument] if argument == "--supervise" => run_supervisor(),
        [argument] if argument == "--self-test" => self_test(),
        _ => Err("guardian arguments are invalid".into()),
    };
    if let Err(error) = result {
        eprintln!("guardian fatal: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run_supervisor() -> Result<(), String> {
    use std::io::Read;
    use std::sync::mpsc::RecvTimeoutError;

    if std::env::vars_os().any(|(name, _)| {
        name.to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("FAIRYPAM_")
    }) {
        return Err("guardian environment contains a forbidden FairyPam variable".into());
    }
    let install_root = supervisor_install_root()?;
    fairypam_agent_suite::windows_security::verify_trusted_install_entry(&install_root, true)
        .map_err(|error| error.to_string())?;
    let mut activation = ActivationWatch::load(&install_root)?;
    let (owner_tx, owner_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guardian-owner".into())
        .spawn(move || {
            let mut input = std::io::stdin().lock();
            let mut buffer = [0_u8; 1];
            while matches!(input.read(&mut buffer), Ok(1)) {}
            let _ = owner_tx.send(());
        })
        .map_err(|error| error.to_string())?;

    let mut backoff = Duration::from_millis(250);
    let mut agent_generation = 0_u64;
    loop {
        let started = Instant::now();
        let agent = fairypam_agent_suite::resolve_active_suite(&install_root)
            .map_err(|error| error.to_string())?
            .version_root
            .join("fairypam-agent.exe");
        agent_generation = agent_generation
            .checked_add(1)
            .ok_or_else(|| "guardian Agent generation exhausted".to_owned())?;
        let pipe_name = format!(
            r"\\.\pipe\FairyPam.Guardian.v1.{}.{}",
            std::process::id(),
            agent_generation
        );
        let listener = match SecureLocalPipeListener::bind(&pipe_name) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("guardian pipe start failed: {error}");
                if let Some(watch) = activation.take() {
                    watch.rollback()?;
                    return Ok(());
                }
                return Err(error.to_string());
            }
        };
        let mut child = match spawn_agent(&agent, &pipe_name) {
            Ok(child) => child,
            Err(error) => {
                eprintln!("guardian agent start failed: {error}");
                if let Some(watch) = activation.take() {
                    watch.rollback()?;
                    return Ok(());
                }
                match owner_rx.recv_timeout(backoff) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
                    Err(RecvTimeoutError::Timeout) => {
                        backoff = (backoff * 2).min(Duration::from_secs(5));
                        continue;
                    }
                }
            }
        };
        let outcome = match supervise_agent(
            &mut child,
            &owner_rx,
            activation.as_mut(),
            listener,
            &pipe_name,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if activation
                    .as_ref()
                    .is_some_and(|watch| activation_failure_requires_rollback(watch.promoted()))
                {
                    let watch = activation.take().expect("pending activation is present");
                    watch.rollback()?;
                }
                return Err(error);
            }
        };
        match outcome {
            SupervisorOutcome::OwnerStopped => return Ok(()),
            SupervisorOutcome::Restart { failed } => {
                if activation.as_ref().is_some_and(|watch| {
                    activation_termination_requires_rollback(watch.promoted(), failed)
                }) {
                    let watch = activation.take().expect("pending activation is present");
                    watch.rollback()?;
                    return Ok(());
                }
                if activation.as_ref().is_some_and(ActivationWatch::promoted) {
                    activation = None;
                }
            }
        }
        if activation.as_ref().is_some_and(ActivationWatch::promoted) {
            activation = None;
        }
        if started.elapsed() >= Duration::from_secs(30) {
            backoff = Duration::from_millis(250);
        } else {
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
        match owner_rx.recv_timeout(backoff) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

#[cfg(not(windows))]
fn run_supervisor() -> Result<(), String> {
    Err("guardian supervision is only supported on Windows".into())
}

#[cfg(windows)]
enum SupervisorOutcome {
    OwnerStopped,
    Restart { failed: bool },
}

#[cfg(windows)]
struct ActivationWatch {
    install_root: std::path::PathBuf,
    pending: fairypam_agent_suite::RollbackPending,
    health: ActivationHealthWindow,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
struct ActivationHealthWindow {
    started: Instant,
    last_worker_healthy: Option<Instant>,
    promoted: bool,
}

#[cfg(any(windows, test))]
impl ActivationHealthWindow {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            last_worker_healthy: None,
            promoted: false,
        }
    }

    fn observe_worker_health(&mut self, ready: bool, now: Instant) -> bool {
        if ready {
            self.last_worker_healthy = Some(now);
        }
        ready
    }

    fn worker_health_stale(&self, now: Instant) -> bool {
        !self.promoted
            && now.duration_since(self.last_worker_healthy.unwrap_or(self.started))
                >= Duration::from_secs(12)
    }

    fn ready_to_promote(&self, now: Instant) -> bool {
        !self.promoted
            && self.last_worker_healthy == Some(now)
            && now.duration_since(self.started) >= Duration::from_secs(30)
    }
}

#[cfg(windows)]
impl ActivationWatch {
    fn load(install_root: &std::path::Path) -> Result<Option<Self>, String> {
        let Some(pending) = fairypam_agent_suite::read_rollback_pending(install_root)
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let active = fairypam_agent_suite::resolve_active_suite(install_root)
            .map_err(|error| error.to_string())?;
        if active.pointer != pending.candidate {
            return Err("rollback candidate does not match the active suite".into());
        }
        Ok(Some(Self {
            install_root: install_root.to_path_buf(),
            pending,
            health: ActivationHealthWindow::new(Instant::now()),
        }))
    }

    fn observe_worker_health(&mut self, ready: bool, now: Instant) -> Result<(), String> {
        if !self.health.observe_worker_health(ready, now) {
            return Err("candidate Worker is unhealthy".into());
        }
        self.promote_if_due(now)
    }

    fn worker_health_stale(&self, now: Instant) -> bool {
        self.health.worker_health_stale(now)
    }

    fn promote_if_due(&mut self, now: Instant) -> Result<(), String> {
        if self.health.ready_to_promote(now) {
            let active = fairypam_agent_suite::resolve_active_suite(&self.install_root)
                .map_err(|error| error.to_string())?;
            if active.pointer != self.pending.candidate {
                return Err("active suite changed during its health window".into());
            }
            fairypam_agent_suite::clear_rollback_pending(&self.install_root)
                .map_err(|error| error.to_string())?;
            self.health.promoted = true;
        }
        Ok(())
    }

    const fn promoted(&self) -> bool {
        self.health.promoted
    }

    fn rollback(self) -> Result<(), String> {
        if self.health.promoted {
            return Ok(());
        }
        fairypam_agent_suite::activate_suite_pointer(&self.install_root, &self.pending.previous)
            .map_err(|error| error.to_string())?;
        fairypam_agent_suite::clear_rollback_pending(&self.install_root)
            .map_err(|error| error.to_string())
    }
}

#[cfg(any(windows, test))]
const fn activation_failure_requires_rollback(promoted: bool) -> bool {
    !promoted
}

#[cfg(any(windows, test))]
const fn activation_termination_requires_rollback(promoted: bool, _failed: bool) -> bool {
    !promoted
}

#[cfg(windows)]
enum AgentEvent {
    Request(GuardianRequest, mpsc::SyncSender<GuardianResponse>),
    Closed,
    Invalid(String),
}

#[cfg(windows)]
fn supervise_agent(
    child: &mut std::process::Child,
    owner: &mpsc::Receiver<()>,
    activation: Option<&mut ActivationWatch>,
    listener: SecureLocalPipeListener,
    pipe_name: &str,
) -> Result<SupervisorOutcome, String> {
    let mut monitor = GuardianMonitor::new(SystemReleaseDriver);
    let outcome =
        supervise_agent_inner(child, owner, activation, listener, pipe_name, &mut monitor);
    finalize_supervision(outcome, child, &mut monitor)
}

#[cfg(windows)]
fn supervise_agent_inner(
    child: &mut std::process::Child,
    owner: &mpsc::Receiver<()>,
    mut activation: Option<&mut ActivationWatch>,
    mut listener: SecureLocalPipeListener,
    pipe_name: &str,
    monitor: &mut GuardianMonitor<SystemReleaseDriver>,
) -> Result<SupervisorOutcome, String> {
    use std::os::windows::io::AsRawHandle;

    monitor.register_agent(
        child.id(),
        child.as_raw_handle() as usize as u64,
        Duration::from_secs(2),
        Instant::now(),
    )?;
    let (connected_tx, connected_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guardian-pipe-accept".into())
        .spawn(move || {
            let _ = connected_tx.send(listener.accept().map_err(|error| error.to_string()));
        })
        .map_err(|error| error.to_string())?;
    let connect_deadline = Instant::now() + Duration::from_secs(3);
    let mut pipe = loop {
        match owner.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                let _ = connect_local_agent_pipe(pipe_name, Duration::from_millis(100));
                stop_agent(child, monitor, ReleaseReason::EmergencyStop)?;
                return Ok(SupervisorOutcome::OwnerStopped);
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            let _ = connect_local_agent_pipe(pipe_name, Duration::from_millis(100));
            release_on_exit(monitor)?;
            return Ok(SupervisorOutcome::Restart {
                failed: !status.success(),
            });
        }
        match connected_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(Ok(pipe)) => break pipe,
            Ok(Err(error)) => return Err(error),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("guardian pipe accept worker disconnected".into())
            }
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= connect_deadline => {
                let _ = connect_local_agent_pipe(pipe_name, Duration::from_millis(100));
                stop_agent(child, monitor, ReleaseReason::GuardianFailure)?;
                return Ok(SupervisorOutcome::Restart { failed: true });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    let (events_tx, events_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guardian-agent".into())
        .spawn(move || loop {
            let request = match read_bounded_frame(&mut pipe) {
                Ok(Some(frame)) => match decode_request(&frame) {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = events_tx.send(AgentEvent::Invalid(error.to_string()));
                        break;
                    }
                },
                Ok(None) => {
                    let _ = events_tx.send(AgentEvent::Closed);
                    break;
                }
                Err(error) => {
                    let _ = events_tx.send(AgentEvent::Invalid(error.to_string()));
                    break;
                }
            };
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            if events_tx
                .send(AgentEvent::Request(request, reply_tx))
                .is_err()
            {
                break;
            }
            let Ok(response) = reply_rx.recv() else {
                break;
            };
            let response = match encode_response(&response) {
                Ok(response) => response,
                Err(error) => {
                    let _ = events_tx.send(AgentEvent::Invalid(error.to_string()));
                    break;
                }
            };
            if pipe
                .write_all(&response)
                .and_then(|_| pipe.flush())
                .is_err()
            {
                let _ = events_tx.send(AgentEvent::Closed);
                break;
            }
        })
        .map_err(|error| error.to_string())?;

    loop {
        match owner.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                drop(events_rx);
                stop_agent(child, monitor, ReleaseReason::EmergencyStop)?;
                return Ok(SupervisorOutcome::OwnerStopped);
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            release_on_exit(monitor)?;
            return Ok(SupervisorOutcome::Restart {
                failed: !status.success(),
            });
        }
        if activation
            .as_deref()
            .is_some_and(|watch| watch.worker_health_stale(Instant::now()))
        {
            drop(events_rx);
            stop_agent(child, monitor, ReleaseReason::PlatformFailure)?;
            return Ok(SupervisorOutcome::Restart { failed: true });
        }
        match events_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(AgentEvent::Request(request, reply)) => {
                let worker_health = match &request {
                    GuardianRequest::WorkerHealth { ready } => Some(*ready),
                    _ => None,
                };
                let mut response = match request {
                    GuardianRequest::RegisterAgent { .. } => GuardianResponse::Error {
                        code: "guardian.agent_already_registered".into(),
                        message: "guardian.agent_already_registered".into(),
                    },
                    request => monitor.handle(request, Instant::now()),
                };
                let mut candidate_failed = false;
                if let Some(ready) = worker_health {
                    if let Some(watch) = activation.as_deref_mut() {
                        if !watch.promoted() {
                            candidate_failed =
                                watch.observe_worker_health(ready, Instant::now()).is_err();
                        }
                    }
                }
                if let GuardianResponse::Ack {
                    activation_pending, ..
                } = &mut response
                {
                    *activation_pending =
                        activation.as_deref().is_some_and(|watch| !watch.promoted());
                }
                if reply.send(response).is_err() {
                    drop(events_rx);
                    stop_agent(child, monitor, ReleaseReason::GuardianFailure)?;
                    return Ok(SupervisorOutcome::Restart { failed: true });
                }
                if candidate_failed {
                    drop(events_rx);
                    stop_agent(child, monitor, ReleaseReason::PlatformFailure)?;
                    return Ok(SupervisorOutcome::Restart { failed: true });
                }
            }
            Ok(AgentEvent::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop_agent(child, monitor, ReleaseReason::AgentDisconnected)?;
                return Ok(SupervisorOutcome::Restart { failed: true });
            }
            Ok(AgentEvent::Invalid(message)) => {
                eprintln!("guardian invalid agent message: {message}");
                stop_agent(child, monitor, ReleaseReason::GuardianFailure)?;
                return Ok(SupervisorOutcome::Restart { failed: true });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        monitor.tick(Instant::now(), true)?;
        if monitor.last_release_reason() == Some(ReleaseReason::HeartbeatExpired) {
            drop(events_rx);
            stop_agent(child, monitor, ReleaseReason::HeartbeatExpired)?;
            return Ok(SupervisorOutcome::Restart { failed: true });
        }
    }
}

#[cfg(windows)]
fn supervisor_install_root() -> Result<std::path::PathBuf, String> {
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    let version_root = current
        .parent()
        .ok_or_else(|| "guardian version directory is unavailable".to_owned())?;
    let versions = version_root
        .parent()
        .ok_or_else(|| "guardian versions directory is unavailable".to_owned())?;
    if versions.file_name().and_then(|value| value.to_str()) != Some("versions") {
        return Err("guardian is outside the installed suite".into());
    }
    versions
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| "guardian install root is unavailable".to_owned())
}

#[cfg(windows)]
fn spawn_agent(path: &std::path::Path, pipe_name: &str) -> Result<std::process::Child, String> {
    use std::process::{Command, Stdio};

    let mut command = Command::new(path);
    command
        .arg("--guardian-pipe")
        .arg(pipe_name)
        .env_clear()
        .env("SystemDrive", r"C:")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    command.spawn().map_err(|error| error.to_string())
}

#[cfg(windows)]
fn stop_agent<R: ReleaseDriver>(
    child: &mut std::process::Child,
    monitor: &mut GuardianMonitor<R>,
    reason: ReleaseReason,
) -> Result<(), String> {
    stop_agent_with_grace(child, monitor, reason, Duration::from_secs(5))
}

#[cfg(any(windows, test))]
fn stop_agent_with_grace<R: ReleaseDriver>(
    child: &mut std::process::Child,
    monitor: &mut GuardianMonitor<R>,
    reason: ReleaseReason,
    grace: Duration,
) -> Result<(), String> {
    let holds = monitor.release_holds();
    if let Err(error) = monitor.release_all(reason) {
        eprintln!("guardian pre-stop release failed: {error}");
    }
    let termination = terminate_agent(child, grace);
    let final_release = monitor.release_snapshot(&holds);
    match (termination, final_release) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(termination), Ok(())) => Err(termination),
        (Ok(()), Err(release)) => Err(release),
        (Err(termination), Err(release)) => {
            Err(format!("{termination}; final release failed: {release}"))
        }
    }
}

#[cfg(any(windows, test))]
fn terminate_agent(child: &mut std::process::Child, grace: Duration) -> Result<(), String> {
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    child.wait().map(|_| ()).map_err(|error| error.to_string())
}

#[cfg(any(windows, test))]
fn cleanup_after_supervision_error<R: ReleaseDriver>(
    child: &mut std::process::Child,
    monitor: &mut GuardianMonitor<R>,
) -> Result<(), String> {
    let termination = terminate_agent(child, Duration::ZERO);
    let release = monitor.release_all(ReleaseReason::GuardianFailure);
    termination?;
    release
}

#[cfg(any(windows, test))]
fn finalize_supervision<T, R: ReleaseDriver>(
    outcome: Result<T, String>,
    child: &mut std::process::Child,
    monitor: &mut GuardianMonitor<R>,
) -> Result<T, String> {
    match outcome {
        Ok(outcome) => Ok(outcome),
        Err(error) => match cleanup_after_supervision_error(child, monitor) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; Guardian cleanup failed: {cleanup}")),
        },
    }
}

fn self_test() -> Result<(), String> {
    let mut monitor = GuardianMonitor::new(SystemReleaseDriver);
    let now = Instant::now();
    let pid = std::process::id();
    for (request, expected) in [
        (
            GuardianRequest::RegisterAgent {
                agent_pid: pid,
                agent_process_handle: 1,
                heartbeat_timeout_ms: 5_000,
                isolation_key_name: None,
            },
            GuardianResponse::Ack {
                isolation_status: None,
                activation_pending: false,
            },
        ),
        (
            GuardianRequest::Heartbeat { sequence: 0 },
            GuardianResponse::Ack {
                isolation_status: None,
                activation_pending: false,
            },
        ),
        (
            GuardianRequest::Status {},
            GuardianResponse::Status {
                agent_pid: Some(pid),
                committed_hold_count: 0,
                last_sequence: 0,
            },
        ),
        (
            GuardianRequest::ReleaseAll {
                reason: ReleaseReason::EmergencyStop,
            },
            GuardianResponse::Ack {
                isolation_status: None,
                activation_pending: false,
            },
        ),
    ] {
        if monitor.handle(request, now) != expected {
            return Err("guardian self-test failed".into());
        }
    }
    Ok(())
}

#[cfg(test)]
fn write_response_or_release<R: ReleaseDriver, W: Write>(
    monitor: &mut GuardianMonitor<R>,
    writer: &mut W,
    response: &GuardianResponse,
) -> Result<(), String> {
    let result = encode_response(response)
        .map_err(|error| error.to_string())
        .and_then(|line| writer.write_all(&line).map_err(|error| error.to_string()))
        .and_then(|()| writer.flush().map_err(|error| error.to_string()));
    if let Err(write_error) = result {
        return match release_on_exit(monitor) {
            Ok(()) => Err(write_error),
            Err(release_error) => Err(format!(
                "{write_error}; Guardian release after response failure also failed: {release_error}"
            )),
        };
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn release_on_exit<R: ReleaseDriver>(monitor: &mut GuardianMonitor<R>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(300);
    loop {
        match monitor.release_all(ReleaseReason::AgentExited) {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() < deadline => {
                eprintln!("guardian exit release retry: {error}");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("guardian exit release failed: {error}")),
        }
    }
}

struct SystemReleaseDriver;

#[cfg(windows)]
impl ReleaseDriver for SystemReleaseDriver {
    fn release_all(&mut self, holds: &[PhysicalHold]) -> Result<(), String> {
        use fairypam_agent_guardian_protocol::MouseButton;
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT,
            KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_LEFTUP,
            MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
        };

        let inputs: Vec<INPUT> = holds
            .iter()
            .map(|hold| match hold {
                PhysicalHold::ScanCode {
                    scan_code,
                    extended,
                    ..
                } => INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: *scan_code,
                            dwFlags: KEYEVENTF_SCANCODE
                                | KEYEVENTF_KEYUP
                                | if *extended {
                                    KEYEVENTF_EXTENDEDKEY
                                } else {
                                    Default::default()
                                },
                            time: 0,
                            dwExtraInfo: 0x4650_414D,
                        },
                    },
                },
                PhysicalHold::MouseButton { button, .. } => INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dx: 0,
                            dy: 0,
                            mouseData: match button {
                                MouseButton::X1 => 1,
                                MouseButton::X2 => 2,
                                _ => 0,
                            },
                            dwFlags: match button {
                                MouseButton::Left => MOUSEEVENTF_LEFTUP,
                                MouseButton::Right => MOUSEEVENTF_RIGHTUP,
                                MouseButton::Middle => MOUSEEVENTF_MIDDLEUP,
                                MouseButton::X1 | MouseButton::X2 => MOUSEEVENTF_XUP,
                            },
                            time: 0,
                            dwExtraInfo: 0x4650_414D,
                        },
                    },
                },
            })
            .collect();
        if inputs.is_empty() {
            return Ok(());
        }
        let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent == inputs.len() as u32 {
            Ok(())
        } else {
            Err(format!("SendInput sent {sent}/{} releases", inputs.len()))
        }
    }
}

#[cfg(not(windows))]
impl ReleaseDriver for SystemReleaseDriver {
    fn release_all(&mut self, holds: &[PhysicalHold]) -> Result<(), String> {
        if holds.is_empty() {
            Ok(())
        } else {
            Err("guardian physical release is only supported on Windows".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use fairypam_agent_guardian_protocol::{ActionId, PhysicalHold};

    use super::*;

    #[derive(Default)]
    struct RecordingRelease {
        calls: usize,
    }

    impl ReleaseDriver for RecordingRelease {
        fn release_all(&mut self, _holds: &[PhysicalHold]) -> Result<(), String> {
            self.calls += 1;
            Ok(())
        }
    }

    fn sleeping_child() -> std::process::Child {
        #[cfg(windows)]
        return std::process::Command::new("cmd")
            .args(["/C", "ping -n 31 127.0.0.1 >NUL"])
            .spawn()
            .unwrap();
        #[cfg(not(windows))]
        return std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
    }

    fn monitor_with_hold(pid: u32) -> GuardianMonitor<RecordingRelease> {
        let mut monitor = GuardianMonitor::new(RecordingRelease::default());
        monitor
            .register_agent(pid, 1, Duration::from_secs(2), Instant::now())
            .unwrap();
        monitor
            .register_intent(
                1,
                vec![PhysicalHold::ScanCode {
                    action_id: ActionId::new("music.note.a").unwrap(),
                    scan_code: 30,
                    extended: false,
                }],
            )
            .unwrap();
        monitor.commit_holds(1).unwrap();
        monitor
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn installed_binary_self_test_covers_registration_heartbeat_and_release() {
        self_test().unwrap();
    }

    #[test]
    fn any_pre_promotion_agent_exit_requires_suite_rollback() {
        assert!(activation_failure_requires_rollback(false));
        assert!(!activation_failure_requires_rollback(true));
        for failed in [false, true] {
            assert!(activation_termination_requires_rollback(false, failed));
            assert!(!activation_termination_requires_rollback(true, failed));
        }
    }

    #[test]
    fn candidate_health_window_requires_fresh_worker_health_for_promotion() {
        let started = Instant::now();
        let mut window = ActivationHealthWindow::new(started);
        assert!(!window.observe_worker_health(false, started));
        assert!(window.worker_health_stale(started + Duration::from_secs(12)));

        window = ActivationHealthWindow::new(started);
        let before = started + Duration::from_secs(29);
        assert!(window.observe_worker_health(true, before));
        assert!(!window.ready_to_promote(before));
        let due = started + Duration::from_secs(30);
        assert!(window.observe_worker_health(true, due));
        assert!(window.ready_to_promote(due));

        window.promoted = true;
        assert!(!window.worker_health_stale(due + Duration::from_secs(60)));
        assert!(!activation_failure_requires_rollback(window.promoted));
    }

    #[test]
    fn broken_response_pipe_releases_registered_input_before_exit() {
        let now = Instant::now();
        let mut monitor = GuardianMonitor::new(RecordingRelease::default());
        monitor
            .register_agent(42, 1, Duration::from_millis(300), now)
            .unwrap();
        monitor
            .register_intent(
                1,
                vec![PhysicalHold::ScanCode {
                    action_id: ActionId::new("movement.forward").unwrap(),
                    scan_code: 17,
                    extended: false,
                }],
            )
            .unwrap();
        monitor.commit_holds(1).unwrap();

        let error = write_response_or_release(
            &mut monitor,
            &mut BrokenWriter,
            &GuardianResponse::Ack {
                isolation_status: None,
                activation_pending: false,
            },
        )
        .unwrap_err();

        assert!(error.contains("reader closed"));
        assert_eq!(monitor.release_driver().calls, 1);
        assert!(monitor.committed_holds().is_empty());
    }

    #[test]
    fn supervision_error_releases_and_reaps_the_spawned_agent() {
        let mut child = sleeping_child();
        let mut monitor = monitor_with_hold(child.id());

        let result: Result<(), String> = finalize_supervision(
            Err("injected supervisor failure".into()),
            &mut child,
            &mut monitor,
        );

        assert!(result.unwrap_err().contains("injected supervisor failure"));
        assert_eq!(monitor.release_driver().calls, 1);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn forced_stop_releases_again_after_the_agent_is_reaped() {
        let mut child = sleeping_child();
        let mut monitor = monitor_with_hold(child.id());

        assert!(stop_agent_with_grace(
            &mut child,
            &mut monitor,
            ReleaseReason::EmergencyStop,
            Duration::ZERO,
        )
        .is_ok());

        assert!(child.try_wait().unwrap().is_some());
        assert_eq!(monitor.release_driver().calls, 2);
    }
}
