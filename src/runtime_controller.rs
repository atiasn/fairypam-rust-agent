use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::thread::JoinHandle;

use anyhow::Result;
use tokio::sync::watch;

use crate::config::AppConfig;

#[derive(Clone, Debug)]
pub struct RuntimeStartSpec {
    pub app_config: AppConfig,
    pub config_path: PathBuf,
    pub log_path: PathBuf,
    pub auto_start_executable: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RuntimePhase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

impl RuntimePhase {
    pub fn label(self) -> &'static str {
        match self {
            RuntimePhase::Stopped => "已停止",
            RuntimePhase::Starting => "启动中",
            RuntimePhase::Running => "运行中",
            RuntimePhase::Stopping => "停止中",
            RuntimePhase::Error => "错误",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            RuntimePhase::Starting | RuntimePhase::Running | RuntimePhase::Stopping
        )
    }
}

#[derive(Debug)]
pub enum RuntimeStatusUpdate {
    Starting,
    Running,
    Stopped(std::result::Result<(), String>),
}

pub type RuntimeRunner = fn(
    RuntimeStartSpec,
    watch::Receiver<bool>,
    mpsc::Sender<RuntimeStatusUpdate>,
) -> Result<JoinHandle<()>>;

#[derive(Debug)]
pub struct RuntimeController {
    phase: RuntimePhase,
    message: String,
    last_spec: Option<RuntimeStartSpec>,
    restart_pending: bool,
    stop_tx: Option<watch::Sender<bool>>,
    status_rx: Option<mpsc::Receiver<RuntimeStatusUpdate>>,
    worker: Option<JoinHandle<()>>,
    runner: RuntimeRunner,
}

impl RuntimeController {
    pub fn new(runner: RuntimeRunner) -> Self {
        Self {
            phase: RuntimePhase::Stopped,
            message: "Agent 未启动".to_string(),
            last_spec: None,
            restart_pending: false,
            stop_tx: None,
            status_rx: None,
            worker: None,
            runner,
        }
    }

    pub fn phase(&self) -> RuntimePhase {
        self.phase
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn set_message(&mut self, message: String) {
        self.message = message;
    }

    pub fn set_error(&mut self, message: String) {
        self.phase = RuntimePhase::Error;
        self.message = message;
    }

    pub fn status_text(&self) -> String {
        format!("{} - {}", self.phase.label(), self.message)
    }

    pub fn can_start(&self) -> bool {
        matches!(self.phase, RuntimePhase::Stopped | RuntimePhase::Error)
    }

    pub fn can_stop(&self) -> bool {
        self.phase.is_active()
    }

    pub fn can_restart(&self) -> bool {
        self.phase.is_active() || matches!(self.phase, RuntimePhase::Stopped | RuntimePhase::Error)
    }

    pub fn start(&mut self, spec: RuntimeStartSpec) -> Result<()> {
        if self.phase.is_active() {
            self.message = "Agent runtime 已在运行".to_string();
            return Ok(());
        }

        self.last_spec = Some(spec.clone());
        self.restart_pending = false;
        self.phase = RuntimePhase::Starting;
        self.message = "正在启动 Agent runtime".to_string();

        let (status_tx, status_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = watch::channel(false);
        let worker = match (self.runner)(spec, stop_rx, status_tx) {
            Ok(worker) => worker,
            Err(err) => {
                self.phase = RuntimePhase::Error;
                self.message = format!("启动线程失败：{err}");
                self.stop_tx = None;
                self.status_rx = None;
                return Err(err);
            }
        };

        self.stop_tx = Some(stop_tx);
        self.status_rx = Some(status_rx);
        self.worker = Some(worker);
        Ok(())
    }

    pub fn request_stop(&mut self) {
        if !self.phase.is_active() {
            self.message = "Agent runtime 当前未运行".to_string();
            return;
        }

        if let Some(stop_tx) = &self.stop_tx {
            let _ = stop_tx.send(true);
        }
        self.phase = RuntimePhase::Stopping;
        self.message = "正在停止 Agent runtime".to_string();
    }

    pub fn request_restart(&mut self, spec: RuntimeStartSpec) -> Result<()> {
        if self.phase.is_active() {
            self.restart_pending = true;
            self.last_spec = Some(spec);
            self.request_stop();
            return Ok(());
        }

        self.start(spec)
    }

    pub fn shutdown_and_wait(&mut self) {
        self.restart_pending = false;
        if let Some(stop_tx) = &self.stop_tx {
            let _ = stop_tx.send(true);
        }
        let join_result = self.worker.take().map(JoinHandle::join);
        self.stop_tx = None;
        self.status_rx = None;
        self.phase = if join_result.is_some_and(|result| result.is_err()) {
            RuntimePhase::Error
        } else {
            RuntimePhase::Stopped
        };
        self.message = if self.phase == RuntimePhase::Error {
            "Agent runtime worker panicked".to_string()
        } else {
            "Agent runtime 已停止".to_string()
        };
    }

    pub fn poll(&mut self) {
        let mut restart_spec = None;
        let mut cleanup_finished = false;

        while let Some(rx) = self.status_rx.as_ref() {
            match rx.try_recv() {
                Ok(RuntimeStatusUpdate::Starting) => {
                    self.phase = RuntimePhase::Starting;
                    self.message = "正在连接 Hub".to_string();
                }
                Ok(RuntimeStatusUpdate::Running) => {
                    self.phase = RuntimePhase::Running;
                    self.message = "Agent runtime 运行中".to_string();
                }
                Ok(RuntimeStatusUpdate::Stopped(result)) => {
                    self.cleanup_finished_worker();
                    self.stop_tx = None;
                    self.status_rx = None;
                    self.phase = if result.is_ok() {
                        RuntimePhase::Stopped
                    } else {
                        RuntimePhase::Error
                    };
                    self.message = result
                        .map(|_| "Agent runtime 已停止".to_string())
                        .unwrap_or_else(|err| format!("Agent runtime 失败：{err}"));
                    if self.restart_pending {
                        self.restart_pending = false;
                        restart_spec = self.last_spec.clone();
                    }
                    cleanup_finished = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if let Some(stop_tx) = &self.stop_tx {
                        let _ = stop_tx.send(true);
                    }
                    self.cleanup_finished_worker();
                    self.stop_tx = None;
                    self.status_rx = None;
                    self.phase = RuntimePhase::Error;
                    self.message = "runtime status channel closed".to_string();
                    cleanup_finished = true;
                    break;
                }
            }
        }

        if !cleanup_finished
            && self
                .worker
                .as_ref()
                .is_some_and(|handle| handle.is_finished())
        {
            self.cleanup_finished_worker();
            self.stop_tx = None;
            self.status_rx = None;
            if matches!(self.phase, RuntimePhase::Stopping) {
                self.phase = RuntimePhase::Stopped;
                self.message = "Agent runtime 已停止".to_string();
            }
        }

        if let Some(spec) = restart_spec {
            if let Err(err) = self.start(spec) {
                self.phase = RuntimePhase::Error;
                self.message = format!("自动重启失败：{err}");
            }
        }
    }

    fn cleanup_finished_worker(&mut self) {
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;

    fn waiting_runner(
        _spec: RuntimeStartSpec,
        mut stop_rx: watch::Receiver<bool>,
        status_tx: mpsc::Sender<RuntimeStatusUpdate>,
    ) -> Result<JoinHandle<()>> {
        Ok(std::thread::spawn(move || {
            let _status_tx = status_tx;
            while !*stop_rx.borrow() {
                if stop_rx.has_changed().unwrap_or(true) {
                    let _ = stop_rx.borrow_and_update();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }))
    }

    #[test]
    fn worker_creation_stays_starting_until_ready_update() {
        let mut controller = RuntimeController::new(waiting_runner);
        controller
            .start(RuntimeStartSpec {
                app_config: AppConfig::default(),
                config_path: PathBuf::new(),
                log_path: PathBuf::new(),
                auto_start_executable: None,
            })
            .unwrap();

        controller.poll();

        assert_eq!(controller.phase(), RuntimePhase::Starting);
        controller.shutdown_and_wait();
    }

    #[test]
    fn disconnected_status_channel_stops_and_joins_live_worker() {
        static JOINED: AtomicBool = AtomicBool::new(false);

        fn runner(
            _spec: RuntimeStartSpec,
            mut stop_rx: watch::Receiver<bool>,
            status_tx: mpsc::Sender<RuntimeStatusUpdate>,
        ) -> Result<JoinHandle<()>> {
            drop(status_tx);
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
        let mut controller = RuntimeController::new(runner);
        controller
            .start(RuntimeStartSpec {
                app_config: AppConfig::default(),
                config_path: PathBuf::new(),
                log_path: PathBuf::new(),
                auto_start_executable: None,
            })
            .unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let poller = std::thread::spawn(move || {
            controller.poll();
            done_tx.send(controller.phase()).unwrap();
        });

        let phase = done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("poll must stop and join a live worker after status disconnect");
        poller.join().unwrap();
        assert_eq!(phase, RuntimePhase::Error);
        assert!(JOINED.load(Ordering::SeqCst));
    }

    #[test]
    fn running_runtime_returns_to_starting_during_reconnect() {
        let mut controller = RuntimeController::new(waiting_runner);
        let (status_tx, status_rx) = mpsc::channel();
        controller.status_rx = Some(status_rx);

        status_tx.send(RuntimeStatusUpdate::Running).unwrap();
        controller.poll();
        assert_eq!(controller.phase(), RuntimePhase::Running);

        status_tx.send(RuntimeStatusUpdate::Starting).unwrap();
        controller.poll();
        assert_eq!(controller.phase(), RuntimePhase::Starting);
        assert_eq!(controller.message(), "正在连接 Hub");

        status_tx.send(RuntimeStatusUpdate::Running).unwrap();
        controller.poll();
        assert_eq!(controller.phase(), RuntimePhase::Running);
    }

    #[test]
    fn shutdown_and_wait_joins_runtime_worker() {
        static JOINED: AtomicBool = AtomicBool::new(false);

        fn runner(
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
        let mut controller = RuntimeController::new(runner);
        controller
            .start(RuntimeStartSpec {
                app_config: AppConfig::default(),
                config_path: PathBuf::new(),
                log_path: PathBuf::new(),
                auto_start_executable: None,
            })
            .unwrap();

        controller.shutdown_and_wait();

        assert!(JOINED.load(Ordering::SeqCst));
        assert_eq!(controller.phase(), RuntimePhase::Stopped);
    }
}
