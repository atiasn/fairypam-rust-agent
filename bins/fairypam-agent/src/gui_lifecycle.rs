use std::sync::{Arc, Mutex};

use fairypam_agent_core::AgentError;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiExitReason {
    ExplicitShutdown,
    MaintenanceShutdown,
    ProcessExited,
    WatcherFailed,
}

#[derive(Debug, Default)]
pub struct LifecycleState {
    bound_pid: Option<u32>,
    exit_reason: Option<GuiExitReason>,
}

impl LifecycleState {
    pub fn bind(&mut self, pid: u32) -> Result<(), AgentError> {
        if pid == 0 {
            return Err(AgentError::new(
                "local.lifecycle.pid_invalid",
                "GUI process id is invalid",
            ));
        }
        match self.bound_pid {
            Some(_) => Err(AgentError::new(
                "local.lifecycle.already_bound",
                "the Agent is already bound to a GUI process",
            )),
            None => {
                self.bound_pid = Some(pid);
                Ok(())
            }
        }
    }

    pub fn request_shutdown(&mut self, pid: u32) -> Result<GuiExitReason, AgentError> {
        self.require_bound_pid(pid)?;
        self.exit_reason = Some(GuiExitReason::ExplicitShutdown);
        Ok(GuiExitReason::ExplicitShutdown)
    }

    pub fn request_maintenance_shutdown(&mut self) -> GuiExitReason {
        self.exit_reason = Some(GuiExitReason::MaintenanceShutdown);
        GuiExitReason::MaintenanceShutdown
    }

    pub fn process_exited(&mut self, pid: u32) {
        if self.bound_pid == Some(pid) {
            self.exit_reason = Some(GuiExitReason::ProcessExited);
        }
    }

    #[cfg(any(windows, test))]
    fn watcher_failed(&mut self, pid: u32) {
        if self.bound_pid == Some(pid) {
            self.exit_reason = Some(GuiExitReason::WatcherFailed);
        }
    }

    pub const fn exit_reason(&self) -> Option<GuiExitReason> {
        self.exit_reason
    }

    fn require_bound_pid(&self, pid: u32) -> Result<(), AgentError> {
        match self.bound_pid {
            None => Err(AgentError::new(
                "local.lifecycle.not_bound",
                "the Agent is not bound to a GUI process",
            )),
            Some(bound_pid) if bound_pid != pid => Err(AgentError::new(
                "local.lifecycle.pid_mismatch",
                "only the bound GUI process may shut down the Agent",
            )),
            Some(_) => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct GuiLifetime {
    state: Arc<Mutex<LifecycleState>>,
    shutdown: CancellationToken,
    #[cfg(test)]
    watch_process: Arc<dyn Fn(u32) -> Result<(), AgentError> + Send + Sync>,
}

impl GuiLifetime {
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            state: Arc::new(Mutex::new(LifecycleState::default())),
            shutdown,
            #[cfg(test)]
            watch_process: Arc::new(|_| Ok(())),
        }
    }

    #[cfg(test)]
    pub fn new_with_watcher(
        shutdown: CancellationToken,
        watch_process: impl Fn(u32) -> Result<(), AgentError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(LifecycleState::default())),
            shutdown,
            watch_process: Arc::new(watch_process),
        }
    }

    #[cfg(test)]
    pub fn bind(&self, pid: u32) -> Result<(), AgentError> {
        self.state.lock().map_err(lock_error)?.bind(pid)?;
        if let Err(error) = self.watch_process(pid) {
            self.shutdown.cancel();
            if let Ok(mut lifecycle) = self.state.lock() {
                lifecycle.watcher_failed(pid);
            }
            return Err(error);
        }
        Ok(())
    }

    #[cfg_attr(test, allow(dead_code))]
    pub fn confirm_bound(&self, pid: u32) -> Result<(), AgentError> {
        self.state
            .lock()
            .map_err(lock_error)?
            .require_bound_pid(pid)
    }

    pub fn request_shutdown(&self, pid: u32) -> Result<GuiExitReason, AgentError> {
        let reason = self
            .state
            .lock()
            .map_err(lock_error)?
            .request_shutdown(pid)?;
        self.shutdown.cancel();
        Ok(reason)
    }

    pub fn request_maintenance_shutdown(&self) -> Result<GuiExitReason, AgentError> {
        let reason = self
            .state
            .lock()
            .map_err(lock_error)?
            .request_maintenance_shutdown();
        self.shutdown.cancel();
        Ok(reason)
    }

    #[cfg_attr(test, allow(dead_code))]
    pub fn exit_reason(&self) -> Result<Option<GuiExitReason>, AgentError> {
        Ok(self.state.lock().map_err(lock_error)?.exit_reason())
    }

    #[cfg(test)]
    fn watch_process(&self, pid: u32) -> Result<(), AgentError> {
        (self.watch_process)(pid)
    }
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> AgentError {
    AgentError::new("local.lifecycle.state_poisoned", error.to_string())
}
