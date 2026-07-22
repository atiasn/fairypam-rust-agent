use std::sync::{Arc, Mutex};

use fairypam_agent_core::AgentError;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiExitReason {
    ExplicitShutdown,
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

    pub fn process_exited(&mut self, pid: u32) {
        if self.bound_pid == Some(pid) {
            self.exit_reason = Some(GuiExitReason::ProcessExited);
        }
    }

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

    pub fn bind(&self, pid: u32) -> Result<(), AgentError> {
        self.state.lock().map_err(lock_error)?.bind(pid)?;
        if let Err(error) = self.watch_process(pid) {
            self.state.lock().map_err(lock_error)?.watcher_failed(pid);
            self.shutdown.cancel();
            return Err(error);
        }
        Ok(())
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

    #[cfg_attr(test, allow(dead_code))]
    pub fn exit_reason(&self) -> Result<Option<GuiExitReason>, AgentError> {
        Ok(self.state.lock().map_err(lock_error)?.exit_reason())
    }

    #[cfg(all(windows, not(test)))]
    fn watch_process(&self, pid: u32) -> Result<(), AgentError> {
        use windows::Win32::{
            Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
            System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE},
        };

        // SAFETY: pid came from the authenticated Pipe caller; the returned
        // process handle is owned by this watcher and closed on every exit path.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.map_err(|error| {
            AgentError::new("local.lifecycle.process_unavailable", error.to_string())
        })?;
        let raw_handle = handle.0 as usize;
        let state = Arc::clone(&self.state);
        let shutdown = self.shutdown.clone();
        let watcher = std::thread::Builder::new()
            .name("fairypam-gui-lifetime".to_owned())
            .spawn(move || {
                let handle = HANDLE(raw_handle as _);
                // SAFETY: handle is a valid process handle exclusively owned by this thread.
                let exited = unsafe { WaitForSingleObject(handle, INFINITE) } == WAIT_OBJECT_0;
                // SAFETY: no later operation uses handle after this close.
                let _ = unsafe { CloseHandle(handle) };
                if let Ok(mut lifecycle) = state.lock() {
                    if exited {
                        lifecycle.process_exited(pid);
                    } else {
                        lifecycle.watcher_failed(pid);
                    }
                }
                shutdown.cancel();
            });
        if let Err(error) = watcher {
            // SAFETY: the watcher was not started, so this call retains sole ownership.
            let _ = unsafe { CloseHandle(handle) };
            return Err(AgentError::new(
                "local.lifecycle.watch_failed",
                error.to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn watch_process(&self, pid: u32) -> Result<(), AgentError> {
        (self.watch_process)(pid)
    }

    #[cfg(all(not(windows), not(test)))]
    fn watch_process(&self, _pid: u32) -> Result<(), AgentError> {
        Ok(())
    }
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> AgentError {
    AgentError::new("local.lifecycle.state_poisoned", error.to_string())
}
