use std::sync::{Arc, Mutex};

use fairypam_agent_core::AgentError;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiExitReason {
    ExplicitShutdown,
    ProcessExited,
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
}

impl GuiLifetime {
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            state: Arc::new(Mutex::new(LifecycleState::default())),
            shutdown,
        }
    }

    pub fn bind(&self, pid: u32) -> Result<(), AgentError> {
        self.state.lock().map_err(lock_error)?.bind(pid)?;
        #[cfg(windows)]
        self.watch_process(pid)?;
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

    pub fn exit_reason(&self) -> Result<Option<GuiExitReason>, AgentError> {
        Ok(self.state.lock().map_err(lock_error)?.exit_reason())
    }

    #[cfg(windows)]
    fn watch_process(&self, pid: u32) -> Result<(), AgentError> {
        use windows::Win32::{
            Foundation::{CloseHandle, WAIT_OBJECT_0},
            System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE},
        };

        // SAFETY: pid came from the authenticated Pipe caller; the returned
        // process handle is owned by this watcher and closed on every exit path.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.map_err(|error| {
            AgentError::new("local.lifecycle.process_unavailable", error.to_string())
        })?;
        let state = Arc::clone(&self.state);
        let shutdown = self.shutdown.clone();
        std::thread::Builder::new()
            .name("fairypam-gui-lifetime".to_owned())
            .spawn(move || {
                // SAFETY: handle is a valid process handle exclusively owned by this thread.
                let exited = unsafe { WaitForSingleObject(handle, INFINITE) } == WAIT_OBJECT_0;
                // SAFETY: no later operation uses handle after this close.
                let _ = unsafe { CloseHandle(handle) };
                if exited {
                    if let Ok(mut lifecycle) = state.lock() {
                        lifecycle.process_exited(pid);
                    }
                    shutdown.cancel();
                }
            })
            .map_err(|error| AgentError::new("local.lifecycle.watch_failed", error.to_string()))?;
        Ok(())
    }
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> AgentError {
    AgentError::new("local.lifecycle.state_poisoned", error.to_string())
}
