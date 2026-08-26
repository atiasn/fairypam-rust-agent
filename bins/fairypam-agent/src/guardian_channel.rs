use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use fairypam_agent_core::profile::ActionDefinition;
use fairypam_agent_core::AgentError;
use fairypam_agent_guardian_protocol::{
    decode_response, encode_request, read_bounded_frame, ActionId, GuardianRequest,
    GuardianResponse, MouseButton, PhysicalHold, ReleaseReason,
};
#[cfg(windows)]
use fairypam_agent_protocol::connect_local_agent_pipe;
use tokio_util::sync::CancellationToken;

use crate::execution::CommandExecutor;
use crate::profile_store::ProfileStore;

const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(500);
const START_TIMEOUT: Duration = Duration::from_secs(3);

pub struct GuardianChannel {
    stop: mpsc::SyncSender<()>,
    thread: Option<JoinHandle<Result<(), AgentError>>>,
}

impl GuardianChannel {
    pub fn start(
        profiles: &ProfileStore,
        runtime_shutdown: CancellationToken,
        pipe_name: String,
        execution: Arc<Mutex<CommandExecutor>>,
    ) -> Result<Self, AgentError> {
        let holds = release_set(profiles)?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (stop, stop_rx) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("fairypam-guardian".into())
            .spawn(move || {
                run(
                    holds,
                    runtime_shutdown,
                    pipe_name,
                    execution,
                    ready_tx,
                    stop_rx,
                )
            })
            .map_err(|error| AgentError::new("guardian.start_failed", error.to_string()))?;
        ready_rx.recv_timeout(START_TIMEOUT).map_err(|_| {
            AgentError::new(
                "guardian.start_failed",
                "Guardian did not accept the release set before the deadline",
            )
        })??;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    pub fn stop(mut self) -> Result<(), AgentError> {
        let _ = self.stop.send(());
        self.thread
            .take()
            .expect("Guardian thread is present")
            .join()
            .map_err(|_| AgentError::new("guardian.thread_failed", "Guardian thread panicked"))?
    }
}

fn run(
    holds: Vec<PhysicalHold>,
    runtime_shutdown: CancellationToken,
    pipe_name: String,
    execution: Arc<Mutex<CommandExecutor>>,
    ready: mpsc::SyncSender<Result<(), AgentError>>,
    stop: mpsc::Receiver<()>,
) -> Result<(), AgentError> {
    #[cfg(not(windows))]
    let _ = (
        &holds,
        &runtime_shutdown,
        &pipe_name,
        &execution,
        &ready,
        &stop,
    );
    #[cfg(not(windows))]
    return Err(AgentError::new(
        "guardian.platform_unsupported",
        "Guardian control pipe requires Windows",
    ));

    #[cfg(windows)]
    let mut pipe = connect_local_agent_pipe(&pipe_name, START_TIMEOUT)
        .map_err(|error| AgentError::new("guardian.connect_failed", error.to_string()))?;
    let sequence = 1;
    let initialized = exchange(
        &mut pipe,
        &GuardianRequest::RegisterIntent { sequence, holds },
    )
    .and_then(|_| exchange(&mut pipe, &GuardianRequest::CommitHolds { sequence }));
    let ready_result = initialized
        .as_ref()
        .map(|_| ())
        .map_err(|error| AgentError::new(error.code(), error.to_string()));
    let _ = ready.send(ready_result);
    let mut activation_pending = initialized?;
    let (health_tx, health_rx) = mpsc::channel();
    let mut health_probe_running = false;

    loop {
        match health_rx.try_recv() {
            Ok(worker_ready) => {
                health_probe_running = false;
                if activation_pending {
                    exchange(
                        &mut pipe,
                        &GuardianRequest::WorkerHealth {
                            ready: worker_ready,
                        },
                    )?;
                } else if !worker_ready {
                    tracing::warn!(
                        code = "worker.health_failed",
                        "stable Worker health check failed; Worker will be restarted without restarting Agent"
                    );
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(AgentError::new(
                    "worker.health_probe_failed",
                    "Worker health probe disconnected",
                ));
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if !health_probe_running {
            health_probe_running = true;
            let execution = Arc::clone(&execution);
            let health_tx = health_tx.clone();
            std::thread::Builder::new()
                .name("fairypam-worker-health".into())
                .spawn(move || {
                    let ready = execution
                        .lock()
                        .map_err(|error| {
                            AgentError::new("worker.state_poisoned", error.to_string())
                        })
                        .and_then(|mut execution| execution.ensure_worker_ready())
                        .is_ok();
                    let _ = health_tx.send(ready);
                })
                .map_err(|error| {
                    AgentError::new("worker.health_probe_failed", error.to_string())
                })?;
        }
        match stop.recv_timeout(HEARTBEAT_INTERVAL) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return exchange(
                    &mut pipe,
                    &GuardianRequest::ReleaseAll {
                        reason: ReleaseReason::AgentExited,
                    },
                )
                .map(|_| ());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                match exchange(&mut pipe, &GuardianRequest::Heartbeat { sequence }) {
                    Ok(pending) => activation_pending = pending,
                    Err(error) => {
                        runtime_shutdown.cancel();
                        return Err(error);
                    }
                }
            }
        }
    }
}

fn exchange(pipe: &mut (impl Read + Write), request: &GuardianRequest) -> Result<bool, AgentError> {
    pipe.write_all(&encode_request(request).map_err(protocol_error)?)
        .and_then(|_| pipe.flush())
        .map_err(|error| AgentError::new("guardian.write_failed", error.to_string()))?;
    let frame = read_bounded_frame(pipe)
        .map_err(protocol_error)?
        .ok_or_else(|| AgentError::new("guardian.disconnected", "Guardian response pipe closed"))?;
    match decode_response(&frame).map_err(protocol_error)? {
        GuardianResponse::Ack {
            activation_pending, ..
        } => Ok(activation_pending),
        GuardianResponse::Error { code, .. } => Err(AgentError::new(
            "guardian.rejected",
            format!("Guardian rejected the request with {code}"),
        )),
        GuardianResponse::Status { .. } => Err(AgentError::new(
            "guardian.response_invalid",
            "Guardian returned an unexpected response",
        )),
    }
}

fn release_set(profiles: &ProfileStore) -> Result<Vec<PhysicalHold>, AgentError> {
    let mut keys = BTreeSet::new();
    for profile in profiles.installed() {
        for action in profile.profile().actions.values() {
            if let ActionDefinition::Hold {
                physical_scan_code,
                extended,
                ..
            }
            | ActionDefinition::Pulse {
                physical_scan_code,
                extended,
                ..
            } = action
            {
                keys.insert((*physical_scan_code, *extended));
            }
        }
    }
    let mut holds = keys
        .into_iter()
        .map(|(scan_code, extended)| {
            Ok(PhysicalHold::ScanCode {
                action_id: ActionId::new(format!(
                    "guardian.key.{scan_code:04x}.{}",
                    u8::from(extended)
                ))
                .map_err(protocol_error)?,
                scan_code,
                extended,
            })
        })
        .collect::<Result<Vec<_>, AgentError>>()?;
    holds.extend(
        [
            ("left", MouseButton::Left),
            ("right", MouseButton::Right),
            ("middle", MouseButton::Middle),
            ("x1", MouseButton::X1),
            ("x2", MouseButton::X2),
        ]
        .into_iter()
        .map(|(name, button)| {
            Ok(PhysicalHold::MouseButton {
                action_id: ActionId::new(format!("guardian.mouse.{name}"))
                    .map_err(protocol_error)?,
                button,
            })
        })
        .collect::<Result<Vec<_>, AgentError>>()?,
    );
    Ok(holds)
}

fn protocol_error(error: impl std::fmt::Display) -> AgentError {
    AgentError::new("guardian.protocol_error", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_agent_still_guards_every_mouse_button() {
        let holds = release_set(&ProfileStore::default()).unwrap();

        assert_eq!(holds.len(), 5);
        assert!(holds
            .iter()
            .all(|hold| matches!(hold, PhysicalHold::MouseButton { .. })));
    }
}
