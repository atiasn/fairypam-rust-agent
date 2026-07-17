use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use fairypam_agent_guardian_protocol::{
    decode_response, encode_line, read_bounded_line, GuardianRequest, GuardianResponse,
    PhysicalHold,
};

use crate::{ActionId, GuardianClient, ReleaseReason, SafetyError};

pub struct GuardianProcessClient {
    child: Child,
    requests: mpsc::SyncSender<IoRequest>,
    worker_done: mpsc::Receiver<()>,
    worker: Option<JoinHandle<()>>,
    physical_holds: BTreeMap<ActionId, PhysicalHold>,
}

enum IoRequest {
    Request {
        message: GuardianRequest,
        reply: mpsc::SyncSender<Result<GuardianResponse, SafetyError>>,
    },
    Stop,
}

impl GuardianProcessClient {
    pub fn spawn(
        executable: &Path,
        physical_holds: BTreeMap<ActionId, PhysicalHold>,
        heartbeat_timeout: Duration,
    ) -> Result<Self, SafetyError> {
        let timeout_ms = u32::try_from(heartbeat_timeout.as_millis()).map_err(|_| {
            SafetyError::new(
                "guardian.timeout_invalid",
                "guardian heartbeat timeout exceeds protocol bounds",
            )
        })?;
        if timeout_ms == 0 || timeout_ms > 5_000 {
            return Err(SafetyError::new(
                "guardian.timeout_invalid",
                "guardian heartbeat timeout must be between 1 and 5000 ms",
            ));
        }
        let mut child = Command::new(executable)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| SafetyError::new("guardian.spawn_failed", error.to_string()))?;
        let stdin = child.stdin.take().ok_or_else(|| {
            SafetyError::new("guardian.spawn_failed", "guardian stdin is unavailable")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            SafetyError::new("guardian.spawn_failed", "guardian stdout is unavailable")
        })?;
        let (requests, receiver) = mpsc::sync_channel(1);
        let (worker_done_sender, worker_done) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("fairypam-guardian-io".into())
            .spawn(move || {
                let mut stdin = stdin;
                let mut stdout = BufReader::new(stdout);
                while let Ok(request) = receiver.recv() {
                    match request {
                        IoRequest::Request { message, reply } => {
                            let _ = reply.send(exchange(&mut stdin, &mut stdout, message));
                        }
                        IoRequest::Stop => break,
                    }
                }
                let _ = worker_done_sender.send(());
            })
            .map_err(|error| SafetyError::new("guardian.spawn_failed", error.to_string()))?;
        let mut client = Self {
            child,
            requests,
            worker_done,
            worker: Some(worker),
            physical_holds,
        };
        client.request(GuardianRequest::RegisterAgent {
            agent_pid: std::process::id(),
            heartbeat_timeout_ms: timeout_ms,
        })?;
        Ok(client)
    }

    fn request(&mut self, request: GuardianRequest) -> Result<GuardianResponse, SafetyError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .try_send(IoRequest::Request {
                message: request,
                reply,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    SafetyError::new("guardian.busy", "guardian is still handling a request")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    SafetyError::new("guardian.disconnected", "guardian I/O worker disconnected")
                }
            })?;
        receiver
            .recv_timeout(Duration::from_millis(250))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    SafetyError::new("guardian.deadline", "guardian response exceeded 250 ms")
                }
                mpsc::RecvTimeoutError::Disconnected => {
                    SafetyError::new("guardian.disconnected", "guardian I/O worker disconnected")
                }
            })?
    }

    fn require_ack(&mut self, request: GuardianRequest) -> Result<(), SafetyError> {
        match self.request(request)? {
            GuardianResponse::Ack {} => Ok(()),
            _ => Err(SafetyError::new(
                "guardian.protocol_error",
                "guardian returned a non-ack response",
            )),
        }
    }

    pub fn child_id(&self) -> u32 {
        self.child.id()
    }
}

impl GuardianClient for GuardianProcessClient {
    fn register_intent(
        &mut self,
        sequence: u64,
        holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError> {
        let physical = holds
            .iter()
            .map(|id| {
                self.physical_holds.get(id).cloned().ok_or_else(|| {
                    SafetyError::new(
                        "guardian.hold_not_registered",
                        format!("no physical hold for {}", id.as_str()),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.require_ack(GuardianRequest::RegisterIntent {
            sequence,
            holds: physical,
        })
    }

    fn commit_holds(
        &mut self,
        sequence: u64,
        _holds: &BTreeSet<ActionId>,
    ) -> Result<(), SafetyError> {
        self.require_ack(GuardianRequest::CommitHolds { sequence })
    }

    fn heartbeat(&mut self, sequence: u64) -> Result<(), SafetyError> {
        self.require_ack(GuardianRequest::Heartbeat { sequence })
    }

    fn release_all(&mut self, reason: ReleaseReason) -> Result<(), SafetyError> {
        self.require_ack(GuardianRequest::ReleaseAll { reason })
    }
}

impl Drop for GuardianProcessClient {
    fn drop(&mut self) {
        let _ = self.require_ack(GuardianRequest::ReleaseAll {
            reason: ReleaseReason::AgentDisconnected,
        });
        let _ = self.requests.try_send(IoRequest::Stop);
        if let Some(worker) = self.worker.take() {
            match self.worker_done.recv_timeout(Duration::from_millis(100)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = worker.join();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    drop(worker);
                }
            }
        }
    }
}

fn exchange(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    request: GuardianRequest,
) -> Result<GuardianResponse, SafetyError> {
    let encoded = encode_line(&request)
        .map_err(|error| SafetyError::new("guardian.protocol_error", error.to_string()))?;
    stdin
        .write_all(&encoded)
        .and_then(|()| stdin.flush())
        .map_err(|error| SafetyError::new("guardian.io_failed", error.to_string()))?;
    let response = read_bounded_line(stdout)
        .map_err(|error| SafetyError::new("guardian.protocol_error", error.to_string()))?
        .ok_or_else(|| {
            SafetyError::new(
                "guardian.disconnected",
                "guardian closed its response stream",
            )
        })?;
    let response = decode_response(&response)
        .map_err(|error| SafetyError::new("guardian.protocol_error", error.to_string()))?;
    match response {
        GuardianResponse::Error { code, message } => Err(SafetyError::new(
            "guardian.rejected",
            format!("{code}: {message}"),
        )),
        response => Ok(response),
    }
}
