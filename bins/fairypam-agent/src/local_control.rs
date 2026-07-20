use std::time::SystemTime;

use fairypam_agent_core::AgentError;
use fairypam_agent_local_protocol::{
    LocalCommand, LocalError, LocalResponse, NonceReplayGuard, RequestEnvelope, ResponseEnvelope,
};
use fairypam_agent_windows::{
    verify_pipe_caller, LocalIdentityError, PipeOwner, VerifiedPipeCaller,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

impl LocalControlRuntime for crate::execution::CommandExecutor {
    fn execute(&mut self, command: &LocalCommand) -> Result<Value, AgentError> {
        self.execute_local(command)
    }
}

pub trait LocalControlRuntime {
    fn execute(&mut self, command: &LocalCommand) -> Result<Value, AgentError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub request_id: String,
    pub caller_sid_hash: String,
    pub command: String,
    pub result_code: String,
    pub build_id: String,
    pub occurred_at: SystemTime,
}

impl AuditEvent {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "request_id": self.request_id,
            "caller_sid_hash": self.caller_sid_hash,
            "command": self.command,
            "result_code": self.result_code,
            "build_id": self.build_id,
        })
        .to_string()
    }
}

pub trait AuditSink {
    fn record(&mut self, event: AuditEvent);
}

pub struct LocalControlAdapter<R, A> {
    owner: PipeOwner,
    runtime: R,
    audit: A,
    build_id: String,
    nonces: NonceReplayGuard,
}

impl<R: LocalControlRuntime, A: AuditSink> LocalControlAdapter<R, A> {
    pub fn new(owner: PipeOwner, runtime: R, audit: A, build_id: impl Into<String>) -> Self {
        Self {
            owner,
            runtime,
            audit,
            build_id: build_id.into(),
            nonces: NonceReplayGuard::new(1024),
        }
    }

    pub fn handle(
        &mut self,
        caller: &VerifiedPipeCaller,
        request: RequestEnvelope,
    ) -> Result<ResponseEnvelope, LocalIdentityError> {
        verify_pipe_caller(&self.owner, caller.clone())?;

        if let Err(error) = self.nonces.accept(request.nonce) {
            return Ok(error_response(
                request.request_id,
                error.code(),
                error.to_string(),
            ));
        }

        let mutation = is_mutation(&request.command);
        let command = command_name(&request.command).to_owned();
        let result = self.runtime.execute(&request.command).map_err(domain_error);
        let response = match result {
            Ok(body) => ResponseEnvelope {
                request_id: request.request_id.clone(),
                result: Ok(LocalResponse { body }),
            },
            Err(error) => error_response(request.request_id.clone(), &error.code, error.message),
        };
        if mutation {
            let result_code = match &response.result {
                Ok(_) => "ok".to_owned(),
                Err(error) => error.code.clone(),
            };
            self.audit.record(AuditEvent {
                request_id: request.request_id,
                caller_sid_hash: sha256_hex(&caller.user_sid),
                command,
                result_code,
                build_id: self.build_id.clone(),
                occurred_at: SystemTime::now(),
            });
        }
        Ok(response)
    }

    pub fn into_parts(self) -> (R, A) {
        (self.runtime, self.audit)
    }
}

fn error_response(
    request_id: String,
    code: impl Into<String>,
    message: impl Into<String>,
) -> ResponseEnvelope {
    ResponseEnvelope {
        request_id,
        result: Err(LocalError {
            code: code.into(),
            message: message.into(),
        }),
    }
}

fn domain_error(error: AgentError) -> LocalError {
    let code = error.code();
    LocalError {
        code: if code.starts_with("local.domain.") {
            code.to_owned()
        } else {
            format!("local.domain.{code}")
        },
        message: error.to_string(),
    }
}

fn is_mutation(command: &LocalCommand) -> bool {
    match command {
        LocalCommand::LockTarget { .. }
        | LocalCommand::FocusTarget
        | LocalCommand::StartCapture { .. }
        | LocalCommand::StopCapture { .. }
        | LocalCommand::ReleaseAll => true,
        #[cfg(feature = "dev-automation")]
        LocalCommand::TestbedPulse => true,
        _ => false,
    }
}

fn command_name(command: &LocalCommand) -> &'static str {
    match command {
        LocalCommand::Status => "status",
        LocalCommand::Doctor => "doctor",
        LocalCommand::ListProfiles => "list_profiles",
        LocalCommand::EnumerateTargets { .. } => "enumerate_targets",
        LocalCommand::LockTarget { .. } => "lock_target",
        LocalCommand::FocusTarget => "focus_target",
        LocalCommand::StartCapture { .. } => "start_capture",
        LocalCommand::StopCapture { .. } => "stop_capture",
        #[cfg(feature = "dev-automation")]
        LocalCommand::TestbedPulse => "testbed_pulse",
        LocalCommand::ReleaseAll => "release_all",
        LocalCommand::UpdateStatus => "update_status",
        LocalCommand::StartupStatus => "startup_status",
    }
}

fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
