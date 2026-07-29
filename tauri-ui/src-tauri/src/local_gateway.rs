use std::time::Duration;

#[cfg(windows)]
use fairypam_agent::runtime::EmbeddedRuntimeHandle;
use fairypam_agent::runtime_api::{InputProbeAction, LogLevel, RuntimeCommand as LocalCommand};
use fairypam_agent_core::AgentError;
#[cfg(windows)]
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::Mutex;
#[cfg(windows)]
use tokio::sync::MutexGuard;

use crate::dto::{
    ClosedGameDto, ConnectionStatusDto, EnvironmentCheckDto, InputResultDto, InstalledGamesDto,
    LaunchedGameDto, LogTailDto, OverviewDto, PreviewDto, RegistrationStatusDto, ReleaseAllDto,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Serialize)]
pub struct UiCommandError {
    pub code: String,
    pub message: String,
}

impl UiCommandError {
    pub fn unavailable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    #[cfg(any(windows, test))]
    fn invalid_response(message: impl Into<String>) -> Self {
        Self::unavailable("local.protocol.invalid", message)
    }
}

impl From<AgentError> for UiCommandError {
    fn from(error: AgentError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

pub struct ProductionGateway {
    #[cfg(windows)]
    runtime: EmbeddedRuntimeHandle,
    request_gate: Mutex<()>,
    lifecycle_gate: Mutex<()>,
}

impl ProductionGateway {
    #[cfg(windows)]
    pub fn new(runtime: EmbeddedRuntimeHandle) -> Self {
        Self {
            runtime,
            request_gate: Mutex::new(()),
            lifecycle_gate: Mutex::new(()),
        }
    }

    #[cfg(not(windows))]
    pub fn new() -> Self {
        Self {
            request_gate: Mutex::new(()),
            lifecycle_gate: Mutex::new(()),
        }
    }

    #[cfg(windows)]
    async fn request_with_timeout<T: DeserializeOwned>(
        &self,
        command: LocalCommand,
        timeout: Duration,
    ) -> Result<T, UiCommandError> {
        let _request_gate = self.request_gate.lock().await;
        let runtime = self.runtime.clone();
        let response = tokio::time::timeout(timeout, async move {
            tokio::task::spawn_blocking(move || runtime.execute(&command))
                .await
                .map_err(|error| {
                    UiCommandError::unavailable("local.runtime_join_failed", error.to_string())
                })?
                .map_err(UiCommandError::from)
        })
        .await
        .map_err(|_| UiCommandError::unavailable("local.runtime_timeout", "request timed out"))??;
        decode_response(response)
    }

    #[cfg(windows)]
    async fn request<T: DeserializeOwned>(
        &self,
        command: LocalCommand,
    ) -> Result<T, UiCommandError> {
        self.request_with_timeout(command, REQUEST_TIMEOUT).await
    }

    #[cfg(not(windows))]
    async fn request_with_timeout<T: DeserializeOwned>(
        &self,
        command: LocalCommand,
        _timeout: Duration,
    ) -> Result<T, UiCommandError> {
        let _ = command;
        Err(UiCommandError::unavailable(
            "local.transport.platform_unsupported",
            "FairyPam Agent UI local control requires Windows",
        ))
    }

    #[cfg(not(windows))]
    async fn request<T: DeserializeOwned>(
        &self,
        command: LocalCommand,
    ) -> Result<T, UiCommandError> {
        self.request_with_timeout(command, REQUEST_TIMEOUT).await
    }

    pub async fn overview(&self) -> Result<OverviewDto, UiCommandError> {
        Ok(OverviewDto {
            status: self.request(LocalCommand::Status).await?,
            doctor: self.request(LocalCommand::Doctor).await?,
        })
    }

    pub async fn connection_status(&self) -> Result<ConnectionStatusDto, UiCommandError> {
        self.request(LocalCommand::GetConnectionStatus).await
    }

    #[cfg(windows)]
    pub async fn connection_status_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ConnectionStatusDto, UiCommandError> {
        self.request_with_timeout(LocalCommand::GetConnectionStatus, timeout)
            .await
    }

    pub async fn environment_check(&self) -> Result<EnvironmentCheckDto, UiCommandError> {
        self.request(LocalCommand::RunEnvironmentCheck).await
    }

    pub async fn log_tail(
        &self,
        lines: u16,
        level: LogLevel,
    ) -> Result<LogTailDto, UiCommandError> {
        self.request(LocalCommand::GetLogTail { lines, level })
            .await
    }

    pub async fn installed_games(&self) -> Result<InstalledGamesDto, UiCommandError> {
        self.request(LocalCommand::ScanInstalledGames).await
    }

    pub async fn launch_game(&self, profile_id: String) -> Result<LaunchedGameDto, UiCommandError> {
        self.request(LocalCommand::LaunchTarget { profile_id })
            .await
    }

    pub async fn close_game(&self) -> Result<ClosedGameDto, UiCommandError> {
        self.request(LocalCommand::CloseTarget).await
    }

    pub async fn capture_preview(&self) -> Result<PreviewDto, UiCommandError> {
        self.request(LocalCommand::CapturePreview).await
    }

    pub async fn input_probe(
        &self,
        action: InputProbeAction,
    ) -> Result<InputResultDto, UiCommandError> {
        self.request(LocalCommand::InputProbe { action }).await
    }

    pub async fn release_all(&self) -> Result<ReleaseAllDto, UiCommandError> {
        self.request(LocalCommand::ReleaseAll).await
    }

    pub async fn register_hub(
        &self,
        hub_address: String,
        registration_code: String,
    ) -> Result<RegistrationStatusDto, UiCommandError> {
        let command = LocalCommand::RegisterHub {
            hub_address,
            registration_code,
        };
        #[cfg(windows)]
        {
            return self
                .request_with_timeout(command, REGISTRATION_TIMEOUT)
                .await;
        }
        #[cfg(not(windows))]
        {
            self.request(command).await
        }
    }

    #[cfg(windows)]
    pub fn acquire_lifecycle(&self) -> Result<MutexGuard<'_, ()>, UiCommandError> {
        self.lifecycle_gate.try_lock().map_err(|_| {
            UiCommandError::unavailable(
                "startup.lifecycle_busy",
                "Another FairyPam Agent lifecycle operation is already running",
            )
        })
    }

    #[cfg(windows)]
    pub async fn shutdown_agent(&self) -> Result<(), UiCommandError> {
        let response: LifecycleStatusDto = self.request(LocalCommand::ShutdownAgent).await?;
        require_lifecycle_state(response, "shutting_down")?;
        self.runtime
            .wait_for_shutdown(Duration::from_secs(25))
            .await
            .map_err(UiCommandError::from)
    }
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleStatusDto {
    state: String,
}

#[cfg(windows)]
fn require_lifecycle_state(
    response: LifecycleStatusDto,
    expected: &str,
) -> Result<(), UiCommandError> {
    if response.state == expected {
        Ok(())
    } else {
        Err(UiCommandError::invalid_response(format!(
            "expected lifecycle state {expected}"
        )))
    }
}

#[cfg(any(windows, test))]
fn decode_response<T: DeserializeOwned>(response: serde_json::Value) -> Result<T, UiCommandError> {
    serde_json::from_value(response)
        .map_err(|error| UiCommandError::invalid_response(error.to_string()))
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use fairypam_agent::runtime::EmbeddedRuntimeHandle;
    use fairypam_agent_core::AgentError;
    use serde_json::json;

    use super::{decode_response, UiCommandError};
    #[cfg(windows)]
    use super::{LocalCommand, ProductionGateway};
    use crate::dto::{EnvironmentCheckDto, StatusDto};

    #[cfg(windows)]
    #[tokio::test]
    async fn gui_gateway_reaches_embedded_runtime_executor_for_release_all() {
        let gateway = ProductionGateway::new(EmbeddedRuntimeHandle::for_test());

        let stopped = gateway.release_all().await.expect("release_all succeeds");

        assert_eq!(stopped.state, "EmergencyStopped");
        assert_eq!(stopped.holds, 0);
        assert!(stopped.cleanup_complete);
        let status: StatusDto = gateway.request(LocalCommand::Status).await.unwrap();
        assert_eq!(status.state, "EmergencyStopped");
    }

    #[test]
    fn rejects_unknown_response_fields() {
        let error = decode_response::<StatusDto>(
            json!({ "state": "ConnectedIdle", "capture_active": false, "unexpected": true }),
        )
        .expect_err("DTO must deny unexpected protocol fields");

        assert_eq!(error.code, "local.protocol.invalid");
    }

    #[test]
    fn decodes_runtime_status_contract() {
        let status = decode_response::<StatusDto>(json!({
            "state": "ConnectedIdle",
            "capture_active": false,
            "build_id": "product-installer-1-1",
            "suite_version": "0.1.1",
            "guardian_state": "idle_no_holds"
        }))
        .expect("GUI status DTO must match the Agent runtime status contract");

        assert_eq!(status.build_id, "product-installer-1-1");
        assert_eq!(status.suite_version, "0.1.1");
        assert_eq!(status.guardian_state, "idle_no_holds");
    }

    #[test]
    fn keeps_transport_error_codes_stable() {
        let error = UiCommandError::from(AgentError::new("runtime.failed", "failed"));

        assert_eq!(error.code, "runtime.failed");
    }

    #[test]
    fn decodes_registration_readiness_before_the_environment_checks() {
        let response = decode_response::<EnvironmentCheckDto>(json!({
            "registration_ready": true,
            "registration_pending": false,
            "checks": [{
                "id": "agent",
                "status": "available",
                "code": "agent.running",
                "recovery": "No action required"
            }]
        }))
        .expect("Agent environment checks include strict registration readiness");

        assert!(response.registration_ready);
        assert!(!response.registration_pending);
        assert_eq!(response.checks.len(), 1);
    }
}
