use std::time::Duration;

use fairypam_agent_local_client::LocalClientError;
use fairypam_agent_local_protocol::{LocalCommand, LogLevel};
#[cfg(any(windows, test))]
use fairypam_agent_local_protocol::LocalResponse;
use serde::{de::DeserializeOwned, Serialize};

use crate::dto::{
    ConnectionStatusDto, EnvironmentCheckDto, InstalledGamesDto, LogTailDto, OverviewDto,
};

#[cfg(windows)]
const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\FairyPam.Agent.v1";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

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

impl From<LocalClientError> for UiCommandError {
    fn from(error: LocalClientError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

pub struct ProductionGateway {
    #[cfg(windows)]
    client: tokio::sync::Mutex<
        fairypam_agent_local_client::LocalClient<
            fairypam_agent_local_client::WindowsNamedPipeClientTransport,
        >,
    >,
}

impl ProductionGateway {
    #[cfg(windows)]
    pub fn new() -> Self {
        use fairypam_agent_local_client::{LocalClient, WindowsNamedPipeClientTransport};

        let pipe_name =
            std::env::var("FAIRYPAM_AGENT_PIPE").unwrap_or_else(|_| DEFAULT_PIPE_NAME.to_owned());
        Self {
            client: tokio::sync::Mutex::new(LocalClient::new(
                WindowsNamedPipeClientTransport::new(pipe_name),
            )),
        }
    }

    #[cfg(not(windows))]
    pub fn new() -> Self {
        Self {}
    }

    #[cfg(windows)]
    async fn request_with_timeout<T: DeserializeOwned>(
        &self,
        command: LocalCommand,
        timeout: Duration,
    ) -> Result<T, UiCommandError> {
        let response = self
            .client
            .lock()
            .await
            .request(command, timeout)
            .await
            .map_err(UiCommandError::from)?;
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

    #[cfg(windows)]
    pub async fn overview_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<OverviewDto, UiCommandError> {
        Ok(OverviewDto {
            status: self
                .request_with_timeout(LocalCommand::Status, timeout)
                .await?,
            doctor: self
                .request_with_timeout(LocalCommand::Doctor, timeout)
                .await?,
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
}

#[cfg(any(windows, test))]
fn decode_response<T: DeserializeOwned>(response: LocalResponse) -> Result<T, UiCommandError> {
    serde_json::from_value(response.body)
        .map_err(|error| UiCommandError::invalid_response(error.to_string()))
}

#[cfg(test)]
mod tests {
    use fairypam_agent_local_client::LocalClientError;
    use serde_json::json;

    use super::{decode_response, UiCommandError};
    use crate::dto::StatusDto;

    #[test]
    fn rejects_unknown_response_fields() {
        let error = decode_response::<StatusDto>(fairypam_agent_local_protocol::LocalResponse {
            body: json!({ "state": "ConnectedIdle", "capture_active": false, "unexpected": true }),
        })
        .expect_err("DTO must deny unexpected protocol fields");

        assert_eq!(error.code, "local.protocol.invalid");
    }

    #[test]
    fn keeps_transport_error_codes_stable() {
        let error = UiCommandError::from(LocalClientError::pipe_not_found());

        assert_eq!(error.code, "local.transport.pipe_not_found");
    }
}
