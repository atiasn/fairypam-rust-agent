use std::time::Duration;

use fairypam_agent_local_client::LocalClientError;
use fairypam_agent_local_protocol::{CaptureEncoding, LocalCommand};

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\FairyPam.Agent.v1";
#[cfg(feature = "dev-automation")]
pub const DEV_PIPE_NAME: &str = r"\\.\pipe\FairyPam.Agent.Dev.v1";
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    Usage(String),
    Client(LocalClientError),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Client(error) if error.code().starts_with("local.identity.") => 3,
            Self::Client(error) if error.code().starts_with("local.protocol.") => 3,
            Self::Client(error) if error.code().starts_with("local.transport.") => 4,
            Self::Client(error) if error.code().starts_with("local.domain.") => 5,
            Self::Client(_) => 4,
        }
    }
}

pub fn parse_command(arguments: &[String]) -> Result<LocalCommand, CliError> {
    let values = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    match values.as_slice() {
        ["status"] => Ok(LocalCommand::Status),
        ["doctor"] => Ok(LocalCommand::Doctor),
        ["profiles", "list"] => Ok(LocalCommand::ListProfiles),
        ["target", "enumerate", "--profile", profile_id] => Ok(LocalCommand::EnumerateTargets {
            profile_id: (*profile_id).to_owned(),
        }),
        ["target", "lock", "--profile", profile_id, "--candidate", candidate_id] => {
            Ok(LocalCommand::LockTarget {
                profile_id: (*profile_id).to_owned(),
                candidate_id: (*candidate_id).to_owned(),
            })
        }
        ["target", "focus"] => Ok(LocalCommand::FocusTarget),
        ["capture", "start", "--source", source_id, "--fps", fps, "--encoding", encoding] => {
            let fps = fps
                .parse::<u8>()
                .map_err(|_| usage("--fps must be an integer from 1 to 10"))?;
            if !(1..=10).contains(&fps) {
                return Err(usage("--fps must be between 1 and 10"));
            }
            let encoding = match *encoding {
                "png" => CaptureEncoding::Png,
                "jpeg" => CaptureEncoding::Jpeg { quality: 85 },
                _ => return Err(usage("--encoding must be jpeg or png")),
            };
            Ok(LocalCommand::StartCapture {
                source_id: (*source_id).to_owned(),
                fps,
                encoding,
            })
        }
        ["capture", "stop", "--source", source_id] => Ok(LocalCommand::StopCapture {
            source_id: (*source_id).to_owned(),
        }),
        #[cfg(feature = "dev-automation")]
        ["testbed", "pulse"] => Ok(LocalCommand::TestbedPulse),
        ["release-all"] => Ok(LocalCommand::ReleaseAll),
        ["reset-emergency-stop"] => Ok(LocalCommand::ResetEmergencyStop),
        ["update", "status"] => Ok(LocalCommand::UpdateStatus),
        ["startup", "status"] => Ok(LocalCommand::StartupStatus),
        _ => Err(usage("unsupported local control command")),
    }
}

pub fn usage(message: impl Into<String>) -> CliError {
    CliError::Usage(message.into())
}

#[cfg(feature = "dev-automation")]
pub fn dev_registration_code(line: &[u8]) -> Result<String, CliError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let code = std::str::from_utf8(line)
        .map_err(|_| usage("registration code from stdin must be UTF-8"))?;
    if code.is_empty() || code.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) || code.len() > 256
    {
        return Err(usage(
            "stdin must contain one bounded registration code line",
        ));
    }
    Ok(code.to_owned())
}

#[cfg(windows)]
pub async fn execute(command: LocalCommand) -> Result<serde_json::Value, CliError> {
    use fairypam_agent_local_client::{LocalClient, WindowsNamedPipeClientTransport};

    let pipe =
        std::env::var("FAIRYPAM_AGENT_PIPE").unwrap_or_else(|_| DEFAULT_PIPE_NAME.to_owned());
    let mut client = LocalClient::new(WindowsNamedPipeClientTransport::new(pipe));
    client
        .request(command, REQUEST_TIMEOUT)
        .await
        .map(|response| response.body)
        .map_err(CliError::Client)
}

#[cfg(all(windows, feature = "dev-automation"))]
pub async fn execute_dev(command: LocalCommand) -> Result<serde_json::Value, CliError> {
    use fairypam_agent_local_client::{LocalClient, WindowsNamedPipeClientTransport};

    let mut client = LocalClient::new(WindowsNamedPipeClientTransport::new_verified_dev_sibling(
        DEV_PIPE_NAME,
        "fairypam-agent.exe",
    ));
    client
        .request(command, REQUEST_TIMEOUT)
        .await
        .map(|response| response.body)
        .map_err(CliError::Client)
}

#[cfg(not(windows))]
pub async fn execute(_command: LocalCommand) -> Result<serde_json::Value, CliError> {
    Err(CliError::Client(LocalClientError::transport(
        "local.transport.platform_unsupported",
        "fairypam-agentctl local Named Pipe transport requires Windows",
    )))
}
