use std::time::Duration;

use fairypam_agent_local_client::LocalClientError;
use fairypam_agent_local_protocol::{CaptureEncoding, LocalCommand};

#[cfg(windows)]
pub mod enrollment;

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\FairyPam.Agent.v1";
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const ELEVATED_UI_ARGUMENT: &str = "--enrollment-helper";

pub fn is_fixed_elevated_ui_invocation(arguments: &[String], token_is_elevated: bool) -> bool {
    token_is_elevated && matches!(arguments, [argument] if argument == ELEVATED_UI_ARGUMENT)
}

pub fn is_fixed_interactive_task_xml(xml: &str, action: &str) -> bool {
    let action = action
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    let Some(elements) = opening_element_names(xml) else {
        return false;
    };
    let count = |name: &str| elements.iter().filter(|element| **element == name).count();

    count("Triggers") == 1
        && count("LogonTrigger") == 1
        && elements
            .iter()
            .filter(|element| element.ends_with("Trigger"))
            .count()
            == 1
        && count("Actions") == 1
        && count("Exec") == 1
        && count("Arguments") == 0
        && exact_element_text(xml, "LogonType", "InteractiveToken", count("LogonType"))
        && exact_element_text(xml, "RunLevel", "HighestAvailable", count("RunLevel"))
        && exact_element_text(xml, "Command", &action, count("Command"))
        && element_body(xml, "Actions", count("Actions"))
            .and_then(opening_element_names)
            .is_some_and(|actions| actions.as_slice() == ["Exec", "Command"].as_slice())
}

fn opening_element_names(xml: &str) -> Option<Vec<&str>> {
    let mut elements = Vec::new();
    for fragment in xml.split('<').skip(1) {
        let (tag, _) = fragment.split_once('>')?;
        let tag = tag.trim_start();
        if tag.starts_with('/') || tag.starts_with('?') {
            continue;
        }
        if tag.starts_with('!') {
            return None;
        }
        let end = tag
            .find(|character: char| character.is_ascii_whitespace() || character == '/')
            .unwrap_or(tag.len());
        let name = &tag[..end];
        if name.is_empty()
            || !name.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '-'
            })
        {
            return None;
        }
        elements.push(name);
    }
    Some(elements)
}

fn exact_element_text(xml: &str, name: &str, expected: &str, count: usize) -> bool {
    count == 1 && element_body(xml, name, count).is_some_and(|body| body.trim() == expected)
}

fn element_body<'a>(xml: &'a str, name: &str, count: usize) -> Option<&'a str> {
    if count != 1 {
        return None;
    }
    let opening = format!("<{name}");
    let start = xml.match_indices(&opening).find_map(|(index, _)| {
        let next = xml[index + opening.len()..].chars().next()?;
        (next == '>' || next.is_ascii_whitespace()).then_some(index)
    })?;
    let opening_end = start + xml[start..].find('>')? + 1;
    let closing = format!("</{name}>");
    let end = opening_end + xml[opening_end..].find(&closing)?;
    (xml[end + closing.len()..].matches(&closing).count() == 0).then_some(&xml[opening_end..end])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentInvocation {
    LaunchElevatedHelper,
    ElevatedHelper,
}

/// Enrollment is deliberately outside LocalCommand: it never crosses the
/// same-user Named Pipe and it never accepts an URL or code as a CLI argument.
pub fn parse_enrollment_invocation(
    arguments: &[String],
) -> Result<Option<EnrollmentInvocation>, CliError> {
    let values = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    match values.as_slice() {
        ["enroll"] => Ok(Some(EnrollmentInvocation::LaunchElevatedHelper)),
        ["--enrollment-helper"] => Ok(Some(EnrollmentInvocation::ElevatedHelper)),
        [command, ..] if *command == "enroll" || *command == "--enrollment-helper" => {
            Err(usage("enrollment accepts no arguments"))
        }
        _ => Ok(None),
    }
}

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
        ["update", "status"] => Ok(LocalCommand::UpdateStatus),
        ["startup", "status"] => Ok(LocalCommand::StartupStatus),
        _ => Err(usage("unsupported local control command")),
    }
}

pub fn usage(message: impl Into<String>) -> CliError {
    CliError::Usage(message.into())
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

#[cfg(not(windows))]
pub async fn execute(_command: LocalCommand) -> Result<serde_json::Value, CliError> {
    Err(CliError::Client(LocalClientError::transport(
        "local.transport.platform_unsupported",
        "fairypam-agentctl local Named Pipe transport requires Windows",
    )))
}
