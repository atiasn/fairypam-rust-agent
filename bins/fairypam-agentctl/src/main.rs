use std::collections::VecDeque;
use std::process::ExitCode;
use std::time::Duration;

use fairypam_agent_local_client::{LocalClient, LocalClientError};
use fairypam_agent_local_protocol::{LocalCommand, LocalPayload};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "dev-automation")]
use fairypam_agent_local_protocol::{AutomationCapability, AutomationTarget};
#[cfg(feature = "dev-automation")]
use std::collections::BTreeSet;

#[tokio::main]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()).await {
        Ok(payload) => match serde_json::to_string_pretty(&payload) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => fail("serialization_error", &error.to_string()),
        },
        Err(error) => fail(error.category(), &error.to_string()),
    }
}

async fn run(arguments: Vec<String>) -> Result<LocalPayload, LocalClientError> {
    let mut arguments = VecDeque::from(arguments);
    let command = arguments
        .pop_front()
        .ok_or_else(|| LocalClientError::Protocol(usage().into()))?;

    #[cfg(feature = "dev-automation")]
    if command == "dev" {
        return run_dev(arguments).await;
    }

    let command = parse_production(command, &mut arguments)?;
    require_empty(&arguments)?;
    LocalClient::production("fairypam-agentctl")?
        .with_timeout(Duration::from_secs(5))?
        .request(command, CancellationToken::new())
        .await
}

fn parse_production(
    command: String,
    arguments: &mut VecDeque<String>,
) -> Result<LocalCommand, LocalClientError> {
    match command.as_str() {
        "status" => Ok(LocalCommand::Status {}),
        "doctor" => Ok(LocalCommand::Doctor {}),
        "diagnostics" => Ok(LocalCommand::Diagnostics {}),
        "suite-status" => Ok(LocalCommand::SuiteStatus {}),
        "release-all" => Ok(LocalCommand::ReleaseAll {}),
        "update" if pop(arguments)? == "apply" => Ok(LocalCommand::RequestUpdate {}),
        "autostart" => match pop(arguments)?.as_str() {
            "enable" => Ok(LocalCommand::SetAutostart { enabled: true }),
            "disable" => Ok(LocalCommand::SetAutostart { enabled: false }),
            _ => Err(LocalClientError::Protocol(usage().into())),
        },
        "maintenance-prepare-update" => Ok(LocalCommand::PrepareUpdate {
            timeout_ms: flag(arguments, "--timeout-ms")?
                .parse()
                .map_err(|_| LocalClientError::Protocol("--timeout-ms is invalid".into()))?,
        }),
        "maintenance-resume-update" => Ok(LocalCommand::ResumeAfterUpdateFailure {}),
        "profiles" if pop(arguments)? == "list" => Ok(LocalCommand::ListProfiles {}),
        "targets" => match pop(arguments)?.as_str() {
            "list" => Ok(LocalCommand::ListTargets {
                profile_id: flag(arguments, "--profile")?,
            }),
            "select" => Ok(LocalCommand::SelectTarget {
                profile_id: flag(arguments, "--profile")?,
                target_id: flag(arguments, "--target")?,
            }),
            "focus" => Ok(LocalCommand::FocusTarget {}),
            "close" => Ok(LocalCommand::CloseTarget {
                timeout_ms: flag(arguments, "--timeout-ms")?
                    .parse()
                    .map_err(|_| LocalClientError::Protocol("--timeout-ms is invalid".into()))?,
            }),
            _ => Err(LocalClientError::Protocol(usage().into())),
        },
        _ => Err(LocalClientError::Protocol(usage().into())),
    }
}

#[cfg(feature = "dev-automation")]
async fn run_dev(mut arguments: VecDeque<String>) -> Result<LocalPayload, LocalClientError> {
    match pop(&mut arguments)?.as_str() {
        "provision" => {
            let build_id = flag(&mut arguments, "--build-id")?;
            require_empty(&arguments)?;
            run_provision(&build_id)
        }
        "local-control-prepare" => {
            let request = flag(&mut arguments, "--request")?;
            require_empty(&arguments)?;
            run_local_control_prepare(&request)
        }
        "status" => dev_request(LocalCommand::DevStatus {}, arguments).await,
        "verify-status" => {
            let build_id = flag(&mut arguments, "--build-id")?;
            let build_commit = flag(&mut arguments, "--build-commit")?;
            require_empty(&arguments)?;
            verify_dev_status(&build_id, &build_commit).await
        }
        "verify-production" => {
            let build_commit = flag(&mut arguments, "--build-commit")?;
            require_empty(&arguments)?;
            verify_production_diagnostics(&build_commit).await
        }
        "verify-dev-unavailable" => {
            require_empty(&arguments)?;
            verify_unavailable(true).await
        }
        "verify-production-unavailable" => {
            require_empty(&arguments)?;
            verify_unavailable(false).await
        }
        #[cfg(windows)]
        "diagnostics-as-process" => {
            let process_id = flag(&mut arguments, "--target-pid")?
                .parse()
                .map_err(|_| LocalClientError::Protocol("--target-pid is invalid".into()))?;
            require_empty(&arguments)?;
            LocalClient::production_for_test_process(process_id, "fairypam-agentctl")?
                .with_timeout(Duration::from_secs(5))?
                .request(LocalCommand::Diagnostics {}, CancellationToken::new())
                .await
        }
        "run-testbed-pulse" => {
            let integrity = flag(&mut arguments, "--integrity")?;
            let ttl_ms = flag(&mut arguments, "--ttl-ms")?
                .parse()
                .map_err(|_| LocalClientError::Protocol("--ttl-ms is invalid".into()))?;
            let target = match integrity.as_str() {
                "normal" => AutomationTarget::TestbedNormal {},
                "high" => AutomationTarget::TestbedHigh {},
                _ => {
                    return Err(LocalClientError::Protocol(
                        "--integrity must be normal or high".into(),
                    ))
                }
            };
            require_empty(&arguments)?;
            run_testbed_pulse(target, ttl_ms).await
        }
        "run-testbed-hold" => {
            let integrity = flag(&mut arguments, "--integrity")?;
            let ttl_ms = flag(&mut arguments, "--ttl-ms")?
                .parse()
                .map_err(|_| LocalClientError::Protocol("--ttl-ms is invalid".into()))?;
            let duration_ms = flag(&mut arguments, "--duration-ms")?
                .parse()
                .map_err(|_| LocalClientError::Protocol("--duration-ms is invalid".into()))?;
            let target = match integrity.as_str() {
                "normal" => AutomationTarget::TestbedNormal {},
                "high" => AutomationTarget::TestbedHigh {},
                _ => {
                    return Err(LocalClientError::Protocol(
                        "--integrity must be normal or high".into(),
                    ))
                }
            };
            require_empty(&arguments)?;
            run_testbed_hold(target, ttl_ms, duration_ms).await
        }
        "stop" => dev_request(LocalCommand::DevStopAutomation {}, arguments).await,
        "emergency-stop" => dev_request(LocalCommand::DevEmergencyStop {}, arguments).await,
        _ => Err(LocalClientError::Protocol(dev_usage().into())),
    }
}

#[cfg(feature = "dev-automation")]
async fn verify_dev_status(
    expected_build_id: &str,
    expected_build_commit: &str,
) -> Result<LocalPayload, LocalClientError> {
    let payload = dev_request(LocalCommand::DevStatus {}, VecDeque::new()).await?;
    match &payload {
        LocalPayload::DevStatus { provisioned_build_id, build_commit, active_session_id, .. }
            if provisioned_build_id.as_deref() == Some(expected_build_id)
                && build_commit == expected_build_commit
                && active_session_id.is_none() => Ok(payload),
        _ => Err(LocalClientError::Protocol("development identity probe mismatch".into())),
    }
}

#[cfg(feature = "dev-automation")]
async fn verify_production_diagnostics(
    expected_build_commit: &str,
) -> Result<LocalPayload, LocalClientError> {
    let payload = LocalClient::production("fairypam-agentctl")?
        .with_timeout(Duration::from_secs(5))?
        .request(LocalCommand::Diagnostics {}, CancellationToken::new()).await?;
    match &payload {
        LocalPayload::Diagnostics { build_commit, protocol, control_connected, .. }
            if build_commit == expected_build_commit
                && protocol == "fairypam-local-v1"
                && !control_connected => Ok(payload),
        _ => Err(LocalClientError::Protocol("production identity probe mismatch".into())),
    }
}

#[cfg(feature = "dev-automation")]
async fn verify_unavailable(development: bool) -> Result<LocalPayload, LocalClientError> {
    let client = if development {
        LocalClient::development("fairypam-agentctl")?
    } else {
        LocalClient::production("fairypam-agentctl")?
    };
    match client.with_timeout(Duration::from_secs(5))?
        .request(LocalCommand::Diagnostics {}, CancellationToken::new()).await {
        Err(LocalClientError::Unavailable) => Ok(LocalPayload::Diagnostics {
            agent_version: env!("CARGO_PKG_VERSION").into(), build_commit: String::new(),
            protocol: "agent-unavailable-v1".into(), control_connected: false, audit_enabled: true,
        }),
        Err(error) => Err(error),
        Ok(_) => Err(LocalClientError::Protocol("expected Agent to be unavailable".into())),
    }
}

#[cfg(all(feature = "dev-automation", windows))]
fn run_provision(build_id: &str) -> Result<LocalPayload, LocalClientError> {
    validate_build_id(build_id)?;
    // ponytail: compile-time embedding makes the elevated provisioner the runner trust root.
    let embedded_local_control_runner = include_bytes!("../../../scripts/local-control-safe-runner.ps1");
    let manifest = match fairypam_agent_dev_automation::provision::provision_current_build(
        build_id,
        embedded_local_control_runner,
    ) {
        Ok(manifest) => manifest,
        Err(error)
            if error.code == fairypam_agent_local_protocol::LocalErrorCode::PermissionDenied =>
        {
            elevate_command(&format!("dev provision --build-id {build_id}"))?;
            fairypam_agent_dev_automation::provision::load_and_validate_current_slot()
                .map_err(LocalClientError::from)?
        }
        Err(error) => return Err(LocalClientError::from(error)),
    };
    Ok(LocalPayload::Diagnostics {
        agent_version: env!("CARGO_PKG_VERSION").into(),
        build_commit: manifest.build_id,
        protocol: "dev-provision-v1".into(),
        control_connected: false,
        audit_enabled: true,
    })
}

#[cfg(all(feature = "dev-automation", windows))]
fn run_local_control_prepare(request: &str) -> Result<LocalPayload, LocalClientError> {
    let request = std::path::Path::new(request);
    let manifest = match fairypam_agent_dev_automation::provision::prepare_local_control_authority_request(request) {
        Ok(manifest) => manifest,
        Err(error)
            if error.code == fairypam_agent_local_protocol::LocalErrorCode::PermissionDenied =>
        {
            let request = request.display().to_string();
            if request.contains('"') {
                return Err(LocalClientError::Protocol("request path is invalid".into()));
            }
            elevate_command(&format!("dev local-control-prepare --request \"{request}\""))?;
            fairypam_agent_dev_automation::provision::load_and_validate_current_slot()
                .map_err(LocalClientError::from)?
        }
        Err(error) => return Err(LocalClientError::from(error)),
    };
    Ok(LocalPayload::Diagnostics {
        agent_version: env!("CARGO_PKG_VERSION").into(),
        build_commit: manifest.build_id,
        protocol: "local-control-authority-v1".into(),
        control_connected: false,
        audit_enabled: true,
    })
}

#[cfg(all(feature = "dev-automation", not(windows)))]
fn run_local_control_prepare(_request: &str) -> Result<LocalPayload, LocalClientError> {
    Err(LocalClientError::UnsupportedPlatform)
}

#[cfg(all(feature = "dev-automation", windows))]
fn elevate_command(arguments: &str) -> Result<(), LocalClientError> {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let executable = std::env::current_exe().map_err(LocalClientError::Io)?;
    let executable = wide(&executable.display().to_string());
    let parameters = wide(arguments);
    let mut launch = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut launch) }
        .map_err(|error| LocalClientError::Protocol(format!("UAC launch failed: {error}")))?;
    if launch.hProcess.is_invalid() {
        return Err(LocalClientError::Protocol(
            "UAC launch returned no process handle".into(),
        ));
    }
    let wait = unsafe { WaitForSingleObject(launch.hProcess, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        unsafe {
            let _ = CloseHandle(launch.hProcess);
        }
        return Err(LocalClientError::Protocol(
            "elevated provision wait failed".into(),
        ));
    }
    let mut exit_code = 1_u32;
    let result = unsafe { GetExitCodeProcess(launch.hProcess, &mut exit_code) };
    unsafe {
        let _ = CloseHandle(launch.hProcess);
    }
    result.map_err(|error| {
        LocalClientError::Protocol(format!("cannot read provision exit code: {error}"))
    })?;
    if exit_code != 0 {
        return Err(LocalClientError::Protocol(format!(
            "elevated provision failed with exit code {exit_code}"
        )));
    }
    Ok(())
}

#[cfg(all(feature = "dev-automation", windows))]
fn validate_build_id(value: &str) -> Result<(), LocalClientError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(LocalClientError::Protocol("build id is invalid".into()));
    }
    Ok(())
}

#[cfg(all(feature = "dev-automation", windows))]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(all(feature = "dev-automation", not(windows)))]
fn run_provision(_build_id: &str) -> Result<LocalPayload, LocalClientError> {
    Err(LocalClientError::UnsupportedPlatform)
}

#[cfg(all(feature = "dev-automation", windows))]
async fn run_testbed_pulse(
    target: AutomationTarget,
    ttl_ms: u32,
) -> Result<LocalPayload, LocalClientError> {
    let mut connection = LocalClient::development("fairypam-agentctl-dev")?
        .connect(CancellationToken::new())
        .await?;
    let started = connection
        .request(
            LocalCommand::DevStartAutomation {
                target,
                capabilities: BTreeSet::from([AutomationCapability::PulseTestAction]),
                ttl_ms,
            },
            CancellationToken::new(),
        )
        .await?;
    let LocalPayload::AutomationSession { session_id, .. } = started else {
        return Err(LocalClientError::Protocol(
            "dev Agent returned an invalid automation session".into(),
        ));
    };
    let pulse = connection
        .request(
            LocalCommand::DevPulseTestbed {
                session_id: session_id.clone(),
            },
            CancellationToken::new(),
        )
        .await;
    let stop = connection
        .request(LocalCommand::DevStopAutomation {}, CancellationToken::new())
        .await;
    match (pulse, stop) {
        (Ok(payload), Ok(_)) => Ok(payload),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(all(feature = "dev-automation", windows))]
async fn run_testbed_hold(
    target: AutomationTarget,
    ttl_ms: u32,
    duration_ms: u32,
) -> Result<LocalPayload, LocalClientError> {
    let mut connection = LocalClient::development("fairypam-agentctl-dev")?
        .connect(CancellationToken::new())
        .await?;
    let started = connection
        .request(
            LocalCommand::DevStartAutomation {
                target,
                capabilities: BTreeSet::from([AutomationCapability::HoldTestAction]),
                ttl_ms,
            },
            CancellationToken::new(),
        )
        .await?;
    let LocalPayload::AutomationSession { session_id, .. } = started else {
        return Err(LocalClientError::Protocol(
            "dev Agent returned an invalid automation session".into(),
        ));
    };
    let hold = connection
        .request(
            LocalCommand::DevHoldTestbed {
                session_id,
                duration_ms,
            },
            CancellationToken::new(),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(
        u64::from(duration_ms).saturating_add(100),
    ))
    .await;
    let stop = connection
        .request(LocalCommand::DevStopAutomation {}, CancellationToken::new())
        .await;
    match (hold, stop) {
        (Ok(payload), Ok(_)) => Ok(payload),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(all(feature = "dev-automation", not(windows)))]
async fn run_testbed_pulse(
    _target: AutomationTarget,
    _ttl_ms: u32,
) -> Result<LocalPayload, LocalClientError> {
    Err(LocalClientError::UnsupportedPlatform)
}

#[cfg(all(feature = "dev-automation", not(windows)))]
async fn run_testbed_hold(
    _target: AutomationTarget,
    _ttl_ms: u32,
    _duration_ms: u32,
) -> Result<LocalPayload, LocalClientError> {
    Err(LocalClientError::UnsupportedPlatform)
}

#[cfg(feature = "dev-automation")]
async fn dev_request(
    command: LocalCommand,
    arguments: VecDeque<String>,
) -> Result<LocalPayload, LocalClientError> {
    require_empty(&arguments)?;
    LocalClient::development("fairypam-agentctl-dev")?
        .request(command, CancellationToken::new())
        .await
}

fn pop(arguments: &mut VecDeque<String>) -> Result<String, LocalClientError> {
    arguments
        .pop_front()
        .ok_or_else(|| LocalClientError::Protocol(usage().into()))
}

fn flag(arguments: &mut VecDeque<String>, expected: &str) -> Result<String, LocalClientError> {
    if pop(arguments)? != expected {
        return Err(LocalClientError::Protocol(format!(
            "expected fixed option {expected}"
        )));
    }
    pop(arguments)
}

fn require_empty(arguments: &VecDeque<String>) -> Result<(), LocalClientError> {
    if !arguments.is_empty() {
        return Err(LocalClientError::Protocol(
            "unexpected argument; arbitrary methods and values are not accepted".into(),
        ));
    }
    Ok(())
}

fn usage() -> &'static str {
    "usage: fairypam-agentctl status|doctor|diagnostics|suite-status|release-all|update apply|autostart enable|disable|profiles list|targets list --profile ID|targets select --profile ID --target OPAQUE_ID|targets focus|targets close --timeout-ms MS"
}

#[cfg(feature = "dev-automation")]
fn dev_usage() -> &'static str {
    "usage: fairypam-agentctl dev provision --build-id ID|local-control-prepare --request ABSOLUTE_PATH|status|verify-status --build-id ID --build-commit COMMIT|verify-production --build-commit COMMIT|verify-dev-unavailable|verify-production-unavailable|diagnostics-as-process --target-pid PID|run-testbed-pulse --integrity normal|high --ttl-ms MS|run-testbed-hold --integrity normal|high --ttl-ms MS --duration-ms MS|stop|emergency-stop"
}

fn fail(category: &str, message: &str) -> ExitCode {
    eprintln!(
        "{}",
        serde_json::json!({"error": {"category": category, "message": message}})
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_has_only_fixed_domain_commands() {
        let mut arguments = VecDeque::from([
            "select".into(),
            "--profile".into(),
            "fairypam-test-window".into(),
            "--target".into(),
            "ab".repeat(32),
        ]);
        assert!(matches!(
            parse_production("targets".into(), &mut arguments).unwrap(),
            LocalCommand::SelectTarget { .. }
        ));
        assert!(parse_production("shell".into(), &mut VecDeque::new()).is_err());
    }

    #[test]
    fn extra_fields_and_raw_surfaces_are_rejected() {
        let mut arguments = VecDeque::from(["--path".into(), "C:\\temp".into()]);
        assert!(parse_production("status".into(), &mut arguments).is_ok());
        assert!(require_empty(&arguments).is_err());
    }
}
