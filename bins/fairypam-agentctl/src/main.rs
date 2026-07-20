#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agentctl::CliError;
use fairypam_agentctl::{execute, parse_command};

#[tokio::main]
async fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    #[cfg(all(windows, feature = "dev-automation"))]
    let result = if arguments.first().is_some_and(|value| value == "dev") {
        dev_result(&arguments)
    } else {
        run_local(&arguments).await
    };
    #[cfg(all(windows, not(feature = "dev-automation")))]
    let result = run_local(&arguments).await;
    #[cfg(not(windows))]
    let result = match parse_command(&arguments) {
        Ok(command) => execute(command).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(body) => println!("{body}"),
        Err(error) => {
            eprintln!("{error:?}");
            std::process::exit(error.exit_code());
        }
    }
}

#[cfg(windows)]
async fn run_local(arguments: &[String]) -> Result<serde_json::Value, fairypam_agentctl::CliError> {
    match parse_command(arguments) {
        Ok(command) => execute(command).await,
        Err(error) => Err(error),
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
fn dev_result(arguments: &[String]) -> Result<serde_json::Value, CliError> {
    run_dev(arguments)
}

#[cfg(all(windows, feature = "dev-automation"))]
fn run_dev(arguments: &[String]) -> Result<serde_json::Value, CliError> {
    let (operation, run_id) = match arguments {
        [command, operation, flag, run_id]
            if command == "dev"
                && operation == "install"
                && flag == "--run-id"
                && valid_run_id(run_id) =>
        {
            ("install", Some(run_id.as_str()))
        }
        [command, operation]
            if command == "dev"
                && matches!(operation.as_str(), "provision" | "start" | "unprovision") =>
        {
            (operation.as_str(), None)
        }
        _ => return Err(CliError::Usage("unsupported dev command".to_owned())),
    };
    let script = bundled_script(match operation {
        "install" => "dev-install.ps1",
        _ => "dev-provision.ps1",
    })?;
    let provision_result = script
        .parent()
        .expect("bundled script has a parent directory")
        .join(".dev-provision-result.json");
    let mut command = std::process::Command::new("powershell.exe");
    if operation != "start" {
        if operation == "install" {
            command.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
            command
                .arg(script)
                .arg("-RunId")
                .arg(run_id.expect("validated above"));
            return run_install(command);
        }
        if operation == "provision" {
            let _ = std::fs::remove_file(&provision_result);
        }
        let child_arguments = format!(
            "-NoProfile -ExecutionPolicy Bypass -File \"{}\" {}",
            script.display(),
            operation
        )
        .replace('\'', "''");
        command.args(["-NoProfile", "-Command"]);
        command.arg(format!(
            "$ErrorActionPreference = 'Stop'; $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ErrorAction Stop -ArgumentList '{}'; exit $process.ExitCode",
            child_arguments
        ));
    } else {
        command.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
        command.arg(script).arg(operation);
    }
    let output = command.output().map_err(|error| {
        CliError::Client(fairypam_agent_local_client::LocalClientError::transport(
            "dev.task.launch_failed",
            error.to_string(),
        ))
    })?;
    if output.status.success() {
        Ok(serde_json::json!({"status":"started", "operation":operation}))
    } else {
        let failure_message = if operation == "provision" {
            std::fs::read_to_string(&provision_result)
                .ok()
                .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                .and_then(|result| {
                    result
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| "fixed Dev task operation failed".to_owned())
        } else {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if message.is_empty() {
                "fixed Dev task operation failed".to_owned()
            } else {
                message
            }
        };
        Err(CliError::Client(
            fairypam_agent_local_client::LocalClientError::transport(
                "dev.task.failed",
                failure_message,
            ),
        ))
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
fn valid_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(all(windows, feature = "dev-automation"))]
fn bundled_script(name: &str) -> Result<std::path::PathBuf, CliError> {
    let executable = std::env::current_exe().map_err(|error| {
        CliError::Client(fairypam_agent_local_client::LocalClientError::transport(
            "dev.script.unavailable",
            error.to_string(),
        ))
    })?;
    let script = executable
        .parent()
        .ok_or_else(|| {
            CliError::Client(fairypam_agent_local_client::LocalClientError::transport(
                "dev.script.unavailable",
                "agentctl executable has no parent directory",
            ))
        })?
        .join(name);
    if script.is_file() {
        Ok(script)
    } else {
        Err(CliError::Client(
            fairypam_agent_local_client::LocalClientError::transport(
                "dev.script.missing",
                format!("bundled Dev script is missing: {}", script.display()),
            ),
        ))
    }
}

#[cfg(all(windows, feature = "dev-automation"))]
fn run_install(mut command: std::process::Command) -> Result<serde_json::Value, CliError> {
    let output = command.output().map_err(|error| {
        CliError::Client(fairypam_agent_local_client::LocalClientError::transport(
            "dev.artifact.install_launch_failed",
            error.to_string(),
        ))
    })?;
    if !output.status.success() {
        return Err(CliError::Client(
            fairypam_agent_local_client::LocalClientError::transport(
                "dev.artifact.install_failed",
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ),
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        CliError::Client(fairypam_agent_local_client::LocalClientError::transport(
            "dev.artifact.install_output_invalid",
            error.to_string(),
        ))
    })
}

#[cfg(all(test, windows, feature = "dev-automation"))]
mod tests {
    use super::valid_run_id;

    #[test]
    fn dev_install_accepts_only_canonical_github_actions_run_ids() {
        assert!(valid_run_id("123456789"));
        for invalid in ["", "0", "01", "12a", "-1", "123456789012345678901"] {
            assert!(!valid_run_id(invalid), "{invalid} must be rejected");
        }
    }
}
