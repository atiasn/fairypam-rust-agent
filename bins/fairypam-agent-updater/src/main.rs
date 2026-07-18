#[cfg(windows)]
use std::collections::VecDeque;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(windows)]
use std::process::{Command, Stdio};

#[cfg(windows)]
use fairypam_agent_suite::{
    download_verified_tuf_target, verify_authenticode_suite, ProductionSecurityPolicy,
    SuiteManifest,
};

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("updater.failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn run(arguments: Vec<String>) -> Result<(), String> {
    let mut arguments = VecDeque::from(arguments);
    if pop(&mut arguments)? != "apply" {
        return Err(usage().into());
    }
    let policy_path = absolute(flag(&mut arguments, "--security-policy")?)?;
    let mut requested_current_version = None;
    let mut rollback_authorized = false;
    while let Some(argument) = arguments.pop_front() {
        match argument.as_str() {
            "--current-version" if requested_current_version.is_none() => {
                requested_current_version = Some(pop(&mut arguments)?);
            }
            "--authorize-downgrade" if !rollback_authorized => rollback_authorized = true,
            _ => return Err(usage().into()),
        }
    }
    let policy: ProductionSecurityPolicy =
        serde_json::from_slice(&fs::read(&policy_path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("security policy is invalid: {error}"))?;

    let install_root = required_environment("ProgramFiles")?.join("FairyPam/Agent");
    let current_version = match requested_current_version {
        Some(value) => value,
        None => installed_version(&install_root)?,
    };
    let program_data = required_environment("ProgramData")?.join("FairyPam/Agent");
    let nonce = format!("{}-{}", std::process::id(), now_millis()?);
    let transaction_root = program_data.join("staging").join(&nonce);
    let download_root = transaction_root.join("tuf");
    let extract_root = transaction_root.join("suite");
    let target =
        download_verified_tuf_target(&policy, &download_root).map_err(|error| error.to_string())?;
    fs::create_dir_all(&extract_root).map_err(|error| error.to_string())?;
    native(
        "tar.exe",
        &["-xf", text(&target)?, "-C", text(&extract_root)?],
    )?;
    let suite = SuiteManifest::load_and_verify(&extract_root).map_err(|error| error.to_string())?;
    suite
        .manifest
        .reject_unauthorized_downgrade(&current_version, rollback_authorized)
        .map_err(|error| error.to_string())?;
    verify_authenticode_suite(&suite, &policy).map_err(|error| error.to_string())?;

    let script = extract_root.join("resources/update-windows-agent-suite.ps1");
    let status = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "AllSigned",
            "-File",
            text(&script)?,
            "-CandidateRoot",
            text(&extract_root)?,
            "-InstallRoot",
            text(&install_root)?,
            "-DataRoot",
            text(&program_data)?,
            "-BuildId",
            &suite.manifest.build_id,
            "-SuiteVersion",
            &suite.manifest.suite_version,
            "-ManifestSha256",
            &suite.manifest_sha256,
        ])
        .stdin(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("update transaction exited with {status}"));
    }
    let _ = fs::remove_dir_all(&transaction_root);
    Ok(())
}

#[cfg(not(windows))]
fn run(_arguments: Vec<String>) -> Result<(), String> {
    Err("Windows is required".into())
}

#[cfg(windows)]
fn native(program: &str, arguments: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

#[cfg(windows)]
fn now_millis() -> Result<u128, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn installed_version(install_root: &Path) -> Result<String, String> {
    let path = install_root.join("active/BUILD-MANIFEST.json");
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    value
        .get("suite_version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "installed suite_version is missing".into())
}

#[cfg(windows)]
fn pop(arguments: &mut VecDeque<String>) -> Result<String, String> {
    arguments.pop_front().ok_or_else(|| usage().into())
}
#[cfg(windows)]
fn flag(arguments: &mut VecDeque<String>, expected: &str) -> Result<String, String> {
    if pop(arguments)? != expected {
        return Err(usage().into());
    }
    pop(arguments)
}
#[cfg(windows)]
fn absolute(value: String) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("paths must be absolute".into())
    }
}
#[cfg(windows)]
fn required_environment(name: &str) -> Result<PathBuf, String> {
    absolute(std::env::var(name).map_err(|_| format!("{name} is missing"))?)
}
#[cfg(windows)]
fn text(path: &Path) -> Result<&str, String> {
    path.to_str().ok_or_else(|| "path is not Unicode".into())
}
#[cfg(windows)]
fn usage() -> &'static str {
    "usage: fairypam-agent-updater apply --security-policy <absolute-json> [--current-version <semver>] [--authorize-downgrade]"
}
