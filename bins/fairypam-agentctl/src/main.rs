#[cfg(all(windows, feature = "dev-automation"))]
use fairypam_agentctl::CliError;
use fairypam_agentctl::{execute, parse_command, parse_enrollment_invocation, EnrollmentInvocation};

#[tokio::main]
async fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    #[cfg(all(windows, feature = "dev-automation"))]
    let result = if arguments.first().is_some_and(|value| value == "dev") {
        dev_result(&arguments)
    } else {
        run_windows(&arguments).await
    };
    #[cfg(all(windows, not(feature = "dev-automation")))]
    let result = run_windows(&arguments).await;
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
async fn run_windows(arguments: &[String]) -> Result<serde_json::Value, fairypam_agentctl::CliError> {
    match parse_enrollment_invocation(arguments) {
        Ok(Some(EnrollmentInvocation::LaunchElevatedHelper)) => enrollment::launch_elevated(),
        Ok(Some(EnrollmentInvocation::ElevatedHelper)) => enrollment::run_helper(),
        Ok(None) => match parse_command(arguments) {
            Ok(command) => execute(command).await,
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
mod enrollment {
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use fairypam_agent_local_client::LocalClientError;
    use fairypam_agentctl::CliError;
    use serde_json::{json, Value};
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, HLOCAL};
    use windows::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpReadData,
        WinHttpReceiveResponse, WinHttpSendRequest, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_FLAG_SECURE,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, SetFileSecurityW, TokenElevation, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    const STATE_ROOT: &str = r"C:\\ProgramData\\FairyPam\\Agent\\enrollment";

    pub fn launch_elevated() -> Result<Value, CliError> {
        let executable = std::env::current_exe().map_err(client_error)?;
        let instance = unsafe {
            ShellExecuteW(
                None,
                HSTRING::from("runas"),
                HSTRING::from(executable.to_string_lossy().as_ref()),
                HSTRING::from("--enrollment-helper"),
                HSTRING::new(),
                SW_SHOWNORMAL,
            )
        };
        if instance.0 as usize <= 32 {
            return Err(client("enrollment.uac_denied"));
        }
        Ok(json!({"status":"elevation_requested"}))
    }

    pub fn run_helper() -> Result<Value, CliError> {
        ensure_elevated()?;
        let hub = prompt("Hub HTTPS address: ")?;
        let code = prompt_secret("One-time registration code: ")?;
        let (host, port, path, display_address) = claim_target(&hub)?;
        if code.len() < 16 || code.len() > 256 {
            return Err(client("enrollment.code_invalid"));
        }
        let response = claim(&host, port, &path, &code)?;
        persist(&response)?;
        Ok(json!({"status":"enrolled", "hub_address":display_address}))
    }

    fn prompt(label: &str) -> Result<String, CliError> {
        print!("{label}");
        io::stdout().flush().map_err(client_error)?;
        let mut value = String::new();
        io::stdin().read_line(&mut value).map_err(client_error)?;
        let value = value.trim().to_owned();
        if value.is_empty() { Err(client("enrollment.input_missing")) } else { Ok(value) }
    }

    fn prompt_secret(label: &str) -> Result<String, CliError> {
        print!("{label}");
        io::stdout().flush().map_err(client_error)?;
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(client_error)?;
        let mut mode = Default::default();
        unsafe { GetConsoleMode(input, &mut mode) }.map_err(client_error)?;
        unsafe { SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT) }.map_err(client_error)?;
        let mut value = String::new();
        let read = io::stdin().read_line(&mut value);
        let restore = unsafe { SetConsoleMode(input, mode) };
        println!();
        read.map_err(client_error)?;
        restore.map_err(client_error)?;
        let value = value.trim().to_owned();
        if value.is_empty() { Err(client("enrollment.input_missing")) } else { Ok(value) }
    }

    fn ensure_elevated() -> Result<(), CliError> {
        let mut token = Default::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(client_error)?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut length = 0;
        let result = unsafe {
            GetTokenInformation(token, TokenElevation, Some((&mut elevation as *mut TOKEN_ELEVATION).cast()), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut length)
        };
        let _ = unsafe { CloseHandle(token) };
        result.map_err(client_error)?;
        if elevation.TokenIsElevated == 0 { return Err(client("enrollment.elevation_required")); }
        Ok(())
    }

    fn claim_target(value: &str) -> Result<(String, u16, String, String), CliError> {
        let base = value.trim_end_matches('/');
        let authority = base.strip_prefix("https://").ok_or_else(|| client("enrollment.hub_invalid"))?;
        if authority.contains('@') { return Err(client("enrollment.hub_invalid")); }
        let (host_port, prefix) = authority.split_once('/').unwrap_or((authority, ""));
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (host.to_owned(), port.parse().map_err(|_| client("enrollment.hub_invalid"))?),
            _ if !host_port.is_empty() => (host_port.to_owned(), 443),
            _ => return Err(client("enrollment.hub_invalid")),
        };
        let path = format!("/{}/api/v1/agent-enrollment/claim", prefix.trim_matches('/'))
            .replace("//api", "/api");
        Ok((host, port, path, format!("https://{host_port}")))
    }

    fn claim(host: &str, port: u16, path: &str, code: &str) -> Result<Value, CliError> {
        let session = unsafe { WinHttpOpen(HSTRING::from("FairyPam enrollment"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, HSTRING::new(), HSTRING::new(), 0) };
        if session.is_null() { return Err(client("enrollment.network_failed")); }
        let connection = unsafe { WinHttpConnect(session, HSTRING::from(host), port, 0) };
        if connection.is_null() { let _ = unsafe { WinHttpCloseHandle(session) }; return Err(client("enrollment.network_failed")); }
        let request = unsafe { WinHttpOpenRequest(connection, HSTRING::from("POST"), HSTRING::from(path), HSTRING::new(), HSTRING::new(), std::ptr::null(), WINHTTP_FLAG_SECURE) };
        if request.is_null() { close(connection); close(session); return Err(client("enrollment.network_failed")); }
        let body = serde_json::to_vec(&json!({"code":code})).map_err(client_error)?;
        let headers = "Content-Type: application/json\r\n".encode_utf16().collect::<Vec<_>>();
        let result = unsafe {
            WinHttpSendRequest(request, Some(&headers), Some(body.as_ptr().cast()), body.len() as u32, body.len() as u32, 0)
                .and_then(|_| WinHttpReceiveResponse(request, std::ptr::null_mut()))
        };
        if result.is_err() { close(request); close(connection); close(session); return Err(client("enrollment.claim_failed")); }
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0_u8; 4096];
            let mut read = 0;
            unsafe { WinHttpReadData(request, buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut read) }.map_err(client_error)?;
            if read == 0 { break; }
            bytes.extend_from_slice(&buffer[..read as usize]);
            if bytes.len() > 65_536 { return Err(client("enrollment.response_too_large")); }
        }
        close(request); close(connection); close(session);
        serde_json::from_slice(&bytes).map_err(|_| client("enrollment.claim_failed"))
    }

    fn persist(payload: &Value) -> Result<(), CliError> {
        for name in ["agent_id", "control_endpoint", "frame_endpoint", "hub_server_name", "profile_root_public_key_hex", "ca_pem", "client_cert_pem", "client_key_pem", "expires_at"] {
            if payload.get(name).and_then(Value::as_str).is_none() { return Err(client("enrollment.response_invalid")); }
        }
        let root = PathBuf::from(STATE_ROOT);
        fs::create_dir_all(&root).map_err(client_error)?;
        restrict(&root)?;
        let generation = format!("g-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).map_err(client_error)?.as_nanos());
        let directory = root.join(&generation);
        fs::create_dir(&directory).map_err(client_error)?;
        restrict(&directory)?;
        write_private(&directory.join("runtime.json"), &serde_json::to_vec(payload).map_err(client_error)?)?;
        for (field, file) in [("ca_pem", "ca.pem"), ("client_cert_pem", "client-cert.pem"), ("client_key_pem", "client-key.pem")] {
            write_private(
                &directory.join(file),
                payload[field].as_str().expect("validated above").as_bytes(),
            )?;
        }
        let pointer = root.join("current.json");
        let temporary = root.join("current.json.tmp");
        write_private(&temporary, &serde_json::to_vec(&json!({"generation":generation})).map_err(client_error)?)?;
        let backup = root.join("current.json.previous");
        let _ = fs::remove_file(&backup);
        if pointer.exists() { fs::rename(&pointer, &backup).map_err(client_error)?; }
        if let Err(error) = fs::rename(&temporary, &pointer) {
            let _ = fs::rename(&backup, &pointer);
            return Err(client_error(error));
        }
        let _ = fs::remove_file(backup);
        Ok(())
    }

    fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
        fs::write(path, bytes).map_err(client_error)?;
        restrict(path)
    }

    fn restrict(path: &Path) -> Result<(), CliError> {
        let mut descriptor = Default::default();
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(HSTRING::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)"), SDDL_REVISION_1, &mut descriptor, None) }.map_err(client_error)?;
        let result = unsafe { SetFileSecurityW(HSTRING::from(path.to_string_lossy().as_ref()), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor).ok() };
        let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
        result.map_err(client_error)
    }

    fn close(handle: *mut core::ffi::c_void) { let _ = unsafe { WinHttpCloseHandle(handle) }; }
    fn client(code: &'static str) -> CliError { CliError::Client(LocalClientError::transport(code, code)) }
    fn client_error(error: impl std::fmt::Display) -> CliError { CliError::Client(LocalClientError::transport("enrollment.failed", error.to_string())) }
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
