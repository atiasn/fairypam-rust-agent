use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use fairypam_agent_local_client::LocalClientError;
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
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::CliError;

pub const PRODUCTION_TASK_NAME: &str = "FairyPam Agent";
const STATE_ROOT: &str = r"C:\\ProgramData\\FairyPam\\Agent\\enrollment";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentResult {
    pub hub_address: String,
}

/// The only elevation edge: the same signed GUI binary with one fixed argument.
pub fn launch_elevated_gui() -> Result<(), CliError> {
    let executable = std::env::current_exe().map_err(client_error)?;
    let instance = unsafe {
        ShellExecuteW(
            None,
            &HSTRING::from("runas"),
            &HSTRING::from(executable.to_string_lossy().as_ref()),
            &HSTRING::from(crate::ELEVATED_UI_ARGUMENT),
            &HSTRING::new(),
            SW_SHOWNORMAL,
        )
    };
    if instance.0 as usize <= 32 {
        return Err(client("enrollment.uac_denied"));
    }
    Ok(())
}

pub fn is_elevated_ui_invocation(arguments: &[String]) -> bool {
    crate::is_fixed_elevated_ui_invocation(
        arguments,
        current_process_is_elevated().unwrap_or(false),
    )
}

pub fn enroll(hub: &str, code: &str) -> Result<EnrollmentResult, CliError> {
    ensure_elevated()?;
    if code.len() < 16 || code.len() > 256 {
        return Err(client("enrollment.code_invalid"));
    }
    let (host, port, path, display_address) = claim_target(hub)?;
    let response = claim(&host, port, &path, code)?;
    persist(&response)?;
    install_fixed_agent_task()?;
    start_fixed_agent_task()?;
    Ok(EnrollmentResult {
        hub_address: display_address,
    })
}

/// Retained for the developer-only CLI. Production calls `enroll` from the elevated GUI.
pub fn enroll_from_console() -> Result<EnrollmentResult, CliError> {
    use std::io::{self, Write};
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };

    fn prompt(label: &str) -> Result<String, CliError> {
        print!("{label}");
        io::stdout().flush().map_err(client_error)?;
        let mut value = String::new();
        io::stdin().read_line(&mut value).map_err(client_error)?;
        let value = value.trim().to_owned();
        (!value.is_empty())
            .then_some(value)
            .ok_or_else(|| client("enrollment.input_missing"))
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
        (!value.is_empty())
            .then_some(value)
            .ok_or_else(|| client("enrollment.input_missing"))
    }

    enroll(
        &prompt("Hub HTTPS address: ")?,
        &prompt_secret("One-time registration code: ")?,
    )
}

pub fn start_fixed_agent_task() -> Result<(), CliError> {
    let (agent, _) = fixed_agent_path()?;
    validate_fixed_task(&agent)?;
    run_schtasks(["/Run", "/TN", PRODUCTION_TASK_NAME])
}

fn install_fixed_agent_task() -> Result<(), CliError> {
    let (agent, _) = fixed_agent_path()?;
    let action = format!("\"{}\"", agent.display());
    // ponytail: schtasks defaults to the current local user; /IT prevents Session 0 service execution.
    run_schtasks([
        "/Create",
        "/TN",
        PRODUCTION_TASK_NAME,
        "/TR",
        &action,
        "/SC",
        "ONLOGON",
        "/IT",
        "/RL",
        "HIGHEST",
        "/F",
    ])?;
    validate_fixed_task(&agent)
}

fn fixed_agent_path() -> Result<(PathBuf, PathBuf), CliError> {
    let executable = std::env::current_exe().map_err(client_error)?;
    let directory = executable
        .parent()
        .ok_or_else(|| client("enrollment.agent_unavailable"))?
        .to_path_buf();
    let agent = directory.join("fairypam-agent.exe");
    let metadata =
        fs::symlink_metadata(&agent).map_err(|_| client("enrollment.agent_unavailable"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(client("enrollment.agent_unavailable"));
    }
    Ok((agent, directory))
}

fn validate_fixed_task(agent: &Path) -> Result<(), CliError> {
    let output = hidden_schtasks(["/Query", "/TN", PRODUCTION_TASK_NAME, "/XML"])?;
    if !output.status.success() {
        return Err(client("startup.task_unavailable"));
    }
    let xml = String::from_utf8_lossy(&output.stdout);
    if !crate::is_fixed_interactive_task_xml(&xml, &agent.to_string_lossy()) {
        return Err(client("startup.task_action_invalid"));
    }
    Ok(())
}

fn run_schtasks<const N: usize>(arguments: [&str; N]) -> Result<(), CliError> {
    let output = hidden_schtasks(arguments)?;
    output
        .status
        .success()
        .then_some(())
        .ok_or_else(|| client("startup.task_failed"))
}

fn hidden_schtasks<const N: usize>(arguments: [&str; N]) -> Result<Output, CliError> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut command = Command::new("schtasks.exe");
    command.args(arguments).creation_flags(CREATE_NO_WINDOW);
    command.output().map_err(client_error)
}

fn ensure_elevated() -> Result<(), CliError> {
    current_process_is_elevated()?
        .then_some(())
        .ok_or_else(|| client("enrollment.elevation_required"))
}

fn current_process_is_elevated() -> Result<bool, CliError> {
    let mut token = Default::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(client_error)?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    result.map_err(client_error)?;
    Ok(elevation.TokenIsElevated != 0)
}

fn claim_target(value: &str) -> Result<(String, u16, String, String), CliError> {
    let base = value.trim_end_matches('/');
    let authority = base
        .strip_prefix("https://")
        .ok_or_else(|| client("enrollment.hub_invalid"))?;
    if authority.contains('@') {
        return Err(client("enrollment.hub_invalid"));
    }
    let (host_port, prefix) = authority.split_once('/').unwrap_or((authority, ""));
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => (
            host.to_owned(),
            port.parse().map_err(|_| client("enrollment.hub_invalid"))?,
        ),
        _ if !host_port.is_empty() => (host_port.to_owned(), 443),
        _ => return Err(client("enrollment.hub_invalid")),
    };
    let path = format!(
        "/{}/api/v1/agent-enrollment/claim",
        prefix.trim_matches('/')
    )
    .replace("//api", "/api");
    Ok((host, port, path, format!("https://{host_port}")))
}

fn claim(host: &str, port: u16, path: &str, code: &str) -> Result<Value, CliError> {
    let session = unsafe {
        WinHttpOpen(
            &HSTRING::from("FairyPam enrollment"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            &HSTRING::new(),
            &HSTRING::new(),
            0,
        )
    };
    if session.is_null() {
        return Err(client("enrollment.network_failed"));
    }
    let connection = unsafe { WinHttpConnect(session, &HSTRING::from(host), port, 0) };
    if connection.is_null() {
        close(session);
        return Err(client("enrollment.network_failed"));
    }
    let request = unsafe {
        WinHttpOpenRequest(
            connection,
            &HSTRING::from("POST"),
            &HSTRING::from(path),
            &HSTRING::new(),
            &HSTRING::new(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        )
    };
    if request.is_null() {
        close(connection);
        close(session);
        return Err(client("enrollment.network_failed"));
    }
    let body = serde_json::to_vec(&json!({"code":code})).map_err(client_error)?;
    let headers = "Content-Type: application/json\r\n"
        .encode_utf16()
        .collect::<Vec<_>>();
    let result = unsafe {
        WinHttpSendRequest(
            request,
            Some(&headers),
            Some(body.as_ptr().cast()),
            body.len() as u32,
            body.len() as u32,
            0,
        )
        .and_then(|_| WinHttpReceiveResponse(request, std::ptr::null_mut()))
    };
    if result.is_err() {
        close(request);
        close(connection);
        close(session);
        return Err(client("enrollment.claim_failed"));
    }
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0_u8; 4096];
        let mut read = 0;
        unsafe {
            WinHttpReadData(
                request,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
            )
        }
        .map_err(client_error)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
        if bytes.len() > 65_536 {
            return Err(client("enrollment.response_too_large"));
        }
    }
    close(request);
    close(connection);
    close(session);
    serde_json::from_slice(&bytes).map_err(|_| client("enrollment.claim_failed"))
}

fn persist(payload: &Value) -> Result<(), CliError> {
    for name in [
        "agent_id",
        "control_endpoint",
        "frame_endpoint",
        "hub_server_name",
        "profile_root_public_key_hex",
        "ca_pem",
        "client_cert_pem",
        "client_key_pem",
        "expires_at",
    ] {
        if payload.get(name).and_then(Value::as_str).is_none() {
            return Err(client("enrollment.response_invalid"));
        }
    }
    let root = PathBuf::from(STATE_ROOT);
    fs::create_dir_all(&root).map_err(client_error)?;
    restrict(&root)?;
    let generation = format!(
        "g-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(client_error)?
            .as_nanos()
    );
    let directory = root.join(&generation);
    fs::create_dir(&directory).map_err(client_error)?;
    restrict(&directory)?;
    write_private(
        &directory.join("runtime.json"),
        &serde_json::to_vec(payload).map_err(client_error)?,
    )?;
    for (field, file) in [
        ("ca_pem", "ca.pem"),
        ("client_cert_pem", "client-cert.pem"),
        ("client_key_pem", "client-key.pem"),
    ] {
        write_private(
            &directory.join(file),
            payload[field].as_str().expect("validated above").as_bytes(),
        )?;
    }
    let pointer = root.join("current.json");
    let temporary = root.join("current.json.tmp");
    write_private(
        &temporary,
        &serde_json::to_vec(&json!({"generation":generation})).map_err(client_error)?,
    )?;
    let backup = root.join("current.json.previous");
    let _ = fs::remove_file(&backup);
    if pointer.exists() {
        fs::rename(&pointer, &backup).map_err(client_error)?;
    }
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
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(client_error)?;
    let result = unsafe {
        SetFileSecurityW(
            &HSTRING::from(path.to_string_lossy().as_ref()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
        .ok()
    };
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(descriptor.0.cast()))) };
    result.map_err(client_error)
}

fn close(handle: *mut core::ffi::c_void) {
    let _ = unsafe { WinHttpCloseHandle(handle) };
}

fn client(code: &'static str) -> CliError {
    CliError::Client(LocalClientError::transport(code, code))
}

fn client_error(error: impl std::fmt::Display) -> CliError {
    CliError::Client(LocalClientError::transport(
        "enrollment.failed",
        error.to_string(),
    ))
}
