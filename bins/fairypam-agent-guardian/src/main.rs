use std::io::{BufReader, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fairypam_agent_guardian::monitor::{GuardianMonitor, ReleaseDriver};
use fairypam_agent_guardian_protocol::{
    decode_request, encode_line, read_bounded_line, GuardianRequest, GuardianResponse,
    PhysicalHold, ReleaseReason,
};

enum StdinEvent {
    Line(Vec<u8>),
    Closed,
    Invalid(String),
}

fn main() {
    let result = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => run(),
        [argument] if argument == "--self-test" => self_test(),
        _ => Err("guardian arguments are invalid".into()),
    };
    if let Err(error) = result {
        eprintln!("guardian fatal: {error}");
        std::process::exit(1);
    }
}

fn self_test() -> Result<(), String> {
    let mut monitor = GuardianMonitor::new(SystemReleaseDriver);
    let now = Instant::now();
    let pid = std::process::id();
    for (request, expected) in [
        (
            GuardianRequest::RegisterAgent {
                agent_pid: pid,
                agent_process_handle: 1,
                heartbeat_timeout_ms: 5_000,
                isolation_key_name: None,
            },
            GuardianResponse::Ack {
                isolation_status: None,
            },
        ),
        (
            GuardianRequest::Heartbeat { sequence: 0 },
            GuardianResponse::Ack {
                isolation_status: None,
            },
        ),
        (
            GuardianRequest::Status {},
            GuardianResponse::Status {
                agent_pid: Some(pid),
                committed_hold_count: 0,
                last_sequence: 0,
            },
        ),
        (
            GuardianRequest::ReleaseAll {
                reason: ReleaseReason::EmergencyStop,
            },
            GuardianResponse::Ack {
                isolation_status: None,
            },
        ),
    ] {
        if monitor.handle(request, now) != expected {
            return Err("guardian self-test failed".into());
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let (sender, receiver) = mpsc::sync_channel::<StdinEvent>(1);
    std::thread::Builder::new()
        .name("guardian-stdin".into())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            loop {
                match read_bounded_line(&mut reader) {
                    Ok(None) => {
                        let _ = sender.send(StdinEvent::Closed);
                        break;
                    }
                    Ok(Some(line)) => {
                        if sender.send(StdinEvent::Line(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(StdinEvent::Invalid(error.to_string()));
                        break;
                    }
                }
            }
        })
        .map_err(|error| error.to_string())?;

    let mut monitor = GuardianMonitor::new(SystemReleaseDriver);
    let mut stdout = std::io::stdout().lock();
    loop {
        match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(StdinEvent::Line(line)) => {
                let response = match decode_request(&line) {
                    Ok(GuardianRequest::RegisterAgent {
                        agent_pid,
                        agent_process_handle,
                        heartbeat_timeout_ms,
                        isolation_key_name,
                    }) => register_agent(
                        &mut monitor,
                        agent_pid,
                        agent_process_handle,
                        heartbeat_timeout_ms,
                        isolation_key_name.as_deref(),
                    ),
                    Ok(request) => monitor.handle(request, Instant::now()),
                    Err(error) => GuardianResponse::Error {
                        code: "guardian.invalid_message".into(),
                        message: error.to_string(),
                    },
                };
                write_response_or_release(&mut monitor, &mut stdout, &response)?;
            }
            Ok(StdinEvent::Invalid(message)) => {
                let response = GuardianResponse::Error {
                    code: "guardian.invalid_message".into(),
                    message,
                };
                write_response_or_release(&mut monitor, &mut stdout, &response)?;
                release_on_exit(&mut monitor)?;
                break;
            }
            Ok(StdinEvent::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                release_on_exit(&mut monitor)?;
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let alive = monitor.agent_process_handle().is_none_or(agent_is_alive);
                if let Err(error) = monitor.tick(Instant::now(), alive) {
                    eprintln!("guardian release failed: {error}");
                }
            }
        }
    }
    Ok(())
}

fn register_agent<R: ReleaseDriver>(
    monitor: &mut GuardianMonitor<R>,
    agent_pid: u32,
    agent_process_handle: u64,
    heartbeat_timeout_ms: u32,
    isolation_key_name: Option<&str>,
) -> GuardianResponse {
    if agent_process_handle == 0 {
        return GuardianResponse::Error {
            code: "guardian.registration_invalid".into(),
            message: "guardian.registration_invalid".into(),
        };
    }
    let isolation_status = match isolation_key_name.map(probe_cng_key_access).transpose() {
        Ok(status) => status,
        Err(response) => return response,
    };
    match monitor.handle(
        GuardianRequest::RegisterAgent {
            agent_pid,
            agent_process_handle,
            heartbeat_timeout_ms,
            isolation_key_name: None,
        },
        Instant::now(),
    ) {
        GuardianResponse::Ack { .. } => GuardianResponse::Ack { isolation_status },
        response => response,
    }
}

#[cfg(windows)]
fn probe_cng_key_access(key_name: &str) -> Result<i32, GuardianResponse> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{E_ACCESSDENIED, NTE_PERM};
    use windows::Win32::Security::Cryptography::{
        NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, CERT_KEY_SPEC,
        MS_KEY_STORAGE_PROVIDER, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PROV_HANDLE,
        NCRYPT_SILENT_FLAG,
    };

    let suffix = key_name.strip_prefix("FairyPam.Agent.").unwrap_or_default();
    if suffix.is_empty()
        || key_name.len() > 128
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(GuardianResponse::Error {
            code: "guardian.key_name_invalid".into(),
            message: "guardian.key_name_invalid".into(),
        });
    }
    let mut provider = NCRYPT_PROV_HANDLE::default();
    if unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) }.is_err() {
        return Err(GuardianResponse::Error {
            code: "guardian.key_probe_failed".into(),
            message: "guardian.key_probe_failed".into(),
        });
    }
    let mut key = NCRYPT_KEY_HANDLE::default();
    let result = unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            &HSTRING::from(key_name),
            CERT_KEY_SPEC(0),
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    let _ = unsafe { NCryptFreeObject(provider.into()) };
    match result {
        Ok(()) => {
            let _ = unsafe { NCryptFreeObject(key.into()) };
            Err(GuardianResponse::Error {
                code: "guardian.key_access_unexpected".into(),
                message: "guardian.key_access_unexpected".into(),
            })
        }
        Err(error) if matches!(error.code(), NTE_PERM | E_ACCESSDENIED) => Ok(error.code().0),
        Err(error) => Err(GuardianResponse::Error {
            code: "guardian.key_probe_failed".into(),
            message: format!("guardian.key_probe_failed:{:08x}", error.code().0 as u32),
        }),
    }
}

#[cfg(not(windows))]
fn probe_cng_key_access(_key_name: &str) -> Result<i32, GuardianResponse> {
    Err(GuardianResponse::Error {
        code: "guardian.key_probe_unsupported".into(),
        message: "guardian.key_probe_unsupported".into(),
    })
}

fn write_response_or_release<R: ReleaseDriver, W: Write>(
    monitor: &mut GuardianMonitor<R>,
    writer: &mut W,
    response: &GuardianResponse,
) -> Result<(), String> {
    let result = encode_line(response)
        .map_err(|error| error.to_string())
        .and_then(|line| writer.write_all(&line).map_err(|error| error.to_string()))
        .and_then(|()| writer.flush().map_err(|error| error.to_string()));
    if let Err(write_error) = result {
        return match release_on_exit(monitor) {
            Ok(()) => Err(write_error),
            Err(release_error) => Err(format!(
                "{write_error}; Guardian release after response failure also failed: {release_error}"
            )),
        };
    }
    Ok(())
}

fn release_on_exit<R: ReleaseDriver>(monitor: &mut GuardianMonitor<R>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(300);
    loop {
        match monitor.release_all(ReleaseReason::AgentExited) {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() < deadline => {
                eprintln!("guardian exit release retry: {error}");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("guardian exit release failed: {error}")),
        }
    }
}

struct SystemReleaseDriver;

#[cfg(windows)]
impl ReleaseDriver for SystemReleaseDriver {
    fn release_all(&mut self, holds: &[PhysicalHold]) -> Result<(), String> {
        use fairypam_agent_guardian_protocol::MouseButton;
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT,
            KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_LEFTUP,
            MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
        };

        let inputs: Vec<INPUT> = holds
            .iter()
            .map(|hold| match hold {
                PhysicalHold::ScanCode {
                    scan_code,
                    extended,
                    ..
                } => INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: *scan_code,
                            dwFlags: KEYEVENTF_SCANCODE
                                | KEYEVENTF_KEYUP
                                | if *extended {
                                    KEYEVENTF_EXTENDEDKEY
                                } else {
                                    Default::default()
                                },
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                },
                PhysicalHold::MouseButton { button, .. } => INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dx: 0,
                            dy: 0,
                            mouseData: match button {
                                MouseButton::X1 => 1,
                                MouseButton::X2 => 2,
                                _ => 0,
                            },
                            dwFlags: match button {
                                MouseButton::Left => MOUSEEVENTF_LEFTUP,
                                MouseButton::Right => MOUSEEVENTF_RIGHTUP,
                                MouseButton::Middle => MOUSEEVENTF_MIDDLEUP,
                                MouseButton::X1 | MouseButton::X2 => MOUSEEVENTF_XUP,
                            },
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                },
            })
            .collect();
        if inputs.is_empty() {
            return Ok(());
        }
        let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent == inputs.len() as u32 {
            Ok(())
        } else {
            Err(format!("SendInput sent {sent}/{} releases", inputs.len()))
        }
    }
}

#[cfg(not(windows))]
impl ReleaseDriver for SystemReleaseDriver {
    fn release_all(&mut self, holds: &[PhysicalHold]) -> Result<(), String> {
        if holds.is_empty() {
            Ok(())
        } else {
            Err("guardian physical release is only supported on Windows".into())
        }
    }
}

#[cfg(windows)]
fn agent_is_alive(handle: u64) -> bool {
    use windows::Win32::Foundation::{HANDLE, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::WaitForSingleObject;

    handle <= usize::MAX as u64
        && unsafe { WaitForSingleObject(HANDLE(handle as usize as *mut _), 0) } == WAIT_TIMEOUT
}

#[cfg(not(windows))]
fn agent_is_alive(_handle: u64) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use std::io;

    use fairypam_agent_guardian_protocol::{ActionId, PhysicalHold};

    use super::*;

    #[derive(Default)]
    struct RecordingRelease {
        calls: usize,
    }

    impl ReleaseDriver for RecordingRelease {
        fn release_all(&mut self, _holds: &[PhysicalHold]) -> Result<(), String> {
            self.calls += 1;
            Ok(())
        }
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn installed_binary_self_test_covers_registration_heartbeat_and_release() {
        self_test().unwrap();
    }

    #[test]
    fn broken_response_pipe_releases_registered_input_before_exit() {
        let now = Instant::now();
        let mut monitor = GuardianMonitor::new(RecordingRelease::default());
        monitor
            .register_agent(42, 1, Duration::from_millis(300), now)
            .unwrap();
        monitor
            .register_intent(
                1,
                vec![PhysicalHold::ScanCode {
                    action_id: ActionId::new("movement.forward").unwrap(),
                    scan_code: 17,
                    extended: false,
                }],
            )
            .unwrap();
        monitor.commit_holds(1).unwrap();

        let error = write_response_or_release(
            &mut monitor,
            &mut BrokenWriter,
            &GuardianResponse::Ack {
                isolation_status: None,
            },
        )
        .unwrap_err();

        assert!(error.contains("reader closed"));
        assert_eq!(monitor.release_driver().calls, 1);
        assert!(monitor.committed_holds().is_empty());
    }
}
