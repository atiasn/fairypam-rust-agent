use std::io::{BufReader, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fairypam_agent_guardian::monitor::{GuardianMonitor, ReleaseDriver};
use fairypam_agent_guardian_protocol::{
    decode_request, encode_line, read_bounded_line, GuardianResponse, PhysicalHold, ReleaseReason,
};

enum StdinEvent {
    Line(Vec<u8>),
    Closed,
    Invalid(String),
}

fn main() {
    if let Err(error) = run() {
        eprintln!("guardian fatal: {error}");
        std::process::exit(1);
    }
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
                let alive = monitor.agent_pid().is_none_or(agent_is_alive);
                if let Err(error) = monitor.tick(Instant::now(), alive) {
                    eprintln!("guardian release failed: {error}");
                }
            }
        }
    }
    Ok(())
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
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
            KEYEVENTF_SCANCODE, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTUP,
            MOUSEINPUT, VIRTUAL_KEY,
        };

        let inputs: Vec<INPUT> = holds
            .iter()
            .map(|hold| match hold {
                PhysicalHold::ScanCode { scan_code, .. } => INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: *scan_code,
                            dwFlags: KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP,
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
                            mouseData: 0,
                            dwFlags: match button {
                                MouseButton::Left => MOUSEEVENTF_LEFTUP,
                                MouseButton::Right => MOUSEEVENTF_RIGHTUP,
                                MouseButton::Middle => MOUSEEVENTF_MIDDLEUP,
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
fn agent_is_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return false;
    };
    let mut exit_code = 0_u32;
    let alive = unsafe { GetExitCodeProcess(handle, &mut exit_code) }.is_ok()
        && windows::Win32::Foundation::NTSTATUS(exit_code as i32) == STILL_ACTIVE;
    unsafe {
        let _ = CloseHandle(handle);
    }
    alive
}

#[cfg(not(windows))]
fn agent_is_alive(_pid: u32) -> bool {
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
    fn broken_response_pipe_releases_registered_input_before_exit() {
        let now = Instant::now();
        let mut monitor = GuardianMonitor::new(RecordingRelease::default());
        monitor
            .register_agent(42, Duration::from_millis(300), now)
            .unwrap();
        monitor
            .register_intent(
                1,
                vec![PhysicalHold::ScanCode {
                    action_id: ActionId::new("movement.forward").unwrap(),
                    scan_code: 17,
                }],
            )
            .unwrap();
        monitor.commit_holds(1).unwrap();

        let error =
            write_response_or_release(&mut monitor, &mut BrokenWriter, &GuardianResponse::Ack {})
                .unwrap_err();

        assert!(error.contains("reader closed"));
        assert_eq!(monitor.release_driver().calls, 1);
        assert!(monitor.committed_holds().is_empty());
    }
}
