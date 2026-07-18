#[cfg(any(windows, test))]
const W_SCAN_CODE: u16 = 17;
#[cfg(any(windows, test))]
const ANIMATION_TIMER_ID: usize = 1;
#[cfg(any(windows, test))]
const ANIMATION_INTERVAL_MS: u32 = 50;
#[cfg(any(windows, test))]
const _: () = assert!(ANIMATION_TIMER_ID != 0 && ANIMATION_INTERVAL_MS <= 100);

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyEvent {
    Down,
    Up,
}

#[cfg(any(windows, test))]
impl KeyEvent {
    const fn label(self) -> &'static str {
        match self {
            Self::Down => "key_down",
            Self::Up => "key_up",
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedIntegrity {
    Normal,
    High,
}

#[cfg(any(windows, test))]
impl ExpectedIntegrity {
    const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    telemetry_nonce: Option<String>,
    expected_integrity: ExpectedIntegrity,
}

#[cfg(any(windows, test))]
fn parse_arguments<I, S>(values: I) -> Result<Arguments, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut nonce = None;
    let mut expected_integrity = ExpectedIntegrity::Normal;
    let mut values = values.into_iter().map(Into::into);
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--telemetry-nonce" => {
                if nonce.is_some() {
                    return Err("--telemetry-nonce may only be provided once".to_owned());
                }
                if !valid_nonce(&value) {
                    return Err("telemetry nonce must be 64 lowercase hex characters".to_owned());
                }
                nonce = Some(value);
            }
            "--expected-integrity" => {
                expected_integrity = match value.as_str() {
                    "normal" => ExpectedIntegrity::Normal,
                    "high" => ExpectedIntegrity::High,
                    _ => return Err("expected integrity must be normal or high".to_owned()),
                };
            }
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    Ok(Arguments {
        telemetry_nonce: nonce,
        expected_integrity,
    })
}

#[cfg(any(windows, test))]
fn valid_nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(windows, test))]
fn key_event_line(
    nonce: &str,
    event: KeyEvent,
    scan_code: u16,
    qpc_ticks: i64,
    qpc_frequency: i64,
    testbed_pid: u32,
) -> String {
    format!(
        "FAIRYPAM_TESTBED_KEY_EVENT={{\"schema_version\":1,\"nonce\":\"{nonce}\",\"event\":\"{}\",\"scan_code\":{scan_code},\"qpc_ticks\":{qpc_ticks},\"qpc_frequency\":{qpc_frequency},\"testbed_pid\":{testbed_pid}}}",
        event.label()
    )
}

#[cfg(any(windows, test))]
fn ready_line(integrity: ExpectedIntegrity, process_id: u32) -> String {
    format!(
        "FAIRYPAM_TESTBED_READY={{\"schema_version\":1,\"integrity\":\"{}\",\"process_id\":{process_id},\"window_class\":\"FairyPamTestWindow\",\"animation_interval_ms\":{ANIMATION_INTERVAL_MS},\"frame_colors\":[\"window\",\"highlight\"]}}",
        integrity.label()
    )
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows::run() {
        eprintln!("fairypam-test-window failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows {
    use std::error::Error;
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;

    use super::{
        key_event_line, parse_arguments, ready_line, ExpectedIntegrity, KeyEvent,
        ANIMATION_INTERVAL_MS, ANIMATION_TIMER_ID, W_SCAN_CODE,
    };
    use windows::core::w;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, EndPaint, FillRect, GetSysColorBrush, InvalidateRect, COLOR_HIGHLIGHT,
        COLOR_WINDOW, PAINTSTRUCT,
    };
    use windows::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
    use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, KillTimer, PostQuitMessage,
        RegisterClassW, SetTimer, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, MSG,
        WINDOW_EX_STYLE, WM_DESTROY, WM_KEYDOWN, WM_KEYUP, WM_PAINT, WM_TIMER, WNDCLASSW,
        WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    struct TelemetryState {
        nonce: String,
        down_recorded: AtomicBool,
        up_recorded: AtomicBool,
    }

    static TELEMETRY: OnceLock<TelemetryState> = OnceLock::new();
    static PAINT_HIGHLIGHT: AtomicBool = AtomicBool::new(false);

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let event = match message {
            WM_KEYDOWN => Some(KeyEvent::Down),
            WM_KEYUP => Some(KeyEvent::Up),
            _ => None,
        };
        let scan_code = ((lparam.0 as usize >> 16) & 0xff) as u16;
        if scan_code == W_SCAN_CODE {
            if let Some(event) = event {
                if let Err(error) = emit_key_event(event) {
                    eprintln!("testbed telemetry failed: {error}");
                }
            }
        }
        if message == WM_TIMER && wparam.0 == ANIMATION_TIMER_ID {
            PAINT_HIGHLIGHT.fetch_xor(true, Ordering::Relaxed);
            unsafe {
                let _ = InvalidateRect(Some(hwnd), None, false);
            }
            return LRESULT(0);
        }
        if message == WM_PAINT {
            let mut paint = PAINTSTRUCT::default();
            let dc = unsafe { BeginPaint(hwnd, &mut paint) };
            let color = if PAINT_HIGHLIGHT.load(Ordering::Relaxed) {
                COLOR_HIGHLIGHT
            } else {
                COLOR_WINDOW
            };
            unsafe {
                FillRect(dc, &paint.rcPaint, GetSysColorBrush(color));
                let _ = EndPaint(hwnd, &paint);
            }
            return LRESULT(0);
        }
        if message == WM_DESTROY {
            let _ = unsafe { KillTimer(Some(hwnd), ANIMATION_TIMER_ID) };
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let arguments = parse_arguments(std::env::args().skip(1))
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
        let actual_integrity = current_integrity()?;
        if actual_integrity != arguments.expected_integrity {
            return Err(format!(
                "testbed integrity mismatch: expected={} actual={}",
                arguments.expected_integrity.label(),
                actual_integrity.label()
            )
            .into());
        }
        if let Some(nonce) = arguments.telemetry_nonce {
            TELEMETRY
                .set(TelemetryState {
                    nonce,
                    down_recorded: AtomicBool::new(false),
                    up_recorded: AtomicBool::new(false),
                })
                .map_err(|_| "telemetry state was already initialized")?;
        }

        let module = unsafe { GetModuleHandleW(None) }?;
        let instance = HINSTANCE(module.0);
        let class = w!("FairyPamTestWindow");
        let window_class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class,
            ..Default::default()
        };
        if unsafe { RegisterClassW(&window_class) } == 0 {
            return Err(windows::core::Error::from_thread().into());
        }
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class,
                w!("FairyPam Test Window"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                800,
                600,
                None,
                None,
                Some(instance),
                None,
            )?
        };
        if unsafe { SetTimer(Some(hwnd), ANIMATION_TIMER_ID, ANIMATION_INTERVAL_MS, None) } == 0 {
            return Err(windows::core::Error::from_thread().into());
        }
        println!("{}", ready_line(actual_integrity, std::process::id()));
        io::stdout().flush()?;

        let mut message = MSG::default();
        while unsafe { GetMessageW(&mut message, None, 0, 0) }.as_bool() {
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        Ok(())
    }

    fn current_integrity() -> Result<ExpectedIntegrity, Box<dyn Error>> {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
        let mut length = 0_u32;
        let _ = unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut length) };
        let words = (length as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                Some(buffer.as_mut_ptr().cast()),
                length,
                &mut length,
            )
        };
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(token);
        }
        result?;
        let label = unsafe { &*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
        let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) } as u32;
        if count == 0 {
            return Err("testbed token integrity SID is invalid".into());
        }
        let rid = unsafe { *GetSidSubAuthority(label.Label.Sid, count - 1) };
        Ok(if rid >= SECURITY_MANDATORY_HIGH_RID as u32 {
            ExpectedIntegrity::High
        } else {
            ExpectedIntegrity::Normal
        })
    }

    fn emit_key_event(event: KeyEvent) -> Result<(), Box<dyn Error>> {
        let Some(state) = TELEMETRY.get() else {
            return Ok(());
        };
        if event == KeyEvent::Up && !state.down_recorded.load(Ordering::Acquire) {
            return Ok(());
        }
        let recorded = match event {
            KeyEvent::Down => &state.down_recorded,
            KeyEvent::Up => &state.up_recorded,
        };
        if recorded.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let mut ticks = 0_i64;
        let mut frequency = 0_i64;
        // SAFETY: both pointers refer to initialized writable i64 values for the
        // duration of the synchronous Win32 calls.
        unsafe {
            QueryPerformanceCounter(&mut ticks)?;
            QueryPerformanceFrequency(&mut frequency)?;
        }
        let line = key_event_line(
            &state.nonce,
            event,
            W_SCAN_CODE,
            ticks,
            frequency,
            std::process::id(),
        );
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{line}")?;
        stdout.flush()?;
        Ok(())
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("fairypam-test-window requires Windows");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn telemetry_nonce_is_optional_but_strict_when_present() {
        assert_eq!(
            parse_arguments(std::iter::empty::<&str>()).unwrap(),
            Arguments {
                telemetry_nonce: None,
                expected_integrity: ExpectedIntegrity::Normal,
            }
        );
        assert_eq!(
            parse_arguments(["--telemetry-nonce", NONCE, "--expected-integrity", "high"]).unwrap(),
            Arguments {
                telemetry_nonce: Some(NONCE.to_owned()),
                expected_integrity: ExpectedIntegrity::High,
            }
        );
        assert!(parse_arguments(["--telemetry-nonce", "reusable"]).is_err());
        assert!(parse_arguments(["--output", "C:\\temp\\events.json"]).is_err());
    }

    #[test]
    fn ready_marker_makes_integrity_and_frame_expectations_machine_decidable() {
        let marker = ready_line(ExpectedIntegrity::High, 99);
        let payload = marker.strip_prefix("FAIRYPAM_TESTBED_READY=").unwrap();
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(value["integrity"], "high");
        assert_eq!(value["process_id"], 99);
        assert_eq!(value["animation_interval_ms"], 50);
        assert_eq!(value["frame_colors"][0], "window");
        assert_eq!(value["frame_colors"][1], "highlight");
    }

    #[test]
    fn key_event_line_is_fixed_nonce_bound_json() {
        let line = key_event_line(NONCE, KeyEvent::Down, W_SCAN_CODE, 1234, 10_000_000, 99);
        let payload = line.strip_prefix("FAIRYPAM_TESTBED_KEY_EVENT=").unwrap();
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["nonce"], NONCE);
        assert_eq!(value["event"], "key_down");
        assert_eq!(value["scan_code"], 17);
        assert_eq!(value["qpc_ticks"], 1234);
        assert_eq!(value["qpc_frequency"], 10_000_000);
        assert_eq!(value["testbed_pid"], 99);

        let up = key_event_line(NONCE, KeyEvent::Up, W_SCAN_CODE, 1250, 10_000_000, 99);
        assert!(up.contains("\"event\":\"key_up\""));
    }
}
