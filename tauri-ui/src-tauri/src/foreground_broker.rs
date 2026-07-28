#![cfg(windows)]

use std::{
    ffi::c_void,
    sync::{mpsc, Mutex, OnceLock},
    time::Duration,
};

use windows::{
    core::w,
    Win32::{
        Foundation::{CloseHandle, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WAIT_TIMEOUT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            Threading::{GetProcessId, WaitForSingleObject},
        },
        UI::WindowsAndMessaging::{
            AllowSetForegroundWindow, CreateWindowExW, DefWindowProcW, DispatchMessageW,
            GetForegroundWindow, GetMessageW, GetWindowThreadProcessId, RegisterClassW,
            RegisterWindowMessageW, TranslateMessage, HWND_MESSAGE, MSG, WINDOW_EX_STYLE,
            WINDOW_STYLE, WNDCLASSW,
        },
    },
};

use crate::local_gateway::UiCommandError;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
static BROKER: OnceLock<ForegroundBroker> = OnceLock::new();
static REQUEST_MESSAGE: OnceLock<u32> = OnceLock::new();
static BOUND_CORE: Mutex<Option<BoundCore>> = Mutex::new(None);

struct BoundCore {
    pid: u32,
    process: isize,
}

impl Drop for BoundCore {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(HANDLE(self.process as *mut c_void)) };
    }
}

pub struct ForegroundBroker {
    hwnd: isize,
}

impl ForegroundBroker {
    fn start() -> Result<Self, UiCommandError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("fairypam-foreground-broker".to_owned())
            .spawn(move || run_message_window(sender))
            .map_err(|error| broker_unavailable(error.to_string()))?;
        receiver
            .recv_timeout(STARTUP_TIMEOUT)
            .map_err(|error| broker_unavailable(error.to_string()))?
    }

    pub const fn hwnd(&self) -> isize {
        self.hwnd
    }

    pub fn bind_core(&self, process: HANDLE) -> Result<u32, UiCommandError> {
        let pid = unsafe { GetProcessId(process) };
        if pid == 0 {
            let _ = unsafe { CloseHandle(process) };
            return Err(broker_unavailable("elevated Agent PID is unavailable"));
        }
        let mut bound = BOUND_CORE
            .lock()
            .map_err(|_| broker_unavailable("foreground broker state is unavailable"))?;
        *bound = Some(BoundCore {
            pid,
            process: process.0 as isize,
        });
        Ok(pid)
    }

    pub fn clear(&self) {
        if let Ok(mut bound) = BOUND_CORE.lock() {
            bound.take();
        }
    }
}

pub fn foreground_broker() -> Result<&'static ForegroundBroker, UiCommandError> {
    if let Some(broker) = BROKER.get() {
        return Ok(broker);
    }
    let broker = ForegroundBroker::start()?;
    let _ = BROKER.set(broker);
    BROKER
        .get()
        .ok_or_else(|| broker_unavailable("foreground broker initialization raced"))
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if REQUEST_MESSAGE.get().copied() == Some(message) {
        return grant_bound_core(wparam.0 as u32);
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn grant_bound_core(requested_pid: u32) -> LRESULT {
    let Ok(bound) = BOUND_CORE.lock() else {
        return LRESULT(0);
    };
    let Some(bound) = bound.as_ref() else {
        return LRESULT(0);
    };
    let mut foreground_pid = 0;
    unsafe { GetWindowThreadProcessId(GetForegroundWindow(), Some(&mut foreground_pid)) };
    let process_running =
        unsafe { WaitForSingleObject(HANDLE(bound.process as *mut c_void), 0) } == WAIT_TIMEOUT;
    if !request_is_allowed(
        requested_pid,
        bound.pid,
        foreground_pid,
        std::process::id(),
        process_running,
    ) {
        return LRESULT(0);
    }
    LRESULT(unsafe { AllowSetForegroundWindow(bound.pid) }.is_ok() as isize)
}

fn run_message_window(sender: mpsc::SyncSender<Result<ForegroundBroker, UiCommandError>>) {
    let result = create_message_window();
    let hwnd = result.as_ref().ok().map(|broker| broker.hwnd);
    let _ = sender.send(result);
    let Some(_hwnd) = hwnd else {
        return;
    };
    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.as_bool() {
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

fn create_message_window() -> Result<ForegroundBroker, UiCommandError> {
    let request_message = unsafe { RegisterWindowMessageW(w!("FairyPam.ForegroundBroker.v1")) };
    if request_message == 0 {
        return Err(broker_unavailable(
            "foreground broker message registration failed",
        ));
    }
    let _ = REQUEST_MESSAGE.set(request_message);
    let module =
        unsafe { GetModuleHandleW(None) }.map_err(|error| broker_unavailable(error.to_string()))?;
    let instance = HINSTANCE(module.0);
    let class = w!("FairyPamForegroundBrokerWindow");
    let window_class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class,
        ..Default::default()
    };
    if unsafe { RegisterClassW(&window_class) } == 0 {
        return Err(broker_unavailable(
            "foreground broker window registration failed",
        ));
    }
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("FairyPam Foreground Broker"),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance),
            None,
        )
    }
    .map_err(|error| broker_unavailable(error.to_string()))?;
    Ok(ForegroundBroker {
        hwnd: hwnd.0 as isize,
    })
}

fn broker_unavailable(message: impl Into<String>) -> UiCommandError {
    UiCommandError::unavailable("startup.foreground_broker_unavailable", message)
}

fn request_is_allowed(
    requested_pid: u32,
    bound_pid: u32,
    foreground_pid: u32,
    gui_pid: u32,
    process_running: bool,
) -> bool {
    requested_pid == bound_pid && foreground_pid == gui_pid && process_running
}

#[cfg(test)]
mod tests {
    use super::request_is_allowed;

    #[test]
    fn grants_only_the_live_bound_core_while_gui_is_foreground() {
        assert!(request_is_allowed(7, 7, 11, 11, true));
        assert!(!request_is_allowed(8, 7, 11, 11, true));
        assert!(!request_is_allowed(7, 7, 12, 11, true));
        assert!(!request_is_allowed(7, 7, 11, 11, false));
    }
}
