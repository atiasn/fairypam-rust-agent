use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fairypam_agent_core::AgentError;
use windows::Win32::Foundation::{LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, PostThreadMessageW, SetWindowsHookExW,
    TranslateMessage, UnhookWindowsHookEx, HC_ACTION, KBDLLHOOKSTRUCT, MSG, MSLLHOOKSTRUCT,
    WH_KEYBOARD_LL, WH_MOUSE_LL, WM_MOUSEMOVE, WM_QUIT,
};

use crate::send_input::SEND_INPUT_MARKER;

static ACTIVE: OnceLock<Mutex<Option<Arc<MonitorState>>>> = OnceLock::new();

struct MonitorState {
    interfered: AtomicBool,
    motion: Mutex<MouseMotion>,
}

#[derive(Default)]
struct MouseMotion {
    last: Option<(Instant, POINT)>,
    distance: u32,
}

pub struct LocalInputMonitor {
    state: Arc<MonitorState>,
    thread_id: u32,
    thread: Option<JoinHandle<()>>,
}

impl LocalInputMonitor {
    pub fn start() -> Result<Self, AgentError> {
        let state = Arc::new(MonitorState {
            interfered: AtomicBool::new(false),
            motion: Mutex::new(MouseMotion::default()),
        });
        let active = ACTIVE.get_or_init(|| Mutex::new(None));
        let mut slot = active.lock().map_err(|_| {
            AgentError::new(
                "environment.monitor_failed",
                "input monitor state is poisoned",
            )
        })?;
        if slot.is_some() {
            return Err(AgentError::new(
                "environment.monitor_failed",
                "an input monitor is already active",
            ));
        }
        *slot = Some(Arc::clone(&state));
        drop(slot);

        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let keyboard =
                unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), None, 0) };
            let mouse = unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), None, 0) };
            match (keyboard, mouse) {
                (Ok(keyboard), Ok(mouse)) => {
                    let _ = ready_tx.send(Ok(unsafe { GetCurrentThreadId() }));
                    let mut message = MSG::default();
                    while unsafe { GetMessageW(&mut message, None, 0, 0) }.as_bool() {
                        let _ = unsafe { TranslateMessage(&message) };
                        unsafe { DispatchMessageW(&message) };
                    }
                    let _ = unsafe { UnhookWindowsHookEx(keyboard) };
                    let _ = unsafe { UnhookWindowsHookEx(mouse) };
                }
                (keyboard, mouse) => {
                    if let Ok(hook) = keyboard {
                        let _ = unsafe { UnhookWindowsHookEx(hook) };
                    }
                    if let Ok(hook) = mouse {
                        let _ = unsafe { UnhookWindowsHookEx(hook) };
                    }
                    let _ =
                        ready_tx.send(Err("Windows low-level input hooks could not be installed"));
                }
            }
        });
        match ready_rx.recv() {
            Ok(Ok(thread_id)) => Ok(Self {
                state,
                thread_id,
                thread: Some(thread),
            }),
            Ok(Err(message)) => {
                clear_active();
                let _ = thread.join();
                Err(AgentError::new("environment.monitor_failed", message))
            }
            Err(error) => {
                clear_active();
                let _ = thread.join();
                Err(AgentError::new(
                    "environment.monitor_failed",
                    format!("Windows input monitor could not report readiness: {error}"),
                ))
            }
        }
    }

    pub fn check(&self) -> Result<(), AgentError> {
        check_state(&self.state)
    }
}

impl Drop for LocalInputMonitor {
    fn drop(&mut self) {
        let _ = unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        clear_active();
    }
}

fn clear_active() {
    if let Some(active) = ACTIVE.get() {
        if let Ok(mut slot) = active.lock() {
            *slot = None;
        }
    }
}

fn active_state() -> Option<Arc<MonitorState>> {
    ACTIVE.get()?.lock().ok()?.as_ref().map(Arc::clone)
}

pub(crate) fn check_active() -> Result<(), AgentError> {
    active_state().map_or(Ok(()), |state| check_state(&state))
}

pub fn require_local_input_monitor() -> Result<(), AgentError> {
    let state = active_state().ok_or_else(|| {
        AgentError::new(
            "environment.monitor_failed",
            "input monitor is not active during local music autoplay",
        )
    })?;
    check_state(&state)
}

fn check_state(state: &MonitorState) -> Result<(), AgentError> {
    if !state.interfered.swap(false, Ordering::AcqRel) {
        return Ok(());
    }
    if let Ok(mut motion) = state.motion.lock() {
        *motion = MouseMotion::default();
    }
    Err(AgentError::new(
        "environment.local_input_detected",
        "local keyboard or mouse input was detected during the attempt",
    ))
}

unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 {
        let event = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
        if event.dwExtraInfo != SEND_INPUT_MARKER {
            if let Some(state) = active_state() {
                state.interfered.store(true, Ordering::Release);
            }
        }
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

unsafe extern "system" fn mouse_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 {
        let event = unsafe { &*(lparam.0 as *const MSLLHOOKSTRUCT) };
        if event.dwExtraInfo != SEND_INPUT_MARKER {
            if let Some(state) = active_state() {
                if wparam.0 as u32 == WM_MOUSEMOVE {
                    record_motion(&state, event.pt);
                } else {
                    state.interfered.store(true, Ordering::Release);
                }
            }
        }
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

fn record_motion(state: &MonitorState, point: POINT) {
    let now = Instant::now();
    let Ok(mut motion) = state.motion.lock() else {
        state.interfered.store(true, Ordering::Release);
        return;
    };
    let Some((previous_at, previous)) = motion.last else {
        motion.last = Some((now, point));
        return;
    };
    if now.duration_since(previous_at) > Duration::from_millis(250) {
        motion.distance = 0;
    }
    motion.distance = motion
        .distance
        .saturating_add(point.x.abs_diff(previous.x))
        .saturating_add(point.y.abs_diff(previous.y));
    motion.last = Some((now, point));
    if motion.distance >= 8 {
        state.interfered.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_motion_requires_eight_accumulated_pixels() {
        let state = MonitorState {
            interfered: AtomicBool::new(false),
            motion: Mutex::new(MouseMotion::default()),
        };

        record_motion(&state, POINT { x: 0, y: 0 });
        record_motion(&state, POINT { x: 3, y: 4 });
        assert!(!state.interfered.load(Ordering::Acquire));

        record_motion(&state, POINT { x: 4, y: 4 });
        assert!(state.interfered.load(Ordering::Acquire));
    }

    #[test]
    fn optional_and_required_checks_differ_without_a_monitor() {
        clear_active();
        assert!(check_active().is_ok());
        assert_eq!(
            require_local_input_monitor().unwrap_err().code(),
            "environment.monitor_failed"
        );
    }
}
