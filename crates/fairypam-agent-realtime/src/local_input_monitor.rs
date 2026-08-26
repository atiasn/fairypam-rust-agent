use crate::RealtimeError;

pub trait LocalInputMonitor {
    fn check(&self) -> Result<(), RealtimeError>;
}

#[cfg(windows)]
pub mod windows {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{LPARAM, LRESULT, POINT, WPARAM};
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, DispatchMessageW, GetMessageW, PostThreadMessageW, SetWindowsHookExW,
        TranslateMessage, UnhookWindowsHookEx, HC_ACTION, KBDLLHOOKSTRUCT, MSG, MSLLHOOKSTRUCT,
        WH_KEYBOARD_LL, WH_MOUSE_LL, WM_MOUSEMOVE, WM_QUIT,
    };

    use super::LocalInputMonitor;
    use crate::input_batch::windows::SEND_INPUT_MARKER;
    use crate::RealtimeError;

    static ACTIVE: OnceLock<Mutex<Option<Arc<State>>>> = OnceLock::new();

    struct State {
        interfered: AtomicBool,
        motion: Mutex<MouseMotion>,
    }

    #[derive(Default)]
    struct MouseMotion {
        last: Option<(Instant, POINT)>,
        distance: u32,
    }

    pub struct WindowsLocalInputMonitor {
        state: Arc<State>,
        thread_id: u32,
        thread: Option<JoinHandle<()>>,
    }

    impl WindowsLocalInputMonitor {
        pub fn start() -> Result<Self, RealtimeError> {
            let state = Arc::new(State {
                interfered: AtomicBool::new(false),
                motion: Mutex::new(MouseMotion::default()),
            });
            let active = ACTIVE.get_or_init(|| Mutex::new(None));
            let mut slot = active
                .lock()
                .map_err(|_| monitor_failed("monitor is poisoned"))?;
            if slot.is_some() {
                return Err(monitor_failed("monitor is already active"));
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
                        if let Ok(value) = keyboard {
                            let _ = unsafe { UnhookWindowsHookEx(value) };
                        }
                        if let Ok(value) = mouse {
                            let _ = unsafe { UnhookWindowsHookEx(value) };
                        }
                        let _ = ready_tx.send(Err(()));
                    }
                }
            });
            match ready_rx.recv() {
                Ok(Ok(thread_id)) => Ok(Self {
                    state,
                    thread_id,
                    thread: Some(thread),
                }),
                _ => {
                    clear_active();
                    let _ = thread.join();
                    Err(monitor_failed("Windows hooks could not be installed"))
                }
            }
        }
    }

    impl LocalInputMonitor for WindowsLocalInputMonitor {
        fn check(&self) -> Result<(), RealtimeError> {
            if self.state.interfered.swap(false, Ordering::AcqRel) {
                return Err(RealtimeError::new(
                    "realtime.local_input_detected",
                    "local keyboard or mouse input was detected",
                ));
            }
            Ok(())
        }
    }

    impl Drop for WindowsLocalInputMonitor {
        fn drop(&mut self) {
            let _ = unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            clear_active();
        }
    }

    fn active() -> Option<Arc<State>> {
        ACTIVE.get()?.lock().ok()?.as_ref().map(Arc::clone)
    }

    fn clear_active() {
        if let Some(active) = ACTIVE.get() {
            if let Ok(mut slot) = active.lock() {
                *slot = None;
            }
        }
    }

    unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 {
            let event = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
            if event.dwExtraInfo != SEND_INPUT_MARKER {
                if let Some(state) = active() {
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
                if let Some(state) = active() {
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

    fn record_motion(state: &State, point: POINT) {
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

    fn monitor_failed(message: &str) -> RealtimeError {
        RealtimeError::new("realtime.local_input_monitor_failed", message)
    }
}
