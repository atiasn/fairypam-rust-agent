#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use fairypam_agent_maa::controller::windows::{MaaBackendSelection, MaaWindowsController};
#[cfg(windows)]
use fairypam_agent_maa::controller::{
    run_compatibility_input_smoke, GenericWindowsController, TargetGeometry,
};
#[cfg(windows)]
use fairypam_agent_maa::MaaRuntimeError;
#[cfg(windows)]
use windows::core::{w, HSTRING};
#[cfg(windows)]
use windows::Win32::Foundation::{HWND, RECT};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, DispatchMessageW, GetClientRect, PeekMessageW,
    TranslateMessage, MSG, PM_REMOVE, WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

#[cfg(windows)]
struct SmokeWindow(HWND);

#[cfg(windows)]
impl Drop for SmokeWindow {
    fn drop(&mut self) {
        let _ = unsafe { DestroyWindow(self.0) };
    }
}

#[cfg(windows)]
pub fn run(runtime_root: &Path, public_key: &OsStr) -> Result<(), MaaRuntimeError> {
    let public_key = public_key.to_str().ok_or_else(|| {
        MaaRuntimeError::new("maa.smoke_arguments_invalid", "public key must be Unicode")
    })?;
    let _runtime = crate::maa_loader::LoadedMaaRuntime::load_active(runtime_root, public_key)?;
    let window = create_window()?;
    let mut rect = RECT::default();
    unsafe { GetClientRect(window.0, &mut rect) }
        .map_err(|error| MaaRuntimeError::new("maa.smoke_window_failed", error.to_string()))?;
    let geometry = TargetGeometry {
        width: u32::try_from(rect.right - rect.left)
            .map_err(|_| MaaRuntimeError::new("maa.smoke_window_failed", "invalid width"))?,
        height: u32::try_from(rect.bottom - rect.top)
            .map_err(|_| MaaRuntimeError::new("maa.smoke_window_failed", "invalid height"))?,
    };
    let hwnd = window.0 .0 as usize;
    let smoke = std::thread::spawn(move || {
        let timeout = Duration::from_secs(10);
        let mut controller = MaaWindowsController::new(MaaBackendSelection::default())?;
        controller.attach_target(hwnd, geometry)?;
        controller.start_capture()?;
        let frame = controller.capture_once(timeout)?;
        controller.stop_capture()?;
        if frame.width == 0 || frame.height == 0 || frame.bgr.is_empty() {
            return Err(MaaRuntimeError::new(
                "maa.smoke_capture_invalid",
                "MAA returned an empty smoke-test capture",
            ));
        }
        let point = (
            i32::try_from(geometry.width / 2).unwrap_or(1),
            i32::try_from(geometry.height / 2).unwrap_or(1),
        );
        run_compatibility_input_smoke(&mut controller, point, timeout)?;
        let health = controller.get_health();
        if health.runtime_version != "5.12.3" || !health.connected || health.event_count == 0 {
            return Err(MaaRuntimeError::new(
                "maa.smoke_health_invalid",
                "MAA controller health did not remain connected",
            ));
        }
        controller.detach_target()
    });
    while !smoke.is_finished() {
        let mut message = MSG::default();
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            let _ = unsafe { TranslateMessage(&message) };
            unsafe { DispatchMessageW(&message) };
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    smoke
        .join()
        .map_err(|_| MaaRuntimeError::new("maa.smoke_thread_failed", "smoke thread panicked"))?
}

#[cfg(windows)]
fn create_window() -> Result<SmokeWindow, MaaRuntimeError> {
    let title = HSTRING::from("FairyPam MAA 5.12.3 smoke");
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            &title,
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            100,
            100,
            640,
            480,
            None,
            None,
            None,
            None,
        )
    }
    .map_err(|error| MaaRuntimeError::new("maa.smoke_window_failed", error.to_string()))?;
    std::thread::sleep(Duration::from_millis(250));
    Ok(SmokeWindow(window))
}
