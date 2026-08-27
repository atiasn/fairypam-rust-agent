use std::time::{Duration, Instant};

use crate::{health::RuntimeHealth, MaaRuntimeError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetGeometry {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bgr: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left = 0,
    Right = 1,
    Middle = 2,
    X1 = 3,
    X2 = 4,
}

pub trait GenericWindowsController {
    fn attach_target(
        &mut self,
        hwnd: usize,
        geometry: TargetGeometry,
    ) -> Result<(), MaaRuntimeError>;
    fn detach_target(&mut self) -> Result<(), MaaRuntimeError>;
    fn capture_once(&mut self, timeout: Duration) -> Result<CapturedFrame, MaaRuntimeError>;
    fn start_capture(&mut self) -> Result<(), MaaRuntimeError>;
    fn stop_capture(&mut self) -> Result<(), MaaRuntimeError>;
    fn click(
        &mut self,
        button: MouseButton,
        x: i32,
        y: i32,
        timeout: Duration,
    ) -> Result<(), MaaRuntimeError>;
    fn key_down(&mut self, virtual_key: i32, timeout: Duration) -> Result<(), MaaRuntimeError>;
    fn key_up(&mut self, virtual_key: i32, timeout: Duration) -> Result<(), MaaRuntimeError>;
    fn move_to(&mut self, x: i32, y: i32, timeout: Duration) -> Result<(), MaaRuntimeError>;
    fn scroll(&mut self, dx: i32, dy: i32, timeout: Duration) -> Result<(), MaaRuntimeError>;
    fn scroll_at(
        &mut self,
        point: Option<(i32, i32)>,
        dx: i32,
        dy: i32,
        timeout: Duration,
    ) -> Result<(), MaaRuntimeError> {
        let deadline = Instant::now() + timeout;
        if let Some((x, y)) = point {
            self.move_to(x, y, timeout)?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(MaaRuntimeError::new(
                "maa.operation_timeout",
                "MAA scroll deadline expired after pointer positioning",
            ));
        }
        self.scroll(dx, dy, remaining)
    }
    fn relative_move(&mut self, dx: i32, dy: i32, timeout: Duration)
        -> Result<(), MaaRuntimeError>;
    fn inactive(&mut self, timeout: Duration) -> Result<(), MaaRuntimeError>;
    fn get_health(&self) -> RuntimeHealth;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        MoveTo(i32, i32),
        Scroll(i32, i32),
    }

    #[derive(Default)]
    struct RecordingController(Vec<Call>);

    impl GenericWindowsController for RecordingController {
        fn attach_target(
            &mut self,
            _hwnd: usize,
            _geometry: TargetGeometry,
        ) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn detach_target(&mut self) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn capture_once(&mut self, _timeout: Duration) -> Result<CapturedFrame, MaaRuntimeError> {
            unreachable!()
        }

        fn start_capture(&mut self) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn stop_capture(&mut self) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn click(
            &mut self,
            _button: MouseButton,
            _x: i32,
            _y: i32,
            _timeout: Duration,
        ) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn key_down(
            &mut self,
            _virtual_key: i32,
            _timeout: Duration,
        ) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn key_up(&mut self, _virtual_key: i32, _timeout: Duration) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn move_to(&mut self, x: i32, y: i32, _timeout: Duration) -> Result<(), MaaRuntimeError> {
            self.0.push(Call::MoveTo(x, y));
            Ok(())
        }

        fn scroll(&mut self, dx: i32, dy: i32, _timeout: Duration) -> Result<(), MaaRuntimeError> {
            self.0.push(Call::Scroll(dx, dy));
            Ok(())
        }

        fn relative_move(
            &mut self,
            _dx: i32,
            _dy: i32,
            _timeout: Duration,
        ) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn inactive(&mut self, _timeout: Duration) -> Result<(), MaaRuntimeError> {
            Ok(())
        }

        fn get_health(&self) -> RuntimeHealth {
            RuntimeHealth::default()
        }
    }

    #[test]
    fn bound_scroll_positions_with_maa_before_scrolling() {
        let mut controller = RecordingController::default();
        controller
            .scroll_at(Some((960, 540)), 0, -120, Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            controller.0,
            [Call::MoveTo(960, 540), Call::Scroll(0, -120)]
        );
    }
}

#[cfg(windows)]
pub mod windows {
    use std::ffi::c_void;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use maa_framework::common::{MaaId, MaaStatus};
    use maa_framework::controller::Controller;
    use maa_framework::sys;

    use super::{CapturedFrame, GenericWindowsController, MouseButton, TargetGeometry};
    use crate::{health::RuntimeHealth, MaaRuntimeError};

    const EXPECTED_MAA_RUNTIME_VERSION: &str = "5.12.3";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MaaBackendSelection {
        pub screencap_method: sys::MaaWin32ScreencapMethod,
        pub mouse_method: sys::MaaWin32InputMethod,
        pub keyboard_method: sys::MaaWin32InputMethod,
    }

    impl Default for MaaBackendSelection {
        fn default() -> Self {
            Self {
                screencap_method: sys::MaaWin32ScreencapMethod_ScreenDC as _,
                mouse_method: sys::MaaWin32InputMethod_Seize as _,
                keyboard_method: sys::MaaWin32InputMethod_Seize as _,
            }
        }
    }

    pub struct MaaWindowsController {
        controller: Option<Controller>,
        geometry: Option<TargetGeometry>,
        backend: MaaBackendSelection,
        capture_running: bool,
        last_error_code: Option<String>,
        telemetry: Arc<Mutex<MaaTelemetry>>,
    }

    #[derive(Default)]
    struct MaaTelemetry {
        event_count: u64,
        last_event: Option<String>,
    }

    impl MaaWindowsController {
        pub fn new(backend: MaaBackendSelection) -> Result<Self, MaaRuntimeError> {
            if maa_runtime_version() != EXPECTED_MAA_RUNTIME_VERSION {
                return Err(MaaRuntimeError::new(
                    "maa.runtime_version_mismatch",
                    format!("loaded MaaVersion is {}", maa_runtime_version()),
                ));
            }
            Ok(Self {
                controller: None,
                geometry: None,
                backend,
                capture_running: false,
                last_error_code: None,
                telemetry: Arc::new(Mutex::new(MaaTelemetry::default())),
            })
        }

        pub fn load_library(path: &std::path::Path) -> Result<(), MaaRuntimeError> {
            maa_framework::load_library(path)
                .map_err(|error| MaaRuntimeError::new("maa.runtime_load_failed", error))?;
            if maa_runtime_version() != EXPECTED_MAA_RUNTIME_VERSION {
                return Err(MaaRuntimeError::new(
                    "maa.runtime_version_mismatch",
                    format!("loaded MaaVersion is {}", maa_runtime_version()),
                ));
            }
            Ok(())
        }

        fn controller(&self) -> Result<&Controller, MaaRuntimeError> {
            self.controller.as_ref().ok_or_else(|| {
                MaaRuntimeError::new("maa.target_detached", "MAA controller has no target")
            })
        }

        fn run(
            &mut self,
            id: Result<MaaId, maa_framework::MaaError>,
            timeout: Duration,
        ) -> Result<(), MaaRuntimeError> {
            let id = id.map_err(|error| self.fail("maa.operation_post_failed", error))?;
            let controller = self.controller()?.clone();
            let deadline = Instant::now() + timeout;
            loop {
                match controller.status(id) {
                    MaaStatus::SUCCEEDED => return Ok(()),
                    MaaStatus::FAILED | MaaStatus::INVALID => {
                        return Err(self.fail_message(
                            "maa.operation_failed",
                            format!("MAA operation {id} failed"),
                        ));
                    }
                    _ if Instant::now() >= deadline => {
                        return Err(self.fail_message(
                            "maa.operation_timeout",
                            format!("MAA operation {id} timed out"),
                        ));
                    }
                    _ => thread::sleep(Duration::from_millis(2)),
                }
            }
        }

        fn fail(&mut self, code: &'static str, error: impl std::fmt::Display) -> MaaRuntimeError {
            self.fail_message(code, error.to_string())
        }

        fn fail_message(&mut self, code: &'static str, message: String) -> MaaRuntimeError {
            self.last_error_code = Some(code.to_owned());
            MaaRuntimeError::new(code, message)
        }
    }

    impl GenericWindowsController for MaaWindowsController {
        fn attach_target(
            &mut self,
            hwnd: usize,
            geometry: TargetGeometry,
        ) -> Result<(), MaaRuntimeError> {
            if hwnd == 0 || geometry.width == 0 || geometry.height == 0 {
                return Err(MaaRuntimeError::new(
                    "maa.target_invalid",
                    "target HWND and client geometry must be valid",
                ));
            }
            let controller = Controller::new_win32(
                hwnd as *mut c_void,
                self.backend.screencap_method,
                self.backend.mouse_method,
                self.backend.keyboard_method,
            )
            .map_err(|error| self.fail("maa.controller_create_failed", error))?;
            controller
                .set_screenshot_use_raw_size(true)
                .map_err(|error| self.fail("maa.controller_option_failed", error))?;
            let telemetry = Arc::clone(&self.telemetry);
            controller
                .add_sink(move |message, _details| {
                    if let Ok(mut telemetry) = telemetry.lock() {
                        telemetry.event_count = telemetry.event_count.saturating_add(1);
                        telemetry.last_event = Some(message.chars().take(128).collect());
                    }
                })
                .map_err(|error| self.fail("maa.callback_register_failed", error))?;
            let connect = controller
                .post_connection()
                .map_err(|error| self.fail("maa.connection_failed", error))?;
            self.controller = Some(controller);
            self.geometry = Some(geometry);
            self.run(Ok(connect), Duration::from_secs(5))?;
            Ok(())
        }

        fn detach_target(&mut self) -> Result<(), MaaRuntimeError> {
            self.capture_running = false;
            self.geometry = None;
            self.controller = None;
            Ok(())
        }

        fn capture_once(&mut self, timeout: Duration) -> Result<CapturedFrame, MaaRuntimeError> {
            let controller = self.controller()?.clone();
            let id = controller.post_screencap();
            self.run(id, timeout)?;
            let image = controller
                .cached_image()
                .map_err(|error| self.fail("maa.capture_read_failed", error))?;
            let width = u32::try_from(image.width()).map_err(|_| {
                self.fail_message("maa.capture_invalid", "negative capture width".into())
            })?;
            let height = u32::try_from(image.height()).map_err(|_| {
                self.fail_message("maa.capture_invalid", "negative capture height".into())
            })?;
            let channels = u32::try_from(image.channels()).map_err(|_| {
                self.fail_message("maa.capture_invalid", "negative channel count".into())
            })?;
            if channels != 3 {
                return Err(self.fail_message(
                    "maa.capture_invalid",
                    format!("expected BGR capture, got {channels} channels"),
                ));
            }
            let bgr = image.raw_data().ok_or_else(|| {
                self.fail_message("maa.capture_read_failed", "capture has no raw data".into())
            })?;
            Ok(CapturedFrame {
                width,
                height,
                stride: width.saturating_mul(channels),
                bgr: bgr.to_vec(),
            })
        }

        fn start_capture(&mut self) -> Result<(), MaaRuntimeError> {
            self.controller()?;
            self.capture_running = true;
            Ok(())
        }

        fn stop_capture(&mut self) -> Result<(), MaaRuntimeError> {
            self.capture_running = false;
            Ok(())
        }

        fn click(
            &mut self,
            button: MouseButton,
            x: i32,
            y: i32,
            timeout: Duration,
        ) -> Result<(), MaaRuntimeError> {
            let id = self.controller()?.post_click_v2(x, y, button as i32, 1);
            self.run(id, timeout)
        }

        fn key_down(&mut self, virtual_key: i32, timeout: Duration) -> Result<(), MaaRuntimeError> {
            let id = self.controller()?.post_key_down(virtual_key);
            self.run(id, timeout)
        }

        fn key_up(&mut self, virtual_key: i32, timeout: Duration) -> Result<(), MaaRuntimeError> {
            let id = self.controller()?.post_key_up(virtual_key);
            self.run(id, timeout)
        }

        fn move_to(&mut self, x: i32, y: i32, timeout: Duration) -> Result<(), MaaRuntimeError> {
            let id = self.controller()?.post_touch_move(0, x, y, 0);
            self.run(id, timeout)
        }

        fn scroll(&mut self, dx: i32, dy: i32, timeout: Duration) -> Result<(), MaaRuntimeError> {
            let id = self.controller()?.post_scroll(dx, dy);
            self.run(id, timeout)
        }

        fn relative_move(
            &mut self,
            dx: i32,
            dy: i32,
            timeout: Duration,
        ) -> Result<(), MaaRuntimeError> {
            let id = self.controller()?.post_relative_move(dx, dy);
            self.run(id, timeout)
        }

        fn inactive(&mut self, timeout: Duration) -> Result<(), MaaRuntimeError> {
            let id = self.controller()?.post_inactive();
            self.run(id, timeout)
        }

        fn get_health(&self) -> RuntimeHealth {
            let telemetry = self.telemetry.lock().ok();
            RuntimeHealth {
                runtime_version: maa_runtime_version().to_owned(),
                backend: format!(
                    "screencap={};mouse={};keyboard={}",
                    self.backend.screencap_method,
                    self.backend.mouse_method,
                    self.backend.keyboard_method
                ),
                connected: self.controller.as_ref().is_some_and(Controller::connected),
                last_error_code: self.last_error_code.clone(),
                event_count: telemetry.as_ref().map_or(0, |value| value.event_count),
                last_event: telemetry.and_then(|value| value.last_event.clone()),
            }
        }
    }

    fn maa_runtime_version() -> &'static str {
        let version = maa_framework::maa_version();
        version.strip_prefix('v').unwrap_or(version)
    }
}
