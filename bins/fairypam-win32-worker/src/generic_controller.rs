use fairypam_agent_maa::MaaRuntimeError;
use std::collections::VecDeque;

const SOURCE_FRAME_WINDOW_CAPACITY: usize = 256;

#[derive(Default)]
struct SourceFrameWindow {
    frames: VecDeque<u64>,
}

impl SourceFrameWindow {
    fn record(&mut self, sequence: u64) {
        while self.frames.len() >= SOURCE_FRAME_WINDOW_CAPACITY {
            self.frames.pop_front();
        }
        self.frames.push_back(sequence);
    }

    fn require(&self, sequence: u64) -> Result<(), MaaRuntimeError> {
        if sequence == 0 || !self.frames.contains(&sequence) {
            return Err(MaaRuntimeError::new(
                "worker.source_frame_stale",
                "Generic coordinates are not bound to a known captured frame",
            ));
        }
        Ok(())
    }

    fn clear(&mut self) {
        self.frames.clear();
    }
}

fn bind_optional_client_point(
    x_ppm: Option<u32>,
    y_ppm: Option<u32>,
    source_frame_sequence: Option<u64>,
    width: u32,
    height: u32,
) -> Result<Option<(i32, i32)>, MaaRuntimeError> {
    if source_frame_sequence == Some(0) {
        return Err(MaaRuntimeError::new(
            "worker.source_frame_stale",
            "Generic coordinates are not bound to a known captured frame",
        ));
    }
    match (x_ppm, y_ppm) {
        (None, None) => Ok(None),
        (Some(x), Some(y)) if source_frame_sequence.is_some() => Ok(Some((
            ppm_coordinate(x, width)?,
            ppm_coordinate(y, height)?,
        ))),
        _ => Err(MaaRuntimeError::new(
            "input.coordinate_invalid",
            "client-relative coordinates require a pair and a current source frame",
        )),
    }
}

fn ppm_coordinate(value: u32, extent: u32) -> Result<i32, MaaRuntimeError> {
    if value > 1_000_000 || extent == 0 {
        return Err(MaaRuntimeError::new(
            "input.coordinate_invalid",
            "client-relative coordinate is invalid",
        ));
    }
    i32::try_from((u64::from(extent - 1) * u64::from(value) + 500_000) / 1_000_000)
        .map_err(|_| MaaRuntimeError::new("input.coordinate_invalid", "coordinate overflow"))
}

#[cfg(test)]
mod tests {
    use super::{bind_optional_client_point, SourceFrameWindow};

    #[test]
    fn scroll_point_accepts_a_known_frame_and_converts_ppm() {
        assert_eq!(
            bind_optional_client_point(Some(500_000), Some(500_000), Some(7), 1920, 1080).unwrap(),
            Some((960, 540))
        );

        assert_eq!(
            bind_optional_client_point(Some(500_000), Some(500_000), Some(6), 1920, 1080).unwrap(),
            Some((960, 540))
        );

        let partial = bind_optional_client_point(Some(1), None, Some(7), 1920, 1080).unwrap_err();
        assert_eq!(partial.code(), "input.coordinate_invalid");
    }

    #[test]
    fn source_frame_window_accepts_known_frames_without_inferring_page_change_from_age() {
        let mut frames = SourceFrameWindow::default();
        frames.record(6);
        frames.record(7);

        frames.require(6).unwrap();
        assert_eq!(
            frames.require(8).unwrap_err().code(),
            "worker.source_frame_stale"
        );
        frames.clear();
        assert_eq!(
            frames.require(7).unwrap_err().code(),
            "worker.source_frame_stale"
        );
    }

    #[test]
    fn release_rejects_a_pre_release_frame_mapped_after_cleanup() {
        let mut frames = SourceFrameWindow::default();
        let worker_sequence = 3;
        frames.record(worker_sequence);

        frames.clear();
        let delayed_public_mapping = (2, worker_sequence);

        assert_eq!(
            frames.require(delayed_public_mapping.1).unwrap_err().code(),
            "worker.source_frame_stale"
        );
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use fairypam_agent_core::profile::{
        verify_profile, ActionDefinition, CaptureRegion, ClientPointButton,
        Ed25519SignatureVerifier, VerifiedProfile,
    };
    use fairypam_agent_maa::controller::windows::{MaaBackendSelection, MaaWindowsController};
    use fairypam_agent_maa::controller::{
        CapturedFrame, GenericWindowsController, MouseButton, TargetGeometry,
    };
    use fairypam_agent_maa::health::RuntimeHealth;
    use fairypam_agent_maa::MaaRuntimeError;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::HiDpi::GetDpiForWindow;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetClientRect, GetWindowThreadProcessId, IsWindow,
    };

    use super::{bind_optional_client_point, ppm_coordinate, SourceFrameWindow};

    const OPERATION_TIMEOUT: Duration = Duration::from_secs(3);

    pub struct GenericController {
        maa: MaaWindowsController,
        profile: Option<VerifiedProfile>,
        hwnd: Option<usize>,
        process_id: u32,
        geometry: Option<VerifiedGeometry>,
        frame_sequence: u64,
        source_frames: SourceFrameWindow,
        held_actions: BTreeSet<String>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct VerifiedGeometry {
        width: u32,
        height: u32,
        dpi: u32,
    }

    impl GenericController {
        pub fn new() -> Result<Self, MaaRuntimeError> {
            Ok(Self {
                maa: MaaWindowsController::new(MaaBackendSelection::default())?,
                profile: None,
                hwnd: None,
                process_id: 0,
                geometry: None,
                frame_sequence: 0,
                source_frames: SourceFrameWindow::default(),
                held_actions: BTreeSet::new(),
            })
        }

        pub fn attach(
            &mut self,
            hwnd_value: u64,
            process_id: u32,
            profile_id: &str,
            profile_digest: &str,
            profile_dir: &Path,
            verifier: &Ed25519SignatureVerifier,
        ) -> Result<(), MaaRuntimeError> {
            if !safe_profile_id(profile_id) {
                return Err(invalid_target("profile id is invalid"));
            }
            let profile = verify_profile(
                &fs::read(profile_dir.join(profile_id).join("profile.json")).map_err(|error| {
                    MaaRuntimeError::new("profile.not_found", error.to_string())
                })?,
                verifier,
            )
            .map_err(|error| MaaRuntimeError::new(error.code(), error.to_string()))?;
            if profile.profile().id != profile_id || profile.content_sha256() != profile_digest {
                return Err(MaaRuntimeError::new(
                    "profile_mismatch",
                    "worker Profile does not match the Agent attachment",
                ));
            }
            let hwnd = HWND(hwnd_value as usize as *mut std::ffi::c_void);
            let geometry = read_geometry(hwnd, process_id)?;
            self.maa.attach_target(
                hwnd_value as usize,
                TargetGeometry {
                    width: geometry.width,
                    height: geometry.height,
                },
            )?;
            self.profile = Some(profile);
            self.hwnd = Some(hwnd_value as usize);
            self.process_id = process_id;
            self.geometry = Some(geometry);
            self.frame_sequence = 0;
            self.source_frames.clear();
            self.held_actions.clear();
            Ok(())
        }

        pub fn detach(&mut self) -> Result<(), MaaRuntimeError> {
            self.release_all()?;
            self.maa.detach_target()?;
            self.profile = None;
            self.hwnd = None;
            self.process_id = 0;
            self.geometry = None;
            self.frame_sequence = 0;
            self.source_frames.clear();
            Ok(())
        }

        pub fn capture_once(&mut self) -> Result<(u64, CapturedFrame), MaaRuntimeError> {
            self.revalidate()?;
            let frame = self.maa.capture_once(OPERATION_TIMEOUT)?;
            let geometry = self
                .geometry
                .ok_or_else(|| invalid_target("target is detached"))?;
            if frame.width != geometry.width || frame.height != geometry.height {
                return Err(MaaRuntimeError::new(
                    "worker.target_geometry_changed",
                    "MAA capture size no longer matches the verified client area",
                ));
            }
            self.frame_sequence = self.frame_sequence.checked_add(1).ok_or_else(|| {
                MaaRuntimeError::new(
                    "worker.frame_sequence_exhausted",
                    "frame sequence exhausted",
                )
            })?;
            self.source_frames.record(self.frame_sequence);
            Ok((self.frame_sequence, frame))
        }

        pub fn start_capture(&mut self) -> Result<(), MaaRuntimeError> {
            self.revalidate()?;
            self.maa.start_capture()
        }

        pub fn validate_capture_source(
            &self,
            source_id: &str,
            fps: Option<u32>,
            encoding: &str,
        ) -> Result<(), MaaRuntimeError> {
            let source = self
                .profile()?
                .profile()
                .capture_sources
                .iter()
                .find(|source| source.id == source_id)
                .ok_or_else(|| {
                    MaaRuntimeError::new(
                        "worker.capture_source_not_allowed",
                        "capture source is not declared by the signed Profile",
                    )
                })?;
            if !matches!(&source.region, CaptureRegion::FullClient) {
                return Err(MaaRuntimeError::new(
                    "worker.capture_region_unsupported",
                    "Generic MAA capture only supports the full client area",
                ));
            }
            if fps.is_some_and(|value| value == 0 || value > source.maximum_fps)
                || !source.encodings.iter().any(|value| value == encoding)
            {
                return Err(MaaRuntimeError::new(
                    "worker.capture_configuration_not_allowed",
                    "capture rate or encoding is not allowed by the signed Profile",
                ));
            }
            Ok(())
        }

        pub fn stop_capture(&mut self) -> Result<(), MaaRuntimeError> {
            self.maa.stop_capture()
        }

        pub fn click(
            &mut self,
            action_id: &str,
            x_ppm: u32,
            y_ppm: u32,
            source_frame_sequence: u64,
        ) -> Result<(), MaaRuntimeError> {
            self.require_source_frame(source_frame_sequence)?;
            let geometry = self.revalidate()?;
            let button = match self.action(action_id)? {
                ActionDefinition::ClientPointClick { button } => profile_button(button),
                _ => return Err(action_kind_invalid()),
            };
            let x = ppm_coordinate(x_ppm, geometry.width)?;
            let y = ppm_coordinate(y_ppm, geometry.height)?;
            self.maa.click(button, x, y, OPERATION_TIMEOUT)
        }

        pub fn key_down(&mut self, action_id: &str) -> Result<(), MaaRuntimeError> {
            self.revalidate()?;
            let virtual_key = match self.action(action_id)? {
                ActionDefinition::Hold {
                    maa_virtual_key, ..
                }
                | ActionDefinition::Pulse {
                    maa_virtual_key, ..
                } => i32::from(*maa_virtual_key),
                _ => return Err(action_kind_invalid()),
            };
            if self.held_actions.contains(action_id) {
                return Ok(());
            }
            self.maa.key_down(virtual_key, OPERATION_TIMEOUT)?;
            self.held_actions.insert(action_id.to_owned());
            Ok(())
        }

        pub fn key_up(&mut self, action_id: &str) -> Result<(), MaaRuntimeError> {
            self.revalidate()?;
            let virtual_key = match self.action(action_id)? {
                ActionDefinition::Hold {
                    maa_virtual_key, ..
                }
                | ActionDefinition::Pulse {
                    maa_virtual_key, ..
                } => i32::from(*maa_virtual_key),
                _ => return Err(action_kind_invalid()),
            };
            if !self.held_actions.contains(action_id) {
                return Ok(());
            }
            self.maa.key_up(virtual_key, OPERATION_TIMEOUT)?;
            self.held_actions.remove(action_id);
            Ok(())
        }

        pub fn scroll(
            &mut self,
            action_id: &str,
            delta: i32,
            x_ppm: Option<u32>,
            y_ppm: Option<u32>,
            source_frame_sequence: Option<u64>,
        ) -> Result<(), MaaRuntimeError> {
            let geometry = self.revalidate()?;
            if let Some(source) = source_frame_sequence {
                self.require_source_frame(source)?;
            }
            let bound_point = bind_optional_client_point(
                x_ppm,
                y_ppm,
                source_frame_sequence,
                geometry.width,
                geometry.height,
            )?;
            match self.action(action_id)? {
                ActionDefinition::Wheel { maximum_delta }
                    if delta != 0
                        && delta % 120 == 0
                        && delta.unsigned_abs() <= *maximum_delta as u32 => {}
                _ => return Err(action_kind_invalid()),
            }
            self.maa.scroll_at(bound_point, 0, delta, OPERATION_TIMEOUT)
        }

        pub fn relative_move(
            &mut self,
            action_id: &str,
            dx: i32,
            dy: i32,
        ) -> Result<(), MaaRuntimeError> {
            self.revalidate()?;
            match self.action(action_id)? {
                ActionDefinition::RelativeMouse { maximum_delta }
                    if dx.unsigned_abs() <= *maximum_delta as u32
                        && dy.unsigned_abs() <= *maximum_delta as u32 => {}
                _ => return Err(action_kind_invalid()),
            }
            self.maa.relative_move(dx, dy, OPERATION_TIMEOUT)
        }

        pub fn inactive(&mut self) -> Result<(), MaaRuntimeError> {
            self.maa.inactive(OPERATION_TIMEOUT)
        }

        pub fn release_all(&mut self) -> Result<(), MaaRuntimeError> {
            self.source_frames.clear();
            let held = std::mem::take(&mut self.held_actions);
            let mut first_error = None;
            for action_id in held {
                let virtual_key = match self.action(&action_id) {
                    Ok(
                        ActionDefinition::Hold {
                            maa_virtual_key, ..
                        }
                        | ActionDefinition::Pulse {
                            maa_virtual_key, ..
                        },
                    ) => i32::from(*maa_virtual_key),
                    _ => continue,
                };
                if let Err(error) = self.maa.key_up(virtual_key, OPERATION_TIMEOUT) {
                    first_error.get_or_insert(error);
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            Ok(())
        }

        pub fn profile(&self) -> Result<&VerifiedProfile, MaaRuntimeError> {
            self.profile
                .as_ref()
                .ok_or_else(|| invalid_target("target is detached"))
        }

        pub fn emergency_keys(
            &self,
        ) -> Result<Vec<fairypam_agent_realtime::input_batch::PhysicalKey>, MaaRuntimeError>
        {
            self.profile().map(|profile| {
                profile
                    .profile()
                    .actions
                    .iter()
                    .filter_map(|(action_id, action)| match action {
                        ActionDefinition::Hold {
                            physical_scan_code,
                            extended,
                            ..
                        }
                        | ActionDefinition::Pulse {
                            physical_scan_code,
                            extended,
                            ..
                        } => Some(fairypam_agent_realtime::input_batch::PhysicalKey {
                            action_id: action_id.clone(),
                            scan_code: *physical_scan_code,
                            extended: *extended,
                        }),
                        _ => None,
                    })
                    .collect()
            })
        }

        pub fn hwnd(&self) -> Result<usize, MaaRuntimeError> {
            self.hwnd
                .ok_or_else(|| invalid_target("target is detached"))
        }

        pub fn held_action_ids(&self) -> Vec<String> {
            self.held_actions.iter().cloned().collect()
        }

        pub fn health(&self) -> RuntimeHealth {
            self.maa.get_health()
        }

        fn require_source_frame(&self, source: u64) -> Result<(), MaaRuntimeError> {
            self.source_frames.require(source)
        }

        fn action(&self, action_id: &str) -> Result<&ActionDefinition, MaaRuntimeError> {
            self.profile()?
                .profile()
                .actions
                .get(action_id)
                .ok_or_else(|| {
                    MaaRuntimeError::new(
                        "input.action_not_allowed",
                        "action is not declared by the signed Profile",
                    )
                })
        }

        fn revalidate(&self) -> Result<VerifiedGeometry, MaaRuntimeError> {
            let hwnd = self
                .hwnd
                .ok_or_else(|| invalid_target("target is detached"))?;
            let hwnd = HWND(hwnd as *mut std::ffi::c_void);
            let current = read_geometry(hwnd, self.process_id)?;
            if Some(current) != self.geometry {
                return Err(MaaRuntimeError::new(
                    "worker.target_geometry_changed",
                    "target client geometry or DPI changed",
                ));
            }
            Ok(current)
        }
    }

    fn read_geometry(
        hwnd: HWND,
        expected_process_id: u32,
    ) -> Result<VerifiedGeometry, MaaRuntimeError> {
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return Err(invalid_target("HWND is no longer valid"));
        }
        let mut process_id = 0;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
        if process_id != expected_process_id {
            return Err(invalid_target("HWND process identity changed"));
        }
        let mut rect = windows::Win32::Foundation::RECT::default();
        unsafe { GetClientRect(hwnd, &mut rect) }
            .map_err(|error| invalid_target(&error.to_string()))?;
        let width = u32::try_from(rect.right - rect.left)
            .map_err(|_| invalid_target("client width is invalid"))?;
        let height = u32::try_from(rect.bottom - rect.top)
            .map_err(|_| invalid_target("client height is invalid"))?;
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        if width == 0 || height == 0 || dpi == 0 {
            return Err(invalid_target("client geometry or DPI is invalid"));
        }
        Ok(VerifiedGeometry { width, height, dpi })
    }

    fn profile_button(value: &ClientPointButton) -> MouseButton {
        match value {
            ClientPointButton::Left => MouseButton::Left,
            ClientPointButton::Right => MouseButton::Right,
            ClientPointButton::Middle => MouseButton::Middle,
            ClientPointButton::X1 => MouseButton::X1,
            ClientPointButton::X2 => MouseButton::X2,
        }
    }

    fn safe_profile_id(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }

    fn invalid_target(message: &str) -> MaaRuntimeError {
        MaaRuntimeError::new("worker.target_invalid", message)
    }

    fn action_kind_invalid() -> MaaRuntimeError {
        MaaRuntimeError::new(
            "input.action_kind_invalid",
            "action kind is not valid for this Generic command",
        )
    }
}

#[cfg(windows)]
pub use windows_impl::GenericController;
