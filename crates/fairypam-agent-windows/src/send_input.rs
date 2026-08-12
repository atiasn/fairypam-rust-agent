use std::time::{Duration, Instant};

use fairypam_agent_core::profile::VerifiedProfile;
use fairypam_agent_core::target::TargetBinding;
use fairypam_agent_input::{
    ActionId, GuardianClient, InputLease, InputPermit, InputPlatform, LeaseExecutor, ReleaseReason,
    SafetyError, SemanticMouseButton, SessionKey,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL,
    MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
    SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

use crate::{LockedInputTarget, NativeWindows, WindowsTargetPlatform};

pub(crate) const SEND_INPUT_MARKER: usize = 0x4650_414D;

pub(crate) fn send_foreground_activation_probe() -> u32 {
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dwExtraInfo: SEND_INPUT_MARKER,
                ..Default::default()
            },
        },
    };
    unsafe { SendInput(&[input], std::mem::size_of::<INPUT>() as i32) }
}

#[derive(Debug)]
struct SendInputPlatform {
    client_left: i32,
    client_top: i32,
    client_width: u32,
    client_height: u32,
}

struct RevalidatingInputPlatform {
    targets: WindowsTargetPlatform<NativeWindows>,
    binding: TargetBinding,
    sender: SendInputPlatform,
}

pub struct MusicLaneSender {
    hwnd: isize,
    lane_keys: [(u16, bool); 6],
    held: [bool; 6],
    sender: SendInputPlatform,
}

pub struct PreparedMusicLaneInput {
    inputs: Vec<INPUT>,
    next: [bool; 6],
}

fn validate_music_send_boundary(
    latest_detected_at: Instant,
    freshness_deadline: Instant,
    input_deadline: Instant,
    send_at: Instant,
) -> Result<(), SafetyError> {
    if latest_detected_at > send_at {
        return Err(SafetyError::new(
            "music.autoplay_event_invalid",
            "music autoplay event timestamp is in the future",
        ));
    }
    if input_deadline <= send_at {
        return Err(SafetyError::new(
            "input.lease_expired",
            "music autoplay input lease expired before SendInput",
        ));
    }
    if freshness_deadline <= send_at {
        return Err(SafetyError::new(
            "music.autoplay_event_stale",
            "music autoplay event exceeded the frozen freshness window",
        ));
    }
    Ok(())
}

impl MusicLaneSender {
    fn new(binding: &TargetBinding, lane_keys: &[(u16, bool)]) -> Result<Self, SafetyError> {
        let lane_keys: [(u16, bool); 6] = lane_keys.try_into().map_err(|_| {
            SafetyError::new(
                "music.autoplay_profile_invalid",
                "music autoplay requires exactly six signed lane keys",
            )
        })?;
        Ok(Self {
            hwnd: binding.window_handle as isize,
            lane_keys,
            held: [false; 6],
            sender: SendInputPlatform {
                client_left: 0,
                client_top: 0,
                client_width: binding.client_rect.width,
                client_height: binding.client_rect.height,
            },
        })
    }

    pub fn prepare_transitions(
        &self,
        transitions: &[(usize, bool)],
    ) -> Result<PreparedMusicLaneInput, SafetyError> {
        if transitions.is_empty() {
            return Ok(PreparedMusicLaneInput {
                inputs: Vec::new(),
                next: self.held,
            });
        }
        let mut next = self.held;
        let mut inputs = Vec::with_capacity(transitions.len());
        for &(lane, pressed) in transitions {
            let Some(&(scan_code, extended)) = self.lane_keys.get(lane) else {
                return Err(SafetyError::new(
                    "music.autoplay_event_invalid",
                    "music autoplay event references an invalid lane",
                ));
            };
            if next[lane] == pressed {
                return Err(SafetyError::new(
                    "music.autoplay_event_invalid",
                    "music autoplay event does not change lane state",
                ));
            }
            inputs.push(SendInputPlatform::keyboard(scan_code, extended, !pressed));
            next[lane] = pressed;
        }
        Ok(PreparedMusicLaneInput { inputs, next })
    }

    pub fn send_prepared(
        &mut self,
        prepared: PreparedMusicLaneInput,
        detected_at: &[Instant],
        input_deadline: Instant,
        freshness: Duration,
    ) -> Result<Instant, SafetyError> {
        use windows::Win32::Foundation::HWND;

        if prepared.inputs.len() != detected_at.len() {
            return Err(SafetyError::new(
                "music.autoplay_event_invalid",
                "music autoplay input and event counts do not match",
            ));
        }
        let Some((&first, rest)) = detected_at.split_first() else {
            return Err(SafetyError::new(
                "music.autoplay_event_invalid",
                "music autoplay input batch is empty",
            ));
        };
        let mut latest_detected_at = first;
        let mut freshness_deadline = first.checked_add(freshness).ok_or_else(|| {
            SafetyError::new(
                "music.autoplay_event_invalid",
                "music autoplay event freshness deadline overflowed",
            )
        })?;
        for detected_at in rest {
            latest_detected_at = latest_detected_at.max(*detected_at);
            freshness_deadline =
                freshness_deadline.min(detected_at.checked_add(freshness).ok_or_else(|| {
                    SafetyError::new(
                        "music.autoplay_event_invalid",
                        "music autoplay event freshness deadline overflowed",
                    )
                })?);
        }
        let hwnd = HWND(self.hwnd as *mut std::ffi::c_void);
        if unsafe { GetForegroundWindow() } != hwnd {
            return Err(SafetyError::new(
                "music.autoplay_target_not_foreground",
                "music autoplay target is not the foreground window",
            ));
        }
        let send_at = Instant::now();
        validate_music_send_boundary(
            latest_detected_at,
            freshness_deadline,
            input_deadline,
            send_at,
        )?;
        self.sender.send(&prepared.inputs)?;
        self.held = prepared.next;
        Ok(send_at)
    }

    pub fn release_all(&mut self) -> Result<(), SafetyError> {
        let inputs = self
            .lane_keys
            .iter()
            .map(|&(scan_code, extended)| SendInputPlatform::keyboard(scan_code, extended, true))
            .collect::<Vec<_>>();
        self.sender.send(&inputs)?;
        self.held = [false; 6];
        Ok(())
    }
}

impl RevalidatingInputPlatform {
    fn new(binding: TargetBinding, target: &LockedInputTarget) -> Self {
        Self {
            targets: WindowsTargetPlatform::new(NativeWindows),
            binding,
            sender: SendInputPlatform::for_locked_target(target),
        }
    }

    fn refresh(&mut self) -> Result<(), SafetyError> {
        let target = self
            .targets
            .lock_input_target(&self.binding)
            .map_err(|error| SafetyError::new(error.code(), error.to_string()))?;
        self.sender = SendInputPlatform::for_locked_target(&target);
        Ok(())
    }
}

impl SendInputPlatform {
    fn for_locked_target(target: &LockedInputTarget) -> Self {
        let identity = target.identity();
        Self {
            client_left: identity.client_rect.left,
            client_top: identity.client_rect.top,
            client_width: identity.client_rect.width,
            client_height: identity.client_rect.height,
        }
    }

    fn send(&self, inputs: &[INPUT]) -> Result<(), SafetyError> {
        let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent == inputs.len() as u32 {
            Ok(())
        } else {
            Err(SafetyError::new(
                "input.send_failed",
                format!("SendInput sent {sent}/{} events", inputs.len()),
            ))
        }
    }

    fn keyboard(scan_code: u16, extended: bool, key_up: bool) -> INPUT {
        let mut flags = KEYEVENTF_SCANCODE;
        if extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if key_up {
            flags |= KEYEVENTF_KEYUP;
        }
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan_code,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: SEND_INPUT_MARKER,
                },
            },
        }
    }

    fn mouse(
        flags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS,
        dx: i32,
        dy: i32,
        data: u32,
    ) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: SEND_INPUT_MARKER,
                },
            },
        }
    }

    fn screen_point_move_input(screen_x: i64, screen_y: i64) -> INPUT {
        let virtual_left = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
        let virtual_top = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
        let virtual_width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) }.max(1);
        let virtual_height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) }.max(1);
        let (absolute_x, absolute_y) = virtual_desktop_coordinates(
            screen_x,
            screen_y,
            virtual_left,
            virtual_top,
            virtual_width,
            virtual_height,
        );
        Self::mouse(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            absolute_x,
            absolute_y,
            0,
        )
    }

    fn screen_point_click_inputs(
        button: SemanticMouseButton,
        screen_x: i64,
        screen_y: i64,
    ) -> [INPUT; 3] {
        let (down, down_data) = mouse_button_event(button, false);
        let (up, up_data) = mouse_button_event(button, true);
        [
            Self::screen_point_move_input(screen_x, screen_y),
            Self::mouse(down, 0, 0, down_data),
            Self::mouse(up, 0, 0, up_data),
        ]
    }

    fn screen_point_wheel_inputs(screen_x: i64, screen_y: i64, delta: i32) -> [INPUT; 2] {
        [
            Self::screen_point_move_input(screen_x, screen_y),
            Self::mouse(MOUSEEVENTF_WHEEL, 0, 0, delta as u32),
        ]
    }

    fn client_screen_point(&self, x_ppm: u32, y_ppm: u32) -> (i64, i64) {
        (
            i64::from(self.client_left)
                + i64::from(self.client_width.saturating_sub(1)) * i64::from(x_ppm) / 1_000_000,
            i64::from(self.client_top)
                + i64::from(self.client_height.saturating_sub(1)) * i64::from(y_ppm) / 1_000_000,
        )
    }
}

fn virtual_desktop_coordinates(
    screen_x: i64,
    screen_y: i64,
    virtual_left: i32,
    virtual_top: i32,
    virtual_width: i32,
    virtual_height: i32,
) -> (i32, i32) {
    let width = virtual_width.max(1);
    let height = virtual_height.max(1);
    let relative_x = (screen_x - i64::from(virtual_left)).clamp(0, i64::from(width - 1));
    let relative_y = (screen_y - i64::from(virtual_top)).clamp(0, i64::from(height - 1));
    (
        (relative_x * 65_535 / i64::from((width - 1).max(1))) as i32,
        (relative_y * 65_535 / i64::from((height - 1).max(1))) as i32,
    )
}

pub struct WindowsInput<G> {
    binding: TargetBinding,
    profile_content_sha256: String,
    executor: LeaseExecutor<RevalidatingInputPlatform, G>,
}

impl<G: GuardianClient> WindowsInput<G> {
    pub(crate) fn for_locked_target(
        profile: &VerifiedProfile,
        binding: TargetBinding,
        target: LockedInputTarget,
        guardian: G,
    ) -> Result<Self, SafetyError> {
        if profile.profile().id != binding.profile_id
            || profile.profile().version != binding.profile_version
        {
            return Err(SafetyError::new(
                "input.profile_binding_mismatch",
                "Windows input Profile does not match the locked target binding",
            ));
        }
        let platform = RevalidatingInputPlatform::new(binding.clone(), &target);
        Ok(Self {
            binding,
            profile_content_sha256: profile.content_sha256().to_owned(),
            executor: LeaseExecutor::new(profile, platform, guardian)?,
        })
    }

    pub fn apply_lease(
        &mut self,
        lease: InputLease,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, &lease.session, now)?;
        self.executor.apply_lease(lease, permit, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_physical_frame(
        &mut self,
        session: SessionKey,
        sequence: u64,
        expires_at: Instant,
        keys: &[(u16, bool)],
        buttons: &[SemanticMouseButton],
        wheel_delta: i32,
        wheel_point: Option<(u32, u32)>,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, &session, now)?;
        self.executor.apply_physical_frame(
            session,
            sequence,
            expires_at,
            keys,
            buttons,
            wheel_delta,
            wheel_point,
            permit,
            now,
        )
    }

    pub fn arm_guarded_physical_frame(
        &mut self,
        session: SessionKey,
        sequence: u64,
        expires_at: Instant,
        keys: &[(u16, bool)],
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, &session, now)?;
        self.executor
            .arm_guarded_physical_frame(session, sequence, expires_at, keys, permit, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn arm_music_lane_sender(
        &mut self,
        session: SessionKey,
        sequence: u64,
        expires_at: Instant,
        keys: &[(u16, bool)],
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<MusicLaneSender, SafetyError> {
        self.arm_guarded_physical_frame(session, sequence, expires_at, keys, permit, now)?;
        MusicLaneSender::new(&self.binding, keys)
    }

    pub fn renew_guarded_physical_frame(
        &mut self,
        session: &SessionKey,
        sequence: u64,
        expires_at: Instant,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, session, now)?;
        self.executor
            .renew_guarded_physical_frame(session, sequence, expires_at, permit, now)
    }

    pub fn apply_guarded_physical_frame(
        &mut self,
        session: &SessionKey,
        keys: &[(u16, bool)],
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, session, now)?;
        self.executor
            .apply_guarded_physical_frame(session, keys, permit, now)
    }

    pub fn execute_pulse(
        &mut self,
        action: &ActionId,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, session, now)?;
        self.executor.execute_pulse(action, session, permit, now)
    }

    pub fn execute_relative_mouse(
        &mut self,
        action: &ActionId,
        delta_x: i32,
        delta_y: i32,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, session, now)?;
        self.executor
            .execute_relative_mouse(action, delta_x, delta_y, session, permit, now)
    }

    pub fn execute_client_point(
        &mut self,
        button: SemanticMouseButton,
        x_ppm: u32,
        y_ppm: u32,
        session: &SessionKey,
        permit: &InputPermit<'_>,
        now: Instant,
    ) -> Result<(), SafetyError> {
        self.require_target_permit(permit, session, now)?;
        self.executor
            .execute_client_point(button, x_ppm, y_ppm, session, permit, now)
    }

    pub fn tick(&mut self, now: Instant) -> Result<(), SafetyError> {
        self.executor.tick(now)
    }

    pub fn release_all(&mut self, reason: ReleaseReason) -> Result<(), SafetyError> {
        self.executor.release_all(reason)
    }

    fn require_target_permit(
        &mut self,
        permit: &InputPermit<'_>,
        session: &SessionKey,
        now: Instant,
    ) -> Result<(), SafetyError> {
        if permit.is_valid_for_target_and_profile(
            now,
            session,
            &self.binding,
            &self.profile_content_sha256,
        ) {
            return Ok(());
        }
        let original = SafetyError::new(
            "input.target_permit_invalid",
            "input capability does not match the revalidated Windows target",
        );
        match self.executor.release_all(ReleaseReason::EmergencyStop) {
            Ok(()) => Err(original),
            Err(release_error) => Err(SafetyError::new(
                "input.fail_closed_failed",
                format!("{original}; emergency release also failed: {release_error}"),
            )),
        }
    }
}

impl InputPlatform for RevalidatingInputPlatform {
    fn validate_before_input(&mut self) -> Result<(), SafetyError> {
        self.refresh()
    }

    fn press_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.press_scan_code(scan_code)
    }

    fn release_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.sender.release_scan_code(scan_code)
    }

    fn press_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.press_key(scan_code, extended)
    }

    fn release_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        self.sender.release_key(scan_code, extended)
    }

    fn apply_guarded_key_transitions(
        &mut self,
        transitions: &[(u16, bool, bool)],
    ) -> Result<(), SafetyError> {
        self.sender.apply_guarded_key_transitions(transitions)
    }

    fn pulse_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.pulse_key(scan_code, extended)
    }

    fn press_mouse_button(&mut self, button: SemanticMouseButton) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.press_mouse_button(button)
    }

    fn release_mouse_button(&mut self, button: SemanticMouseButton) -> Result<(), SafetyError> {
        self.sender.release_mouse_button(button)
    }

    fn wheel(&mut self, delta: i32) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.wheel(delta)
    }

    fn wheel_at_client_point(
        &mut self,
        x_ppm: u32,
        y_ppm: u32,
        delta: i32,
    ) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.wheel_at_client_point(x_ppm, y_ppm, delta)
    }

    fn pulse_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.pulse_scan_code(scan_code)
    }

    fn emergency_release(&mut self, scan_codes: &[u16]) -> Result<(), SafetyError> {
        self.sender.emergency_release(scan_codes)
    }

    fn relative_mouse(&mut self, delta_x: i32, delta_y: i32) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.relative_mouse(delta_x, delta_y)
    }

    fn client_point_click(
        &mut self,
        button: SemanticMouseButton,
        x_ppm: u32,
        y_ppm: u32,
    ) -> Result<(), SafetyError> {
        self.refresh()?;
        self.sender.client_point_click(button, x_ppm, y_ppm)
    }
}

impl InputPlatform for SendInputPlatform {
    fn press_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.send(&[Self::keyboard(scan_code, false, false)])
    }

    fn release_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.send(&[Self::keyboard(scan_code, false, true)])
    }

    fn pulse_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.send(&[
            Self::keyboard(scan_code, false, false),
            Self::keyboard(scan_code, false, true),
        ])
    }

    fn press_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        self.send(&[Self::keyboard(scan_code, extended, false)])
    }

    fn release_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        self.send(&[Self::keyboard(scan_code, extended, true)])
    }

    fn apply_guarded_key_transitions(
        &mut self,
        transitions: &[(u16, bool, bool)],
    ) -> Result<(), SafetyError> {
        let inputs = transitions
            .iter()
            .map(|&(scan_code, extended, pressed)| Self::keyboard(scan_code, extended, !pressed))
            .collect::<Vec<_>>();
        self.send(&inputs)
    }

    fn pulse_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        self.send(&[
            Self::keyboard(scan_code, extended, false),
            Self::keyboard(scan_code, extended, true),
        ])
    }

    fn emergency_release(&mut self, scan_codes: &[u16]) -> Result<(), SafetyError> {
        let mut inputs = scan_codes
            .iter()
            .map(|scan_code| Self::keyboard(*scan_code, false, true))
            .collect::<Vec<_>>();
        inputs.extend([
            Self::mouse(MOUSEEVENTF_LEFTUP, 0, 0, 0),
            Self::mouse(MOUSEEVENTF_RIGHTUP, 0, 0, 0),
            Self::mouse(MOUSEEVENTF_MIDDLEUP, 0, 0, 0),
            Self::mouse(MOUSEEVENTF_XUP, 0, 0, 1),
            Self::mouse(MOUSEEVENTF_XUP, 0, 0, 2),
        ]);
        self.send(&inputs)
    }

    fn press_mouse_button(&mut self, button: SemanticMouseButton) -> Result<(), SafetyError> {
        let (flags, data) = mouse_button_event(button, false);
        self.send(&[Self::mouse(flags, 0, 0, data)])
    }

    fn release_mouse_button(&mut self, button: SemanticMouseButton) -> Result<(), SafetyError> {
        let (flags, data) = mouse_button_event(button, true);
        self.send(&[Self::mouse(flags, 0, 0, data)])
    }

    fn wheel(&mut self, delta: i32) -> Result<(), SafetyError> {
        self.send(&[Self::mouse(MOUSEEVENTF_WHEEL, 0, 0, delta as u32)])
    }

    fn wheel_at_client_point(
        &mut self,
        x_ppm: u32,
        y_ppm: u32,
        delta: i32,
    ) -> Result<(), SafetyError> {
        let (x, y) = self.client_screen_point(x_ppm, y_ppm);
        self.send(&Self::screen_point_wheel_inputs(x, y, delta))
    }

    fn relative_mouse(&mut self, delta_x: i32, delta_y: i32) -> Result<(), SafetyError> {
        self.send(&[Self::mouse(MOUSEEVENTF_MOVE, delta_x, delta_y, 0)])
    }

    fn client_point_click(
        &mut self,
        button: SemanticMouseButton,
        x_ppm: u32,
        y_ppm: u32,
    ) -> Result<(), SafetyError> {
        let (x, y) = self.client_screen_point(x_ppm, y_ppm);
        self.send(&Self::screen_point_click_inputs(button, x, y))
    }
}

fn mouse_button_event(
    button: SemanticMouseButton,
    released: bool,
) -> (
    windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS,
    u32,
) {
    match (button, released) {
        (SemanticMouseButton::Left, false) => (MOUSEEVENTF_LEFTDOWN, 0),
        (SemanticMouseButton::Left, true) => (MOUSEEVENTF_LEFTUP, 0),
        (SemanticMouseButton::Right, false) => (MOUSEEVENTF_RIGHTDOWN, 0),
        (SemanticMouseButton::Right, true) => (MOUSEEVENTF_RIGHTUP, 0),
        (SemanticMouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEDOWN, 0),
        (SemanticMouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEUP, 0),
        (SemanticMouseButton::X1, false) => (MOUSEEVENTF_XDOWN, 1),
        (SemanticMouseButton::X1, true) => (MOUSEEVENTF_XUP, 1),
        (SemanticMouseButton::X2, false) => (MOUSEEVENTF_XDOWN, 2),
        (SemanticMouseButton::X2, true) => (MOUSEEVENTF_XUP, 2),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{Rect, TargetIdentity};
    use fairypam_agent_core::profile::{
        profile_content_sha256, verify_profile, ActionDefinition, CaptureRegion, CaptureSource,
        Profile, ProfileContent, ProfileEnvelope, SignatureVerifier, TargetRules,
    };
    use fairypam_agent_core::target::{ClientRect, IntegrityLevel};

    use super::*;

    struct TestRoot;

    impl SignatureVerifier for TestRoot {
        fn verify(&self, _digest: &[u8; 32], signature: &str) -> bool {
            signature == "test-signature"
        }
    }

    struct FakeGuardian;

    impl GuardianClient for FakeGuardian {
        fn register_intent(
            &mut self,
            _sequence: u64,
            _holds: &BTreeSet<ActionId>,
        ) -> Result<(), SafetyError> {
            Ok(())
        }

        fn commit_holds(
            &mut self,
            _sequence: u64,
            _holds: &BTreeSet<ActionId>,
        ) -> Result<(), SafetyError> {
            Ok(())
        }

        fn heartbeat(&mut self, _sequence: u64) -> Result<(), SafetyError> {
            Ok(())
        }

        fn release_all(&mut self, _reason: ReleaseReason) -> Result<(), SafetyError> {
            Ok(())
        }
    }

    fn profile() -> VerifiedProfile {
        let content = ProfileContent {
            schema_version: 1,
            profile: Profile {
                id: "profile-a".into(),
                version: "1.0.0".into(),
                display_name: "Profile A".into(),
                target: TargetRules {
                    process_names: vec!["game.exe".into()],
                    process_path_sha256: vec!["aa".repeat(32)],
                    window_classes: vec!["GameWindow".into()],
                    title_patterns: vec!["Game".into()],
                    require_elevated: false,
                    minimum_client_width: 1,
                    minimum_client_height: 1,
                    minimum_dpi: 96,
                },
                capture_sources: vec![CaptureSource {
                    id: "client".into(),
                    region: CaptureRegion::FullClient,
                    maximum_fps: 1,
                    encodings: vec!["jpeg".into()],
                }],
                actions: BTreeMap::from([(
                    "movement.forward".into(),
                    ActionDefinition::Hold { scan_code: 17 },
                )]),
            },
            files: Vec::new(),
        };
        let content_sha256 = profile_content_sha256(&content).unwrap();
        verify_profile(
            &serde_json::to_vec(&ProfileEnvelope {
                content,
                content_sha256,
                signature: "test-signature".into(),
            })
            .unwrap(),
            &TestRoot,
        )
        .unwrap()
    }

    #[test]
    fn windows_input_rejects_cross_profile_binding_before_native_access() {
        let binding = TargetBinding {
            profile_id: "profile-b".into(),
            profile_version: "1.0.0".into(),
            process_id: 42,
            process_name: "game.exe".into(),
            process_started_at_unix_ms: 1,
            process_path_sha256: "aa".repeat(32),
            window_handle: 100,
            window_title: "Game".into(),
            window_class: "GameWindow".into(),
            client_rect: ClientRect {
                width: 100,
                height: 100,
            },
            dpi: 96,
            integrity: IntegrityLevel::Medium,
        };

        let target = LockedInputTarget::test(TargetIdentity {
            hwnd: binding.window_handle as isize,
            pid: binding.process_id,
            process_started_at: binding.process_started_at_unix_ms,
            process_path_sha256: [0xbb; 32],
            window_class: binding.window_class.clone(),
            client_rect: Rect::new(0, 0, binding.client_rect.width, binding.client_rect.height)
                .unwrap(),
            dpi: binding.dpi,
        });
        let result = WindowsInput::for_locked_target(&profile(), binding, target, FakeGuardian);
        let Err(error) = result else {
            panic!("cross-profile binding unexpectedly created WindowsInput");
        };

        assert_eq!(error.code(), "input.profile_binding_mismatch");
    }

    #[test]
    fn positioned_wheel_moves_then_wheels_without_mouse_buttons() {
        let inputs = SendInputPlatform::screen_point_wheel_inputs(0, 0, -120);
        let move_input = unsafe { inputs[0].Anonymous.mi };
        let wheel_input = unsafe { inputs[1].Anonymous.mi };

        assert_eq!(
            move_input.dwFlags,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
        );
        assert_eq!(wheel_input.dwFlags, MOUSEEVENTF_WHEEL);
        assert_eq!(wheel_input.mouseData, (-120_i32) as u32);
    }

    #[test]
    fn virtual_desktop_coordinates_include_negative_origins() {
        assert_eq!(
            virtual_desktop_coordinates(0, 0, -1920, -1080, 3840, 2160),
            (32_776, 32_782)
        );
        assert_eq!(
            virtual_desktop_coordinates(-3_000, 3_000, -1920, -1080, 3840, 2160),
            (0, 65_535)
        );
    }

    #[test]
    fn music_send_boundary_rejects_exact_freshness_and_lease_deadlines() {
        let start = Instant::now();
        let freshness_deadline = start + Duration::from_millis(80);
        let input_deadline = start + Duration::from_secs(1);

        validate_music_send_boundary(
            start,
            freshness_deadline,
            input_deadline,
            freshness_deadline - Duration::from_nanos(1),
        )
        .unwrap();
        assert_eq!(
            validate_music_send_boundary(
                start,
                freshness_deadline,
                input_deadline,
                freshness_deadline,
            )
            .unwrap_err()
            .code(),
            "music.autoplay_event_stale"
        );
        assert_eq!(
            validate_music_send_boundary(start, input_deadline, input_deadline, input_deadline)
                .unwrap_err()
                .code(),
            "input.lease_expired"
        );
        assert_eq!(
            validate_music_send_boundary(
                start + Duration::from_nanos(1),
                freshness_deadline,
                input_deadline,
                start,
            )
            .unwrap_err()
            .code(),
            "music.autoplay_event_invalid"
        );
    }
}
