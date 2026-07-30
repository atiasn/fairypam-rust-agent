use fairypam_agent_core::platform::TargetPlatform;
use fairypam_agent_core::profile::VerifiedProfile;
use fairypam_agent_core::target::{
    ClientRect, IntegrityLevel, TargetBinding, TargetCandidate, TargetSelector, TargetSnapshot,
};
use fairypam_agent_core::AgentError;
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct WindowsError {
    code: &'static str,
    message: String,
}

impl WindowsError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl From<WindowsError> for AgentError {
    fn from(error: WindowsError) -> Self {
        AgentError::new(error.code, error.message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(left: i32, top: i32, width: u32, height: u32) -> Result<Self, WindowsError> {
        if width == 0 || height == 0 {
            return Err(WindowsError::new(
                "target.client_rect_invalid",
                "client rectangle must have non-zero dimensions",
            ));
        }
        Ok(Self {
            left,
            top,
            width,
            height,
        })
    }

    fn contains(&self, x: i32, y: i32) -> bool {
        let right = i64::from(self.left) + i64::from(self.width);
        let bottom = i64::from(self.top) + i64::from(self.height);
        i64::from(x) >= i64::from(self.left)
            && i64::from(x) < right
            && i64::from(y) >= i64::from(self.top)
            && i64::from(y) < bottom
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetIdentity {
    pub hwnd: isize,
    pub pid: u32,
    pub process_started_at: u64,
    pub process_path_sha256: [u8; 32],
    pub window_class: String,
    pub client_rect: Rect,
    pub dpi: u32,
}

/// Opaque proof that `NativeWindows` revalidated the current input target.
#[cfg(any(windows, test))]
#[derive(Debug)]
pub struct LockedInputTarget {
    identity: TargetIdentity,
}

#[cfg(any(windows, test))]
impl LockedInputTarget {
    pub(crate) const fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    #[cfg(all(test, windows))]
    pub(crate) const fn test(identity: TargetIdentity) -> Self {
        Self { identity }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsTargetCandidate {
    pub identity: TargetIdentity,
    pub process_name: String,
    pub window_title: String,
    pub elevated: bool,
    pub foreground: bool,
    pub minimized: bool,
    pub capturable: bool,
}

pub trait WindowsApi: Send {
    fn enumerate_candidates(&mut self) -> Result<Vec<WindowsTargetCandidate>, WindowsError>;
    fn snapshot(&mut self, hwnd: isize) -> Result<WindowsTargetCandidate, WindowsError>;
    fn focus_target(
        &mut self,
        identity: &TargetIdentity,
        allow_activation_probe: bool,
    ) -> Result<(), WindowsError>;
    fn click_target_point(
        &mut self,
        identity: &TargetIdentity,
        screen_x: i32,
        screen_y: i32,
    ) -> Result<(), WindowsError>;
    fn close_target(
        &mut self,
        identity: &TargetIdentity,
        timeout: Duration,
    ) -> Result<(), WindowsError>;
}

#[derive(Clone, Debug, Default)]
pub struct FakeWindows {
    candidates: Vec<WindowsTargetCandidate>,
    focus_activation_probe: Vec<bool>,
    focus_failures_remaining: usize,
    target_point_clicks: Vec<(i32, i32)>,
}

impl FakeWindows {
    pub fn with_candidates(candidates: Vec<WindowsTargetCandidate>) -> Self {
        Self {
            candidates,
            focus_activation_probe: Vec::new(),
            focus_failures_remaining: 0,
            target_point_clicks: Vec::new(),
        }
    }

    #[cfg(test)]
    fn with_focus_failures(mut self, failures: usize) -> Self {
        self.focus_failures_remaining = failures;
        self
    }
}

impl WindowsApi for FakeWindows {
    fn enumerate_candidates(&mut self) -> Result<Vec<WindowsTargetCandidate>, WindowsError> {
        Ok(self.candidates.clone())
    }

    fn snapshot(&mut self, hwnd: isize) -> Result<WindowsTargetCandidate, WindowsError> {
        self.candidates
            .iter()
            .find(|candidate| candidate.identity.hwnd == hwnd)
            .cloned()
            .ok_or_else(|| WindowsError::new("target.not_found", "target window no longer exists"))
    }

    fn focus_target(
        &mut self,
        identity: &TargetIdentity,
        allow_activation_probe: bool,
    ) -> Result<(), WindowsError> {
        let current = self.snapshot(identity.hwnd)?;
        require_same_identity(identity, &current.identity)?;
        self.focus_activation_probe.push(allow_activation_probe);
        if self.focus_failures_remaining > 0 {
            self.focus_failures_remaining -= 1;
            return Err(WindowsError::new(
                "target.focus_failed",
                "simulated foreground rejection",
            ));
        }
        for candidate in &mut self.candidates {
            let target = candidate.identity.hwnd == identity.hwnd;
            candidate.foreground = target;
            if target {
                candidate.minimized = false;
                candidate.capturable = true;
            }
        }
        Ok(())
    }

    fn click_target_point(
        &mut self,
        identity: &TargetIdentity,
        screen_x: i32,
        screen_y: i32,
    ) -> Result<(), WindowsError> {
        let current = self.snapshot(identity.hwnd)?;
        require_same_identity(identity, &current.identity)?;
        if !current.identity.client_rect.contains(screen_x, screen_y) {
            return Err(WindowsError::new(
                "target.focus_click_outside_target",
                "foreground fallback point is outside the target client area",
            ));
        }
        self.target_point_clicks.push((screen_x, screen_y));
        for candidate in &mut self.candidates {
            candidate.foreground = candidate.identity.hwnd == identity.hwnd;
        }
        Ok(())
    }

    fn close_target(
        &mut self,
        identity: &TargetIdentity,
        _timeout: Duration,
    ) -> Result<(), WindowsError> {
        let current = self.snapshot(identity.hwnd)?;
        require_same_identity(identity, &current.identity)?;
        self.candidates
            .retain(|candidate| candidate.identity.hwnd != identity.hwnd);
        Ok(())
    }
}

pub fn lock_unique(
    api: &mut dyn WindowsApi,
    profile: &VerifiedProfile,
) -> Result<WindowsTargetCandidate, WindowsError> {
    let mut matching = matching_candidates(api, profile)?;
    match matching.len() {
        0 => Err(WindowsError::new(
            "target.not_found",
            "no window satisfies every signed profile rule",
        )),
        1 => Ok(matching.remove(0)),
        _ => Err(WindowsError::new(
            "target.ambiguous",
            "multiple windows satisfy the signed profile",
        )),
    }
}

pub fn revalidate_identity(
    api: &mut dyn WindowsApi,
    identity: &TargetIdentity,
) -> Result<WindowsTargetCandidate, WindowsError> {
    let current = api.snapshot(identity.hwnd)?;
    require_same_identity(identity, &current.identity)?;
    Ok(current)
}

fn require_same_identity(
    expected: &TargetIdentity,
    current: &TargetIdentity,
) -> Result<(), WindowsError> {
    let same_process = current.pid == expected.pid
        && current.process_started_at == expected.process_started_at
        && current.process_path_sha256 == expected.process_path_sha256;
    let same_window = current.hwnd == expected.hwnd
        && current
            .window_class
            .eq_ignore_ascii_case(&expected.window_class);
    if !same_process || !same_window {
        return Err(WindowsError::new(
            "target.stale",
            "window handle or process identity has been reused",
        ));
    }
    Ok(())
}

fn matching_candidates(
    api: &mut dyn WindowsApi,
    profile: &VerifiedProfile,
) -> Result<Vec<WindowsTargetCandidate>, WindowsError> {
    let rules = &profile.profile().target;
    Ok(api
        .enumerate_candidates()?
        .into_iter()
        .filter(|candidate| {
            rules
                .process_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&candidate.process_name))
                && rules.process_path_sha256.iter().any(|hash| {
                    decode_sha256(hash)
                        .is_some_and(|value| value == candidate.identity.process_path_sha256)
                })
                && rules
                    .window_classes
                    .iter()
                    .any(|class| class.eq_ignore_ascii_case(&candidate.identity.window_class))
                && rules
                    .title_patterns
                    .iter()
                    .any(|pattern| wildcard_match(pattern, &candidate.window_title))
                && candidate.identity.client_rect.width >= rules.minimum_client_width
                && candidate.identity.client_rect.height >= rules.minimum_client_height
                && candidate.identity.dpi >= rules.minimum_dpi
                && (!rules.require_elevated || candidate.elevated)
        })
        .collect())
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(output)
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let value = value.to_lowercase();
    let parts: Vec<_> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }
    let mut remaining = value.as_str();
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(position) = remaining.find(part) else {
            return false;
        };
        if index == 0 && !pattern.starts_with('*') && position != 0 {
            return false;
        }
        remaining = &remaining[position + part.len()..];
    }
    pattern.ends_with('*') || remaining.is_empty()
}

fn selector_id(identity: &TargetIdentity) -> String {
    let mut hasher = Sha256::new();
    hasher.update(identity.pid.to_le_bytes());
    hasher.update(identity.process_started_at.to_le_bytes());
    hasher.update(identity.hwnd.to_le_bytes());
    hasher.update(identity.process_path_sha256);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn candidate_to_core(candidate: &WindowsTargetCandidate) -> TargetCandidate {
    TargetCandidate {
        selector: TargetSelector {
            candidate_id: selector_id(&candidate.identity),
        },
        window_handle: candidate.identity.hwnd as u64,
        process_id: candidate.identity.pid,
        process_name: candidate.process_name.clone(),
        process_path_sha256: candidate
            .identity
            .process_path_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        window_title: candidate.window_title.clone(),
        window_class: candidate.identity.window_class.clone(),
    }
}

fn candidate_to_binding(
    candidate: WindowsTargetCandidate,
    profile: &VerifiedProfile,
) -> TargetBinding {
    TargetBinding {
        profile_id: profile.profile().id.clone(),
        profile_version: profile.profile().version.clone(),
        process_id: candidate.identity.pid,
        process_name: candidate.process_name,
        process_started_at_unix_ms: candidate.identity.process_started_at,
        process_path_sha256: candidate
            .identity
            .process_path_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        window_handle: candidate.identity.hwnd as u64,
        window_title: candidate.window_title,
        window_class: candidate.identity.window_class,
        client_rect: ClientRect {
            width: candidate.identity.client_rect.width,
            height: candidate.identity.client_rect.height,
        },
        dpi: candidate.identity.dpi,
        integrity: if candidate.elevated {
            IntegrityLevel::High
        } else {
            IntegrityLevel::Medium
        },
    }
}

pub struct WindowsTargetPlatform<A> {
    api: A,
}

impl<A> WindowsTargetPlatform<A> {
    pub const fn new(api: A) -> Self {
        Self { api }
    }

    pub const fn api(&self) -> &A {
        &self.api
    }
}

fn binding_identity(binding: &TargetBinding) -> Result<TargetIdentity, AgentError> {
    let process_path_sha256 = decode_sha256(&binding.process_path_sha256).ok_or_else(|| {
        WindowsError::new(
            "target.stale",
            "binding contains an invalid process path hash",
        )
    })?;
    Ok(TargetIdentity {
        hwnd: binding.window_handle as isize,
        pid: binding.process_id,
        process_started_at: binding.process_started_at_unix_ms,
        process_path_sha256,
        window_class: binding.window_class.clone(),
        client_rect: Rect::new(0, 0, binding.client_rect.width, binding.client_rect.height)?,
        dpi: binding.dpi,
    })
}

fn revalidate_or_focus_target(
    api: &mut dyn WindowsApi,
    binding: &TargetBinding,
) -> Result<WindowsTargetCandidate, AgentError> {
    let expected = binding_identity(binding)?;
    let mut current = revalidate_identity(api, &expected)?;
    for _ in 0..2 {
        if current.foreground && !current.minimized {
            return Ok(current);
        }
        if let Err(error) = api.focus_target(&current.identity, true) {
            if error.code() != "target.focus_failed" {
                return Err(error.into());
            }
        }
        current = revalidate_identity(api, &expected)?;
    }
    if current.foreground && !current.minimized {
        return Ok(current);
    }
    api.click_target_point(&current.identity, 1, 1)?;
    current = revalidate_identity(api, &expected)?;
    if current.foreground && !current.minimized {
        return Ok(current);
    }
    Err(WindowsError::new(
        "target.focus_failed",
        "target did not become the foreground window after two activation attempts and one target-bound click",
    )
    .into())
}

#[cfg(any(windows, test))]
fn revalidate_input_target(
    api: &mut dyn WindowsApi,
    binding: &TargetBinding,
) -> Result<LockedInputTarget, AgentError> {
    let current = revalidate_or_focus_target(api, binding)?;
    if current.minimized || !current.capturable {
        return Err(WindowsError::new(
            "target.input_not_permitted",
            "input target must be foreground, visible, and capturable",
        )
        .into());
    }
    Ok(LockedInputTarget {
        identity: current.identity,
    })
}

impl<A: WindowsApi> WindowsTargetPlatform<A> {
    #[cfg(any(windows, test))]
    pub fn lock_input_target(
        &mut self,
        binding: &TargetBinding,
    ) -> Result<LockedInputTarget, AgentError> {
        revalidate_input_target(&mut self.api, binding)
    }

    pub fn capture_identity(
        &mut self,
        binding: &TargetBinding,
    ) -> Result<TargetIdentity, AgentError> {
        let current = revalidate_or_focus_target(&mut self.api, binding)?;
        if current.minimized || !current.capturable {
            return Err(WindowsError::new(
                "target.capture_not_permitted",
                "capture target must be foreground, visible, and capturable",
            )
            .into());
        }
        Ok(current.identity)
    }

    pub fn rediscover(
        &mut self,
        profile: &VerifiedProfile,
        binding: &TargetBinding,
    ) -> Result<TargetBinding, AgentError> {
        if binding.profile_id != profile.profile().id
            || binding.profile_version != profile.profile().version
        {
            return Err(WindowsError::new(
                "target.stale",
                "active binding does not belong to the requested signed Profile",
            )
            .into());
        }
        let expected = binding_identity(binding)?;
        let mut matches = matching_candidates(&mut self.api, profile)?
            .into_iter()
            .filter(|candidate| {
                candidate.identity.pid == expected.pid
                    && candidate.identity.process_started_at == expected.process_started_at
                    && candidate.identity.process_path_sha256 == expected.process_path_sha256
            });
        let candidate = matches.next().ok_or_else(|| {
            WindowsError::new(
                "target.not_found",
                "the signed Profile found no replacement window for the active process",
            )
        })?;
        if matches.next().is_some() {
            return Err(WindowsError::new(
                "target.ambiguous",
                "the active process exposes multiple signed Profile windows",
            )
            .into());
        }
        Ok(candidate_to_binding(candidate, profile))
    }

    pub fn focus(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError> {
        revalidate_or_focus_target(&mut self.api, binding)?;
        let snapshot = self.revalidate(binding)?;
        if !snapshot.foreground {
            return Err(WindowsError::new(
                "target.focus_failed",
                "target did not become the foreground window",
            )
            .into());
        }
        Ok(snapshot)
    }

    pub fn close(&mut self, binding: &TargetBinding, timeout: Duration) -> Result<(), AgentError> {
        let current = revalidate_identity(&mut self.api, &binding_identity(binding)?)?;
        self.api.close_target(&current.identity, timeout)?;
        Ok(())
    }
}

impl<A: WindowsApi> TargetPlatform for WindowsTargetPlatform<A> {
    fn enumerate(&mut self, profile: &VerifiedProfile) -> Result<Vec<TargetCandidate>, AgentError> {
        Ok(matching_candidates(&mut self.api, profile)?
            .iter()
            .map(candidate_to_core)
            .collect())
    }

    fn lock(
        &mut self,
        profile: &VerifiedProfile,
        selector: TargetSelector,
    ) -> Result<TargetBinding, AgentError> {
        let candidates = matching_candidates(&mut self.api, profile)?;
        let mut selected = candidates
            .into_iter()
            .filter(|candidate| selector_id(&candidate.identity) == selector.candidate_id);
        let candidate = selected
            .next()
            .ok_or_else(|| WindowsError::new("target.not_found", "candidate is no longer valid"))?;
        if selected.next().is_some() {
            return Err(
                WindowsError::new("target.ambiguous", "candidate identity is not unique").into(),
            );
        }
        Ok(candidate_to_binding(candidate, profile))
    }

    fn revalidate(&mut self, binding: &TargetBinding) -> Result<TargetSnapshot, AgentError> {
        let identity = binding_identity(binding)?;
        let candidate = revalidate_identity(&mut self.api, &identity)?;
        Ok(TargetSnapshot {
            binding: TargetBinding {
                client_rect: ClientRect {
                    width: candidate.identity.client_rect.width,
                    height: candidate.identity.client_rect.height,
                },
                dpi: candidate.identity.dpi,
                window_title: candidate.window_title,
                ..binding.clone()
            },
            foreground: candidate.foreground,
            minimized: candidate.minimized,
            capturable: candidate.capturable,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn input_candidate(foreground: bool) -> WindowsTargetCandidate {
        WindowsTargetCandidate {
            identity: TargetIdentity {
                hwnd: 100,
                pid: 42,
                process_started_at: 1_000,
                process_path_sha256: [0xaa; 32],
                window_class: "FairyPamTestWindow".into(),
                client_rect: Rect::new(10, 20, 1280, 720).unwrap(),
                dpi: 96,
            },
            process_name: "fairypam-test-window.exe".into(),
            window_title: "FairyPam Test Window".into(),
            elevated: false,
            foreground,
            minimized: false,
            capturable: true,
        }
    }

    fn input_binding() -> TargetBinding {
        TargetBinding {
            profile_id: "fairypam-test-window".into(),
            profile_version: "1.0.0".into(),
            process_id: 42,
            process_name: "fairypam-test-window.exe".into(),
            process_started_at_unix_ms: 1_000,
            process_path_sha256: "aa".repeat(32),
            window_handle: 100,
            window_title: "FairyPam Test Window".into(),
            window_class: "FairyPamTestWindow".into(),
            client_rect: ClientRect {
                width: 1280,
                height: 720,
            },
            dpi: 96,
            integrity: IntegrityLevel::Medium,
        }
    }

    #[test]
    fn wildcard_matching_is_anchored() {
        assert!(wildcard_match("FairyPam *", "FairyPam Testbed"));
        assert!(!wildcard_match("FairyPam *", "Other FairyPam Testbed"));
        assert!(!wildcard_match("* Testbed", "Testbed Other"));
    }

    #[test]
    fn input_and_capture_refocus_the_live_locked_target() {
        let mut foreground = FakeWindows::with_candidates(vec![input_candidate(true)]);
        let locked = revalidate_input_target(&mut foreground, &input_binding()).unwrap();
        assert_eq!(locked.identity().client_rect.left, 10);

        let binding = input_binding();
        let mut other = input_candidate(true);
        other.identity.hwnd = 200;
        other.identity.pid = 43;
        let background_game = input_candidate(false);
        let mut input_targets = WindowsTargetPlatform::new(FakeWindows::with_candidates(vec![
            background_game.clone(),
            other.clone(),
        ]));
        input_targets.lock_input_target(&binding).unwrap();
        assert!(input_targets.api().candidates[0].foreground);
        assert!(!input_targets.api().candidates[1].foreground);
        assert_eq!(input_targets.api().focus_activation_probe, [true]);

        let mut capture_targets =
            WindowsTargetPlatform::new(FakeWindows::with_candidates(vec![background_game, other]));
        capture_targets.capture_identity(&binding).unwrap();
        assert!(capture_targets.api().candidates[0].foreground);
        assert!(!capture_targets.api().candidates[1].foreground);
        assert_eq!(capture_targets.api().focus_activation_probe, [true]);

        for foreground in [true, false] {
            let mut minimized = input_candidate(foreground);
            minimized.minimized = true;
            minimized.capturable = false;
            let mut targets =
                WindowsTargetPlatform::new(FakeWindows::with_candidates(vec![minimized]));
            targets.capture_identity(&binding).unwrap();
            assert!(!targets.api().candidates[0].minimized);
        }
    }

    #[test]
    fn input_and_capture_click_the_live_fullscreen_target_after_two_focus_rejections() {
        let binding = input_binding();
        let mut fullscreen = input_candidate(false);
        fullscreen.identity.client_rect = Rect::new(0, 0, 1280, 720).unwrap();
        let mut targets = WindowsTargetPlatform::new(
            FakeWindows::with_candidates(vec![fullscreen]).with_focus_failures(2),
        );

        targets.capture_identity(&binding).unwrap();

        assert_eq!(targets.api().focus_activation_probe, [true, true]);
        assert_eq!(targets.api().target_point_clicks, [(1, 1)]);
        assert!(targets.api().candidates[0].foreground);

        let mut offset = WindowsTargetPlatform::new(
            FakeWindows::with_candidates(vec![input_candidate(false)]).with_focus_failures(2),
        );
        let error = offset.capture_identity(&binding).unwrap_err();
        assert_eq!(error.code(), "target.focus_click_outside_target");
        assert!(offset.api().target_point_clicks.is_empty());
    }

    #[test]
    fn focus_and_close_share_the_locked_target_boundary() {
        let binding = input_binding();
        let mut targets =
            WindowsTargetPlatform::new(FakeWindows::with_candidates(vec![input_candidate(false)]));

        let focused = targets.focus(&binding).unwrap();
        assert!(focused.foreground);
        assert_eq!(targets.api().focus_activation_probe, [true]);

        targets.close(&binding, Duration::from_secs(1)).unwrap();
        let error = targets.revalidate(&binding).unwrap_err();
        assert_eq!(error.code(), "target.not_found");
    }

    #[test]
    fn side_effect_identity_guard_rejects_swapped_process_or_window() {
        let expected = input_candidate(true).identity;
        let mut swapped_process = expected.clone();
        swapped_process.process_path_sha256 = [0xbb; 32];
        assert_eq!(
            require_same_identity(&expected, &swapped_process)
                .unwrap_err()
                .code(),
            "target.stale"
        );

        let mut swapped_window = expected.clone();
        swapped_window.window_class = "ReusedWindowClass".into();
        assert_eq!(
            require_same_identity(&expected, &swapped_window)
                .unwrap_err()
                .code(),
            "target.stale"
        );
    }
}

#[cfg(windows)]
pub struct NativeWindows;

#[cfg(windows)]
impl WindowsApi for NativeWindows {
    fn enumerate_candidates(&mut self) -> Result<Vec<WindowsTargetCandidate>, WindowsError> {
        native::enumerate_candidates()
    }

    fn snapshot(&mut self, hwnd: isize) -> Result<WindowsTargetCandidate, WindowsError> {
        native::candidate_from_raw_hwnd(hwnd)
    }

    fn focus_target(
        &mut self,
        identity: &TargetIdentity,
        allow_activation_probe: bool,
    ) -> Result<(), WindowsError> {
        native::focus_target(identity, allow_activation_probe)
    }

    fn click_target_point(
        &mut self,
        identity: &TargetIdentity,
        screen_x: i32,
        screen_y: i32,
    ) -> Result<(), WindowsError> {
        native::click_target_point(identity, screen_x, screen_y)
    }

    fn close_target(
        &mut self,
        identity: &TargetIdentity,
        timeout: Duration,
    ) -> Result<(), WindowsError> {
        native::close_target(identity, timeout)
    }
}

#[cfg(windows)]
mod native {
    use std::ffi::c_void;
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

    use windows::core::{BOOL, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, FILETIME, HANDLE, HWND, LPARAM, POINT, RECT, WAIT_OBJECT_0, WAIT_TIMEOUT,
        WPARAM,
    };
    use windows::Win32::Graphics::Gdi::ClientToScreen;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::StationsAndDesktops::{
        GetThreadDesktop, GetUserObjectInformationW, UOI_IO,
    };
    use windows::Win32::System::Threading::{
        GetCurrentThreadId, GetProcessTimes, OpenProcess, OpenProcessToken,
        QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    use windows::Win32::UI::HiDpi::GetDpiForWindow;
    use windows::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, EnumWindows, GetClassNameW, GetClientRect, GetForegroundWindow,
        GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindowVisible, PostMessageW,
        SetForegroundWindow, ShowWindowAsync, SW_RESTORE, WM_CLOSE,
    };

    use crate::send_input::{send_foreground_activation_probe, send_foreground_fallback_click};
    use crate::{normalized_process_path_sha256, validate_dpi};

    use super::{
        require_same_identity, Rect, TargetIdentity, WindowsError, WindowsTargetCandidate,
    };

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn wait_for_foreground(hwnd: HWND, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while unsafe { GetForegroundWindow() } != hwnd {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
        true
    }

    fn request_foreground(hwnd: HWND, timeout: Duration) -> (bool, bool) {
        let accepted = unsafe { SetForegroundWindow(hwnd) }.as_bool();
        (accepted, wait_for_foreground(hwnd, timeout))
    }

    pub(super) fn enumerate_candidates() -> Result<Vec<WindowsTargetCandidate>, WindowsError> {
        let mut handles = Vec::<isize>::new();
        unsafe extern "system" fn collect(hwnd: HWND, state: LPARAM) -> BOOL {
            let handles = unsafe { &mut *(state.0 as *mut Vec<isize>) };
            if unsafe { IsWindowVisible(hwnd).as_bool() } {
                handles.push(hwnd.0 as isize);
            }
            true.into()
        }
        unsafe {
            EnumWindows(
                Some(collect),
                LPARAM((&mut handles as *mut Vec<isize>).cast::<c_void>() as isize),
            )
            .map_err(|error| win_error("target.enumeration_failed", error))?;
        }
        Ok(handles
            .into_iter()
            .filter_map(|hwnd| candidate_from_raw_hwnd(hwnd).ok())
            .collect())
    }

    pub(super) fn candidate_from_raw_hwnd(
        raw_hwnd: isize,
    ) -> Result<WindowsTargetCandidate, WindowsError> {
        let hwnd = HWND(raw_hwnd as *mut c_void);
        if !unsafe { IsWindowVisible(hwnd).as_bool() } {
            return Err(WindowsError::new(
                "target.not_found",
                "window is missing or not visible",
            ));
        }
        let mut pid = 0_u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid == 0 {
            return Err(WindowsError::new(
                "target.identity_unavailable",
                "window process id is unavailable",
            ));
        }
        let process = OwnedHandle(
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
                .map_err(|error| win_error("target.permission_denied", error))?,
        );
        let process_path = process_path(process.0)?;
        let process_name = Path::new(&process_path)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                WindowsError::new("target.identity_unavailable", "process name is not UTF-8")
            })?
            .to_string();
        let process_path_sha256 =
            normalized_process_path_sha256(&process_path).ok_or_else(|| {
                WindowsError::new(
                    "target.identity_unavailable",
                    "process path cannot be normalized",
                )
            })?;
        let client_rect = client_rect(hwnd)?;
        let dpi = validate_dpi(unsafe { GetDpiForWindow(hwnd) })?;
        let minimized = unsafe { IsIconic(hwnd).as_bool() };
        Ok(WindowsTargetCandidate {
            identity: TargetIdentity {
                hwnd: raw_hwnd,
                pid,
                process_started_at: process_started_at(process.0)?,
                process_path_sha256,
                window_class: window_class(hwnd)?,
                client_rect,
                dpi,
            },
            process_name,
            window_title: window_title(hwnd)?,
            elevated: process_is_elevated(process.0)?,
            foreground: unsafe { GetForegroundWindow() == hwnd },
            minimized,
            capturable: !minimized,
        })
    }

    pub(super) fn focus_target(
        identity: &TargetIdentity,
        allow_activation_probe: bool,
    ) -> Result<(), WindowsError> {
        let current = candidate_from_raw_hwnd(identity.hwnd)?;
        require_same_identity(identity, &current.identity)?;
        let hwnd = HWND(identity.hwnd as *mut c_void);
        if current.foreground && !current.minimized {
            return Ok(());
        }
        let input_desktop = desktop_receives_input();
        if input_desktop == Some(false) {
            return Err(WindowsError::new(
                "target.noninteractive_desktop",
                "agent desktop is not receiving user input",
            ));
        }
        if current.minimized {
            let _ = unsafe { ShowWindowAsync(hwnd, SW_RESTORE) };
            let deadline = Instant::now() + Duration::from_millis(750);
            while unsafe { IsIconic(hwnd).as_bool() } {
                if Instant::now() >= deadline {
                    return Err(WindowsError::new(
                        "target.restore_timeout",
                        "target remained minimized after the restore request",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        let (direct_accepted, direct_succeeded) =
            request_foreground(hwnd, Duration::from_millis(200));
        if direct_succeeded {
            return Ok(());
        }

        let mut noop_input_sent = 0;
        let mut brought_to_top = false;
        let mut input_retry_accepted = false;
        if allow_activation_probe {
            let refreshed = candidate_from_raw_hwnd(identity.hwnd)?;
            require_same_identity(identity, &refreshed.identity)?;
            noop_input_sent = send_foreground_activation_probe();
            brought_to_top = unsafe { BringWindowToTop(hwnd) }.is_ok();
            let (accepted, succeeded) = request_foreground(hwnd, Duration::from_millis(800));
            input_retry_accepted = accepted;
            if succeeded {
                return Ok(());
            }
        }

        let foreground = unsafe { GetForegroundWindow() };
        let mut foreground_pid = 0;
        let foreground_thread_id_after =
            unsafe { GetWindowThreadProcessId(foreground, Some(&mut foreground_pid)) };
        Err(WindowsError::new(
            "target.focus_failed",
            format!(
                "target did not become the foreground window; desktop_receives_input={input_desktop:?}, minimized={}, direct_accepted={direct_accepted}, allow_activation_probe={allow_activation_probe}, noop_input_sent={noop_input_sent}, brought_to_top={brought_to_top}, input_retry_accepted={input_retry_accepted}, foreground_hwnd=0x{:x}, foreground_thread_id={foreground_thread_id_after}, foreground_pid={foreground_pid}, target_hwnd=0x{:x}, target_pid={}",
                current.minimized,
                foreground.0 as usize,
                identity.hwnd as usize,
                identity.pid
            ),
        ))
    }

    pub(super) fn click_target_point(
        identity: &TargetIdentity,
        screen_x: i32,
        screen_y: i32,
    ) -> Result<(), WindowsError> {
        let current = candidate_from_raw_hwnd(identity.hwnd)?;
        require_same_identity(identity, &current.identity)?;
        if !current.identity.client_rect.contains(screen_x, screen_y) {
            return Err(WindowsError::new(
                "target.focus_click_outside_target",
                "foreground fallback point is outside the target client area",
            ));
        }
        let sent = send_foreground_fallback_click(screen_x, screen_y);
        if sent != 3 {
            return Err(WindowsError::new(
                "target.focus_click_failed",
                format!("SendInput sent {sent}/3 foreground fallback events"),
            ));
        }
        let hwnd = HWND(identity.hwnd as *mut c_void);
        if wait_for_foreground(hwnd, Duration::from_millis(800)) {
            Ok(())
        } else {
            Err(WindowsError::new(
                "target.focus_failed",
                "target-bound foreground fallback click did not activate the target",
            ))
        }
    }

    fn desktop_receives_input() -> Option<bool> {
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.ok()?;
        let mut receives_input = BOOL::default();
        unsafe {
            GetUserObjectInformationW(
                HANDLE(desktop.0),
                UOI_IO,
                Some(std::ptr::from_mut(&mut receives_input).cast()),
                std::mem::size_of::<BOOL>() as u32,
                None,
            )
        }
        .ok()?;
        Some(receives_input.as_bool())
    }

    pub(super) fn close_target(
        identity: &TargetIdentity,
        timeout: Duration,
    ) -> Result<(), WindowsError> {
        let process = OwnedHandle(
            unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    false,
                    identity.pid,
                )
            }
            .map_err(|error| win_error("target.permission_denied", error))?,
        );
        let process_path_sha256 = normalized_process_path_sha256(&process_path(process.0)?)
            .ok_or_else(|| {
                WindowsError::new(
                    "target.identity_unavailable",
                    "process path cannot be normalized",
                )
            })?;
        if process_started_at(process.0)? != identity.process_started_at
            || process_path_sha256 != identity.process_path_sha256
        {
            return Err(WindowsError::new(
                "target.stale",
                "process identity changed before close",
            ));
        }
        let current = candidate_from_raw_hwnd(identity.hwnd)?;
        require_same_identity(identity, &current.identity)?;
        let hwnd = HWND(identity.hwnd as *mut c_void);
        unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) }
            .map_err(|error| win_error("target.close_failed", error))?;
        let timeout_ms = timeout.as_millis().min(u128::from(u32::MAX)) as u32;
        match unsafe { WaitForSingleObject(process.0, timeout_ms) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(WindowsError::new(
                "target.close_timeout",
                "target process did not exit before the close deadline",
            )),
            status => Err(WindowsError::new(
                "target.close_failed",
                format!("waiting for target process failed with status {status:?}"),
            )),
        }
    }

    fn process_path(handle: HANDLE) -> Result<String, WindowsError> {
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
            .map_err(|error| win_error("target.identity_unavailable", error))?;
        }
        String::from_utf16(&buffer[..length as usize])
            .map_err(|error| WindowsError::new("target.identity_unavailable", error.to_string()))
    }

    fn process_started_at(handle: HANDLE) -> Result<u64, WindowsError> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe {
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
                .map_err(|error| win_error("target.identity_unavailable", error))?;
        }
        let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
        ticks
            .checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS)
            .map(|value| value / 10_000)
            .ok_or_else(|| {
                WindowsError::new(
                    "target.identity_unavailable",
                    "process creation time predates Unix epoch",
                )
            })
    }

    fn process_is_elevated(handle: HANDLE) -> Result<bool, WindowsError> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) }
            .map_err(|error| win_error("target.permission_denied", error))?;
        let token = OwnedHandle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0_u32;
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
            .map_err(|error| win_error("target.permission_denied", error))?;
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    fn client_rect(hwnd: HWND) -> Result<Rect, WindowsError> {
        let mut bounds = RECT::default();
        unsafe { GetClientRect(hwnd, &mut bounds) }
            .map_err(|error| win_error("target.client_rect_invalid", error))?;
        let mut origin = POINT { x: 0, y: 0 };
        if !unsafe { ClientToScreen(hwnd, &mut origin).as_bool() } {
            return Err(WindowsError::new(
                "target.client_rect_invalid",
                "client origin cannot be converted to screen coordinates",
            ));
        }
        let width = u32::try_from(bounds.right - bounds.left).map_err(|_| {
            WindowsError::new("target.client_rect_invalid", "negative client width")
        })?;
        let height = u32::try_from(bounds.bottom - bounds.top).map_err(|_| {
            WindowsError::new("target.client_rect_invalid", "negative client height")
        })?;
        Rect::new(origin.x, origin.y, width, height)
    }

    fn window_title(hwnd: HWND) -> Result<String, WindowsError> {
        let mut buffer = vec![0_u16; 2048];
        let copied = unsafe { GetWindowTextW(hwnd, &mut buffer) };
        if copied <= 0 {
            return Err(WindowsError::new(
                "target.identity_unavailable",
                "window title is empty or unavailable",
            ));
        }
        Ok(String::from_utf16_lossy(&buffer[..copied as usize]))
    }

    fn window_class(hwnd: HWND) -> Result<String, WindowsError> {
        let mut buffer = vec![0_u16; 512];
        let copied = unsafe { GetClassNameW(hwnd, &mut buffer) };
        if copied <= 0 {
            return Err(WindowsError::new(
                "target.identity_unavailable",
                "window class is unavailable",
            ));
        }
        Ok(String::from_utf16_lossy(&buffer[..copied as usize]))
    }

    fn win_error(code: &'static str, error: windows::core::Error) -> WindowsError {
        WindowsError::new(code, error.to_string())
    }
}
