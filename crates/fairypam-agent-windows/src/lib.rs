//! Windows target discovery and target-window BitBlt capture boundary.

mod capture;
mod dpi;
#[cfg(windows)]
mod local_input;
mod pixel;
mod process;
#[cfg(windows)]
mod send_input;
mod window;

#[cfg(windows)]
pub use capture::WindowsTargetCapture;
pub use capture::{
    CaptureBackend, CaptureEncoding, CapturePipeline, CaptureSession, CapturedBgraFrame,
    CapturedFrame, LatestFrameSlot,
};
pub use dpi::{physical_to_logical, validate_dpi};
#[cfg(windows)]
pub use process::{matching_process_ids, process_matches_executable};
pub use process::{normalize_process_path, normalized_process_path_sha256, process_path_is_within};
pub use window::{
    lock_unique, revalidate_identity, FakeWindows, Rect, TargetIdentity, WindowsApi, WindowsError,
    WindowsTargetCandidate, WindowsTargetPlatform,
};

#[cfg(any(windows, test))]
pub use window::LockedInputTarget;

#[cfg(windows)]
pub use capture::BitBltCaptureBackend;
#[cfg(windows)]
pub use local_input::{require_local_input_monitor, LocalInputMonitor};
#[cfg(windows)]
pub use pixel::{ClientPixelSampler, PixelSampleTiming};
#[cfg(windows)]
pub use send_input::{MusicLaneSender, PreparedMusicLaneInput, WindowsInput};
#[cfg(windows)]
pub use window::NativeWindows;

#[cfg(windows)]
impl WindowsTargetPlatform<NativeWindows> {
    pub fn start_capture(
        &mut self,
        binding: &fairypam_agent_core::target::TargetBinding,
        region: fairypam_agent_core::profile::CaptureRegion,
        encoding: CaptureEncoding,
    ) -> Result<WindowsTargetCapture, fairypam_agent_core::AgentError> {
        self.focus(binding)?;
        let identity = self.capture_identity(binding)?;
        WindowsTargetCapture::new(binding.clone(), identity, region, encoding)
            .map_err(fairypam_agent_core::AgentError::from)
    }

    pub fn start_input<G: fairypam_agent_input::GuardianClient>(
        &mut self,
        profile: &fairypam_agent_core::profile::VerifiedProfile,
        binding: fairypam_agent_core::target::TargetBinding,
        guardian: G,
    ) -> Result<WindowsInput<G>, fairypam_agent_input::SafetyError> {
        self.focus(&binding).map_err(|error| {
            fairypam_agent_input::SafetyError::new(error.code(), error.to_string())
        })?;
        let target = self.lock_input_target(&binding).map_err(|error| {
            fairypam_agent_input::SafetyError::new(error.code(), error.to_string())
        })?;
        WindowsInput::for_locked_target(profile, binding, target, guardian)
    }
}
