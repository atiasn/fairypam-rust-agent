//! Windows process/window lifecycle, local-input monitoring, and emergency release boundary.

mod dpi;
#[cfg(windows)]
mod local_input;
mod process;
#[cfg(windows)]
mod send_input;
mod window;

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
pub use local_input::{require_local_input_monitor, LocalInputMonitor};
#[cfg(windows)]
pub use send_input::emergency_release_profile;
#[cfg(windows)]
pub use window::NativeWindows;
