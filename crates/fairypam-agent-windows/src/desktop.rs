use std::sync::OnceLock;

use windows::core::{w, BOOL};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, GetThreadDesktop, GetUserObjectInformationW,
    OpenInputDesktop, OpenWindowStationW, SetProcessWindowStation, SetThreadDesktop,
    DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS, UOI_IO,
    UOI_NAME,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::WINSTA_ALL_ACCESS;

use crate::WindowsError;

static INPUT_WINDOW_STATION: OnceLock<Result<usize, WindowsError>> = OnceLock::new();

pub(crate) fn ensure_input_desktop() -> Result<(), WindowsError> {
    if current_desktop_receives_input()? {
        return Ok(());
    }
    ensure_input_window_station()?;
    let desktop = unsafe {
        OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS::default(),
            false,
            DESKTOP_ACCESS_FLAGS(DESKTOP_READOBJECTS.0 | DESKTOP_WRITEOBJECTS.0),
        )
    }
    .map_err(|error| desktop_error("desktop.input_unavailable", error))?;
    let name = match user_object_name(HANDLE(desktop.0)) {
        Ok(name) => name,
        Err(error) => {
            let _ = unsafe { CloseDesktop(desktop) };
            return Err(error);
        }
    };
    if !supported_input_desktop(&name) {
        let _ = unsafe { CloseDesktop(desktop) };
        return Err(WindowsError::new(
            "desktop.secure_active",
            format!("refusing desktop automation while the {name} desktop is active"),
        ));
    }
    if let Err(error) = unsafe { SetThreadDesktop(desktop) } {
        let _ = unsafe { CloseDesktop(desktop) };
        return Err(desktop_error("desktop.thread_attach_failed", error));
    }
    if !current_desktop_receives_input()? {
        return Err(WindowsError::new(
            "desktop.input_changed",
            "the input desktop changed while the Agent was attaching",
        ));
    }
    // ponytail: Windows cannot close a desktop assigned to a live thread; the
    // bounded worker set keeps one handle until process exit.
    Ok(())
}

fn ensure_input_window_station() -> Result<(), WindowsError> {
    INPUT_WINDOW_STATION
        .get_or_init(|| {
            let station =
                unsafe { OpenWindowStationW(w!("WinSta0"), false, WINSTA_ALL_ACCESS as u32) }
                    .map_err(|error| desktop_error("desktop.window_station_unavailable", error))?;
            if let Err(error) = unsafe { SetProcessWindowStation(station) } {
                let _ = unsafe { CloseWindowStation(station) };
                return Err(desktop_error("desktop.window_station_attach_failed", error));
            }
            Ok(station.0 as usize)
        })
        .as_ref()
        .map(|_| ())
        .map_err(Clone::clone)
}

fn current_desktop_receives_input() -> Result<bool, WindowsError> {
    let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
        .map_err(|error| desktop_error("desktop.thread_unavailable", error))?;
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
    .map_err(|error| desktop_error("desktop.state_unavailable", error))?;
    Ok(receives_input.as_bool())
}

fn user_object_name(handle: HANDLE) -> Result<String, WindowsError> {
    let mut needed = 0;
    let _ = unsafe { GetUserObjectInformationW(handle, UOI_NAME, None, 0, Some(&mut needed)) };
    if needed < 2 {
        return Err(WindowsError::new(
            "desktop.name_unavailable",
            "Windows returned no input desktop name",
        ));
    }
    let mut buffer = vec![0_u16; (needed as usize + 1) / 2];
    unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            Some(&mut needed),
        )
    }
    .map_err(|error| desktop_error("desktop.name_unavailable", error))?;
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).map_err(|_| {
        WindowsError::new(
            "desktop.name_unavailable",
            "the input desktop name is not valid UTF-16",
        )
    })
}

fn supported_input_desktop(name: &str) -> bool {
    name.eq_ignore_ascii_case("Default")
}

fn desktop_error(code: &'static str, error: windows::core::Error) -> WindowsError {
    WindowsError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::supported_input_desktop;

    #[test]
    fn only_the_normal_user_desktop_is_supported() {
        assert!(supported_input_desktop("Default"));
        assert!(supported_input_desktop("default"));
        assert!(!supported_input_desktop("Winlogon"));
        assert!(!supported_input_desktop("ScreenSaver"));
    }
}
