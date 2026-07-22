#[cfg(windows)]
use windows::{
    core::HSTRING,
    Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE},
        System::Threading::CreateMutexW,
        UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE},
    },
};

#[cfg(windows)]
const GUI_MUTEX: &str = r"Local\FairyPam.Agent.TauriUi.v1";
#[cfg(windows)]
const MAIN_WINDOW_TITLE: &str = "FairyPam Agent UI";

pub enum GuiInstance {
    Primary(GuiSingleInstance),
    Existing,
}

pub struct GuiSingleInstance {
    #[cfg(windows)]
    handle: HANDLE,
}

impl GuiSingleInstance {
    pub fn acquire() -> tauri::Result<GuiInstance> {
        #[cfg(windows)]
        {
            let handle = unsafe { CreateMutexW(None, false, &HSTRING::from(GUI_MUTEX)) }
                .map_err(|error| tauri::Error::Anyhow(error.into()))?;
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                // SAFETY: this process only owns `handle`; the existing GUI owns its window.
                let _ = unsafe { CloseHandle(handle) };
                return Ok(GuiInstance::Existing);
            }
            return Ok(GuiInstance::Primary(Self { handle }));
        }

        #[cfg(not(windows))]
        Ok(GuiInstance::Primary(Self {}))
    }
}

pub fn activate_existing() {
    #[cfg(windows)]
    {
        let title = HSTRING::from(MAIN_WINDOW_TITLE);
        // SAFETY: the title is NUL-terminated by HSTRING and the returned HWND is only activated.
        if let Ok(window) = unsafe { FindWindowW(None, &title) } {
            // SAFETY: activating and restoring an existing top-level window does not transfer ownership.
            unsafe {
                let _ = ShowWindow(window, SW_RESTORE);
                let _ = SetForegroundWindow(window);
            }
        }
    }
}

impl Drop for GuiSingleInstance {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            // SAFETY: the primary instance exclusively owns this mutex handle.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}
