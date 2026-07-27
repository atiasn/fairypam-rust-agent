#[cfg(windows)]
use windows::{
    core::HSTRING,
    Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0},
        System::Threading::{CreateEventW, CreateMutexW, SetEvent, WaitForSingleObject, INFINITE},
        UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE},
    },
};

#[cfg(windows)]
const GUI_MUTEX: &str = r"Local\FairyPam.Agent.TauriUi.v1";
#[cfg(windows)]
const GUI_ACTIVATION_EVENT: &str = r"Local\FairyPam.Agent.TauriUi.Activate.v1";
#[cfg(windows)]
const MAIN_WINDOW_TITLE: &str = "FairyPam Agent UI";

pub enum GuiInstance {
    Primary(GuiSingleInstance),
    Existing,
}

pub struct GuiSingleInstance {
    #[cfg(windows)]
    handle: usize,
    #[cfg(windows)]
    activation: usize,
}

impl GuiSingleInstance {
    pub fn acquire() -> tauri::Result<GuiInstance> {
        #[cfg(windows)]
        {
            let activation =
                unsafe { CreateEventW(None, false, false, &HSTRING::from(GUI_ACTIVATION_EVENT)) }
                    .map_err(|error| tauri::Error::Anyhow(error.into()))?;
            let handle = unsafe { CreateMutexW(None, false, &HSTRING::from(GUI_MUTEX)) }.map_err(
                |error| {
                    let _ = unsafe { CloseHandle(activation) };
                    tauri::Error::Anyhow(error.into())
                },
            )?;
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                // SAFETY: this process only owns `handle`; the existing GUI owns its window.
                let _ = unsafe { SetEvent(activation) };
                let _ = unsafe { CloseHandle(activation) };
                let _ = unsafe { CloseHandle(handle) };
                return Ok(GuiInstance::Existing);
            }
            Ok(GuiInstance::Primary(Self {
                handle: handle.0 as usize,
                activation: activation.0 as usize,
            }))
        }

        #[cfg(not(windows))]
        Ok(GuiInstance::Primary(Self {}))
    }

    pub fn watch_activation(&self, callback: impl Fn() + Send + 'static) -> tauri::Result<()> {
        #[cfg(windows)]
        {
            let activation = self.activation;
            std::thread::Builder::new()
                .name("fairypam-gui-activation".to_owned())
                .spawn(move || loop {
                    if unsafe { WaitForSingleObject(HANDLE(activation as _), INFINITE) }
                        != WAIT_OBJECT_0
                    {
                        break;
                    }
                    callback();
                })
                .map_err(|error| tauri::Error::Anyhow(error.into()))?;
        }
        #[cfg(not(windows))]
        let _ = callback;
        Ok(())
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
            // ponytail: the activation event lives until process exit; closing a
            // handle while the watcher waits on it has undefined Win32 behavior.
            let _ = unsafe { CloseHandle(HANDLE(self.handle as _)) };
        }
    }
}
