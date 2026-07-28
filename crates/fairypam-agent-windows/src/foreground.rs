#![cfg(windows)]

use std::{ffi::c_void, sync::OnceLock};

use windows::{
    core::w,
    Win32::{
        Foundation::{HWND, LPARAM, WPARAM},
        UI::WindowsAndMessaging::{
            GetWindowThreadProcessId, IsWindow, RegisterWindowMessageW, SendMessageTimeoutW,
            SMTO_ABORTIFHUNG, SMTO_BLOCK,
        },
    },
};

use crate::WindowsError;

const REQUEST_TIMEOUT_MS: u32 = 250;
static BROKER: OnceLock<ForegroundBroker> = OnceLock::new();

struct ForegroundBroker {
    gui_pid: u32,
    hwnd: isize,
    message: u32,
}

pub fn configure_foreground_broker(gui_pid: u32, hwnd: isize) -> Result<(), WindowsError> {
    verify_broker_window(gui_pid, hwnd)?;
    let message = unsafe { RegisterWindowMessageW(w!("FairyPam.ForegroundBroker.v1")) };
    if message == 0 {
        return Err(broker_error(
            "foreground broker message registration failed",
        ));
    }
    BROKER
        .set(ForegroundBroker {
            gui_pid,
            hwnd,
            message,
        })
        .map_err(|_| broker_error("foreground broker was already configured"))
}

pub(crate) fn request_foreground_authorization() -> Result<bool, WindowsError> {
    let Some(broker) = BROKER.get() else {
        return Ok(false);
    };
    verify_broker_window(broker.gui_pid, broker.hwnd)?;
    let mut granted = 0_usize;
    let sent = unsafe {
        SendMessageTimeoutW(
            HWND(broker.hwnd as *mut c_void),
            broker.message,
            WPARAM(std::process::id() as usize),
            LPARAM(0),
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            REQUEST_TIMEOUT_MS,
            Some(&mut granted),
        )
    };
    if sent.0 == 0 || granted != 1 {
        return Err(broker_error(
            "bound GUI did not grant foreground permission",
        ));
    }
    Ok(true)
}

fn verify_broker_window(gui_pid: u32, hwnd: isize) -> Result<(), WindowsError> {
    let hwnd = HWND(hwnd as *mut c_void);
    let mut actual_pid = 0;
    if !unsafe { IsWindow(Some(hwnd)) }.as_bool()
        || unsafe { GetWindowThreadProcessId(hwnd, Some(&mut actual_pid)) } == 0
        || actual_pid != gui_pid
    {
        return Err(broker_error(
            "foreground broker does not belong to the verified GUI",
        ));
    }
    Ok(())
}

fn broker_error(message: impl Into<String>) -> WindowsError {
    WindowsError::new("target.focus_broker_failed", message)
}
