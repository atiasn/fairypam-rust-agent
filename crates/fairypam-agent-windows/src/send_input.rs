use std::collections::BTreeSet;

use fairypam_agent_core::profile::{ActionDefinition, VerifiedProfile};
use fairypam_agent_core::AgentError;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEUP,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_XUP, MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
};

pub(crate) const SEND_INPUT_MARKER: usize = 0x4650_414D;

pub fn emergency_release_profile(profile: &VerifiedProfile) -> Result<(), AgentError> {
    let mut keys = BTreeSet::new();
    for action in profile.profile().actions.values() {
        if let ActionDefinition::Hold {
            physical_scan_code,
            extended,
            ..
        }
        | ActionDefinition::Pulse {
            physical_scan_code,
            extended,
            ..
        } = action
        {
            keys.insert((*physical_scan_code, *extended));
        }
    }
    let mut inputs = keys
        .into_iter()
        .map(|(scan_code, extended)| keyboard_release(scan_code, extended))
        .collect::<Vec<_>>();
    inputs.extend([
        mouse_release(MOUSEEVENTF_LEFTUP, 0),
        mouse_release(MOUSEEVENTF_RIGHTUP, 0),
        mouse_release(MOUSEEVENTF_MIDDLEUP, 0),
        mouse_release(MOUSEEVENTF_XUP, 1),
        mouse_release(MOUSEEVENTF_XUP, 2),
    ]);
    send(&inputs)
}

fn keyboard_release(scan_code: u16, extended: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: scan_code,
                dwFlags: KEYEVENTF_SCANCODE
                    | KEYEVENTF_KEYUP
                    | if extended {
                        KEYEVENTF_EXTENDEDKEY
                    } else {
                        Default::default()
                    },
                dwExtraInfo: SEND_INPUT_MARKER,
                ..Default::default()
            },
        },
    }
}

fn mouse_release(flags: MOUSE_EVENT_FLAGS, data: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                mouseData: data,
                dwFlags: flags,
                dwExtraInfo: SEND_INPUT_MARKER,
                ..Default::default()
            },
        },
    }
}

fn send(inputs: &[INPUT]) -> Result<(), AgentError> {
    let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    if sent == inputs.len() as u32 {
        Ok(())
    } else {
        Err(AgentError::new(
            "input.release_failed",
            format!("SendInput released {sent}/{} inputs", inputs.len()),
        ))
    }
}
