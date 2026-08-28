use crate::RealtimeError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalKey {
    pub action_id: String,
    pub scan_code: u16,
    pub extended: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyTransition {
    pub key: PhysicalKey,
    pub pressed: bool,
}

pub trait PhysicalInputBatch {
    fn apply(&mut self, transitions: &[KeyTransition]) -> Result<(), RealtimeError>;
    fn release_all(&mut self) -> Result<(), RealtimeError>;
}

#[cfg(windows)]
pub mod windows {
    use std::collections::{BTreeMap, BTreeSet};

    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
        KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, VIRTUAL_KEY,
    };

    use super::{KeyTransition, PhysicalInputBatch, PhysicalKey};
    use crate::RealtimeError;

    pub const SEND_INPUT_MARKER: usize = 0x4650_414D;

    pub struct WindowsPhysicalInputBatch {
        keys: BTreeMap<String, PhysicalKey>,
        held: BTreeSet<String>,
    }

    impl WindowsPhysicalInputBatch {
        pub fn new(keys: Vec<PhysicalKey>) -> Result<Self, RealtimeError> {
            let mut mapped = BTreeMap::new();
            for key in keys {
                if key.action_id.is_empty()
                    || key.scan_code == 0
                    || mapped.insert(key.action_id.clone(), key).is_some()
                {
                    return Err(RealtimeError::new(
                        "realtime.input_profile_invalid",
                        "realtime physical input map is invalid",
                    ));
                }
            }
            Ok(Self {
                keys: mapped,
                held: BTreeSet::new(),
            })
        }

        fn input(key: &PhysicalKey, pressed: bool) -> INPUT {
            let mut flags = KEYEVENTF_SCANCODE;
            if key.extended {
                flags |= KEYEVENTF_EXTENDEDKEY;
            }
            if !pressed {
                flags |= KEYEVENTF_KEYUP;
            }
            INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: VIRTUAL_KEY(0),
                        wScan: key.scan_code,
                        dwFlags: flags,
                        dwExtraInfo: SEND_INPUT_MARKER,
                        ..Default::default()
                    },
                },
            }
        }

        fn send(inputs: &[INPUT]) -> Result<(), RealtimeError> {
            if inputs.is_empty() {
                return Ok(());
            }
            let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
            if sent != inputs.len() as u32 {
                return Err(RealtimeError::new(
                    "realtime.input_uncertain",
                    format!("SendInput applied {sent}/{} events", inputs.len()),
                ));
            }
            Ok(())
        }
    }

    impl PhysicalInputBatch for WindowsPhysicalInputBatch {
        fn apply(&mut self, transitions: &[KeyTransition]) -> Result<(), RealtimeError> {
            let mut next = self.held.clone();
            let mut inputs = Vec::with_capacity(transitions.len());
            for transition in transitions {
                let key = self.keys.get(&transition.key.action_id).ok_or_else(|| {
                    RealtimeError::new(
                        "realtime.input_profile_invalid",
                        "transition action is not installed",
                    )
                })?;
                if key != &transition.key || next.contains(&key.action_id) == transition.pressed {
                    return Err(RealtimeError::new(
                        "realtime.transition_invalid",
                        "transition does not change the installed key state",
                    ));
                }
                if transition.pressed {
                    next.insert(key.action_id.clone());
                } else {
                    next.remove(&key.action_id);
                }
                inputs.push(Self::input(key, transition.pressed));
            }
            Self::send(&inputs)?;
            self.held = next;
            Ok(())
        }

        fn release_all(&mut self) -> Result<(), RealtimeError> {
            let inputs = self
                .keys
                .values()
                .map(|key| Self::input(key, false))
                .collect::<Vec<_>>();
            Self::send(&inputs)?;
            self.held.clear();
            Ok(())
        }
    }
}
