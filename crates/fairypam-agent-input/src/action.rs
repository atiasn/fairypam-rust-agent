use std::collections::{BTreeMap, BTreeSet};

use fairypam_agent_core::profile::{ActionDefinition, ClientPointButton, VerifiedProfile};
use fairypam_agent_guardian_protocol::{ActionId, PhysicalHold};

use crate::SafetyError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticMouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedAction {
    HoldKey { scan_code: u16, extended: bool },
    PulseKey { scan_code: u16, extended: bool },
    Wheel { maximum_delta: i32 },
    RelativeMouse { maximum_delta: i32 },
    ClientPointClick { button: SemanticMouseButton },
}

#[derive(Clone, Debug, Default)]
pub struct ActionMap {
    actions: BTreeMap<ActionId, ResolvedAction>,
}

impl ActionMap {
    pub fn from_verified_profile(profile: &VerifiedProfile) -> Result<Self, SafetyError> {
        let actions = profile
            .profile()
            .actions
            .iter()
            .map(|(id, definition)| {
                let id = ActionId::new(id.clone())
                    .map_err(|error| SafetyError::new("input.action_invalid", error.to_string()))?;
                let action = match definition {
                    ActionDefinition::Hold { scan_code } => ResolvedAction::HoldKey {
                        scan_code: *scan_code,
                        extended: false,
                    },
                    ActionDefinition::Pulse { scan_code } => ResolvedAction::PulseKey {
                        scan_code: *scan_code,
                        extended: false,
                    },
                    ActionDefinition::PhysicalHold {
                        scan_code,
                        extended,
                    } => ResolvedAction::HoldKey {
                        scan_code: *scan_code,
                        extended: *extended,
                    },
                    ActionDefinition::PhysicalPulse {
                        scan_code,
                        extended,
                    } => ResolvedAction::PulseKey {
                        scan_code: *scan_code,
                        extended: *extended,
                    },
                    ActionDefinition::Wheel { maximum_delta } => ResolvedAction::Wheel {
                        maximum_delta: *maximum_delta,
                    },
                    ActionDefinition::RelativeMouse { maximum_delta } => {
                        ResolvedAction::RelativeMouse {
                            maximum_delta: *maximum_delta,
                        }
                    }
                    ActionDefinition::ClientPointClick { button } => {
                        ResolvedAction::ClientPointClick {
                            button: match button {
                                ClientPointButton::Left => SemanticMouseButton::Left,
                                ClientPointButton::Right => SemanticMouseButton::Right,
                                ClientPointButton::Middle => SemanticMouseButton::Middle,
                                ClientPointButton::X1 => SemanticMouseButton::X1,
                                ClientPointButton::X2 => SemanticMouseButton::X2,
                            },
                        }
                    }
                };
                Ok((id, action))
            })
            .collect::<Result<_, SafetyError>>()?;
        Ok(Self { actions })
    }

    pub fn resolve(&self, id: &ActionId) -> Result<&ResolvedAction, SafetyError> {
        self.actions.get(id).ok_or_else(|| {
            SafetyError::new(
                "input.action_not_allowed",
                format!(
                    "action is not declared by the verified profile: {}",
                    id.as_str()
                ),
            )
        })
    }

    pub fn hold_scan_code(&self, id: &ActionId) -> Result<u16, SafetyError> {
        match self.resolve(id)? {
            ResolvedAction::HoldKey {
                scan_code,
                extended: false,
            } => Ok(*scan_code),
            _ => Err(SafetyError::new(
                "input.action_kind_invalid",
                "only hold actions may appear in an input lease",
            )),
        }
    }

    pub fn physical_actions(
        &self,
        keys: &[(u16, bool)],
        buttons: &[SemanticMouseButton],
    ) -> Result<BTreeSet<ActionId>, SafetyError> {
        keys.iter()
            .map(|key| self.action_for_key(*key))
            .chain(buttons.iter().map(|button| self.action_for_button(*button)))
            .collect()
    }

    fn action_for_key(&self, key: (u16, bool)) -> Result<ActionId, SafetyError> {
        self.actions
            .iter()
            .find_map(|(id, action)| match action {
                ResolvedAction::HoldKey {
                    scan_code,
                    extended,
                }
                | ResolvedAction::PulseKey {
                    scan_code,
                    extended,
                } if (*scan_code, *extended) == key => Some(id.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                SafetyError::new(
                    "input.key_not_allowed",
                    "physical key is not declared by the verified Profile",
                )
            })
    }

    pub(crate) fn action_for_button(
        &self,
        button: SemanticMouseButton,
    ) -> Result<ActionId, SafetyError> {
        self.actions
            .iter()
            .find_map(|(id, action)| match action {
                ResolvedAction::ClientPointClick { button: allowed } if *allowed == button => {
                    Some(id.clone())
                }
                _ => None,
            })
            .ok_or_else(|| {
                SafetyError::new(
                    "input.mouse_button_not_allowed",
                    "mouse button is not declared by the verified Profile",
                )
            })
    }

    pub fn wheel_limit(&self) -> Option<i32> {
        self.actions.values().find_map(|action| match action {
            ResolvedAction::Wheel { maximum_delta } => Some(*maximum_delta),
            _ => None,
        })
    }

    pub fn physical_holds(&self) -> BTreeMap<ActionId, PhysicalHold> {
        self.actions
            .iter()
            .filter_map(|(id, action)| match action {
                ResolvedAction::HoldKey {
                    scan_code,
                    extended,
                }
                | ResolvedAction::PulseKey {
                    scan_code,
                    extended,
                } => Some((
                    id.clone(),
                    PhysicalHold::ScanCode {
                        action_id: id.clone(),
                        scan_code: *scan_code,
                        extended: *extended,
                    },
                )),
                ResolvedAction::ClientPointClick { button } => Some((
                    id.clone(),
                    PhysicalHold::MouseButton {
                        action_id: id.clone(),
                        button: match button {
                            SemanticMouseButton::Left => {
                                fairypam_agent_guardian_protocol::MouseButton::Left
                            }
                            SemanticMouseButton::Right => {
                                fairypam_agent_guardian_protocol::MouseButton::Right
                            }
                            SemanticMouseButton::Middle => {
                                fairypam_agent_guardian_protocol::MouseButton::Middle
                            }
                            SemanticMouseButton::X1 => {
                                fairypam_agent_guardian_protocol::MouseButton::X1
                            }
                            SemanticMouseButton::X2 => {
                                fairypam_agent_guardian_protocol::MouseButton::X2
                            }
                        },
                    },
                )),
                _ => None,
            })
            .collect()
    }

    pub fn all_scan_codes(&self) -> Vec<u16> {
        self.actions
            .values()
            .filter_map(|action| match action {
                ResolvedAction::HoldKey { scan_code, .. }
                | ResolvedAction::PulseKey { scan_code, .. } => Some(*scan_code),
                ResolvedAction::Wheel { .. }
                | ResolvedAction::RelativeMouse { .. }
                | ResolvedAction::ClientPointClick { .. } => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

pub trait InputPlatform: Send {
    fn validate_before_input(&mut self) -> Result<(), SafetyError> {
        Ok(())
    }

    fn press_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError>;
    fn release_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError>;

    fn pulse_scan_code(&mut self, scan_code: u16) -> Result<(), SafetyError> {
        self.press_scan_code(scan_code)?;
        self.release_scan_code(scan_code)
    }

    fn press_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        if extended {
            return Err(SafetyError::new(
                "input.platform_unsupported",
                "extended scan codes are unsupported by this platform",
            ));
        }
        self.press_scan_code(scan_code)
    }

    fn release_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        if extended {
            return Err(SafetyError::new(
                "input.platform_unsupported",
                "extended scan codes are unsupported by this platform",
            ));
        }
        self.release_scan_code(scan_code)
    }

    fn pulse_key(&mut self, scan_code: u16, extended: bool) -> Result<(), SafetyError> {
        if extended {
            return Err(SafetyError::new(
                "input.platform_unsupported",
                "extended scan codes are unsupported by this platform",
            ));
        }
        self.pulse_scan_code(scan_code)
    }

    fn press_mouse_button(&mut self, _button: SemanticMouseButton) -> Result<(), SafetyError> {
        Err(SafetyError::new(
            "input.platform_unsupported",
            "held mouse buttons are unsupported by this platform",
        ))
    }

    fn release_mouse_button(&mut self, _button: SemanticMouseButton) -> Result<(), SafetyError> {
        Err(SafetyError::new(
            "input.platform_unsupported",
            "held mouse buttons are unsupported by this platform",
        ))
    }

    fn wheel(&mut self, _delta: i32) -> Result<(), SafetyError> {
        Err(SafetyError::new(
            "input.platform_unsupported",
            "mouse wheel input is unsupported by this platform",
        ))
    }

    fn wheel_at_client_point(
        &mut self,
        _x_ppm: u32,
        _y_ppm: u32,
        _delta: i32,
    ) -> Result<(), SafetyError> {
        Err(SafetyError::new(
            "input.platform_unsupported",
            "positioned mouse wheel input is unsupported by this platform",
        ))
    }

    fn emergency_release(&mut self, scan_codes: &[u16]) -> Result<(), SafetyError> {
        let mut first_error = None;
        for scan_code in scan_codes {
            if let Err(error) = self.release_scan_code(*scan_code) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn relative_mouse(&mut self, _delta_x: i32, _delta_y: i32) -> Result<(), SafetyError> {
        Err(SafetyError::new(
            "input.platform_unsupported",
            "relative mouse input is unsupported by this platform",
        ))
    }

    fn client_point_click(
        &mut self,
        _button: SemanticMouseButton,
        _x_ppm: u32,
        _y_ppm: u32,
    ) -> Result<(), SafetyError> {
        Err(SafetyError::new(
            "input.platform_unsupported",
            "client point input is unsupported by this platform",
        ))
    }
}
