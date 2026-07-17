use std::collections::{BTreeMap, BTreeSet};

use fairypam_agent_core::profile::{ActionDefinition, ClientPointButton, VerifiedProfile};
use fairypam_agent_guardian_protocol::{ActionId, PhysicalHold};

use crate::SafetyError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticMouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedAction {
    HoldScanCode(u16),
    PulseScanCode(u16),
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
                    ActionDefinition::Hold { scan_code } => {
                        ResolvedAction::HoldScanCode(*scan_code)
                    }
                    ActionDefinition::Pulse { scan_code } => {
                        ResolvedAction::PulseScanCode(*scan_code)
                    }
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
            ResolvedAction::HoldScanCode(scan_code) => Ok(*scan_code),
            _ => Err(SafetyError::new(
                "input.action_kind_invalid",
                "only hold actions may appear in an input lease",
            )),
        }
    }

    pub fn physical_holds(&self) -> BTreeMap<ActionId, PhysicalHold> {
        self.actions
            .iter()
            .filter_map(|(id, action)| match action {
                ResolvedAction::HoldScanCode(scan_code) => Some((
                    id.clone(),
                    PhysicalHold::ScanCode {
                        action_id: id.clone(),
                        scan_code: *scan_code,
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
                ResolvedAction::HoldScanCode(scan_code)
                | ResolvedAction::PulseScanCode(scan_code) => Some(*scan_code),
                ResolvedAction::RelativeMouse { .. } | ResolvedAction::ClientPointClick { .. } => {
                    None
                }
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
