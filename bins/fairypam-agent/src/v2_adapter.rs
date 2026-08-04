use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::{
    v1 as internal,
    v2::{self as wire, command_identity, hub_control_command},
    verify_execution_contract, verify_task_command_digest,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{execution::CommandOutcome, profile_store::ProfileStore};

#[derive(Default)]
pub struct Translator {
    active_contract: Option<wire::ExecutionContract>,
    hub_max_input_lease_ms: u32,
    last_input_sequence: u64,
    task_digests: BTreeMap<(String, String), String>,
}

#[derive(Debug)]
pub enum TranslatedCommand {
    Internal(internal::HubControlCommand),
    CloseTarget {
        value: wire::CloseTarget,
    },
    ConfigureIdleClose {
        value: wire::ConfigureIdleClose,
    },
    BeginAttempt {
        task: internal::TaskCommandRef,
        contract: wire::ExecutionContract,
        digest_key: (String, String),
        payload_digest: String,
    },
    InputFrame {
        task: internal::TaskCommandRef,
        frame: wire::InputFrame,
    },
    ClientPointClick {
        task: internal::TaskCommandRef,
        value: wire::ClientPointClick,
    },
}

impl Translator {
    pub const fn new(hub_max_input_lease_ms: u32) -> Self {
        Self {
            active_contract: None,
            hub_max_input_lease_ms,
            last_input_sequence: 0,
            task_digests: BTreeMap::new(),
        }
    }

    pub fn translate(
        &mut self,
        command: &wire::HubControlCommand,
    ) -> Result<TranslatedCommand, AgentError> {
        let pending_digest = identity(command)
            .and_then(|identity| match identity.value {
                Some(command_identity::Value::Task(task)) => Some(task),
                _ => None,
            })
            .map(|task| {
                let command_id = task
                    .command
                    .as_ref()
                    .ok_or_else(reference_invalid)?
                    .command_id
                    .clone();
                let attempt_id = task
                    .attempt
                    .as_ref()
                    .ok_or_else(reference_invalid)?
                    .attempt_id
                    .clone();
                let key = (attempt_id, command_id);
                if self
                    .task_digests
                    .get(&key)
                    .is_some_and(|digest| digest != &task.payload_digest)
                {
                    return Err(AgentError::new(
                        "command.payload_digest_conflict",
                        "logical task command payload digest changed",
                    ));
                }
                Ok((key, task.payload_digest))
            })
            .transpose()?;
        let translated = translate(command, self)?;
        if !matches!(translated, TranslatedCommand::BeginAttempt { .. }) {
            if let Some((key, digest)) = pending_digest {
                self.task_digests.entry(key).or_insert(digest);
            }
        }
        Ok(translated)
    }

    pub fn accept_begin(
        &mut self,
        contract: wire::ExecutionContract,
        digest_key: (String, String),
        payload_digest: String,
    ) {
        self.active_contract = Some(contract.clone());
        self.task_digests
            .retain(|(attempt_id, _), _| attempt_id == &contract.attempt_id);
        self.task_digests.insert(digest_key, payload_digest);
        self.last_input_sequence = 0;
    }
}

pub fn hello(
    agent_id: String,
    agent_version: String,
    build_commit: String,
    profiles: &ProfileStore,
    active_catalog: Option<(u64, &str)>,
) -> wire::AgentControlEvent {
    wire::AgentControlEvent {
        payload: Some(wire::agent_control_event::Payload::Hello(
            wire::AgentHello {
                agent_id,
                agent_version,
                protocol_major: 2,
                protocol_minor: 4,
                build_commit,
                suite_build_id: option_env!("FAIRYPAM_BUILD_ID")
                    .unwrap_or("unknown")
                    .to_owned(),
                installed_profiles: profiles
                    .installed()
                    .map(|profile| wire::InstalledProfile {
                        profile_id: profile.profile().id.clone(),
                        schema_version: 1,
                        content_digest: profile.content_sha256().to_owned(),
                    })
                    .collect(),
                active_profile_catalog_version: active_catalog.map(|catalog| catalog.0),
                active_profile_catalog_digest: active_catalog.map(|catalog| catalog.1.to_owned()),
            },
        )),
    }
}

pub fn profile_catalog_status(
    session: wire::SessionRef,
    desired_version: u64,
    desired_digest: String,
    state: wire::ProfileCatalogApplyState,
    active_catalog: Option<(u64, &str)>,
    error_code: Option<String>,
) -> wire::AgentControlEvent {
    wire::AgentControlEvent {
        payload: Some(wire::agent_control_event::Payload::ProfileCatalogStatus(
            wire::ProfileCatalogStatus {
                session: Some(session),
                desired_catalog_version: desired_version,
                desired_catalog_digest: desired_digest,
                state: state as i32,
                active_catalog_version: active_catalog.map(|catalog| catalog.0),
                active_catalog_digest: active_catalog.map(|catalog| catalog.1.to_owned()),
                error_code,
            },
        )),
    }
}

pub fn discovery_snapshot(
    session: wire::SessionRef,
    profiles: &ProfileStore,
) -> Result<wire::AgentControlEvent, AgentError> {
    let mut games = discovered_games(profiles)?;
    games.sort_by_key(|game| {
        (
            game.profile_id.clone(),
            game.normalized_install_root.to_ascii_lowercase(),
            game.executable_name.to_ascii_lowercase(),
        )
    });
    let payload = serde_json::json!({
        "games": games.iter().map(|game| serde_json::json!({
            "available": game.available,
            "executable_name": game.executable_name,
            "executable_sha256": game.executable_sha256,
            "normalized_install_root": game.normalized_install_root,
            "process_name": game.process_name,
            "profile_id": game.profile_id,
            "publisher_subject": if game.publisher_subject.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(game.publisher_subject.clone()) },
        })).collect::<Vec<_>>(),
    });
    let payload_digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&payload)
                .map_err(|error| AgentError::new("discovery.invalid", error.to_string()))?
        )
    );
    Ok(wire::AgentControlEvent {
        payload: Some(wire::agent_control_event::Payload::DiscoverySnapshot(
            wire::DiscoverySnapshot {
                session: Some(session),
                scan_id: discovery_uuid(),
                observed_at_unix_ms: now_unix_ms(),
                payload_digest,
                games,
            },
        )),
    })
}

#[cfg(windows)]
fn discovered_games(profiles: &ProfileStore) -> Result<Vec<wire::DiscoveredGame>, AgentError> {
    use std::io::Read;

    profiles
        .installed()
        .filter_map(|profile| {
            let executable = crate::observability::resolve_profile_executable(profile).ok()?;
            let root = executable.parent()?.to_str()?.replace('/', "\\");
            let executable_name = executable.file_name()?.to_str()?.to_owned();
            let mut file = std::fs::File::open(&executable).ok()?;
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).ok()?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
            let digest = digest.finalize();
            Some(Ok(wire::DiscoveredGame {
                profile_id: profile.profile().id.clone(),
                normalized_install_root: root,
                process_name: executable_name
                    .strip_suffix(".exe")
                    .unwrap_or(&executable_name)
                    .to_owned(),
                executable_name,
                publisher_subject: String::new(),
                executable_sha256: Some(format!("{digest:x}")),
                available: true,
            }))
        })
        .collect()
}

#[cfg(not(windows))]
fn discovered_games(_profiles: &ProfileStore) -> Result<Vec<wire::DiscoveredGame>, AgentError> {
    Ok(Vec::new())
}

fn discovery_uuid() -> String {
    let seed = format!("{}:{}", now_unix_ms(), std::process::id());
    let mut bytes: [u8; 16] = Sha256::digest(seed.as_bytes())[..16]
        .try_into()
        .expect("fixed digest slice");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub fn identity(command: &wire::HubControlCommand) -> Option<wire::CommandIdentity> {
    use hub_control_command::Payload;
    match command.payload.as_ref()? {
        Payload::Hello(_) => None,
        Payload::LaunchTarget(value) => value.reference.clone(),
        Payload::CloseTarget(value) => value.reference.clone(),
        Payload::ConfigureIdleClose(value) => value.reference.clone(),
        Payload::AcknowledgeManagedGameClose(_) | Payload::ProfileCatalog(_) => None,
        Payload::BeginAttempt(value) => value.reference.clone(),
        Payload::StartAttemptTarget(value) => value.reference.clone(),
        Payload::StartCapture(value) => value.reference.clone(),
        Payload::CaptureFrame(value) => value.reference.clone(),
        Payload::StopCapture(value) => value.reference.clone(),
        Payload::InputFrame(value) => value.reference.clone(),
        Payload::ClientPointClick(value) => value.reference.clone(),
        Payload::ReleaseAll(value) => value.reference.clone(),
        Payload::FinishAttempt(value) => value.reference.clone(),
        Payload::InspectAttempt(value) => value.reference.clone(),
        Payload::StopSession(value) => value.reference.clone(),
    }
}

pub fn internal_task_identity(
    identity: &wire::CommandIdentity,
) -> Result<internal::TaskCommandRef, AgentError> {
    internal_task(wire_task(Some(identity))?)
}

fn translate(
    command: &wire::HubControlCommand,
    translator: &mut Translator,
) -> Result<TranslatedCommand, AgentError> {
    use hub_control_command::Payload;
    verify_task_command_digest(command)
        .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
    let payload = match command.payload.as_ref() {
        Some(Payload::LaunchTarget(value)) => {
            internal::hub_control_command::Payload::LaunchTarget(internal::LaunchTarget {
                command: session_command(value.reference.as_ref())?,
                profile_id: value.profile_id.clone(),
            })
        }
        Some(Payload::CloseTarget(value)) => {
            session_command(value.reference.as_ref())?;
            return Ok(TranslatedCommand::CloseTarget {
                value: value.clone(),
            });
        }
        Some(Payload::ConfigureIdleClose(value)) => {
            session_command(value.reference.as_ref())?;
            return Ok(TranslatedCommand::ConfigureIdleClose {
                value: value.clone(),
            });
        }
        Some(Payload::BeginAttempt(value)) => {
            let contract = value.contract.as_ref().ok_or_else(reference_invalid)?;
            verify_execution_contract(contract)
                .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
            if contract.deadline_unix_ms <= now_unix_ms() {
                return Err(AgentError::new(
                    "task.contract_expired",
                    "execution contract deadline has expired",
                ));
            }
            let task = wire_task(value.reference.as_ref())?;
            if task.attempt.as_ref()
                != Some(&wire::AttemptRef {
                    task_run_id: contract.task_run_id.clone(),
                    attempt_id: contract.attempt_id.clone(),
                    contract_version: contract.contract_version,
                    contract_digest: contract.contract_digest.clone(),
                })
                || task
                    .command
                    .as_ref()
                    .is_none_or(|command| command.expires_at_unix_ms > contract.deadline_unix_ms)
            {
                return Err(AgentError::new(
                    "task.contract_binding_invalid",
                    "execution contract does not match the task command",
                ));
            }
            let command = task.command.as_ref().ok_or_else(reference_invalid)?;
            let attempt = task.attempt.as_ref().ok_or_else(reference_invalid)?;
            return Ok(TranslatedCommand::BeginAttempt {
                task: internal_task(task)?,
                contract: contract.clone(),
                digest_key: (attempt.attempt_id.clone(), command.command_id.clone()),
                payload_digest: task.payload_digest.clone(),
            });
        }
        Some(Payload::StartAttemptTarget(value)) => {
            translator.require_capability(value.reference.as_ref(), 1)?;
            internal::hub_control_command::Payload::StartTaskTarget(internal::StartTaskTarget {
                task: task_command(value.reference.as_ref())?,
            })
        }
        Some(Payload::StartCapture(value)) => {
            translator.require_capability(value.reference.as_ref(), 3)?;
            if value.capture_source_id.is_empty()
                || value.encoding != "jpeg"
                || !(1..=30).contains(&value.fps)
                || !(1..=100).contains(&value.quality)
            {
                return Err(AgentError::new(
                    "capture.command_invalid",
                    "capture command is outside v2 bounds",
                ));
            }
            internal::hub_control_command::Payload::StartCapture(internal::StartCapture {
                source_id: value.capture_source_id.clone(),
                fps: value.fps,
                encoding: value.encoding.clone(),
                quality: value.quality,
                task: task_command(value.reference.as_ref())?,
                ..internal::StartCapture::default()
            })
        }
        Some(Payload::CaptureFrame(value)) => {
            translator.require_capability(value.reference.as_ref(), 3)?;
            if value.capture_source_id.is_empty()
                || value.encoding != "jpeg"
                || !(1..=100).contains(&value.quality)
            {
                return Err(AgentError::new(
                    "capture.command_invalid",
                    "single-frame capture command is outside v2 bounds",
                ));
            }
            internal::hub_control_command::Payload::CaptureFrame(internal::CaptureFrame {
                source_id: value.capture_source_id.clone(),
                encoding: value.encoding.clone(),
                quality: value.quality,
                task: task_command(value.reference.as_ref())?,
                ..internal::CaptureFrame::default()
            })
        }
        Some(Payload::StopCapture(value)) => {
            translator.require_capability(value.reference.as_ref(), 3)?;
            if value.capture_source_id.is_empty() {
                return Err(AgentError::new(
                    "capture.command_invalid",
                    "capture source must not be empty",
                ));
            }
            internal::hub_control_command::Payload::StopCapture(internal::StopCapture {
                source_id: value.capture_source_id.clone(),
                task: task_command(value.reference.as_ref())?,
                ..internal::StopCapture::default()
            })
        }
        Some(Payload::InputFrame(value)) => {
            return translator.translate_input_frame(value);
        }
        Some(Payload::ClientPointClick(value)) => {
            translator.require_capability(value.reference.as_ref(), 5)?;
            if value.input_sequence == 0
                || value.input_sequence <= translator.last_input_sequence
                || value.lease_ms == 0
                || value.lease_ms
                    > translator
                        .active_contract
                        .as_ref()
                        .ok_or_else(|| {
                            AgentError::new(
                                "task.contract_missing",
                                "execution contract has not been accepted",
                            )
                        })?
                        .max_input_lease_ms
                        .min(translator.hub_max_input_lease_ms)
                || !matches!(
                    wire::MouseButton::try_from(value.button),
                    Ok(wire::MouseButton::Left
                        | wire::MouseButton::Right
                        | wire::MouseButton::Middle
                        | wire::MouseButton::X1
                        | wire::MouseButton::X2)
                )
                || value.x_ppm > 1_000_000
                || value.y_ppm > 1_000_000
                || value.source_frame_sequence == 0
            {
                return Err(AgentError::new(
                    "input.frame_invalid",
                    "client point click is outside the v2 fixed bounds",
                ));
            }
            translator.last_input_sequence = value.input_sequence;
            return Ok(TranslatedCommand::ClientPointClick {
                task: internal_task(wire_task(value.reference.as_ref())?)?,
                value: value.clone(),
            });
        }
        Some(Payload::ReleaseAll(value)) => {
            let (command, task) = either_command(value.reference.as_ref())?;
            internal::hub_control_command::Payload::ReleaseAll(internal::ReleaseAll {
                command,
                task,
                reason: value.reason_code.clone(),
            })
        }
        Some(Payload::FinishAttempt(value)) => {
            internal::hub_control_command::Payload::FinishTaskAttempt(internal::FinishTaskAttempt {
                task: task_command(value.reference.as_ref())?,
            })
        }
        Some(Payload::InspectAttempt(value)) => {
            internal::hub_control_command::Payload::InspectTaskAttempt(
                internal::InspectTaskAttempt {
                    task: task_command(value.reference.as_ref())?,
                },
            )
        }
        Some(Payload::StopSession(value)) => {
            internal::hub_control_command::Payload::StopSession(internal::StopSession {
                command: session_command(value.reference.as_ref())?,
                reason: value.reason_code.clone(),
            })
        }
        Some(Payload::AcknowledgeManagedGameClose(_))
        | Some(Payload::ProfileCatalog(_))
        | Some(Payload::Hello(_))
        | None => {
            return Err(reference_invalid());
        }
    };
    Ok(TranslatedCommand::Internal(internal::HubControlCommand {
        payload: Some(payload),
    }))
}

impl Translator {
    fn require_capability(
        &self,
        identity: Option<&wire::CommandIdentity>,
        capability: i32,
    ) -> Result<(), AgentError> {
        let task = wire_task(identity)?;
        let contract = self.active_contract.clone().ok_or_else(|| {
            AgentError::new(
                "task.contract_missing",
                "execution contract has not been accepted",
            )
        })?;
        if task.attempt.as_ref().is_none_or(|attempt| {
            attempt.task_run_id != contract.task_run_id
                || attempt.attempt_id != contract.attempt_id
                || attempt.contract_version != contract.contract_version
                || attempt.contract_digest != contract.contract_digest
        }) || task
            .command
            .as_ref()
            .is_none_or(|command| command.expires_at_unix_ms > contract.deadline_unix_ms)
        {
            return Err(AgentError::new(
                "task.contract_binding_invalid",
                "task command does not match the active execution contract",
            ));
        }
        if !contract.allowed_capabilities.contains(&capability) {
            return Err(AgentError::new(
                "task.capability_denied",
                "execution contract does not allow this capability",
            ));
        }
        Ok(())
    }

    fn translate_input_frame(
        &mut self,
        value: &wire::InputFrame,
    ) -> Result<TranslatedCommand, AgentError> {
        let contract = self.active_contract.clone().ok_or_else(|| {
            AgentError::new(
                "task.contract_missing",
                "execution contract has not been accepted",
            )
        })?;
        if value.input_sequence == 0
            || value.lease_ms == 0
            || value.lease_ms > contract.max_input_lease_ms.min(self.hub_max_input_lease_ms)
            || !canonical_keys(&value.held_keys)
            || !canonical_buttons(&value.held_mouse_buttons)
            || !(-1200..=1200).contains(&value.wheel_delta)
            || value.wheel_delta % 120 != 0
            || value
                .source_frame_sequence
                .is_some_and(|sequence| sequence == 0)
            || value.wheel_x_ppm.is_some() != value.wheel_y_ppm.is_some()
            || value.wheel_x_ppm.is_some_and(|value| value > 1_000_000)
            || value.wheel_y_ppm.is_some_and(|value| value > 1_000_000)
            || (value.wheel_x_ppm.is_some() && value.wheel_delta == 0)
            || dangerous_keys(&value.held_keys)
        {
            return Err(AgentError::new(
                "input.frame_invalid",
                "input frame is outside the current signed Profile policy",
            ));
        }
        if value.input_sequence <= self.last_input_sequence {
            return Err(AgentError::new(
                "input.sequence_invalid",
                "input frame sequence must increase monotonically",
            ));
        }
        let capabilities = [
            (!value.held_keys.is_empty(), 4),
            (!value.held_mouse_buttons.is_empty(), 5),
            (value.wheel_delta != 0, 6),
        ];
        if capabilities.iter().all(|(used, _)| !used) {
            if ![4, 5, 6]
                .iter()
                .any(|capability| contract.allowed_capabilities.contains(capability))
            {
                return Err(AgentError::new(
                    "task.capability_denied",
                    "execution contract does not allow physical input",
                ));
            }
            self.require_task_binding(value.reference.as_ref())?;
        } else {
            for (_, capability) in capabilities.iter().filter(|(used, _)| *used) {
                self.require_capability(value.reference.as_ref(), *capability)?;
            }
        }
        let task = internal_task(wire_task(value.reference.as_ref())?)?;
        self.last_input_sequence = value.input_sequence;
        Ok(TranslatedCommand::InputFrame {
            task,
            frame: value.clone(),
        })
    }

    fn require_task_binding(
        &self,
        identity: Option<&wire::CommandIdentity>,
    ) -> Result<(), AgentError> {
        let capability = self
            .active_contract
            .as_ref()
            .and_then(|contract| {
                contract
                    .allowed_capabilities
                    .iter()
                    .find(|value| **value >= 4)
            })
            .copied()
            .ok_or_else(|| AgentError::new("task.capability_denied", "physical input is denied"))?;
        self.require_capability(identity, capability)
    }
}

fn canonical_keys(keys: &[wire::PhysicalKey]) -> bool {
    keys.iter().all(|key| (1..=255).contains(&key.scan_code))
        && keys.windows(2).all(|pair| {
            (pair[0].scan_code, pair[0].extended) < (pair[1].scan_code, pair[1].extended)
        })
}

fn canonical_buttons(buttons: &[i32]) -> bool {
    buttons.iter().all(|button| {
        wire::MouseButton::try_from(*button)
            .is_ok_and(|button| button != wire::MouseButton::Unspecified)
    }) && buttons.windows(2).all(|pair| pair[0] < pair[1])
}

fn dangerous_keys(keys: &[wire::PhysicalKey]) -> bool {
    let has = |scan_code, extended| {
        keys.iter()
            .any(|key| key.scan_code == scan_code && key.extended == extended)
    };
    has(0x5b, true) || has(0x5c, true) || (has(0x1d, false) && has(0x38, false) && has(0x53, true))
}

fn session_command(
    identity: Option<&wire::CommandIdentity>,
) -> Result<Option<internal::CommandRef>, AgentError> {
    match identity.and_then(|identity| identity.value.as_ref()) {
        Some(command_identity::Value::Command(command)) => Ok(Some(internal_command(command))),
        _ => Err(reference_invalid()),
    }
}

fn task_command(
    identity: Option<&wire::CommandIdentity>,
) -> Result<Option<internal::TaskCommandRef>, AgentError> {
    match identity.and_then(|identity| identity.value.as_ref()) {
        Some(command_identity::Value::Task(task)) => Ok(Some(internal_task(task)?)),
        _ => Err(reference_invalid()),
    }
}

fn wire_task(
    identity: Option<&wire::CommandIdentity>,
) -> Result<&wire::TaskCommandRef, AgentError> {
    match identity.and_then(|identity| identity.value.as_ref()) {
        Some(command_identity::Value::Task(task)) => Ok(task),
        _ => Err(reference_invalid()),
    }
}

fn either_command(
    identity: Option<&wire::CommandIdentity>,
) -> Result<
    (
        Option<internal::CommandRef>,
        Option<internal::TaskCommandRef>,
    ),
    AgentError,
> {
    match identity.and_then(|identity| identity.value.as_ref()) {
        Some(command_identity::Value::Command(command)) => {
            Ok((Some(internal_command(command)), None))
        }
        Some(command_identity::Value::Task(task)) => Ok((None, Some(internal_task(task)?))),
        None => Err(reference_invalid()),
    }
}

fn internal_command(command: &wire::CommandRef) -> internal::CommandRef {
    internal::CommandRef {
        session: command
            .session
            .as_ref()
            .map(|session| internal::SessionRef {
                agent_id: session.agent_id.clone(),
                session_id: session.session_id.clone(),
                generation: session.generation,
            }),
        command_id: command.command_id.clone(),
        sequence: command.sequence,
        expires_at_unix_ms: command.expires_at_unix_ms,
    }
}

fn internal_task(task: &wire::TaskCommandRef) -> Result<internal::TaskCommandRef, AgentError> {
    let attempt = task.attempt.as_ref().ok_or_else(reference_invalid)?;
    Ok(internal::TaskCommandRef {
        command: task.command.as_ref().map(internal_command),
        attempt: Some(internal::AttemptRef {
            task_run_id: attempt.task_run_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            contract_version: attempt.contract_version,
            contract_digest: attempt.contract_digest.clone(),
        }),
        payload_digest: task.payload_digest.clone(),
    })
}

pub fn result(
    reference: wire::CommandIdentity,
    outcome: CommandOutcome,
) -> wire::AgentControlEvent {
    let result = match outcome {
        CommandOutcome::Ack(_) => wire::CommandResult {
            reference: Some(reference),
            outcome: wire::CommandOutcome::Applied as i32,
            ..wire::CommandResult::default()
        },
        CommandOutcome::CloseAck(receipt) => wire::CommandResult {
            reference: Some(reference),
            outcome: wire::CommandOutcome::Applied as i32,
            close_receipt: Some(receipt),
            ..wire::CommandResult::default()
        },
        CommandOutcome::CloseNack { receipt, code, .. } => {
            let mut result = error_result(reference, &code);
            result.close_receipt = Some(receipt);
            result
        }
        CommandOutcome::Nack { code, .. } => error_result(reference, &code),
        CommandOutcome::TaskAck {
            outcome, receipt, ..
        } => task_result(reference, outcome, *receipt),
    };
    wire::AgentControlEvent {
        payload: Some(wire::agent_control_event::Payload::CommandResult(result)),
    }
}

pub fn error(reference: wire::CommandIdentity, error: &AgentError) -> wire::AgentControlEvent {
    wire::AgentControlEvent {
        payload: Some(wire::agent_control_event::Payload::CommandResult(
            error_result(reference, error.code()),
        )),
    }
}

pub fn safety_event(
    event: internal::AgentControlEvent,
) -> Result<wire::AgentControlEvent, AgentError> {
    let Some(internal::agent_control_event::Payload::SafetyEvent(event)) = event.payload else {
        return Err(AgentError::new(
            "runtime.safety_event_invalid",
            "internal safety event has the wrong payload",
        ));
    };
    Ok(wire::AgentControlEvent {
        payload: Some(wire::agent_control_event::Payload::SafetyEvent(
            wire::SafetyEvent {
                session: event.session.map(|session| wire::SessionRef {
                    agent_id: session.agent_id,
                    session_id: session.session_id,
                    generation: session.generation,
                }),
                reason_code: event.reason,
                state: wire::AgentRuntimeState::RecoveryBlocked as i32,
                attempt: event.attempt.map(|attempt| wire::AttemptRef {
                    task_run_id: attempt.task_run_id,
                    attempt_id: attempt.attempt_id,
                    contract_version: attempt.contract_version,
                    contract_digest: attempt.contract_digest,
                }),
                attempt_receipt: None,
            },
        )),
    })
}

fn error_result(reference: wire::CommandIdentity, code: &str) -> wire::CommandResult {
    let receipt = match reference.value.as_ref() {
        Some(command_identity::Value::Task(task)) => Some(empty_receipt(task.clone(), code)),
        _ => None,
    };
    wire::CommandResult {
        reference: Some(reference),
        outcome: wire::CommandOutcome::NotApplied as i32,
        attempt_receipt: receipt,
        error_code: Some(code.to_owned()),
        ..wire::CommandResult::default()
    }
}

fn task_result(
    reference: wire::CommandIdentity,
    outcome: Option<internal::TaskCommandOutcomeV1>,
    receipt: internal::TaskAttemptReceiptV1,
) -> wire::CommandResult {
    let task = match reference.value.as_ref() {
        Some(command_identity::Value::Task(task)) => task.clone(),
        _ => return error_result(reference, "command.identity_invalid"),
    };
    let (mapped_outcome, source_frame_sequence, error_code) = match outcome {
        Some(outcome) => (
            map_outcome(outcome.outcome),
            outcome.source_frame_sequence,
            outcome.error_code,
        ),
        None => (wire::CommandOutcome::Applied as i32, None, None),
    };
    wire::CommandResult {
        reference: Some(reference),
        outcome: mapped_outcome,
        source_frame_sequence,
        attempt_receipt: Some(map_receipt(
            receipt,
            task.clone(),
            mapped_outcome,
            source_frame_sequence,
        )),
        error_code,
        close_receipt: None,
    }
}

fn map_receipt(
    receipt: internal::TaskAttemptReceiptV1,
    incoming: wire::TaskCommandRef,
    last_command_outcome: i32,
    last_command_source_frame_sequence: Option<u64>,
) -> wire::AttemptReceipt {
    let command = incoming.command.as_ref().map(|command| wire::CommandRef {
        session: command.session.as_ref().map(|session| wire::SessionRef {
            agent_id: session.agent_id.clone(),
            session_id: session.session_id.clone(),
            generation: receipt.last_command_generation,
        }),
        command_id: receipt.last_command_id.clone(),
        sequence: receipt.last_command_sequence,
        expires_at_unix_ms: command.expires_at_unix_ms,
    });
    let last_command = wire::TaskCommandRef {
        command,
        attempt: receipt.attempt.as_ref().map(|attempt| wire::AttemptRef {
            task_run_id: attempt.task_run_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            contract_version: attempt.contract_version,
            contract_digest: attempt.contract_digest.clone(),
        }),
        payload_digest: receipt.last_command_payload_digest.clone(),
    };
    wire::AttemptReceipt {
        receipt_version: receipt.receipt_version,
        attempt: receipt.attempt.map(|attempt| wire::AttemptRef {
            task_run_id: attempt.task_run_id,
            attempt_id: attempt.attempt_id,
            contract_version: attempt.contract_version,
            contract_digest: attempt.contract_digest,
        }),
        attempt_state: receipt.attempt_state,
        last_command: Some(last_command),
        last_command_outcome,
        last_command_source_frame_sequence,
        side_effect_state: receipt.side_effect_state,
        last_side_effect_command_id: receipt.last_side_effect_command_id,
        input_state: receipt.input_state,
        capture_state: receipt.capture_state,
        managed_target_state: receipt.owned_target_state,
        cleanup_complete: receipt.cleanup_complete,
        error_code: receipt.error_code,
    }
}

fn map_outcome(value: i32) -> i32 {
    match internal::TaskCommandOutcomeState::try_from(value) {
        Ok(internal::TaskCommandOutcomeState::Applied) => wire::CommandOutcome::Applied as i32,
        Ok(internal::TaskCommandOutcomeState::NotApplied) => {
            wire::CommandOutcome::NotApplied as i32
        }
        Ok(internal::TaskCommandOutcomeState::Uncertain) => wire::CommandOutcome::Uncertain as i32,
        _ => wire::CommandOutcome::Unspecified as i32,
    }
}

fn empty_receipt(task: wire::TaskCommandRef, code: &str) -> wire::AttemptReceipt {
    wire::AttemptReceipt {
        receipt_version: 1,
        attempt: task.attempt.clone(),
        attempt_state: wire::AttemptState::NotFound as i32,
        last_command: Some(task),
        last_command_outcome: wire::CommandOutcome::NotApplied as i32,
        side_effect_state: wire::SideEffectState::NotApplied as i32,
        input_state: wire::InputState::Released as i32,
        capture_state: wire::CaptureState::NotStarted as i32,
        managed_target_state: wire::ManagedTargetState::NotStarted as i32,
        cleanup_complete: Some(false),
        error_code: Some(code.to_owned()),
        ..wire::AttemptReceipt::default()
    }
}

fn reference_invalid() -> AgentError {
    AgentError::new(
        "command.identity_invalid",
        "v2 command identity does not match the command kind",
    )
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn manual_close_failure_keeps_typed_receipt_on_not_applied_result() {
        let identity = wire::CommandIdentity {
            value: Some(command_identity::Value::Command(wire::CommandRef {
                session: Some(wire::SessionRef {
                    agent_id: "11111111-1111-4111-8111-111111111111".into(),
                    session_id: "session-1".into(),
                    generation: 1,
                }),
                command_id: "close-1".into(),
                sequence: 1,
                expires_at_unix_ms: 1_700_000_000_000,
            })),
        };
        let receipt = wire::ManagedGameCloseReceipt {
            game_session_id: "33333333-3333-4333-8333-333333333333".into(),
            state_version: 4,
            trigger: wire::ManagedGameCloseTrigger::Manual as i32,
            result: wire::ManagedGameCloseResult::Failed as i32,
            occurred_at_unix_ms: 1_700_000_000_000,
            error_code: Some("target.close_failed".into()),
        };

        let event = result(
            identity,
            CommandOutcome::CloseNack {
                receipt: receipt.clone(),
                code: "target.close_failed".into(),
                message: "close failed".into(),
            },
        );
        let command_result = match event.payload.unwrap() {
            wire::agent_control_event::Payload::CommandResult(value) => value,
            other => panic!("unexpected payload: {other:?}"),
        };

        assert_eq!(
            command_result.outcome,
            wire::CommandOutcome::NotApplied as i32
        );
        assert_eq!(
            command_result.error_code.as_deref(),
            Some("target.close_failed")
        );
        assert_eq!(command_result.close_receipt, Some(receipt));
    }

    fn task_identity(contract: &wire::ExecutionContract, sequence: u64) -> wire::CommandIdentity {
        wire::CommandIdentity {
            value: Some(command_identity::Value::Task(wire::TaskCommandRef {
                command: Some(wire::CommandRef {
                    session: Some(wire::SessionRef {
                        agent_id: "11111111-1111-4111-8111-111111111111".into(),
                        session_id: "session-1".into(),
                        generation: 1,
                    }),
                    command_id: format!("command-{sequence}"),
                    sequence,
                    expires_at_unix_ms: contract.deadline_unix_ms,
                }),
                attempt: Some(wire::AttemptRef {
                    task_run_id: contract.task_run_id.clone(),
                    attempt_id: contract.attempt_id.clone(),
                    contract_version: contract.contract_version,
                    contract_digest: contract.contract_digest.clone(),
                }),
                payload_digest: "c".repeat(64),
            })),
        }
    }

    fn contract(capabilities: Vec<i32>) -> wire::ExecutionContract {
        let mut contract = wire::ExecutionContract {
            task_run_id: "11111111-1111-4111-8111-111111111111".into(),
            attempt_id: "22222222-2222-4222-8222-222222222222".into(),
            agent_build_id: "build-test".into(),
            profile_id: "genshin-impact".into(),
            profile_digest: "b".repeat(64),
            allowed_capabilities: capabilities,
            deadline_unix_ms: i64::MAX,
            max_input_lease_ms: 500,
            cleanup_policy: wire::CleanupPolicy::ReleaseInputKeepManagedTarget as i32,
            contract_version: 2,
            contract_digest: String::new(),
        };
        let canonical = fairypam_agent_protocol::canonical_execution_contract(&contract).unwrap();
        contract.contract_digest = format!("{:x}", Sha256::digest(canonical));
        contract
    }

    fn with_digest(mut command: wire::HubControlCommand) -> wire::HubControlCommand {
        let (identity, kind, payload) = match command.payload.as_ref().unwrap() {
            hub_control_command::Payload::BeginAttempt(value) => (
                value.reference.as_ref().unwrap(),
                "BeginAttempt",
                serde_json::json!({"contract": {
                    "agent_build_id": value.contract.as_ref().unwrap().agent_build_id,
                    "allowed_capabilities": value.contract.as_ref().unwrap().allowed_capabilities,
                    "attempt_id": value.contract.as_ref().unwrap().attempt_id,
                    "cleanup_policy": value.contract.as_ref().unwrap().cleanup_policy,
                    "contract_digest": value.contract.as_ref().unwrap().contract_digest,
                    "contract_version": value.contract.as_ref().unwrap().contract_version,
                    "deadline_unix_ms": value.contract.as_ref().unwrap().deadline_unix_ms,
                    "max_input_lease_ms": value.contract.as_ref().unwrap().max_input_lease_ms,
                    "profile_digest": value.contract.as_ref().unwrap().profile_digest,
                    "profile_id": value.contract.as_ref().unwrap().profile_id,
                    "task_run_id": value.contract.as_ref().unwrap().task_run_id,
                }}),
            ),
            hub_control_command::Payload::InputFrame(value) => {
                let mut payload = serde_json::json!({
                    "held_keys": value.held_keys.iter().map(|key| serde_json::json!({"extended": key.extended, "scan_code": key.scan_code})).collect::<Vec<_>>(),
                    "held_mouse_buttons": value.held_mouse_buttons,
                    "input_sequence": value.input_sequence,
                    "lease_ms": value.lease_ms,
                    "wheel_delta": value.wheel_delta,
                });
                if let Some(sequence) = value.source_frame_sequence {
                    payload["source_frame_sequence"] = sequence.into();
                }
                if let Some(x_ppm) = value.wheel_x_ppm {
                    payload["wheel_x_ppm"] = x_ppm.into();
                }
                if let Some(y_ppm) = value.wheel_y_ppm {
                    payload["wheel_y_ppm"] = y_ppm.into();
                }
                (value.reference.as_ref().unwrap(), "InputFrame", payload)
            }
            hub_control_command::Payload::ClientPointClick(value) => (
                value.reference.as_ref().unwrap(),
                "ClientPointClick",
                serde_json::json!({
                    "button": value.button,
                    "input_sequence": value.input_sequence,
                    "lease_ms": value.lease_ms,
                    "source_frame_sequence": value.source_frame_sequence,
                    "x_ppm": value.x_ppm,
                    "y_ppm": value.y_ppm,
                }),
            ),
            hub_control_command::Payload::StartCapture(value) => (
                value.reference.as_ref().unwrap(),
                "StartCapture",
                serde_json::json!({
                    "capture_source_id": value.capture_source_id,
                    "encoding": value.encoding,
                    "fps": value.fps,
                    "quality": value.quality,
                }),
            ),
            hub_control_command::Payload::CaptureFrame(value) => (
                value.reference.as_ref().unwrap(),
                "CaptureFrame",
                serde_json::json!({
                    "capture_source_id": value.capture_source_id,
                    "encoding": value.encoding,
                    "quality": value.quality,
                }),
            ),
            _ => unreachable!(),
        };
        let task = wire_task(Some(identity)).unwrap();
        let attempt = task.attempt.as_ref().unwrap();
        let digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&serde_json::json!({
                    "attempt": {
                        "attempt_id": attempt.attempt_id,
                        "contract_digest": attempt.contract_digest,
                        "contract_version": attempt.contract_version,
                        "task_run_id": attempt.task_run_id,
                    },
                    "kind": format!("fairypam.agent.v2.{kind}"),
                    "payload": payload,
                }))
                .unwrap()
            )
        );
        let identity = match command.payload.as_mut().unwrap() {
            hub_control_command::Payload::BeginAttempt(value) => value.reference.as_mut().unwrap(),
            hub_control_command::Payload::InputFrame(value) => value.reference.as_mut().unwrap(),
            hub_control_command::Payload::ClientPointClick(value) => {
                value.reference.as_mut().unwrap()
            }
            hub_control_command::Payload::StartCapture(value) => value.reference.as_mut().unwrap(),
            hub_control_command::Payload::CaptureFrame(value) => value.reference.as_mut().unwrap(),
            _ => unreachable!(),
        };
        match identity.value.as_mut().unwrap() {
            command_identity::Value::Task(task) => task.payload_digest = digest,
            command_identity::Value::Command(_) => unreachable!(),
        }
        command
    }

    fn accept_begin(translator: &mut Translator, contract: &wire::ExecutionContract) {
        let TranslatedCommand::BeginAttempt {
            contract,
            digest_key,
            payload_digest,
            ..
        } = translator
            .translate(&with_digest(wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::BeginAttempt(
                    wire::BeginAttempt {
                        reference: Some(task_identity(contract, 1)),
                        contract: Some(contract.clone()),
                    },
                )),
            }))
            .unwrap()
        else {
            unreachable!()
        };
        translator.accept_begin(contract, digest_key, payload_digest);
    }

    #[test]
    fn historical_digest_conflict_event_matches_the_shared_backend_contract() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../proto/fairypam/agent/v2/testdata/historical-digest-conflict.json"
        ))
        .unwrap();
        let contract = contract(vec![1]);
        let mut identity = task_identity(&contract, vector["sequence"].as_u64().unwrap());
        let command_identity::Value::Task(task) = identity.value.as_mut().unwrap() else {
            unreachable!()
        };
        task.command.as_mut().unwrap().command_id = vector["command_id"].as_str().unwrap().into();
        task.payload_digest = vector["incoming_payload_digest"].as_str().unwrap().into();
        let attempt = task.attempt.clone().unwrap();
        let event = result(
            identity.clone(),
            CommandOutcome::TaskAck {
                result: "{}".into(),
                outcome: Some(internal::TaskCommandOutcomeV1 {
                    attempt: Some(internal::AttemptRef {
                        task_run_id: attempt.task_run_id.clone(),
                        attempt_id: attempt.attempt_id.clone(),
                        contract_version: attempt.contract_version,
                        contract_digest: attempt.contract_digest.clone(),
                    }),
                    command_id: vector["command_id"].as_str().unwrap().into(),
                    payload_digest: vector["incoming_payload_digest"].as_str().unwrap().into(),
                    outcome: internal::TaskCommandOutcomeState::Uncertain as i32,
                    source_frame_sequence: None,
                    error_code: Some(vector["error_code"].as_str().unwrap().into()),
                }),
                receipt: Box::new(internal::TaskAttemptReceiptV1 {
                    receipt_version: 1,
                    attempt: Some(internal::AttemptRef {
                        task_run_id: attempt.task_run_id,
                        attempt_id: attempt.attempt_id,
                        contract_version: attempt.contract_version,
                        contract_digest: attempt.contract_digest,
                    }),
                    attempt_state: internal::TaskAttemptState::Active as i32,
                    last_command_id: vector["command_id"].as_str().unwrap().into(),
                    last_command_sequence: vector["sequence"].as_u64().unwrap(),
                    last_command_generation: 1,
                    last_command_payload_digest: vector["stored_payload_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    side_effect_state: internal::TaskSideEffectState::Uncertain as i32,
                    input_state: internal::TaskInputState::Released as i32,
                    capture_state: internal::TaskCaptureState::Stopped as i32,
                    owned_target_state: internal::TaskOwnedTargetState::Running as i32,
                    cleanup_complete: Some(false),
                    error_code: Some(vector["error_code"].as_str().unwrap().into()),
                    ..internal::TaskAttemptReceiptV1::default()
                }),
                local_diagnostic: None,
            },
        );
        let wire::agent_control_event::Payload::CommandResult(result) = event.payload.unwrap()
        else {
            unreachable!()
        };
        assert_eq!(result.reference, Some(identity));
        assert_eq!(result.outcome, wire::CommandOutcome::Uncertain as i32);
        assert_eq!(
            result
                .attempt_receipt
                .unwrap()
                .last_command
                .unwrap()
                .payload_digest,
            vector["stored_payload_digest"].as_str().unwrap()
        );
    }

    #[test]
    fn input_frame_rejects_noncanonical_keys() {
        let frame = wire::InputFrame {
            input_sequence: 1,
            lease_ms: 100,
            held_keys: vec![
                wire::PhysicalKey {
                    scan_code: 44,
                    extended: false,
                },
                wire::PhysicalKey {
                    scan_code: 17,
                    extended: false,
                },
            ],
            ..wire::InputFrame::default()
        };

        assert!(!canonical_keys(&frame.held_keys));
    }

    #[test]
    fn translator_enforces_contract_capability_and_hub_lease_limit() {
        let contract = contract(vec![1, 2, 3, 4]);
        let mut translator = Translator::new(100);
        accept_begin(&mut translator, &contract);
        let error = translator
            .translate(&with_digest(wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::InputFrame(wire::InputFrame {
                    reference: Some(task_identity(&contract, 2)),
                    input_sequence: 1,
                    lease_ms: 101,
                    ..wire::InputFrame::default()
                })),
            }))
            .unwrap_err();

        assert_eq!(error.code(), "input.frame_invalid");
    }

    #[test]
    fn translator_preserves_canonical_physical_input_frame() {
        let contract = contract(vec![1, 2, 3, 4, 5, 6]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &contract);
        let command = with_digest(wire::HubControlCommand {
            payload: Some(hub_control_command::Payload::InputFrame(wire::InputFrame {
                reference: Some(task_identity(&contract, 2)),
                input_sequence: 1,
                lease_ms: 250,
                held_keys: vec![wire::PhysicalKey {
                    scan_code: 17,
                    extended: false,
                }],
                held_mouse_buttons: vec![wire::MouseButton::Left as i32],
                wheel_delta: 1200,
                source_frame_sequence: Some(7),
                wheel_x_ppm: Some(500_000),
                wheel_y_ppm: Some(500_000),
            })),
        });

        let TranslatedCommand::InputFrame { frame, .. } = translator.translate(&command).unwrap()
        else {
            panic!("InputFrame was not preserved");
        };
        assert_eq!(frame.input_sequence, 1);
        assert_eq!(frame.held_keys[0].scan_code, 17);
        assert_eq!(frame.held_mouse_buttons, [wire::MouseButton::Left as i32]);
        assert_eq!(frame.wheel_delta, 1200);
        assert_eq!(frame.source_frame_sequence, Some(7));
        assert_eq!(frame.wheel_x_ppm, Some(500_000));
        assert_eq!(frame.wheel_y_ppm, Some(500_000));
    }

    #[test]
    fn translator_rejects_invalid_wheel_points() {
        for (wheel_delta, wheel_x_ppm, wheel_y_ppm) in [
            (-1200, Some(500_000), None),
            (0, Some(500_000), Some(500_000)),
            (-1200, Some(1_000_001), Some(500_000)),
            (-1200, Some(500_000), Some(1_000_001)),
        ] {
            let contract = contract(vec![1, 2, 3, 6]);
            let mut translator = Translator::new(500);
            accept_begin(&mut translator, &contract);
            let command = with_digest(wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::InputFrame(wire::InputFrame {
                    reference: Some(task_identity(&contract, 2)),
                    input_sequence: 1,
                    lease_ms: 250,
                    wheel_delta,
                    source_frame_sequence: Some(7),
                    wheel_x_ppm,
                    wheel_y_ppm,
                    ..wire::InputFrame::default()
                })),
            });

            assert_eq!(
                translator.translate(&command).unwrap_err().code(),
                "input.frame_invalid"
            );
        }
    }

    #[test]
    fn translator_preserves_the_typed_client_point_click() {
        let contract = contract(vec![1, 2, 3, 5]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &contract);
        let command = with_digest(wire::HubControlCommand {
            payload: Some(hub_control_command::Payload::ClientPointClick(
                wire::ClientPointClick {
                    reference: Some(task_identity(&contract, 2)),
                    input_sequence: 1,
                    lease_ms: 250,
                    button: wire::MouseButton::Left as i32,
                    x_ppm: 500_000,
                    y_ppm: 583_333,
                    source_frame_sequence: 7,
                },
            )),
        });

        let TranslatedCommand::ClientPointClick { value, .. } =
            translator.translate(&command).unwrap()
        else {
            panic!("ClientPointClick was not preserved");
        };
        assert_eq!(value.x_ppm, 500_000);
        assert_eq!(value.source_frame_sequence, 7);
    }

    #[test]
    fn translator_rejects_unapproved_or_unbound_client_point_click() {
        let contract_without_mouse = contract(vec![1, 2, 3]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &contract_without_mouse);
        let error = translator
            .translate(&with_digest(wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::ClientPointClick(
                    wire::ClientPointClick {
                        reference: Some(task_identity(&contract_without_mouse, 2)),
                        input_sequence: 1,
                        lease_ms: 250,
                        button: wire::MouseButton::Left as i32,
                        x_ppm: 500_000,
                        y_ppm: 583_333,
                        source_frame_sequence: 7,
                    },
                )),
            }))
            .unwrap_err();
        assert_eq!(error.code(), "task.capability_denied");

        let contract = contract(vec![1, 2, 3, 5]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &contract);
        let error = translator
            .translate(&with_digest(wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::ClientPointClick(
                    wire::ClientPointClick {
                        reference: Some(task_identity(&contract, 2)),
                        input_sequence: 1,
                        lease_ms: 250,
                        button: wire::MouseButton::Left as i32,
                        x_ppm: 500_000,
                        y_ppm: 583_333,
                        source_frame_sequence: 0,
                    },
                )),
            }))
            .unwrap_err();
        assert_eq!(error.code(), "input.frame_invalid");
    }

    #[test]
    fn translator_rejects_task_payload_digest_tampering() {
        let contract = contract(vec![1]);
        let error = Translator::new(500)
            .translate(&wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::BeginAttempt(
                    wire::BeginAttempt {
                        reference: Some(task_identity(&contract, 1)),
                        contract: Some(contract),
                    },
                )),
            })
            .unwrap_err();

        assert_eq!(error.code(), "command.payload_digest_conflict");
    }

    #[test]
    fn translator_rejects_capture_values_outside_v2_bounds() {
        let contract = contract(vec![1, 3]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &contract);

        for (sequence, source, encoding, fps, quality) in [
            (2, "", "jpeg", 1, 1),
            (3, "client", "png", 1, 1),
            (4, "client", "jpeg", 0, 1),
            (5, "client", "jpeg", 1, 0),
        ] {
            let error = translator
                .translate(&with_digest(wire::HubControlCommand {
                    payload: Some(hub_control_command::Payload::StartCapture(
                        wire::StartCapture {
                            reference: Some(task_identity(&contract, sequence)),
                            capture_source_id: source.into(),
                            encoding: encoding.into(),
                            fps,
                            quality,
                        },
                    )),
                }))
                .unwrap_err();
            assert_eq!(error.code(), "capture.command_invalid");
        }
    }

    #[test]
    fn translator_accepts_attempt_bound_single_frame_capture() {
        let contract = contract(vec![1, 3]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &contract);

        let translated = translator
            .translate(&with_digest(wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::CaptureFrame(
                    wire::CaptureFrame {
                        reference: Some(task_identity(&contract, 2)),
                        capture_source_id: "client".into(),
                        encoding: "jpeg".into(),
                        quality: 85,
                    },
                )),
            }))
            .unwrap();

        assert!(matches!(
            translated,
            TranslatedCommand::Internal(internal::HubControlCommand {
                payload: Some(internal::hub_control_command::Payload::CaptureFrame(
                    internal::CaptureFrame {
                        ref source_id,
                        ref encoding,
                        quality: 85,
                        task: Some(_),
                        ..
                    }
                ))
            }) if source_id == "client" && encoding == "jpeg"
        ));
    }

    #[test]
    fn translator_rejects_invalid_single_frame_capture() {
        let contract = contract(vec![1, 3]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &contract);

        for (sequence, source, encoding, quality) in [
            (2, "", "jpeg", 85),
            (3, "client", "png", 85),
            (4, "client", "jpeg", 0),
            (5, "client", "jpeg", 101),
        ] {
            let error = translator
                .translate(&with_digest(wire::HubControlCommand {
                    payload: Some(hub_control_command::Payload::CaptureFrame(
                        wire::CaptureFrame {
                            reference: Some(task_identity(&contract, sequence)),
                            capture_source_id: source.into(),
                            encoding: encoding.into(),
                            quality,
                        },
                    )),
                }))
                .unwrap_err();
            assert_eq!(error.code(), "capture.command_invalid");
        }
    }

    #[test]
    fn command_digest_deduplication_is_scoped_to_the_attempt() {
        let first = contract(vec![1]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &first);

        let mut second = contract(vec![1]);
        second.attempt_id = "33333333-3333-4333-8333-333333333333".into();
        second.contract_digest = String::new();
        second.contract_digest = format!(
            "{:x}",
            Sha256::digest(fairypam_agent_protocol::canonical_execution_contract(&second).unwrap())
        );
        accept_begin(&mut translator, &second);

        assert_eq!(translator.task_digests.len(), 1);
        assert!(translator
            .task_digests
            .keys()
            .all(|(attempt_id, _)| attempt_id == &second.attempt_id));
    }

    #[test]
    fn rejected_begin_does_not_pollute_command_digest_state() {
        let valid = contract(vec![1]);
        let mut invalid = valid.clone();
        invalid.contract_digest = "0".repeat(64);
        let invalid_command = with_digest(wire::HubControlCommand {
            payload: Some(hub_control_command::Payload::BeginAttempt(
                wire::BeginAttempt {
                    reference: Some(task_identity(&invalid, 1)),
                    contract: Some(invalid),
                },
            )),
        });
        let mut translator = Translator::new(500);
        assert_eq!(
            translator.translate(&invalid_command).unwrap_err().code(),
            "task.contract_mismatch"
        );
        assert!(translator.task_digests.is_empty());

        accept_begin(&mut translator, &valid);
    }

    #[test]
    fn unaccepted_valid_begin_keeps_the_active_attempt_unchanged() {
        let active = contract(vec![1, 4]);
        let mut translator = Translator::new(500);
        accept_begin(&mut translator, &active);

        let mut conflicting = contract(vec![1, 4]);
        conflicting.attempt_id = "44444444-4444-4444-8444-444444444444".into();
        conflicting.contract_digest = String::new();
        conflicting.contract_digest = format!(
            "{:x}",
            Sha256::digest(
                fairypam_agent_protocol::canonical_execution_contract(&conflicting).unwrap()
            )
        );
        assert!(matches!(
            translator
                .translate(&with_digest(wire::HubControlCommand {
                    payload: Some(hub_control_command::Payload::BeginAttempt(
                        wire::BeginAttempt {
                            reference: Some(task_identity(&conflicting, 1)),
                            contract: Some(conflicting),
                        },
                    )),
                }))
                .unwrap(),
            TranslatedCommand::BeginAttempt { .. }
        ));

        assert!(translator
            .translate(&with_digest(wire::HubControlCommand {
                payload: Some(hub_control_command::Payload::InputFrame(wire::InputFrame {
                    reference: Some(task_identity(&active, 2)),
                    input_sequence: 1,
                    lease_ms: 100,
                    ..wire::InputFrame::default()
                })),
            }))
            .is_ok());
        assert_eq!(
            translator.active_contract.as_ref().unwrap().attempt_id,
            active.attempt_id
        );
        assert!(translator
            .task_digests
            .keys()
            .all(|(attempt_id, _)| attempt_id == &active.attempt_id));
    }
}
