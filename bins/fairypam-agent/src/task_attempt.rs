use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use fairypam_agent_core::target::TargetBinding;
use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v1::{
    AgentAttemptContractV1, AttemptRef, TaskAttemptReceiptV1, TaskAttemptState, TaskCaptureState,
    TaskCommandOutcomeState, TaskCommandOutcomeV1, TaskCommandRef, TaskInputState,
    TaskOwnedTargetState, TaskSideEffectState,
};
use fairypam_agent_protocol::verify_agent_attempt_contract;
use serde::{Deserialize, Serialize};

const RECEIPT_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 64 * 1024;

pub struct TaskAttemptRuntime {
    root: Option<PathBuf>,
    active: Option<AttemptState>,
    loaded: bool,
}

pub struct TaskCommandResult {
    pub outcome: TaskCommandOutcomeV1,
    pub receipt: TaskAttemptReceiptV1,
}

impl TaskAttemptRuntime {
    pub fn production() -> Self {
        Self {
            root: production_root(),
            active: None,
            loaded: false,
        }
    }

    pub fn memory() -> Self {
        Self {
            root: None,
            active: None,
            loaded: true,
        }
    }

    #[cfg(test)]
    fn at(root: PathBuf) -> Self {
        Self {
            root: Some(root),
            active: None,
            loaded: false,
        }
    }

    pub fn begin(
        &mut self,
        task: &TaskCommandRef,
        contract: &AgentAttemptContractV1,
    ) -> Result<TaskAttemptReceiptV1, AgentError> {
        verify_agent_attempt_contract(contract)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        let (reference, command) = validate_task(task)?;
        validate_contract_reference(reference, contract)?;
        self.load_active()?;

        if self.active.as_ref().is_some_and(|active| {
            active.attempt_state == TaskAttemptState::Terminal as i32 && active.cleanup_complete
        }) {
            self.active = None;
        }

        if let Some(active) = self.active.as_ref() {
            active.require_reference(reference)?;
            active
                .require_same_command(command.command_id.as_str(), task.payload_digest.as_str())?;
            return Ok(active.receipt());
        }

        let state = AttemptState::claimed(contract.clone(), reference.clone(), task)?;
        self.persist(&state)?;
        let receipt = state.receipt();
        self.active = Some(state);
        Ok(receipt)
    }

    pub fn inspect(&mut self, task: &TaskCommandRef) -> Result<TaskAttemptReceiptV1, AgentError> {
        let (reference, command) = validate_task(task)?;
        self.load_active()?;
        let Some(mut active) = self.active.take() else {
            let Some(mut terminal) = self.load_named(reference)? else {
                return Ok(not_found_receipt());
            };
            terminal.require_reference(reference)?;
            terminal.record_command(command, &task.payload_digest)?;
            self.persist(&terminal)?;
            return Ok(terminal.receipt());
        };
        if let Err(error) = active.require_reference(reference) {
            self.active = Some(active);
            return Err(error);
        }
        active.record_command(command, &task.payload_digest)?;
        if let Err(error) = self.persist(&active) {
            self.active = Some(active);
            return Err(error);
        }
        let receipt = active.receipt();
        self.active = Some(active);
        Ok(receipt)
    }

    fn load_named(&self, reference: &AttemptRef) -> Result<Option<AttemptState>, AgentError> {
        let Some(root) = self.root.as_ref() else {
            return Ok(None);
        };
        let path = root.join(format!("{}.jsonl", reference.attempt_id));
        match load_last(&path) {
            Ok(state) => Ok(Some(state)),
            Err(error) if error.code() == "task.ledger_not_found" => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn is_active(&mut self) -> Result<bool, AgentError> {
        self.load_active()?;
        Ok(self.active.as_ref().is_some_and(|active| {
            active.attempt_state != TaskAttemptState::Terminal as i32 || !active.cleanup_complete
        }))
    }

    pub fn profile_id(&mut self, task: &TaskCommandRef) -> Result<String, AgentError> {
        let active = self.require_active(task)?;
        Ok(active.contract.profile_id.clone())
    }

    pub fn attempt_ref(&mut self, task: &TaskCommandRef) -> Result<AttemptRef, AgentError> {
        Ok(self.require_active(task)?.reference.message())
    }

    pub fn owned_target(
        &mut self,
        task: &TaskCommandRef,
    ) -> Result<Option<TargetBinding>, AgentError> {
        Ok(self.require_active(task)?.owned_target.clone())
    }

    pub fn prepare(
        &mut self,
        task: &TaskCommandRef,
        side_effect: bool,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        self.prepare_inner(task, side_effect, false)
    }

    pub fn prepare_finish(
        &mut self,
        task: &TaskCommandRef,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        self.prepare_inner(task, false, true)
    }

    fn prepare_inner(
        &mut self,
        task: &TaskCommandRef,
        side_effect: bool,
        allow_uncertain: bool,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        let (reference, command) = validate_task(task)?;
        self.load_active()?;
        let Some(mut active) = self.active.take() else {
            return Err(attempt_not_found());
        };
        if let Err(error) = active.require_reference(reference) {
            self.active = Some(active);
            return Err(error);
        }
        if active.last_command_id == command.command_id {
            if let Err(error) =
                active.require_same_command(&command.command_id, &task.payload_digest)
            {
                self.active = Some(active);
                return Err(error);
            }
            if allow_uncertain
                && active.last_command_outcome == TaskCommandOutcomeState::Unspecified as i32
            {
                self.active = Some(active);
                return Ok(None);
            }
            if active.last_command_outcome == TaskCommandOutcomeState::Unspecified as i32 {
                let (outcome, error_code) = if side_effect
                    && active.side_effect_state == TaskSideEffectState::IntentRecorded as i32
                {
                    active.side_effect_state = TaskSideEffectState::Uncertain as i32;
                    (
                        TaskCommandOutcomeState::Uncertain,
                        "side_effect_uncertain",
                    )
                } else {
                    (
                        TaskCommandOutcomeState::NotApplied,
                        "command_interrupted",
                    )
                };
                active.last_command_outcome = outcome as i32;
                active.last_command_error_code = Some(error_code.into());
                active.error_code = Some(error_code.into());
                if let Err(error) = self.persist(&active) {
                    self.active = Some(active);
                    return Err(error);
                }
            }
            let result = active.command_result()?;
            self.active = Some(active);
            return Ok(Some(result));
        }
        if active.attempt_state == TaskAttemptState::Terminal as i32 {
            self.active = Some(active);
            return Err(AgentError::new(
                "attempt_terminal",
                "task attempt is already terminal",
            ));
        }
        if !allow_uncertain
            && matches!(
            TaskSideEffectState::try_from(active.side_effect_state),
            Ok(TaskSideEffectState::IntentRecorded | TaskSideEffectState::Uncertain)
        )
        {
            self.active = Some(active);
            return Err(AgentError::new(
                "side_effect_uncertain",
                "task attempt has an unresolved side effect",
            ));
        }
        if let Err(error) = active.record_command(command, &task.payload_digest) {
            self.active = Some(active);
            return Err(error);
        }
        active.last_command_outcome = TaskCommandOutcomeState::Unspecified as i32;
        active.last_command_source_frame_sequence = None;
        active.last_command_error_code = None;
        active.error_code = None;
        if side_effect {
            active.side_effect_state = TaskSideEffectState::IntentRecorded as i32;
            active
                .last_side_effect_command_id
                .clone_from(&command.command_id);
        }
        if let Err(error) = self.persist(&active) {
            self.active = Some(active);
            return Err(error);
        }
        self.active = Some(active);
        Ok(None)
    }

    pub fn complete_target_start(
        &mut self,
        task: &TaskCommandRef,
        binding: Option<TargetBinding>,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        let applied = binding.is_some();
        self.complete(
            task,
            if applied {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::NotApplied
            },
            None,
            error_code,
            true,
            |state| {
                state.owned_target = binding;
                state.owned_target_state = if applied {
                    TaskOwnedTargetState::Running as i32
                } else {
                    TaskOwnedTargetState::NotStarted as i32
                };
                if applied {
                    state.attempt_state = TaskAttemptState::TargetReady as i32;
                }
            },
        )
    }

    pub fn complete_capture(
        &mut self,
        task: &TaskCommandRef,
        running: bool,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        self.complete(
            task,
            if error_code.is_none() {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::NotApplied
            },
            None,
            error_code,
            false,
            |state| {
                if error_code.is_none() {
                    state.capture_state = if running {
                        TaskCaptureState::Running as i32
                    } else {
                        TaskCaptureState::Stopped as i32
                    };
                    if running {
                        state.attempt_state = TaskAttemptState::Active as i32;
                    }
                }
            },
        )
    }

    pub fn complete_input_lease(
        &mut self,
        task: &TaskCommandRef,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        self.complete(
            task,
            if error_code.is_none() {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::NotApplied
            },
            None,
            error_code,
            false,
            |state| {
                state.input_state = if error_code.is_none() {
                    TaskInputState::Active as i32
                } else {
                    TaskInputState::Released as i32
                };
            },
        )
    }

    pub fn complete_pulse(
        &mut self,
        task: &TaskCommandRef,
        source_frame_sequence: u64,
        applied: bool,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        self.complete(
            task,
            if applied {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::Uncertain
            },
            Some(source_frame_sequence),
            error_code,
            true,
            |_| {},
        )
    }

    pub fn complete_release(
        &mut self,
        task: &TaskCommandRef,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        self.complete(
            task,
            if error_code.is_none() {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::NotApplied
            },
            None,
            error_code,
            false,
            |state| {
                state.input_state = if error_code.is_none() {
                    TaskInputState::Released as i32
                } else {
                    TaskInputState::Unknown as i32
                };
            },
        )
    }

    pub fn complete_finish(
        &mut self,
        task: &TaskCommandRef,
        input_released: bool,
        capture_stopped: bool,
        target_closed: bool,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        let side_effect_resolved = !matches!(
            TaskSideEffectState::try_from(self.require_active(task)?.side_effect_state),
            Ok(TaskSideEffectState::IntentRecorded | TaskSideEffectState::Uncertain)
        );
        let cleanup_complete =
            input_released && capture_stopped && target_closed && side_effect_resolved;
        let derived_error = if !side_effect_resolved {
            Some("side_effect_uncertain")
        } else if !cleanup_complete {
            Some("cleanup_incomplete")
        } else {
            None
        };
        self.complete(
            task,
            if cleanup_complete {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::NotApplied
            },
            None,
            error_code.or(derived_error),
            false,
            |state| {
                state.attempt_state = TaskAttemptState::Terminal as i32;
                state.input_state = if input_released {
                    TaskInputState::Released as i32
                } else {
                    TaskInputState::Unknown as i32
                };
                state.capture_state = if capture_stopped {
                    TaskCaptureState::Stopped as i32
                } else {
                    TaskCaptureState::Unknown as i32
                };
                state.owned_target_state = if target_closed {
                    TaskOwnedTargetState::Closed as i32
                } else {
                    TaskOwnedTargetState::Unknown as i32
                };
                state.cleanup_complete = cleanup_complete;
                if target_closed {
                    state.owned_target = None;
                }
            },
        )
    }

    fn require_active(&mut self, task: &TaskCommandRef) -> Result<&AttemptState, AgentError> {
        let (reference, _) = validate_task(task)?;
        self.load_active()?;
        let active = self.active.as_ref().ok_or_else(attempt_not_found)?;
        active.require_reference(reference)?;
        Ok(active)
    }

    fn complete(
        &mut self,
        task: &TaskCommandRef,
        outcome: TaskCommandOutcomeState,
        source_frame_sequence: Option<u64>,
        error_code: Option<&str>,
        side_effect: bool,
        update: impl FnOnce(&mut AttemptState),
    ) -> Result<TaskCommandResult, AgentError> {
        let (_, command) = validate_task(task)?;
        let Some(mut active) = self.active.take() else {
            return Err(attempt_not_found());
        };
        if let Err(error) = active.require_same_command(&command.command_id, &task.payload_digest) {
            self.active = Some(active);
            return Err(error);
        }
        active.last_command_outcome = outcome as i32;
        active.last_command_source_frame_sequence = source_frame_sequence;
        active.last_command_error_code = error_code.map(str::to_owned);
        active.error_code = error_code.map(str::to_owned);
        if side_effect {
            active.side_effect_state = match outcome {
                TaskCommandOutcomeState::Applied => TaskSideEffectState::Applied,
                TaskCommandOutcomeState::NotApplied => TaskSideEffectState::NotApplied,
                TaskCommandOutcomeState::Uncertain | TaskCommandOutcomeState::Unspecified => {
                    TaskSideEffectState::Uncertain
                }
            } as i32;
        }
        update(&mut active);
        if let Err(error) = self.persist(&active) {
            self.active = Some(active);
            return Err(error);
        }
        let result = active.command_result()?;
        self.active = Some(active);
        Ok(result)
    }

    fn load_active(&mut self) -> Result<(), AgentError> {
        if self.loaded {
            return Ok(());
        }
        let Some(root) = self.root.as_ref() else {
            self.loaded = true;
            return Ok(());
        };
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.loaded = true;
                return Ok(());
            }
            Err(error) => return Err(io_error("task.ledger_unavailable", error)),
        };
        for entry in entries {
            let path = entry
                .map_err(|error| io_error("task.ledger_unavailable", error))?
                .path();
            if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
                continue;
            }
            let state = load_last(&path)?;
            if state.attempt_state == TaskAttemptState::Terminal as i32 && state.cleanup_complete {
                continue;
            }
            if self.active.replace(state).is_some() {
                return Err(AgentError::new(
                    "task.ledger_conflict",
                    "multiple non-terminal task attempts are persisted",
                ));
            }
        }
        self.loaded = true;
        Ok(())
    }

    fn persist(&self, state: &AttemptState) -> Result<(), AgentError> {
        let Some(root) = self.root.as_ref() else {
            return Ok(());
        };
        fs::create_dir_all(root).map_err(|error| io_error("task.ledger_unavailable", error))?;
        let path = root.join(format!("{}.jsonl", state.reference.attempt_id));
        let mut bytes = serde_json::to_vec(state).map_err(|error| {
            AgentError::new(
                "task.ledger_invalid",
                format!("cannot encode attempt ledger: {error}"),
            )
        })?;
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| io_error("task.ledger_unavailable", error))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| io_error("task.ledger_unavailable", error))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttemptState {
    contract: StoredContract,
    reference: StoredAttemptRef,
    attempt_state: i32,
    last_command_id: String,
    last_command_sequence: u64,
    last_command_generation: u64,
    last_command_payload_digest: String,
    #[serde(default)]
    last_command_outcome: i32,
    #[serde(default)]
    last_command_source_frame_sequence: Option<u64>,
    #[serde(default)]
    last_command_error_code: Option<String>,
    side_effect_state: i32,
    last_side_effect_command_id: String,
    input_state: i32,
    capture_state: i32,
    owned_target_state: i32,
    #[serde(default)]
    owned_target: Option<TargetBinding>,
    cleanup_complete: bool,
    error_code: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredContract {
    task_run_id: String,
    attempt_id: String,
    agent_build_id: String,
    profile_id: String,
    profile_digest: String,
    cleanup_policy: String,
    contract_version: u32,
    contract_digest: String,
}

impl StoredContract {
    fn message(&self) -> AgentAttemptContractV1 {
        AgentAttemptContractV1 {
            task_run_id: self.task_run_id.clone(),
            attempt_id: self.attempt_id.clone(),
            agent_build_id: self.agent_build_id.clone(),
            profile_id: self.profile_id.clone(),
            profile_digest: self.profile_digest.clone(),
            cleanup_policy: self.cleanup_policy.clone(),
            contract_version: self.contract_version,
            contract_digest: self.contract_digest.clone(),
        }
    }
}

impl From<&AgentAttemptContractV1> for StoredContract {
    fn from(contract: &AgentAttemptContractV1) -> Self {
        Self {
            task_run_id: contract.task_run_id.clone(),
            attempt_id: contract.attempt_id.clone(),
            agent_build_id: contract.agent_build_id.clone(),
            profile_id: contract.profile_id.clone(),
            profile_digest: contract.profile_digest.clone(),
            cleanup_policy: contract.cleanup_policy.clone(),
            contract_version: contract.contract_version,
            contract_digest: contract.contract_digest.clone(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredAttemptRef {
    task_run_id: String,
    attempt_id: String,
    contract_version: u32,
    contract_digest: String,
}

impl StoredAttemptRef {
    fn message(&self) -> AttemptRef {
        AttemptRef {
            task_run_id: self.task_run_id.clone(),
            attempt_id: self.attempt_id.clone(),
            contract_version: self.contract_version,
            contract_digest: self.contract_digest.clone(),
        }
    }
}

impl From<&AttemptRef> for StoredAttemptRef {
    fn from(reference: &AttemptRef) -> Self {
        Self {
            task_run_id: reference.task_run_id.clone(),
            attempt_id: reference.attempt_id.clone(),
            contract_version: reference.contract_version,
            contract_digest: reference.contract_digest.clone(),
        }
    }
}

impl AttemptState {
    fn claimed(
        contract: AgentAttemptContractV1,
        reference: AttemptRef,
        task: &TaskCommandRef,
    ) -> Result<Self, AgentError> {
        let command = task.command.as_ref().ok_or_else(task_ref_invalid)?;
        Ok(Self {
            contract: StoredContract::from(&contract),
            reference: StoredAttemptRef::from(&reference),
            attempt_state: TaskAttemptState::Claimed as i32,
            last_command_id: command.command_id.clone(),
            last_command_sequence: command.sequence,
            last_command_generation: command
                .session
                .as_ref()
                .map_or(0, |session| session.generation),
            last_command_payload_digest: task.payload_digest.clone(),
            last_command_outcome: TaskCommandOutcomeState::Unspecified as i32,
            last_command_source_frame_sequence: None,
            last_command_error_code: None,
            side_effect_state: TaskSideEffectState::None as i32,
            last_side_effect_command_id: String::new(),
            input_state: TaskInputState::Released as i32,
            capture_state: TaskCaptureState::NotStarted as i32,
            owned_target_state: TaskOwnedTargetState::NotStarted as i32,
            owned_target: None,
            cleanup_complete: false,
            error_code: None,
        })
    }

    fn require_reference(&self, reference: &AttemptRef) -> Result<(), AgentError> {
        if self.reference.task_run_id != reference.task_run_id
            || self.reference.attempt_id != reference.attempt_id
            || self.reference.contract_version != reference.contract_version
            || self.reference.contract_digest != reference.contract_digest
        {
            return Err(AgentError::new(
                "attempt_contract_mismatch",
                "task attempt reference does not match the persisted claim",
            ));
        }
        Ok(())
    }

    fn require_same_command(
        &self,
        command_id: &str,
        payload_digest: &str,
    ) -> Result<(), AgentError> {
        if self.last_command_id != command_id {
            return Err(AgentError::new(
                "attempt_already_claimed",
                "task attempt is already claimed by another logical command",
            ));
        }
        if self.last_command_payload_digest != payload_digest {
            return Err(AgentError::new(
                "command_payload_mismatch",
                "logical task command payload digest changed",
            ));
        }
        Ok(())
    }

    fn record_command(
        &mut self,
        command: &fairypam_agent_protocol::v1::CommandRef,
        payload_digest: &str,
    ) -> Result<(), AgentError> {
        if self.last_command_id == command.command_id
            && self.last_command_payload_digest != payload_digest
        {
            return Err(AgentError::new(
                "command_payload_mismatch",
                "logical task command payload digest changed",
            ));
        }
        self.last_command_id.clone_from(&command.command_id);
        self.last_command_sequence = command.sequence;
        self.last_command_generation = command
            .session
            .as_ref()
            .map_or(0, |session| session.generation);
        self.last_command_payload_digest = payload_digest.to_owned();
        Ok(())
    }

    fn receipt(&self) -> TaskAttemptReceiptV1 {
        TaskAttemptReceiptV1 {
            receipt_version: RECEIPT_VERSION,
            attempt: Some(self.reference.message()),
            attempt_state: self.attempt_state,
            last_command_id: self.last_command_id.clone(),
            last_command_sequence: self.last_command_sequence,
            last_command_generation: self.last_command_generation,
            last_command_payload_digest: self.last_command_payload_digest.clone(),
            side_effect_state: self.side_effect_state,
            last_side_effect_command_id: self.last_side_effect_command_id.clone(),
            input_state: self.input_state,
            capture_state: self.capture_state,
            owned_target_state: self.owned_target_state,
            cleanup_complete: Some(self.cleanup_complete),
            error_code: self.error_code.clone(),
        }
    }

    fn command_result(&self) -> Result<TaskCommandResult, AgentError> {
        let outcome = TaskCommandOutcomeState::try_from(self.last_command_outcome)
            .ok()
            .filter(|outcome| *outcome != TaskCommandOutcomeState::Unspecified)
            .ok_or_else(ledger_invalid)?;
        Ok(TaskCommandResult {
            outcome: TaskCommandOutcomeV1 {
                attempt: Some(self.reference.message()),
                command_id: self.last_command_id.clone(),
                payload_digest: self.last_command_payload_digest.clone(),
                outcome: outcome as i32,
                source_frame_sequence: self.last_command_source_frame_sequence,
                error_code: self.last_command_error_code.clone(),
            },
            receipt: self.receipt(),
        })
    }

    fn validate(&self) -> Result<(), AgentError> {
        let contract = self.contract.message();
        verify_agent_attempt_contract(&contract)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        let reference = self.reference.message();
        validate_contract_reference(&reference, &contract)?;
        let attempt_state = TaskAttemptState::try_from(self.attempt_state).ok();
        let side_effect_state = TaskSideEffectState::try_from(self.side_effect_state).ok();
        let input_state = TaskInputState::try_from(self.input_state).ok();
        let capture_state = TaskCaptureState::try_from(self.capture_state).ok();
        let owned_target_state = TaskOwnedTargetState::try_from(self.owned_target_state).ok();
        let cleanup_complete = attempt_state == Some(TaskAttemptState::Terminal)
            && input_state == Some(TaskInputState::Released)
            && matches!(
                capture_state,
                Some(TaskCaptureState::NotStarted | TaskCaptureState::Stopped)
            )
            && matches!(
                owned_target_state,
                Some(TaskOwnedTargetState::NotStarted | TaskOwnedTargetState::Closed)
            )
            && !matches!(
                side_effect_state,
                Some(TaskSideEffectState::IntentRecorded | TaskSideEffectState::Uncertain)
            );
        if !TaskAttemptState::try_from(self.attempt_state)
            .is_ok_and(|state| state != TaskAttemptState::Unspecified)
            || !TaskSideEffectState::try_from(self.side_effect_state)
                .is_ok_and(|state| state != TaskSideEffectState::Unspecified)
            || !TaskInputState::try_from(self.input_state)
                .is_ok_and(|state| state != TaskInputState::Unspecified)
            || !TaskCaptureState::try_from(self.capture_state)
                .is_ok_and(|state| state != TaskCaptureState::Unspecified)
            || !TaskOwnedTargetState::try_from(self.owned_target_state)
                .is_ok_and(|state| state != TaskOwnedTargetState::Unspecified)
            || self.last_command_id.is_empty()
            || !is_digest(&self.last_command_payload_digest)
            || (self.last_command_outcome != TaskCommandOutcomeState::Unspecified as i32
                && TaskCommandOutcomeState::try_from(self.last_command_outcome).is_err())
            || self
                .owned_target
                .as_ref()
                .is_some_and(|binding| binding.profile_id != self.contract.profile_id)
            || self.cleanup_complete != cleanup_complete
            || (self.owned_target.is_some()
                && !matches!(
                    owned_target_state,
                    Some(TaskOwnedTargetState::Running | TaskOwnedTargetState::Unknown)
                ))
            || (self.owned_target.is_none()
                && owned_target_state == Some(TaskOwnedTargetState::Running))
        {
            return Err(ledger_invalid());
        }
        Ok(())
    }
}

fn validate_task(
    task: &TaskCommandRef,
) -> Result<(&AttemptRef, &fairypam_agent_protocol::v1::CommandRef), AgentError> {
    let reference = task.attempt.as_ref().ok_or_else(task_ref_invalid)?;
    let command = task.command.as_ref().ok_or_else(task_ref_invalid)?;
    if command.session.is_none()
        || command.command_id.is_empty()
        || !is_digest(&task.payload_digest)
        || !is_uuid(&reference.task_run_id)
        || !is_uuid(&reference.attempt_id)
        || reference.contract_version != 1
        || !is_digest(&reference.contract_digest)
    {
        return Err(task_ref_invalid());
    }
    Ok((reference, command))
}

fn validate_contract_reference(
    reference: &AttemptRef,
    contract: &AgentAttemptContractV1,
) -> Result<(), AgentError> {
    if reference.task_run_id != contract.task_run_id
        || reference.attempt_id != contract.attempt_id
        || reference.contract_version != contract.contract_version
        || reference.contract_digest != contract.contract_digest
    {
        return Err(AgentError::new(
            "attempt_contract_mismatch",
            "task attempt reference does not match its Agent contract",
        ));
    }
    Ok(())
}

fn not_found_receipt() -> TaskAttemptReceiptV1 {
    TaskAttemptReceiptV1 {
        receipt_version: RECEIPT_VERSION,
        attempt_state: TaskAttemptState::NotFound as i32,
        side_effect_state: TaskSideEffectState::None as i32,
        input_state: TaskInputState::Released as i32,
        capture_state: TaskCaptureState::NotStarted as i32,
        owned_target_state: TaskOwnedTargetState::NotStarted as i32,
        cleanup_complete: Some(false),
        ..TaskAttemptReceiptV1::default()
    }
}

fn load_last(path: &Path) -> Result<AttemptState, AgentError> {
    let file = fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AgentError::new("task.ledger_not_found", "task attempt ledger does not exist")
        } else {
            io_error("task.ledger_unavailable", error)
        }
    })?;
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| io_error("task.ledger_unavailable", error))?;
        if line.len() > MAX_RECORD_BYTES {
            return Err(ledger_invalid());
        }
        last = Some(serde_json::from_str::<AttemptState>(&line).map_err(|_| ledger_invalid())?);
    }
    let state = last.ok_or_else(ledger_invalid)?;
    state.validate()?;
    Ok(state)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn production_root() -> Option<PathBuf> {
    #[cfg(windows)]
    return Some(PathBuf::from(
        r"C:\ProgramData\FairyPam.Agent\Agent\attempts",
    ));
    #[cfg(not(windows))]
    None
}

fn task_ref_invalid() -> AgentError {
    AgentError::new(
        "task.reference_invalid",
        "task command reference is incomplete or invalid",
    )
}

fn attempt_not_found() -> AgentError {
    AgentError::new("attempt_not_found", "task attempt is not claimed")
}

fn ledger_invalid() -> AgentError {
    AgentError::new(
        "task.ledger_invalid",
        "persisted task attempt ledger is invalid",
    )
}

fn io_error(code: &'static str, error: std::io::Error) -> AgentError {
    AgentError::new(code, format!("task attempt ledger I/O failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fairypam_agent_protocol::v1::{CommandRef, SessionRef};
    use sha2::{Digest, Sha256};

    fn contract() -> AgentAttemptContractV1 {
        let mut contract = AgentAttemptContractV1 {
            task_run_id: "11111111-1111-4111-8111-111111111111".into(),
            attempt_id: "22222222-2222-4222-8222-222222222222".into(),
            agent_build_id: "test-build".into(),
            profile_id: "genshin-impact".into(),
            profile_digest: "b".repeat(64),
            cleanup_policy: "close_owned_target".into(),
            contract_version: 1,
            contract_digest: String::new(),
        };
        let canonical =
            fairypam_agent_protocol::canonical_agent_attempt_contract(&contract).unwrap();
        contract.contract_digest = Sha256::digest(canonical.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        contract
    }

    fn task(contract: &AgentAttemptContractV1, command_id: &str, payload: char) -> TaskCommandRef {
        TaskCommandRef {
            command: Some(CommandRef {
                session: Some(SessionRef {
                    agent_id: "agent".into(),
                    session_id: "session".into(),
                    generation: 7,
                }),
                command_id: command_id.into(),
                sequence: 3,
                expires_at_unix_ms: i64::MAX,
            }),
            attempt: Some(AttemptRef {
                task_run_id: contract.task_run_id.clone(),
                attempt_id: contract.attempt_id.clone(),
                contract_version: contract.contract_version,
                contract_digest: contract.contract_digest.clone(),
            }),
            payload_digest: payload.to_string().repeat(64),
        }
    }

    fn temporary_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "fairypam-task-attempt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn claim_survives_restart_and_same_command_is_idempotent() {
        let root = temporary_root();
        let contract = contract();
        let begin = task(&contract, "begin-1", 'c');
        let receipt = TaskAttemptRuntime::at(root.clone())
            .begin(&begin, &contract)
            .unwrap();
        assert_eq!(receipt.attempt_state, TaskAttemptState::Claimed as i32);

        let replay = TaskAttemptRuntime::at(root.clone())
            .begin(&begin, &contract)
            .unwrap();
        assert_eq!(replay.last_command_id, "begin-1");

        let changed = task(&contract, "begin-1", 'd');
        assert_eq!(
            TaskAttemptRuntime::at(root.clone())
                .begin(&changed, &contract)
                .unwrap_err()
                .code(),
            "command_payload_mismatch"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unresolved_side_effect_becomes_uncertain_after_restart_without_replay() {
        let root = temporary_root();
        let contract = contract();
        let begin = task(&contract, "begin-1", 'c');
        let effect = task(&contract, "pulse-1", 'd');
        let mut runtime = TaskAttemptRuntime::at(root.clone());
        runtime.begin(&begin, &contract).unwrap();
        assert!(runtime.prepare(&effect, true).unwrap().is_none());

        let replay = TaskAttemptRuntime::at(root.clone())
            .prepare(&effect, true)
            .unwrap()
            .unwrap();
        assert_eq!(
            replay.outcome.outcome,
            TaskCommandOutcomeState::Uncertain as i32
        );
        assert_eq!(
            replay.receipt.side_effect_state,
            TaskSideEffectState::Uncertain as i32
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspect_unknown_attempt_returns_typed_not_found() {
        let root = temporary_root();
        let contract = contract();
        let receipt = TaskAttemptRuntime::at(root.clone())
            .inspect(&task(&contract, "inspect-1", 'e'))
            .unwrap();
        assert_eq!(receipt.attempt_state, TaskAttemptState::NotFound as i32);
        assert!(receipt.attempt.is_none());
        let _ = fs::remove_dir_all(root);
    }
}
