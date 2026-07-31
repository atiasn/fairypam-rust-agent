use std::collections::BTreeMap;
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
use fairypam_agent_protocol::v2;
use fairypam_agent_protocol::{verify_agent_attempt_contract, verify_execution_contract};
use serde::{Deserialize, Serialize};

const RECEIPT_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_BUSINESS_COMMAND_RESULTS: usize = 98_304;
const MAX_INSPECT_COMMAND_RESULTS: usize = 8;
const MAX_RELEASE_COMMAND_RESULTS: usize = 4;
const MAX_FINISH_COMMAND_RESULTS: usize = 4;
const MAX_RECOVERY_COMMAND_RESULTS: usize =
    MAX_INSPECT_COMMAND_RESULTS + MAX_RELEASE_COMMAND_RESULTS + MAX_FINISH_COMMAND_RESULTS;
const MAX_COMMAND_RESULTS: usize = MAX_BUSINESS_COMMAND_RESULTS + MAX_RECOVERY_COMMAND_RESULTS;
const EMERGENCY_STOP_MARKER: &str = "emergency-stopped";

pub struct TaskAttemptRuntime {
    root: Option<PathBuf>,
    active: Option<AttemptState>,
    loaded: bool,
    emergency_stopped: bool,
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
            emergency_stopped: false,
        }
    }

    pub fn memory() -> Self {
        Self {
            root: None,
            active: None,
            loaded: true,
            emergency_stopped: false,
        }
    }

    #[cfg(test)]
    fn at(root: PathBuf) -> Self {
        Self {
            root: Some(root),
            active: None,
            loaded: false,
            emergency_stopped: false,
        }
    }

    pub fn begin(
        &mut self,
        task: &TaskCommandRef,
        contract: &AgentAttemptContractV1,
    ) -> Result<TaskAttemptReceiptV1, AgentError> {
        verify_stored_contract(contract)?;
        let (reference, command) = validate_task(task)?;
        validate_contract_reference(reference, contract)?;
        self.load_active()?;

        if self.emergency_stopped {
            return Err(AgentError::new(
                "emergency_stopped",
                "local emergency stop must be reset before accepting a task attempt",
            ));
        }

        if self.active.as_ref().is_some_and(|active| {
            active.attempt_state == TaskAttemptState::Terminal as i32 && active.cleanup_complete
        }) {
            self.active = None;
        }

        if let Some(active) = self.active.as_ref() {
            active.require_reference(reference)?;
            if let Some(stored) = active.stored_result(&command.command_id) {
                if stored.payload_digest != task.payload_digest {
                    return self
                        .payload_digest_conflict(task)
                        .map(|result| result.receipt);
                }
                return stored
                    .result(&active.reference)
                    .map(|result| result.receipt);
            }
            active
                .require_same_command(command.command_id.as_str(), task.payload_digest.as_str())?;
            return Ok(active.receipt());
        }

        let state = AttemptState::claimed(StoredContract::from(contract), reference.clone(), task)?;
        self.persist(&state)?;
        let receipt = state.receipt();
        self.active = Some(state);
        Ok(receipt)
    }

    pub fn begin_v2(
        &mut self,
        task: &TaskCommandRef,
        contract: &v2::ExecutionContract,
    ) -> Result<TaskAttemptReceiptV1, AgentError> {
        verify_execution_contract(contract)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        let (reference, command) = validate_task(task)?;
        if reference.task_run_id != contract.task_run_id
            || reference.attempt_id != contract.attempt_id
            || reference.contract_version != contract.contract_version
            || reference.contract_digest != contract.contract_digest
        {
            return Err(AgentError::new(
                "attempt_contract_mismatch",
                "task attempt reference does not match the v2 contract",
            ));
        }
        self.load_active()?;
        if self.emergency_stopped {
            return Err(AgentError::new(
                "emergency_stopped",
                "local emergency stop must be reset before accepting a task attempt",
            ));
        }
        if self.active.as_ref().is_some_and(|active| {
            active.attempt_state == TaskAttemptState::Terminal as i32 && active.cleanup_complete
        }) {
            self.active = None;
        }
        if let Some(active) = self.active.as_ref() {
            active.require_reference(reference)?;
            if let Some(stored) = active.stored_result(&command.command_id) {
                if stored.payload_digest != task.payload_digest {
                    return self
                        .payload_digest_conflict(task)
                        .map(|result| result.receipt);
                }
                return stored
                    .result(&active.reference)
                    .map(|result| result.receipt);
            }
            active.require_same_command(&command.command_id, &task.payload_digest)?;
            return Ok(active.receipt());
        }
        let state = AttemptState::claimed(StoredContract::from(contract), reference.clone(), task)?;
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
            if let Some(stored) = terminal.stored_result(&command.command_id) {
                if stored.payload_digest != task.payload_digest {
                    self.active = Some(terminal);
                    return self
                        .payload_digest_conflict(task)
                        .map(|result| result.receipt);
                }
                return stored
                    .result(&terminal.reference)
                    .map(|result| result.receipt);
            }
            terminal.record_command(
                command,
                &task.payload_digest,
                MAX_BUSINESS_COMMAND_RESULTS + MAX_INSPECT_COMMAND_RESULTS,
            )?;
            terminal.last_command_outcome = TaskCommandOutcomeState::Applied as i32;
            terminal.last_command_source_frame_sequence = None;
            terminal.last_command_error_code = None;
            terminal.store_current_result()?;
            self.persist(&terminal)?;
            return Ok(terminal.receipt());
        };
        if let Err(error) = active.require_reference(reference) {
            self.active = Some(active);
            return Err(error);
        }
        if let Some(stored) = active.stored_result(&command.command_id) {
            if stored.payload_digest != task.payload_digest {
                self.active = Some(active);
                return self
                    .payload_digest_conflict(task)
                    .map(|result| result.receipt);
            }
            let receipt = stored.result(&active.reference)?.receipt;
            self.active = Some(active);
            return Ok(receipt);
        }
        if let Err(error) = active.record_command(
            command,
            &task.payload_digest,
            MAX_BUSINESS_COMMAND_RESULTS + MAX_INSPECT_COMMAND_RESULTS,
        ) {
            self.active = Some(active);
            return Err(error);
        }
        active.last_command_outcome = TaskCommandOutcomeState::Applied as i32;
        active.last_command_source_frame_sequence = None;
        active.last_command_error_code = None;
        if let Err(error) = active.store_current_result() {
            self.active = Some(active);
            return Err(error);
        }
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

    #[cfg(test)]
    pub fn owned_target(
        &mut self,
        task: &TaskCommandRef,
    ) -> Result<Option<TargetBinding>, AgentError> {
        Ok(self.require_active(task)?.owned_target.clone())
    }

    pub fn refresh_owned_target(
        &mut self,
        reference: &AttemptRef,
        binding: TargetBinding,
    ) -> Result<(), AgentError> {
        self.load_active()?;
        let Some(mut active) = self.active.take() else {
            return Err(attempt_not_found());
        };
        if let Err(error) = active.require_reference(reference) {
            self.active = Some(active);
            return Err(error);
        }
        let Some(previous) = active.owned_target.as_ref() else {
            self.active = Some(active);
            return Err(AgentError::new(
                "target_invalid",
                "task attempt has no Agent-owned target to refresh",
            ));
        };
        if previous.profile_id != binding.profile_id
            || previous.profile_version != binding.profile_version
            || previous.process_id != binding.process_id
            || previous.process_started_at_unix_ms != binding.process_started_at_unix_ms
            || previous.process_path_sha256 != binding.process_path_sha256
        {
            self.active = Some(active);
            return Err(AgentError::new(
                "target.stale",
                "refreshed window does not belong to the claimed Agent-owned process",
            ));
        }
        active.owned_target = Some(binding);
        if let Err(error) = self.persist(&active) {
            self.active = Some(active);
            return Err(error);
        }
        self.active = Some(active);
        Ok(())
    }

    pub fn replay(
        &mut self,
        task: &TaskCommandRef,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        let (reference, command) = validate_task(task)?;
        self.load_active()?;
        let active = self.active.as_ref().ok_or_else(attempt_not_found)?;
        active.require_reference(reference)?;
        if let Some(stored) = active.stored_result(&command.command_id) {
            if stored.payload_digest != task.payload_digest {
                return self.payload_digest_conflict(task).map(Some);
            }
            return stored.result(&active.reference).map(Some);
        }
        if active.last_command_id != command.command_id {
            return Ok(None);
        }
        if active.last_command_payload_digest != task.payload_digest {
            return self.payload_digest_conflict(task).map(Some);
        }
        active.require_same_command(&command.command_id, &task.payload_digest)?;
        if active.last_command_outcome == TaskCommandOutcomeState::Unspecified as i32 {
            return self.prepare(task, true);
        }
        active.command_result().map(Some)
    }

    pub fn payload_digest_conflict(
        &mut self,
        task: &TaskCommandRef,
    ) -> Result<TaskCommandResult, AgentError> {
        let (reference, command) = validate_task(task)?;
        self.load_active()?;
        let Some(mut active) = self.active.take() else {
            return Err(attempt_not_found());
        };
        if let Err(error) = active.require_reference(reference) {
            self.active = Some(active);
            return Err(error);
        }
        let known_digest = active
            .stored_result(&command.command_id)
            .map(|result| result.payload_digest.clone())
            .or_else(|| {
                (active.last_command_id == command.command_id)
                    .then(|| active.last_command_payload_digest.clone())
            });
        if known_digest
            .as_deref()
            .is_none_or(|digest| digest == task.payload_digest)
        {
            self.active = Some(active);
            return Err(AgentError::new(
                "command.payload_digest_conflict",
                "digest conflict requires the same logical command id and a changed payload",
            ));
        }
        active.side_effect_state = TaskSideEffectState::Uncertain as i32;
        active.cleanup_complete = false;
        active.error_code = Some("command.payload_digest_conflict".into());
        if let Err(error) = self.persist(&active) {
            self.active = Some(active);
            return Err(error);
        }
        let mut receipt = active.receipt();
        receipt.last_command_id.clone_from(&command.command_id);
        receipt.last_command_sequence = command.sequence;
        receipt.last_command_generation = command
            .session
            .as_ref()
            .map_or(0, |session| session.generation);
        receipt.last_command_payload_digest =
            known_digest.expect("changed digest has a stored value");
        let result = TaskCommandResult {
            outcome: TaskCommandOutcomeV1 {
                attempt: Some(active.reference.message()),
                command_id: command.command_id.clone(),
                payload_digest: task.payload_digest.clone(),
                outcome: TaskCommandOutcomeState::Uncertain as i32,
                source_frame_sequence: None,
                error_code: Some("command.payload_digest_conflict".into()),
            },
            receipt,
        };
        self.active = Some(active);
        Ok(result)
    }

    pub fn reject(
        &mut self,
        task: &TaskCommandRef,
        error_code: &str,
    ) -> Result<TaskCommandResult, AgentError> {
        let (reference, command) = validate_task(task)?;
        self.load_active()?;
        if let Some(active) = self.active.as_ref() {
            if let Some(stored) = active.stored_result(&command.command_id) {
                if stored.payload_digest != task.payload_digest {
                    return self.payload_digest_conflict(task);
                }
                return stored.result(&active.reference);
            }
            if active.last_command_id == command.command_id
                && active.last_command_payload_digest != task.payload_digest
            {
                return self.payload_digest_conflict(task);
            }
        }
        let Some(mut active) = self.active.take() else {
            return Err(attempt_not_found());
        };
        if let Err(error) = active.require_reference(reference) {
            self.active = Some(active);
            return Err(error);
        }
        if active.last_command_id == command.command_id
            && active.last_command_outcome != TaskCommandOutcomeState::Unspecified as i32
        {
            let result = active.command_result()?;
            self.active = Some(active);
            return Ok(result);
        }
        if let Err(error) =
            active.record_command(command, &task.payload_digest, MAX_BUSINESS_COMMAND_RESULTS)
        {
            self.active = Some(active);
            return Err(error);
        }
        active.last_command_outcome = TaskCommandOutcomeState::NotApplied as i32;
        active.last_command_source_frame_sequence = None;
        active.last_command_error_code = Some(error_code.into());
        active.error_code = Some(error_code.into());
        if let Err(error) = active.store_current_result() {
            self.active = Some(active);
            return Err(error);
        }
        if let Err(error) = self.persist(&active) {
            self.active = Some(active);
            return Err(error);
        }
        let result = active.command_result()?;
        self.active = Some(active);
        Ok(result)
    }

    pub fn prepare(
        &mut self,
        task: &TaskCommandRef,
        side_effect: bool,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        self.prepare_inner(task, side_effect, false, MAX_BUSINESS_COMMAND_RESULTS)
    }

    pub fn prepare_recovery(
        &mut self,
        task: &TaskCommandRef,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        self.prepare_inner(
            task,
            false,
            true,
            MAX_BUSINESS_COMMAND_RESULTS
                + MAX_INSPECT_COMMAND_RESULTS
                + MAX_RELEASE_COMMAND_RESULTS,
        )
    }

    pub fn prepare_finish(
        &mut self,
        task: &TaskCommandRef,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        self.prepare_inner(task, false, true, MAX_COMMAND_RESULTS)
    }

    fn prepare_inner(
        &mut self,
        task: &TaskCommandRef,
        side_effect: bool,
        allow_uncertain: bool,
        command_limit: usize,
    ) -> Result<Option<TaskCommandResult>, AgentError> {
        let (reference, command) = validate_task(task)?;
        self.load_active()?;
        if let Some(active) = self.active.as_ref() {
            if let Some(stored) = active.stored_result(&command.command_id) {
                if stored.payload_digest != task.payload_digest {
                    return self.payload_digest_conflict(task).map(Some);
                }
                return stored.result(&active.reference).map(Some);
            }
            if active.last_command_id == command.command_id
                && active.last_command_payload_digest != task.payload_digest
            {
                return self.payload_digest_conflict(task).map(Some);
            }
        }
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
                    (TaskCommandOutcomeState::Uncertain, "side_effect_uncertain")
                } else {
                    (TaskCommandOutcomeState::NotApplied, "command_interrupted")
                };
                active.last_command_outcome = outcome as i32;
                active.last_command_error_code = Some(error_code.into());
                active.error_code = Some(error_code.into());
                if let Err(error) = active.store_current_result() {
                    self.active = Some(active);
                    return Err(error);
                }
                if let Err(error) = self.persist(&active) {
                    self.active = Some(active);
                    return Err(error);
                }
            }
            let result = active.command_result()?;
            self.active = Some(active);
            return Ok(Some(result));
        }
        if active.attempt_state == TaskAttemptState::Terminal as i32 && !allow_uncertain {
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
        if let Err(error) = active.record_command(command, &task.payload_digest, command_limit) {
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

    pub fn complete_capture_frame(
        &mut self,
        task: &TaskCommandRef,
        source_frame_sequence: Option<u64>,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        self.complete(
            task,
            if error_code.is_none() {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::NotApplied
            },
            source_frame_sequence,
            error_code,
            false,
            |state| {
                if error_code.is_none() {
                    state.attempt_state = TaskAttemptState::Active as i32;
                    state.capture_state = TaskCaptureState::Stopped as i32;
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

    pub fn complete_input_frame(
        &mut self,
        task: &TaskCommandRef,
        source_frame_sequence: Option<u64>,
        applied: bool,
        holds_active: bool,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        self.complete(
            task,
            if applied {
                TaskCommandOutcomeState::Applied
            } else {
                TaskCommandOutcomeState::Uncertain
            },
            source_frame_sequence,
            error_code,
            true,
            |state| {
                state.input_state = if applied && holds_active {
                    TaskInputState::Active as i32
                } else if applied {
                    TaskInputState::Released as i32
                } else {
                    TaskInputState::Unknown as i32
                };
            },
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
        managed_target_running: bool,
        error_code: Option<&str>,
    ) -> Result<TaskCommandResult, AgentError> {
        let side_effect_resolved = !matches!(
            TaskSideEffectState::try_from(self.require_active(task)?.side_effect_state),
            Ok(TaskSideEffectState::IntentRecorded | TaskSideEffectState::Uncertain)
        );
        let cleanup_complete = input_released && capture_stopped && side_effect_resolved;
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
                TaskCommandOutcomeState::Uncertain
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
                state.owned_target_state = if managed_target_running {
                    TaskOwnedTargetState::Running as i32
                } else {
                    TaskOwnedTargetState::NotStarted as i32
                };
                state.cleanup_complete = cleanup_complete;
                state.owned_target = None;
            },
        )
    }

    pub fn emergency_finish(
        &mut self,
        input_released: bool,
        capture_stopped: bool,
        managed_target_running: bool,
        error_code: Option<&str>,
    ) -> Result<Option<TaskAttemptReceiptV1>, AgentError> {
        self.load_active()?;
        let Some(mut active) = self.active.take() else {
            return Ok(None);
        };
        let side_effect_resolved = !matches!(
            TaskSideEffectState::try_from(active.side_effect_state),
            Ok(TaskSideEffectState::IntentRecorded | TaskSideEffectState::Uncertain)
        );
        let cleanup_complete = input_released && capture_stopped && side_effect_resolved;
        active.attempt_state = TaskAttemptState::Terminal as i32;
        active.input_state = if input_released {
            TaskInputState::Released as i32
        } else {
            TaskInputState::Unknown as i32
        };
        active.capture_state = if capture_stopped {
            TaskCaptureState::Stopped as i32
        } else {
            TaskCaptureState::Unknown as i32
        };
        active.owned_target_state = if managed_target_running {
            TaskOwnedTargetState::Running as i32
        } else {
            TaskOwnedTargetState::NotStarted as i32
        };
        active.cleanup_complete = cleanup_complete;
        active.error_code = error_code
            .or((!side_effect_resolved).then_some("side_effect_uncertain"))
            .or((!cleanup_complete).then_some("cleanup_incomplete"))
            .map(str::to_owned);
        active.owned_target = None;
        self.persist(&active)?;
        let receipt = active.receipt();
        self.active = Some(active);
        Ok(Some(receipt))
    }

    pub fn emergency_stopped(&mut self) -> Result<bool, AgentError> {
        self.load_active()?;
        Ok(self.emergency_stopped)
    }

    pub fn set_emergency_stopped(&mut self, stopped: bool) -> Result<(), AgentError> {
        self.load_active()?;
        let previous = self.emergency_stopped;
        self.emergency_stopped = stopped;
        if let Some(root) = self.root.as_ref() {
            if let Err(error) = fs::create_dir_all(root) {
                if !stopped {
                    self.emergency_stopped = previous;
                }
                return Err(io_error("task.ledger_unavailable", error));
            }
            let marker = root.join(EMERGENCY_STOP_MARKER);
            if stopped {
                let file = match OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(marker)
                {
                    Ok(file) => file,
                    Err(error) => return Err(io_error("task.ledger_unavailable", error)),
                };
                if let Err(error) = file.sync_all() {
                    return Err(io_error("task.ledger_unavailable", error));
                }
            } else if let Err(error) = fs::remove_file(marker) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    self.emergency_stopped = previous;
                    return Err(io_error("task.ledger_unavailable", error));
                }
            }
        }
        Ok(())
    }

    pub fn reset_emergency(&mut self) -> Result<(), AgentError> {
        if self.is_active()? {
            return Err(AgentError::new(
                "emergency_cleanup_incomplete",
                "task cleanup must be complete before resetting emergency stop",
            ));
        }
        self.set_emergency_stopped(false)
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
        if let Err(error) = active.store_current_result() {
            self.active = Some(active);
            return Err(error);
        }
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
        self.emergency_stopped = root.join(EMERGENCY_STOP_MARKER).is_file();
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
        // ponytail: append only the current snapshot; load_last rebuilds the
        // command index so ledger growth stays linear for long visual tasks.
        let mut record = state.clone();
        record.command_results.clear();
        let mut bytes = serde_json::to_vec(&record).map_err(|error| {
            AgentError::new(
                "task.ledger_invalid",
                format!("cannot encode attempt ledger: {error}"),
            )
        })?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(AgentError::new(
                "task.ledger_full",
                "task attempt ledger record reached its fixed safety bound",
            ));
        }
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttemptState {
    contract: StoredContract,
    reference: StoredAttemptRef,
    attempt_state: i32,
    last_command_id: String,
    last_command_sequence: u64,
    last_command_generation: u64,
    #[serde(default)]
    last_command_session_id: String,
    last_command_payload_digest: String,
    #[serde(default)]
    last_command_outcome: i32,
    #[serde(default)]
    last_command_source_frame_sequence: Option<u64>,
    #[serde(default)]
    last_command_error_code: Option<String>,
    #[serde(default)]
    command_results: BTreeMap<String, StoredCommandResult>,
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCommandResult {
    command_id: String,
    sequence: u64,
    generation: u64,
    session_id: String,
    payload_digest: String,
    outcome: i32,
    source_frame_sequence: Option<u64>,
    command_error_code: Option<String>,
    attempt_state: i32,
    side_effect_state: i32,
    last_side_effect_command_id: String,
    input_state: i32,
    capture_state: i32,
    owned_target_state: i32,
    cleanup_complete: bool,
    receipt_error_code: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
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
    #[serde(default)]
    allowed_capabilities: Vec<i32>,
    #[serde(default)]
    deadline_unix_ms: i64,
    #[serde(default)]
    max_input_lease_ms: u32,
    #[serde(default)]
    cleanup_policy_value: i32,
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

    fn validate(&self) -> Result<(), AgentError> {
        if self.contract_version == 1 {
            return verify_agent_attempt_contract(&self.message())
                .map_err(|error| AgentError::new(error.code(), error.to_string()));
        }
        let contract = v2::ExecutionContract {
            task_run_id: self.task_run_id.clone(),
            attempt_id: self.attempt_id.clone(),
            agent_build_id: self.agent_build_id.clone(),
            profile_id: self.profile_id.clone(),
            profile_digest: self.profile_digest.clone(),
            allowed_capabilities: self.allowed_capabilities.clone(),
            deadline_unix_ms: self.deadline_unix_ms,
            max_input_lease_ms: self.max_input_lease_ms,
            cleanup_policy: self.cleanup_policy_value,
            contract_version: self.contract_version,
            contract_digest: self.contract_digest.clone(),
        };
        verify_execution_contract(&contract)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))
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
            allowed_capabilities: Vec::new(),
            deadline_unix_ms: 0,
            max_input_lease_ms: 0,
            cleanup_policy_value: 0,
        }
    }
}

impl From<&v2::ExecutionContract> for StoredContract {
    fn from(contract: &v2::ExecutionContract) -> Self {
        Self {
            task_run_id: contract.task_run_id.clone(),
            attempt_id: contract.attempt_id.clone(),
            agent_build_id: contract.agent_build_id.clone(),
            profile_id: contract.profile_id.clone(),
            profile_digest: contract.profile_digest.clone(),
            cleanup_policy: "release_input_and_close_owned_target".into(),
            contract_version: contract.contract_version,
            contract_digest: contract.contract_digest.clone(),
            allowed_capabilities: contract.allowed_capabilities.clone(),
            deadline_unix_ms: contract.deadline_unix_ms,
            max_input_lease_ms: contract.max_input_lease_ms,
            cleanup_policy_value: contract.cleanup_policy,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
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
        contract: StoredContract,
        reference: AttemptRef,
        task: &TaskCommandRef,
    ) -> Result<Self, AgentError> {
        let command = task.command.as_ref().ok_or_else(task_ref_invalid)?;
        let mut state = Self {
            contract,
            reference: StoredAttemptRef::from(&reference),
            attempt_state: TaskAttemptState::Claimed as i32,
            last_command_id: command.command_id.clone(),
            last_command_sequence: command.sequence,
            last_command_generation: command
                .session
                .as_ref()
                .map_or(0, |session| session.generation),
            last_command_session_id: command
                .session
                .as_ref()
                .map_or_else(String::new, |session| session.session_id.clone()),
            last_command_payload_digest: task.payload_digest.clone(),
            last_command_outcome: TaskCommandOutcomeState::Applied as i32,
            last_command_source_frame_sequence: None,
            last_command_error_code: None,
            command_results: BTreeMap::new(),
            side_effect_state: TaskSideEffectState::None as i32,
            last_side_effect_command_id: String::new(),
            input_state: TaskInputState::Released as i32,
            capture_state: TaskCaptureState::NotStarted as i32,
            owned_target_state: TaskOwnedTargetState::NotStarted as i32,
            owned_target: None,
            cleanup_complete: false,
            error_code: None,
        };
        state.store_current_result()?;
        Ok(state)
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
                "command.payload_digest_conflict",
                "logical task command payload digest changed",
            ));
        }
        Ok(())
    }

    fn record_command(
        &mut self,
        command: &fairypam_agent_protocol::v1::CommandRef,
        payload_digest: &str,
        command_limit: usize,
    ) -> Result<(), AgentError> {
        if let Some(stored) = self.stored_result(&command.command_id) {
            if stored.payload_digest != payload_digest {
                return Err(AgentError::new(
                    "command.payload_digest_conflict",
                    "logical task command payload digest changed",
                ));
            }
        } else if self.command_results.len() >= command_limit {
            return Err(AgentError::new(
                "task.ledger_full",
                "task command journal reached its fixed safety bound",
            ));
        }
        let same_session = command
            .session
            .as_ref()
            .is_some_and(|session| session.session_id == self.last_command_session_id);
        if self.last_command_id != command.command_id
            && same_session
            && command.sequence <= self.last_command_sequence
        {
            return Err(AgentError::new(
                "command_sequence_invalid",
                "new task command sequence must increase monotonically",
            ));
        }
        self.last_command_id.clone_from(&command.command_id);
        self.last_command_sequence = command.sequence;
        self.last_command_generation = command
            .session
            .as_ref()
            .map_or(0, |session| session.generation);
        self.last_command_session_id = command
            .session
            .as_ref()
            .map_or_else(String::new, |session| session.session_id.clone());
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

    fn stored_result(&self, command_id: &str) -> Option<&StoredCommandResult> {
        self.command_results.get(command_id)
    }

    fn store_current_result(&mut self) -> Result<(), AgentError> {
        let result = StoredCommandResult {
            command_id: self.last_command_id.clone(),
            sequence: self.last_command_sequence,
            generation: self.last_command_generation,
            session_id: self.last_command_session_id.clone(),
            payload_digest: self.last_command_payload_digest.clone(),
            outcome: self.last_command_outcome,
            source_frame_sequence: self.last_command_source_frame_sequence,
            command_error_code: self.last_command_error_code.clone(),
            attempt_state: self.attempt_state,
            side_effect_state: self.side_effect_state,
            last_side_effect_command_id: self.last_side_effect_command_id.clone(),
            input_state: self.input_state,
            capture_state: self.capture_state,
            owned_target_state: self.owned_target_state,
            cleanup_complete: self.cleanup_complete,
            receipt_error_code: self.error_code.clone(),
        };
        if let Some(stored) = self.command_results.get_mut(&result.command_id) {
            if stored.payload_digest != result.payload_digest {
                return Err(AgentError::new(
                    "command.payload_digest_conflict",
                    "logical task command payload digest changed",
                ));
            }
            *stored = result;
            return Ok(());
        }
        if self.command_results.len() >= MAX_COMMAND_RESULTS {
            return Err(AgentError::new(
                "task.ledger_full",
                "task command journal reached its fixed safety bound",
            ));
        }
        self.command_results
            .insert(result.command_id.clone(), result);
        Ok(())
    }

    fn validate(&self) -> Result<(), AgentError> {
        self.contract.validate()?;
        let contract = self.contract.message();
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
                Some(
                    TaskOwnedTargetState::NotStarted
                        | TaskOwnedTargetState::Running
                        | TaskOwnedTargetState::Closed
                )
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
            || self.command_results.len() > MAX_COMMAND_RESULTS
            || self
                .command_results
                .iter()
                .any(|(command_id, result)| command_id != &result.command_id || !result.validate())
            || (self.last_command_outcome != TaskCommandOutcomeState::Unspecified as i32
                && self
                    .stored_result(&self.last_command_id)
                    .is_none_or(|result| {
                        result.payload_digest != self.last_command_payload_digest
                            || result.outcome != self.last_command_outcome
                    }))
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
                && owned_target_state == Some(TaskOwnedTargetState::Running)
                && attempt_state != Some(TaskAttemptState::Terminal))
        {
            return Err(ledger_invalid());
        }
        Ok(())
    }
}

impl StoredCommandResult {
    fn result(&self, reference: &StoredAttemptRef) -> Result<TaskCommandResult, AgentError> {
        let outcome = TaskCommandOutcomeState::try_from(self.outcome)
            .ok()
            .filter(|outcome| *outcome != TaskCommandOutcomeState::Unspecified)
            .ok_or_else(ledger_invalid)?;
        Ok(TaskCommandResult {
            outcome: TaskCommandOutcomeV1 {
                attempt: Some(reference.message()),
                command_id: self.command_id.clone(),
                payload_digest: self.payload_digest.clone(),
                outcome: outcome as i32,
                source_frame_sequence: self.source_frame_sequence,
                error_code: self.command_error_code.clone(),
            },
            receipt: TaskAttemptReceiptV1 {
                receipt_version: RECEIPT_VERSION,
                attempt: Some(reference.message()),
                attempt_state: self.attempt_state,
                last_command_id: self.command_id.clone(),
                last_command_sequence: self.sequence,
                last_command_generation: self.generation,
                last_command_payload_digest: self.payload_digest.clone(),
                side_effect_state: self.side_effect_state,
                last_side_effect_command_id: self.last_side_effect_command_id.clone(),
                input_state: self.input_state,
                capture_state: self.capture_state,
                owned_target_state: self.owned_target_state,
                cleanup_complete: Some(self.cleanup_complete),
                error_code: self.receipt_error_code.clone(),
            },
        })
    }

    fn validate(&self) -> bool {
        let cleanup_complete = self.attempt_state == TaskAttemptState::Terminal as i32
            && self.input_state == TaskInputState::Released as i32
            && matches!(
                TaskCaptureState::try_from(self.capture_state),
                Ok(TaskCaptureState::NotStarted | TaskCaptureState::Stopped)
            )
            && matches!(
                TaskOwnedTargetState::try_from(self.owned_target_state),
                Ok(TaskOwnedTargetState::NotStarted
                    | TaskOwnedTargetState::Running
                    | TaskOwnedTargetState::Closed)
            )
            && !matches!(
                TaskSideEffectState::try_from(self.side_effect_state),
                Ok(TaskSideEffectState::IntentRecorded | TaskSideEffectState::Uncertain)
            );
        !self.command_id.is_empty()
            && is_digest(&self.payload_digest)
            && TaskCommandOutcomeState::try_from(self.outcome)
                .is_ok_and(|outcome| outcome != TaskCommandOutcomeState::Unspecified)
            && TaskAttemptState::try_from(self.attempt_state)
                .is_ok_and(|state| state != TaskAttemptState::Unspecified)
            && TaskSideEffectState::try_from(self.side_effect_state)
                .is_ok_and(|state| state != TaskSideEffectState::Unspecified)
            && TaskInputState::try_from(self.input_state)
                .is_ok_and(|state| state != TaskInputState::Unspecified)
            && TaskCaptureState::try_from(self.capture_state)
                .is_ok_and(|state| state != TaskCaptureState::Unspecified)
            && TaskOwnedTargetState::try_from(self.owned_target_state)
                .is_ok_and(|state| state != TaskOwnedTargetState::Unspecified)
            && self.cleanup_complete == cleanup_complete
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
        || !matches!(reference.contract_version, 1 | 2)
        || !is_digest(&reference.contract_digest)
    {
        return Err(task_ref_invalid());
    }
    Ok((reference, command))
}

fn verify_stored_contract(contract: &AgentAttemptContractV1) -> Result<(), AgentError> {
    if contract.contract_version == 1 {
        return verify_agent_attempt_contract(contract)
            .map_err(|error| AgentError::new(error.code(), error.to_string()));
    }
    if contract.contract_version != 2
        || contract.cleanup_policy != "release_input_and_close_owned_target"
        || !is_uuid(&contract.task_run_id)
        || !is_uuid(&contract.attempt_id)
        || contract.agent_build_id.is_empty()
        || contract.profile_id.is_empty()
        || !is_digest(&contract.profile_digest)
        || !is_digest(&contract.contract_digest)
    {
        return Err(AgentError::new(
            "task.contract_value_invalid",
            "translated v2 task contract is invalid",
        ));
    }
    Ok(())
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
            AgentError::new(
                "task.ledger_not_found",
                "task attempt ledger does not exist",
            )
        } else {
            io_error("task.ledger_unavailable", error)
        }
    })?;
    let mut last = None;
    let mut command_results = BTreeMap::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| io_error("task.ledger_unavailable", error))?;
        if line.len() > MAX_RECORD_BYTES {
            return Err(ledger_invalid());
        }
        let mut state =
            serde_json::from_str::<AttemptState>(&line).map_err(|_| ledger_invalid())?;
        for (command_id, result) in std::mem::take(&mut state.command_results) {
            command_results.insert(command_id, result);
        }
        if state.last_command_outcome != TaskCommandOutcomeState::Unspecified as i32 {
            state.store_current_result()?;
            for (command_id, result) in std::mem::take(&mut state.command_results) {
                command_results.insert(command_id, result);
            }
        }
        last = Some(state);
    }
    let mut state = last.ok_or_else(ledger_invalid)?;
    state.command_results = command_results;
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
                sequence: payload as u64,
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

    fn target_binding(hwnd: u64, started_at: u64) -> TargetBinding {
        TargetBinding {
            profile_id: "genshin-impact".into(),
            profile_version: "1.0.0".into(),
            process_id: 42,
            process_name: "YuanShen.exe".into(),
            process_started_at_unix_ms: started_at,
            process_path_sha256: "11".repeat(32),
            window_handle: hwnd,
            window_title: "原神".into(),
            window_class: "UnityWndClass".into(),
            client_rect: fairypam_agent_core::target::ClientRect {
                width: 1920,
                height: 1080,
            },
            dpi: 96,
            integrity: fairypam_agent_core::target::IntegrityLevel::High,
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
        let conflict = TaskAttemptRuntime::at(root.clone())
            .begin(&changed, &contract)
            .unwrap();
        assert_eq!(
            conflict.error_code.as_deref(),
            Some("command.payload_digest_conflict")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn historical_command_replay_and_digest_conflict_survive_restart() {
        let root = temporary_root();
        let contract = contract();
        let mut begin = task(&contract, "begin-1", 'a');
        begin.command.as_mut().unwrap().sequence = 1;
        let first = task(&contract, "release-1", 'b');
        let second = task(&contract, "release-2", 'c');
        let changed_first = task(&contract, "release-1", 'd');
        let later_effect = task(&contract, "pulse-3", 'e');
        let mut runtime = TaskAttemptRuntime::at(root.clone());
        runtime.begin(&begin, &contract).unwrap();
        for command in [&first, &second] {
            assert!(runtime.prepare(command, false).unwrap().is_none());
            assert_eq!(
                runtime
                    .complete_release(command, None)
                    .unwrap()
                    .outcome
                    .outcome,
                TaskCommandOutcomeState::Applied as i32
            );
        }

        let replay = TaskAttemptRuntime::at(root.clone())
            .replay(&first)
            .unwrap()
            .unwrap();
        assert_eq!(replay.outcome.command_id, "release-1");
        assert_eq!(replay.receipt.last_command_id, "release-1");
        assert_eq!(
            replay.outcome.outcome,
            TaskCommandOutcomeState::Applied as i32
        );

        let conflict = TaskAttemptRuntime::at(root.clone())
            .replay(&changed_first)
            .unwrap()
            .unwrap();
        assert_eq!(conflict.outcome.command_id, "release-1");
        assert_eq!(conflict.outcome.payload_digest, "d".repeat(64));
        assert_eq!(
            conflict.outcome.outcome,
            TaskCommandOutcomeState::Uncertain as i32
        );
        assert_eq!(conflict.receipt.last_command_id, "release-1");
        assert_eq!(conflict.receipt.last_command_payload_digest, "b".repeat(64));
        assert_eq!(
            conflict.receipt.error_code.as_deref(),
            Some("command.payload_digest_conflict")
        );

        let error = match TaskAttemptRuntime::at(root.clone()).prepare(&later_effect, true) {
            Err(error) => error,
            Ok(_) => panic!("digest conflict must block later side effects"),
        };
        assert_eq!(error.code(), "side_effect_uncertain");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn business_capacity_keeps_recovery_slots_available() {
        let contract = contract();
        let mut begin = task(&contract, "begin-1", 'a');
        begin.command.as_mut().unwrap().sequence = 1;
        let mut runtime = TaskAttemptRuntime::memory();
        runtime.begin(&begin, &contract).unwrap();
        let template = runtime
            .active
            .as_ref()
            .unwrap()
            .command_results
            .values()
            .next()
            .unwrap()
            .clone();
        for sequence in 2..=MAX_BUSINESS_COMMAND_RESULTS as u64 {
            let mut result = template.clone();
            result.command_id = format!("command-{sequence}");
            result.sequence = sequence;
            result.payload_digest = format!("{sequence:064x}");
            runtime
                .active
                .as_mut()
                .unwrap()
                .command_results
                .insert(result.command_id.clone(), result);
        }

        let mut overflow = task(&contract, "business-overflow", 'c');
        overflow.command.as_mut().unwrap().sequence = 1_000;
        let error = match runtime.prepare(&overflow, false) {
            Err(error) => error,
            Ok(_) => panic!("business commands must not consume recovery slots"),
        };
        assert_eq!(error.code(), "task.ledger_full");

        let mut restarted = runtime;
        for index in 0..MAX_INSPECT_COMMAND_RESULTS {
            let mut inspect = task(&contract, &format!("recovery-inspect-{index}"), 'c');
            inspect.command.as_mut().unwrap().sequence = 1_001 + index as u64;
            restarted.inspect(&inspect).unwrap();
        }
        let mut inspect_overflow = task(&contract, "recovery-inspect-overflow", 'c');
        inspect_overflow.command.as_mut().unwrap().sequence = 1_100;
        let error = restarted.inspect(&inspect_overflow).unwrap_err();
        assert_eq!(error.code(), "task.ledger_full");

        for index in 0..MAX_RELEASE_COMMAND_RESULTS {
            let mut release = task(&contract, &format!("recovery-release-{index}"), 'd');
            release.command.as_mut().unwrap().sequence = 1_101 + index as u64;
            assert!(restarted.prepare_recovery(&release).unwrap().is_none());
            restarted.complete_release(&release, None).unwrap();
        }
        let mut release_overflow = task(&contract, "recovery-release-overflow", 'd');
        release_overflow.command.as_mut().unwrap().sequence = 1_200;
        let error = match restarted.prepare_recovery(&release_overflow) {
            Err(error) => error,
            Ok(_) => panic!("release commands must not consume finish slots"),
        };
        assert_eq!(error.code(), "task.ledger_full");

        let mut finish = task(&contract, "recovery-finish", 'e');
        finish.command.as_mut().unwrap().sequence = 1_201;
        assert!(restarted.prepare_finish(&finish).unwrap().is_none());
        let completed = restarted
            .complete_finish(&finish, true, true, true, None)
            .unwrap();
        assert_eq!(
            completed.outcome.outcome,
            TaskCommandOutcomeState::Applied as i32
        );
        assert_eq!(completed.receipt.cleanup_complete, Some(true));
    }

    #[test]
    fn command_capacity_matches_the_shared_product_budget() {
        let budget: serde_json::Value = serde_json::from_str(include_str!(
            "../../../proto/fairypam/agent/v2/testdata/task-command-budget.json"
        ))
        .unwrap();
        assert_eq!(
            budget["business_command_results"].as_u64().unwrap() as usize,
            MAX_BUSINESS_COMMAND_RESULTS
        );
        assert_eq!(
            budget["recovery_command_results"].as_u64().unwrap() as usize,
            MAX_RECOVERY_COMMAND_RESULTS
        );
        assert_eq!(
            budget["inspect_command_results"].as_u64().unwrap() as usize,
            MAX_INSPECT_COMMAND_RESULTS
        );
        assert_eq!(
            budget["release_command_results"].as_u64().unwrap() as usize,
            MAX_RELEASE_COMMAND_RESULTS
        );
        assert_eq!(
            budget["finish_command_results"].as_u64().unwrap() as usize,
            MAX_FINISH_COMMAND_RESULTS
        );
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
            .replay(&effect)
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

    #[test]
    fn refreshed_window_must_stay_on_the_claimed_owned_process() {
        let contract = contract();
        let begin = task(&contract, "begin-1", 'a');
        let start = task(&contract, "target-1", 'b');
        let mut runtime = TaskAttemptRuntime::memory();
        runtime.begin(&begin, &contract).unwrap();
        assert!(runtime.prepare(&start, true).unwrap().is_none());
        runtime
            .complete_target_start(&start, Some(target_binding(1, 100)), None)
            .unwrap();
        let reference = start.attempt.as_ref().unwrap();

        runtime
            .refresh_owned_target(reference, target_binding(2, 100))
            .unwrap();
        assert_eq!(
            runtime.owned_target(&start).unwrap().unwrap().window_handle,
            2
        );
        assert_eq!(
            runtime
                .refresh_owned_target(reference, target_binding(3, 101))
                .unwrap_err()
                .code(),
            "target.stale"
        );
    }

    #[test]
    fn emergency_stop_marker_survives_restart_until_local_reset() {
        let root = temporary_root();
        let contract = contract();
        let begin = task(&contract, "begin-1", 'c');
        let mut runtime = TaskAttemptRuntime::at(root.clone());
        runtime.begin(&begin, &contract).unwrap();
        runtime.set_emergency_stopped(true).unwrap();
        assert!(runtime
            .emergency_finish(true, true, true, None)
            .unwrap()
            .unwrap()
            .cleanup_complete
            .unwrap());

        let mut restarted = TaskAttemptRuntime::at(root.clone());
        assert!(restarted.emergency_stopped().unwrap());
        assert_eq!(
            restarted.begin(&begin, &contract).unwrap_err().code(),
            "emergency_stopped"
        );
        restarted.reset_emergency().unwrap();
        assert!(!TaskAttemptRuntime::at(root.clone())
            .emergency_stopped()
            .unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_terminal_cleanup_can_be_inspected_and_retried() {
        let root = temporary_root();
        let contract = contract();
        let begin = task(&contract, "begin-1", 'a');
        let first_finish = task(&contract, "finish-1", 'b');
        let mut runtime = TaskAttemptRuntime::at(root.clone());
        runtime.begin(&begin, &contract).unwrap();
        assert!(runtime.prepare_finish(&first_finish).unwrap().is_none());
        let incomplete = runtime
            .complete_finish(
                &first_finish,
                false,
                true,
                false,
                Some("cleanup_incomplete"),
            )
            .unwrap();
        assert_eq!(
            incomplete.outcome.outcome,
            TaskCommandOutcomeState::Uncertain as i32
        );
        assert_eq!(incomplete.receipt.cleanup_complete, Some(false));

        let inspect = task(&contract, "inspect-1", 'c');
        assert_eq!(
            TaskAttemptRuntime::at(root.clone())
                .inspect(&inspect)
                .unwrap()
                .cleanup_complete,
            Some(false)
        );
        let retry = task(&contract, "finish-2", 'd');
        let mut restarted = TaskAttemptRuntime::at(root.clone());
        assert!(restarted.prepare_finish(&retry).unwrap().is_none());
        let complete = restarted
            .complete_finish(&retry, true, true, true, None)
            .unwrap();
        assert_eq!(
            complete.outcome.outcome,
            TaskCommandOutcomeState::Applied as i32
        );
        assert_eq!(complete.receipt.cleanup_complete, Some(true));
        fs::remove_dir_all(root).unwrap();
    }
}
