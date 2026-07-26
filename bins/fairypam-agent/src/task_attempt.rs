use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v1::{
    AgentAttemptContractV1, AttemptRef, TaskAttemptReceiptV1, TaskAttemptState, TaskCaptureState,
    TaskCommandRef, TaskInputState, TaskOwnedTargetState, TaskSideEffectState,
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
            return Ok(not_found_receipt());
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
            if state.attempt_state == TaskAttemptState::Terminal as i32 {
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
    side_effect_state: i32,
    last_side_effect_command_id: String,
    input_state: i32,
    capture_state: i32,
    owned_target_state: i32,
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
            side_effect_state: TaskSideEffectState::None as i32,
            last_side_effect_command_id: String::new(),
            input_state: TaskInputState::Released as i32,
            capture_state: TaskCaptureState::NotStarted as i32,
            owned_target_state: TaskOwnedTargetState::NotStarted as i32,
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

    fn validate(&self) -> Result<(), AgentError> {
        let contract = self.contract.message();
        verify_agent_attempt_contract(&contract)
            .map_err(|error| AgentError::new(error.code(), error.to_string()))?;
        let reference = self.reference.message();
        validate_contract_reference(&reference, &contract)?;
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
    let file = fs::File::open(path).map_err(|error| io_error("task.ledger_unavailable", error))?;
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
