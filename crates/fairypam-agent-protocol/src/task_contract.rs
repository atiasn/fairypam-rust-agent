use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    v1::AgentAttemptContractV1,
    v2::{
        command_identity, hub_control_command, AttemptRef, CleanupPolicy, ExecutionCapability,
        ExecutionContract, HubControlCommand, TaskCommandRef,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractError(&'static str);

impl ContractError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ContractError {}

pub fn canonical_agent_attempt_contract(
    contract: &AgentAttemptContractV1,
) -> Result<String, ContractError> {
    if !is_uuid(&contract.task_run_id) || !is_uuid(&contract.attempt_id) {
        return Err(ContractError("task.contract_uuid_invalid"));
    }
    if !is_safe(&contract.agent_build_id) || !is_safe(&contract.profile_id) {
        return Err(ContractError("task.contract_string_invalid"));
    }
    if !is_digest(&contract.profile_digest) {
        return Err(ContractError("task.contract_digest_invalid"));
    }
    if contract.contract_version != 1 || contract.cleanup_policy != "close_owned_target" {
        return Err(ContractError("task.contract_value_invalid"));
    }

    Ok(format!(
        concat!(
            "{{\"agent_build_id\":\"{}\",\"attempt_id\":\"{}\",",
            "\"cleanup_policy\":\"{}\",\"contract_version\":{},",
            "\"profile_digest\":\"{}\",\"profile_id\":\"{}\",",
            "\"task_run_id\":\"{}\"}}"
        ),
        contract.agent_build_id,
        contract.attempt_id,
        contract.cleanup_policy,
        contract.contract_version,
        contract.profile_digest,
        contract.profile_id,
        contract.task_run_id,
    ))
}

pub fn verify_agent_attempt_contract(
    contract: &AgentAttemptContractV1,
) -> Result<(), ContractError> {
    if !is_digest(&contract.contract_digest) {
        return Err(ContractError("task.contract_digest_invalid"));
    }
    let canonical = canonical_agent_attempt_contract(contract)?;
    let digest = Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != contract.contract_digest {
        return Err(ContractError("task.contract_mismatch"));
    }
    Ok(())
}

pub fn canonical_execution_contract(contract: &ExecutionContract) -> Result<String, ContractError> {
    if !is_uuid(&contract.task_run_id) || !is_uuid(&contract.attempt_id) {
        return Err(ContractError("task.contract_uuid_invalid"));
    }
    if !is_safe(&contract.agent_build_id) || !is_safe(&contract.profile_id) {
        return Err(ContractError("task.contract_string_invalid"));
    }
    if !is_digest(&contract.profile_digest)
        || contract.contract_version != 2
        || contract.deadline_unix_ms <= 0
        || contract.max_input_lease_ms == 0
        || contract.cleanup_policy != CleanupPolicy::ReleaseInputAndCloseOwnedTarget as i32
        || contract.allowed_capabilities.is_empty()
    {
        return Err(ContractError("task.contract_value_invalid"));
    }
    let mut previous = 0;
    for capability in &contract.allowed_capabilities {
        if *capability <= previous
            || ExecutionCapability::try_from(*capability).is_err()
            || *capability == ExecutionCapability::Unspecified as i32
        {
            return Err(ContractError("task.contract_value_invalid"));
        }
        previous = *capability;
    }
    let capabilities = contract
        .allowed_capabilities
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{\"agent_build_id\":\"{}\",\"allowed_capabilities\":[{}],",
            "\"attempt_id\":\"{}\",\"cleanup_policy\":{},",
            "\"contract_version\":{},\"deadline_unix_ms\":{},",
            "\"max_input_lease_ms\":{},\"profile_digest\":\"{}\",",
            "\"profile_id\":\"{}\",\"task_run_id\":\"{}\"}}"
        ),
        contract.agent_build_id,
        capabilities,
        contract.attempt_id,
        contract.cleanup_policy,
        contract.contract_version,
        contract.deadline_unix_ms,
        contract.max_input_lease_ms,
        contract.profile_digest,
        contract.profile_id,
        contract.task_run_id,
    ))
}

pub fn verify_execution_contract(contract: &ExecutionContract) -> Result<(), ContractError> {
    if !is_digest(&contract.contract_digest) {
        return Err(ContractError("task.contract_digest_invalid"));
    }
    let digest = Sha256::digest(canonical_execution_contract(contract)?.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != contract.contract_digest {
        return Err(ContractError("task.contract_mismatch"));
    }
    Ok(())
}

pub fn verify_task_command_digest(command: &HubControlCommand) -> Result<(), ContractError> {
    use hub_control_command::Payload;

    let (task, kind, payload) = match command.payload.as_ref() {
        Some(Payload::BeginAttempt(value)) => (
            task(value.reference.as_ref())?,
            "BeginAttempt",
            serde_json::json!({"contract": execution_contract_value(value.contract.as_ref().ok_or(ContractError("command.payload_invalid"))?)}),
        ),
        Some(Payload::StartAttemptTarget(value)) => (
            task(value.reference.as_ref())?,
            "StartAttemptTarget",
            serde_json::json!({}),
        ),
        Some(Payload::StartCapture(value)) => (
            task(value.reference.as_ref())?,
            "StartCapture",
            serde_json::json!({
                "capture_source_id": value.capture_source_id,
                "encoding": value.encoding,
                "fps": value.fps,
                "quality": value.quality,
            }),
        ),
        Some(Payload::CaptureFrame(value)) => (
            task(value.reference.as_ref())?,
            "CaptureFrame",
            serde_json::json!({
                "capture_source_id": value.capture_source_id,
                "encoding": value.encoding,
                "quality": value.quality,
            }),
        ),
        Some(Payload::StopCapture(value)) => (
            task(value.reference.as_ref())?,
            "StopCapture",
            serde_json::json!({"capture_source_id": value.capture_source_id}),
        ),
        Some(Payload::InputFrame(value)) => {
            let mut payload = serde_json::json!({
                "held_keys": value.held_keys.iter().map(|key| serde_json::json!({
                    "extended": key.extended,
                    "scan_code": key.scan_code,
                })).collect::<Vec<_>>(),
                "held_mouse_buttons": value.held_mouse_buttons,
                "input_sequence": value.input_sequence,
                "lease_ms": value.lease_ms,
                "wheel_delta": value.wheel_delta,
            });
            if let Some(source) = value.source_frame_sequence {
                payload["source_frame_sequence"] = serde_json::json!(source);
            }
            (task(value.reference.as_ref())?, "InputFrame", payload)
        }
        Some(Payload::ReleaseAll(value)) => match task_optional(value.reference.as_ref())? {
            Some(task) => (
                task,
                "ReleaseAll",
                serde_json::json!({"reason_code": value.reason_code}),
            ),
            None => return Ok(()),
        },
        Some(Payload::FinishAttempt(value)) => (
            task(value.reference.as_ref())?,
            "FinishAttempt",
            serde_json::json!({}),
        ),
        Some(Payload::InspectAttempt(value)) => (
            task(value.reference.as_ref())?,
            "InspectAttempt",
            serde_json::json!({}),
        ),
        _ => return Ok(()),
    };
    if !is_digest(&task.payload_digest) {
        return Err(ContractError("command.payload_digest_invalid"));
    }
    let attempt = task
        .attempt
        .as_ref()
        .ok_or(ContractError("command.identity_invalid"))?;
    let canonical = serde_json::to_vec(&serde_json::json!({
        "attempt": attempt_value(attempt),
        "kind": format!("fairypam.agent.v2.{kind}"),
        "payload": payload,
    }))
    .map_err(|_| ContractError("command.payload_invalid"))?;
    let digest = Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != task.payload_digest {
        return Err(ContractError("command.payload_digest_conflict"));
    }
    Ok(())
}

fn task(identity: Option<&crate::v2::CommandIdentity>) -> Result<&TaskCommandRef, ContractError> {
    task_optional(identity)?.ok_or(ContractError("command.identity_invalid"))
}

fn task_optional(
    identity: Option<&crate::v2::CommandIdentity>,
) -> Result<Option<&TaskCommandRef>, ContractError> {
    match identity.and_then(|identity| identity.value.as_ref()) {
        Some(command_identity::Value::Task(task)) => Ok(Some(task)),
        Some(command_identity::Value::Command(_)) => Ok(None),
        None => Err(ContractError("command.identity_invalid")),
    }
}

fn attempt_value(attempt: &AttemptRef) -> serde_json::Value {
    serde_json::json!({
        "attempt_id": attempt.attempt_id,
        "contract_digest": attempt.contract_digest,
        "contract_version": attempt.contract_version,
        "task_run_id": attempt.task_run_id,
    })
}

fn execution_contract_value(contract: &ExecutionContract) -> serde_json::Value {
    serde_json::json!({
        "agent_build_id": contract.agent_build_id,
        "allowed_capabilities": contract.allowed_capabilities,
        "attempt_id": contract.attempt_id,
        "cleanup_policy": contract.cleanup_policy,
        "contract_digest": contract.contract_digest,
        "contract_version": contract.contract_version,
        "deadline_unix_ms": contract.deadline_unix_ms,
        "max_input_lease_ms": contract.max_input_lease_ms,
        "profile_digest": contract.profile_digest,
        "profile_id": contract.profile_id,
        "task_run_id": contract.task_run_id,
    })
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_safe(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            let allowed = byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'+' | b'-');
            allowed && (index != 0 || byte.is_ascii_alphanumeric())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL: &str = include_str!(
        "../../../proto/fairypam/agent/v1/testdata/agent-attempt-contract-v1.canonical.json"
    );
    const DIGEST: &str =
        include_str!("../../../proto/fairypam/agent/v1/testdata/agent-attempt-contract-v1.sha256");

    fn contract() -> AgentAttemptContractV1 {
        AgentAttemptContractV1 {
            task_run_id: "11111111-1111-4111-8111-111111111111".into(),
            attempt_id: "22222222-2222-4222-8222-222222222222".into(),
            agent_build_id: "build-2026.07.27".into(),
            profile_id: "genshin-impact".into(),
            profile_digest: "b".repeat(64),
            cleanup_policy: "close_owned_target".into(),
            contract_version: 1,
            contract_digest: DIGEST.trim().into(),
        }
    }

    #[test]
    fn shared_golden_vector_is_canonical_and_verified() {
        let contract = contract();
        assert_eq!(
            canonical_agent_attempt_contract(&contract).unwrap(),
            CANONICAL.trim()
        );
        verify_agent_attempt_contract(&contract).unwrap();
    }

    #[test]
    fn rejects_noncanonical_or_mismatched_contracts() {
        let mut invalid = contract();
        invalid.task_run_id = "AAAAAAAA-1111-4111-8111-111111111111".into();
        assert_eq!(
            verify_agent_attempt_contract(&invalid).unwrap_err().code(),
            "task.contract_uuid_invalid"
        );

        let mut mismatched = contract();
        mismatched.profile_id = "genshin-impact-beta".into();
        assert_eq!(
            verify_agent_attempt_contract(&mismatched)
                .unwrap_err()
                .code(),
            "task.contract_mismatch"
        );
    }

    #[test]
    fn shared_v2_execution_contract_is_canonical_and_verified() {
        let mut contract = ExecutionContract {
            task_run_id: "11111111-1111-4111-8111-111111111111".into(),
            attempt_id: "22222222-2222-4222-8222-222222222222".into(),
            agent_build_id: "build-2026.07.28".into(),
            profile_id: "genshin-impact".into(),
            profile_digest: "b".repeat(64),
            allowed_capabilities: vec![1, 2, 3, 4],
            deadline_unix_ms: 1_785_258_000_000,
            max_input_lease_ms: 1_000,
            cleanup_policy: CleanupPolicy::ReleaseInputAndCloseOwnedTarget as i32,
            contract_version: 2,
            contract_digest: include_str!(
                "../../../proto/fairypam/agent/v2/testdata/execution-contract.sha256"
            )
            .trim()
            .into(),
        };
        assert_eq!(
            canonical_execution_contract(&contract).unwrap(),
            include_str!(
                "../../../proto/fairypam/agent/v2/testdata/execution-contract.canonical.json"
            )
            .trim()
        );
        verify_execution_contract(&contract).unwrap();

        contract.allowed_capabilities.swap(0, 1);
        assert_eq!(
            verify_execution_contract(&contract).unwrap_err().code(),
            "task.contract_value_invalid"
        );
    }
}
