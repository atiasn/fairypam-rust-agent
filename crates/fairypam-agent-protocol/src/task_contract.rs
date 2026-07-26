use std::fmt;

use sha2::{Digest, Sha256};

use crate::v1::AgentAttemptContractV1;

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
}
