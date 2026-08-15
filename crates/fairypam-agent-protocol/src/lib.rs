pub mod v1 {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("fairypam.agent.v1");
}

pub mod v2 {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("fairypam.agent.v2");
}

mod task_contract;
mod telemetry;

pub use task_contract::{
    canonical_agent_attempt_contract, canonical_execution_contract, verify_agent_attempt_contract,
    verify_execution_contract, verify_task_command_digest, ContractError,
};
pub use telemetry::{
    canonical_telemetry_record, decode_telemetry_record, encode_telemetry_record,
    TelemetryCanonicalError,
};
