pub mod internal_v1 {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("fairypam.internal.v1");
}

pub mod v3 {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("fairypam.agent.v3");
}

pub mod worker_v1 {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("fairypam.worker.v1");
}

pub mod local_v1 {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("fairypam.local.v1");
}

pub mod guardian_v1 {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("fairypam.guardian.v1");
}

mod agent_local;
mod local;
mod task_contract;
mod telemetry;

pub const AGENT_PROTOCOL_MAJOR: u32 = 3;
pub const AGENT_PROTOCOL_MINOR: u32 = 1;

pub use agent_local::{
    decode_local_control_envelope, encode_local_control_envelope, validate_local_control_request,
    LocalControlProtocolError, LOCAL_AGENT_PIPE_NAME, LOCAL_CONTROL_PROTOCOL_MAJOR,
    LOCAL_CONTROL_PROTOCOL_MINOR,
};
pub use local::{
    decode_local_envelope, encode_local_envelope, verify_worker_request,
    worker_realtime_metrics_digest, worker_request_digest, LocalProtocolError,
    LOCAL_PROTOCOL_MAJOR, LOCAL_PROTOCOL_MINOR, MAX_LOCAL_MESSAGE_BYTES,
};

#[cfg(windows)]
pub use agent_local::{
    connect_local_agent_pipe, read_local_control_frame, write_local_control_frame,
    SecureLocalPipeListener,
};

pub use task_contract::{
    canonical_agent_attempt_contract, canonical_execution_contract, verify_agent_attempt_contract,
    verify_execution_contract, verify_task_command_digest, ContractError,
};
pub use telemetry::{
    canonical_telemetry_record, decode_telemetry_record, encode_telemetry_record,
    TelemetryCanonicalError,
};
