pub mod v1 {
    tonic::include_proto!("fairypam.agent.v1");
}

mod task_contract;

pub use task_contract::{
    canonical_agent_attempt_contract, verify_agent_attempt_contract, ContractError,
};
