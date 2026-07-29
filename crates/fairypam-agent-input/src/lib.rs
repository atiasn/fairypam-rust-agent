//! Profile-bound semantic input and lease safety.

mod action;
mod lease;
mod release;

pub use action::{ActionMap, InputPlatform, ResolvedAction, SemanticMouseButton};
pub use fairypam_agent_guardian_protocol::{ActionId, PhysicalHold, ReleaseReason};
pub use lease::{GuardianClient, InputLease, InputPermit, LeaseExecutor, SafetyError, SessionKey};
pub use release::GuardianProcessClient;
