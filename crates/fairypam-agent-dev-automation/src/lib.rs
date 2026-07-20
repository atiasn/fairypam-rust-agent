//! Feature-gated Dev Automation session authority.

mod artifact;
mod session;

pub use artifact::{
    replace_current_slot, verify_dev_artifact, ArtifactFile, DevArtifactError, DevArtifactReceipt,
    RunIdentity,
};

pub use session::{
    AutomationCapability, AutomationTarget, DevSession, DevSessionError, DevSessionManager,
    DevSessionRequest, DevSessionRevocation, DevSessionRevocationReason,
};
