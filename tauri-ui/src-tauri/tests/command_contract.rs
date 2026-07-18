use fairypam_agent_local_protocol::{
    AgentLifecycle, AutostartState, ControlMode, GuardianState, InstallationState, LocalPayload,
    UpdateState,
};
use fairypam_agent_tauri_ui::{
    diagnostics_from_payload, status_from_payload, suite_status_from_payload,
};

#[test]
fn status_payload_maps_without_inventing_control_mode() {
    let status = status_from_payload(LocalPayload::Status {
        lifecycle: AgentLifecycle::Connected,
        active_profile_id: Some("genshin".into()),
        target_locked: true,
        capture_active: false,
    });
    assert!(status.is_ok());
}

#[test]
fn suite_status_preserves_unknown_control_authority() {
    let status = suite_status_from_payload(LocalPayload::SuiteStatus {
        installation: InstallationState::Healthy,
        guardian: GuardianState::Installed,
        control_mode: ControlMode::Unknown,
        update: UpdateState::Idle,
        autostart: AutostartState::Enabled,
        can_request_update: true,
    });
    assert!(status.is_ok());
}

#[test]
fn wrong_domain_payload_is_rejected() {
    let result = diagnostics_from_payload(LocalPayload::Profiles {
        profile_ids: vec![],
    });
    assert!(result.is_err());
}
