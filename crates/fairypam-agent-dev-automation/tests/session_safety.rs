use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use fairypam_agent_core::state::Effect;
use fairypam_agent_dev_automation::{
    AutomationCapability, AutomationTarget, DevSessionManager, DevSessionRequest,
    DevSessionRevocationReason,
};

#[test]
fn expiry_disconnect_and_emergency_stop_revoke_and_release() {
    let now = Instant::now();
    let mut sessions = DevSessionManager::default();
    let session = sessions
        .create(
            "S-1-5-21-owner",
            AutomationTarget::Testbed,
            BTreeSet::from([AutomationCapability::Input]),
            now + Duration::from_secs(1),
            "build-1",
            now,
        )
        .unwrap();
    assert_ne!(session.audit_id, [0; 16]);
    assert_eq!(
        sessions.on_expiry(session.nonce, now + Duration::from_secs(2)),
        vec![Effect::ReleaseAll]
    );
    assert_eq!(
        sessions.last_revocation().unwrap().reason,
        DevSessionRevocationReason::Expired
    );
    assert_eq!(
        sessions.last_revocation().unwrap().audit_id,
        session.audit_id
    );
    assert_eq!(
        sessions
            .authorize(session.nonce, AutomationCapability::Input, now)
            .unwrap_err()
            .code(),
        "dev.session.missing"
    );

    let session = sessions
        .create(
            "S-1-5-21-owner",
            AutomationTarget::Testbed,
            BTreeSet::from([AutomationCapability::Input]),
            now + Duration::from_secs(1),
            "build-1",
            now,
        )
        .unwrap();
    assert_eq!(
        sessions.on_client_disconnect(session.nonce),
        vec![Effect::ReleaseAll]
    );
    assert_eq!(
        sessions.last_revocation().unwrap().reason,
        DevSessionRevocationReason::ClientDisconnected
    );
    assert!(sessions.emergency_stop().is_empty());
}

#[test]
fn active_session_cannot_be_replaced_without_a_release() {
    let now = Instant::now();
    let mut sessions = DevSessionManager::default();
    let active = sessions
        .create(
            "S-1-5-21-owner",
            AutomationTarget::Testbed,
            BTreeSet::from([AutomationCapability::Input]),
            now + Duration::from_secs(1),
            "build-1",
            now,
        )
        .unwrap();
    assert_eq!(
        sessions
            .create(
                "S-1-5-21-owner",
                AutomationTarget::Testbed,
                BTreeSet::from([AutomationCapability::Input]),
                now + Duration::from_secs(1),
                "build-2",
                now,
            )
            .unwrap_err()
            .code(),
        "dev.session.already_active"
    );
    assert!(sessions
        .authorize(active.nonce, AutomationCapability::Input, now)
        .is_ok());
    assert_eq!(sessions.emergency_stop(), vec![Effect::ReleaseAll]);
    assert_eq!(
        sessions.last_revocation().unwrap().reason,
        DevSessionRevocationReason::EmergencyStop
    );
    assert_eq!(
        sessions.last_revocation().unwrap().audit_id,
        active.audit_id
    );
}

#[test]
fn validated_protocol_nonce_is_bound_to_the_dev_session() {
    let now = Instant::now();
    let nonce = [42; 32];
    let mut sessions = DevSessionManager::default();
    let session = sessions
        .create_with_nonce(
            nonce,
            DevSessionRequest {
                caller_sid: "S-1-5-21-owner".into(),
                target: AutomationTarget::Testbed,
                capabilities: BTreeSet::from([AutomationCapability::Capture]),
                expires_at: now + Duration::from_secs(1),
                build_id: "build-1".into(),
            },
            now,
        )
        .unwrap();
    assert_eq!(session.nonce, nonce);
    assert_eq!(
        sessions.active_expires_at(),
        Some(now + Duration::from_secs(1))
    );
    assert!(sessions
        .authorize(nonce, AutomationCapability::Capture, now)
        .is_ok());
    assert!(sessions
        .expire_active(now + Duration::from_secs(2))
        .is_empty());
    assert_eq!(
        sessions.last_revocation().unwrap().reason,
        DevSessionRevocationReason::Expired
    );
}

#[test]
fn live_game_and_expired_or_missing_capabilities_are_denied() {
    let now = Instant::now();
    let mut sessions = DevSessionManager::default();
    assert_eq!(
        sessions
            .create(
                "S",
                AutomationTarget::LiveGame,
                BTreeSet::from([AutomationCapability::Input]),
                now + Duration::from_secs(1),
                "build",
                now
            )
            .unwrap_err()
            .code(),
        "dev.session.target_denied"
    );
    let session = sessions
        .create(
            "S",
            AutomationTarget::Testbed,
            BTreeSet::from([AutomationCapability::Capture]),
            now + Duration::from_secs(1),
            "build",
            now,
        )
        .unwrap();
    assert_eq!(
        sessions
            .authorize(session.nonce, AutomationCapability::Input, now)
            .unwrap_err()
            .code(),
        "dev.session.capability_denied"
    );
}
