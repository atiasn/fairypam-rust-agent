use std::collections::BTreeSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_local_client::CallerIdentity;
use fairypam_agent_local_protocol::{
    random_nonce, AutomationCapability, AutomationTarget, LocalErrorCode, ProtocolError,
};

#[cfg(windows)]
pub mod provision;

pub const MAX_AUTOMATION_TTL: Duration = Duration::from_secs(30);
pub const MAX_LIVE_GAME_ARM_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomationSession {
    pub session_id: String,
    pub caller_process_id: u32,
    pub caller_user_sid_hash: String,
    pub caller_logon_sid_hash: String,
    pub caller_session_id: u32,
    pub target: AutomationTarget,
    pub capabilities: BTreeSet<AutomationCapability>,
    pub expires_at: Instant,
    pub expires_at_unix_ms: u64,
    pub audit_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveGameArmChallenge {
    pub challenge_id: String,
    pub caller_process_id: u32,
    pub caller_user_sid_hash: String,
    pub caller_logon_sid_hash: String,
    pub caller_session_id: u32,
    pub profile_id: String,
    pub allowed_actions: BTreeSet<String>,
    pub build_id: String,
    pub expires_at: Instant,
}

impl LiveGameArmChallenge {
    pub fn local_interactive(
        caller: &CallerIdentity,
        profile_id: String,
        allowed_actions: BTreeSet<String>,
        build_id: String,
        ttl: Duration,
        now: Instant,
    ) -> Result<Self, ProtocolError> {
        if profile_id.is_empty()
            || allowed_actions.is_empty()
            || ttl.is_zero()
            || ttl > MAX_LIVE_GAME_ARM_TTL
        {
            return Err(ProtocolError::new(
                LocalErrorCode::InvalidArgument,
                "LiveGameArm requires one Profile, allowed actions, and a TTL up to 30 seconds",
            ));
        }
        Ok(Self {
            challenge_id: random_nonce()?,
            caller_process_id: caller.process_id,
            caller_user_sid_hash: caller.user_sid_hash.clone(),
            caller_logon_sid_hash: caller.logon_sid_hash.clone(),
            caller_session_id: caller.session_id,
            profile_id,
            allowed_actions,
            build_id,
            expires_at: now + ttl,
        })
    }

    pub fn confirmation(&self) -> String {
        format!(
            "ARM LIVE {} {} {}",
            self.build_id, self.profile_id, self.challenge_id
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LiveGameArm {
    caller_process_id: u32,
    caller_user_sid_hash: String,
    caller_logon_sid_hash: String,
    caller_session_id: u32,
    profile_id: String,
    allowed_actions: BTreeSet<String>,
    expires_at: Instant,
}

#[derive(Default)]
pub struct AutomationManager {
    provisioned_build_id: Option<String>,
    active: Option<AutomationSession>,
    live_game_arm: Option<LiveGameArm>,
}

impl AutomationManager {
    pub fn set_provisioned_build_id(&mut self, build_id: String) {
        self.provisioned_build_id = Some(build_id);
    }

    pub fn provisioned_build_id(&self) -> Option<&str> {
        self.provisioned_build_id.as_deref()
    }

    pub fn active(&self) -> Option<&AutomationSession> {
        self.active.as_ref()
    }

    pub fn arm_live_game(
        &mut self,
        challenge: LiveGameArmChallenge,
        typed_confirmation: &str,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        if now >= challenge.expires_at || typed_confirmation != challenge.confirmation() {
            return Err(ProtocolError::new(
                LocalErrorCode::PermissionDenied,
                "LiveGameArm interactive confirmation is invalid or expired",
            ));
        }
        self.live_game_arm = Some(LiveGameArm {
            caller_process_id: challenge.caller_process_id,
            caller_user_sid_hash: challenge.caller_user_sid_hash,
            caller_logon_sid_hash: challenge.caller_logon_sid_hash,
            caller_session_id: challenge.caller_session_id,
            profile_id: challenge.profile_id,
            allowed_actions: challenge.allowed_actions,
            expires_at: challenge.expires_at,
        });
        Ok(())
    }

    pub fn start(
        &mut self,
        caller: &CallerIdentity,
        target: AutomationTarget,
        capabilities: BTreeSet<AutomationCapability>,
        ttl: Duration,
        audit_id: String,
        now: Instant,
    ) -> Result<&AutomationSession, ProtocolError> {
        self.expire(now);
        if self.active.is_some() {
            return Err(ProtocolError::new(
                LocalErrorCode::OperationFailed,
                "an automation session is already active",
            ));
        }
        if capabilities.is_empty() || ttl.is_zero() || ttl > MAX_AUTOMATION_TTL {
            return Err(ProtocolError::new(
                LocalErrorCode::InvalidArgument,
                "automation session scope or TTL is invalid",
            ));
        }
        if let AutomationTarget::LiveGame { profile_id } = &target {
            let arm = self.live_game_arm.as_ref().ok_or_else(|| {
                ProtocolError::new(LocalErrorCode::PermissionDenied, "LIVE_GAME_ARM_REQUIRED")
            })?;
            if now >= arm.expires_at
                || arm.caller_process_id != caller.process_id
                || arm.caller_user_sid_hash != caller.user_sid_hash
                || arm.caller_logon_sid_hash != caller.logon_sid_hash
                || arm.caller_session_id != caller.session_id
                || &arm.profile_id != profile_id
                || arm.allowed_actions.is_empty()
            {
                return Err(ProtocolError::new(
                    LocalErrorCode::PermissionDenied,
                    "LIVE_GAME_ARM_REQUIRED",
                ));
            }
        }
        let expires_at = now + ttl;
        let expires_at_unix_ms = unix_ms().saturating_add(ttl.as_millis() as u64);
        self.active = Some(AutomationSession {
            session_id: random_nonce()?,
            caller_process_id: caller.process_id,
            caller_user_sid_hash: caller.user_sid_hash.clone(),
            caller_logon_sid_hash: caller.logon_sid_hash.clone(),
            caller_session_id: caller.session_id,
            target,
            capabilities,
            expires_at,
            expires_at_unix_ms,
            audit_id,
        });
        self.active.as_ref().ok_or_else(|| {
            ProtocolError::new(
                LocalErrorCode::OperationFailed,
                "automation session state could not be established",
            )
        })
    }

    pub fn stop(&mut self) -> bool {
        let had_active = self.active.take().is_some();
        self.live_game_arm = None;
        had_active
    }

    pub fn authorize_testbed_action(
        &mut self,
        caller: &CallerIdentity,
        session_id: &str,
        capability: AutomationCapability,
        now: Instant,
    ) -> Result<&AutomationSession, ProtocolError> {
        self.expire(now);
        let session = self.active.as_ref().ok_or_else(|| {
            ProtocolError::new(
                LocalErrorCode::PermissionDenied,
                "automation session is not active",
            )
        })?;
        if session.session_id != session_id
            || session.caller_process_id != caller.process_id
            || session.caller_user_sid_hash != caller.user_sid_hash
            || session.caller_logon_sid_hash != caller.logon_sid_hash
            || session.caller_session_id != caller.session_id
            || !matches!(
                &session.target,
                AutomationTarget::TestbedNormal {} | AutomationTarget::TestbedHigh {}
            )
            || !session.capabilities.contains(&capability)
            || now >= session.expires_at
        {
            return Err(ProtocolError::new(
                LocalErrorCode::PermissionDenied,
                "testbed action is outside the active automation session",
            ));
        }
        Ok(session)
    }

    pub fn emergency_stop(&mut self) -> bool {
        self.stop()
    }

    pub fn client_disconnected(&mut self, process_id: u32) -> bool {
        if self
            .active
            .as_ref()
            .is_some_and(|session| session.caller_process_id == process_id)
        {
            return self.stop();
        }
        false
    }

    pub fn expire(&mut self, now: Instant) -> bool {
        if self
            .active
            .as_ref()
            .is_some_and(|session| now >= session.expires_at)
        {
            return self.stop();
        }
        if self
            .live_game_arm
            .as_ref()
            .is_some_and(|arm| now >= arm.expires_at)
        {
            self.live_game_arm = None;
        }
        false
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use fairypam_agent_local_client::ClientIntegrity;

    fn caller(process_id: u32) -> CallerIdentity {
        CallerIdentity {
            process_id,
            user_sid_hash: "user".into(),
            logon_sid_hash: "logon".into(),
            session_id: 1,
            integrity: ClientIntegrity::Medium,
        }
    }

    fn capabilities() -> BTreeSet<AutomationCapability> {
        BTreeSet::from([AutomationCapability::PulseTestAction])
    }

    #[test]
    fn unattended_session_is_testbed_only_without_local_live_arm() {
        let now = Instant::now();
        let mut manager = AutomationManager::default();
        manager
            .start(
                &caller(10),
                AutomationTarget::TestbedNormal {},
                capabilities(),
                Duration::from_secs(5),
                "audit-1".into(),
                now,
            )
            .unwrap();
        manager.stop();
        assert_eq!(
            manager
                .start(
                    &caller(10),
                    AutomationTarget::LiveGame {
                        profile_id: "genshin-impact".into(),
                    },
                    capabilities(),
                    Duration::from_secs(5),
                    "audit-2".into(),
                    now,
                )
                .unwrap_err()
                .message,
            "LIVE_GAME_ARM_REQUIRED"
        );
    }

    #[test]
    fn expiry_client_exit_and_emergency_stop_revoke_session() {
        let now = Instant::now();
        let mut manager = AutomationManager::default();
        manager
            .start(
                &caller(10),
                AutomationTarget::TestbedHigh {},
                capabilities(),
                Duration::from_secs(1),
                "audit-1".into(),
                now,
            )
            .unwrap();
        assert!(manager.expire(now + Duration::from_secs(2)));

        manager
            .start(
                &caller(10),
                AutomationTarget::TestbedNormal {},
                capabilities(),
                Duration::from_secs(5),
                "audit-2".into(),
                now,
            )
            .unwrap();
        assert!(!manager.client_disconnected(11));
        assert!(manager.client_disconnected(10));

        manager
            .start(
                &caller(10),
                AutomationTarget::TestbedNormal {},
                capabilities(),
                Duration::from_secs(5),
                "audit-3".into(),
                now,
            )
            .unwrap();
        assert!(manager.emergency_stop());
    }

    #[test]
    fn live_arm_is_nonce_bound_to_local_caller_and_cannot_be_extended() {
        let now = Instant::now();
        let user = caller(10);
        let challenge = LiveGameArmChallenge::local_interactive(
            &user,
            "genshin-impact".into(),
            BTreeSet::from(["interaction.confirm".into()]),
            "dev-build".into(),
            Duration::from_secs(10),
            now,
        )
        .unwrap();
        let confirmation = challenge.confirmation();
        let mut manager = AutomationManager::default();
        manager
            .arm_live_game(challenge, &confirmation, now)
            .unwrap();
        assert_eq!(
            manager
                .start(
                    &caller(11),
                    AutomationTarget::LiveGame {
                        profile_id: "genshin-impact".into(),
                    },
                    capabilities(),
                    Duration::from_secs(5),
                    "audit".into(),
                    now,
                )
                .unwrap_err()
                .code,
            LocalErrorCode::PermissionDenied
        );
    }
}
