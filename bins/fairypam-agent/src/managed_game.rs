use std::collections::BTreeMap;
use std::fs;
#[cfg(any(windows, test))]
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v3;
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use sha2::{Digest, Sha256};

const MIN_IDLE_TIMEOUT_MS: u64 = 5 * 60 * 1_000;
const MAX_IDLE_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct PolicySnapshot {
    game_id: String,
    game_session_id: String,
    profile_id: String,
    state_version: u64,
    enabled: bool,
    idle_timeout_ms: u64,
    occupied: bool,
}

impl From<&v3::ConfigureIdleClose> for PolicySnapshot {
    fn from(value: &v3::ConfigureIdleClose) -> Self {
        Self {
            game_id: value.game_id.clone(),
            game_session_id: value.game_session_id.clone(),
            profile_id: value.profile_id.clone(),
            state_version: value.state_version,
            enabled: value.enabled,
            idle_timeout_ms: value.idle_timeout_ms,
            occupied: value.occupied,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct PendingCloseReceipt {
    game_session_id: String,
    state_version: u64,
    trigger: i32,
    result: i32,
    occurred_at_unix_ms: i64,
    error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct ClosingSnapshot {
    game_session_id: String,
    state_version: u64,
    failed: bool,
}

impl PendingCloseReceipt {
    fn to_proto(&self) -> v3::ManagedGameCloseReceipt {
        v3::ManagedGameCloseReceipt {
            game_session_id: self.game_session_id.clone(),
            state_version: self.state_version,
            trigger: self.trigger,
            result: self.result,
            occurred_at_unix_ms: self.occurred_at_unix_ms,
            error_code: self.error_code.clone(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct PersistedState {
    agent_id: Option<String>,
    policies: BTreeMap<String, PolicySnapshot>,
    status_sequence: u64,
    pending_close_receipt: Option<PendingCloseReceipt>,
    closing: Option<ClosingSnapshot>,
}

struct ActiveState {
    policy: PolicySnapshot,
    last_activity: Instant,
    last_activity_at_unix_ms: i64,
    closing: bool,
    close_failed: bool,
}

pub struct ManagedGameLifecycle {
    path: Option<PathBuf>,
    persisted: PersistedState,
    bound_profile_id: Option<String>,
    active: Option<ActiveState>,
    pending_close_report: bool,
    recovery_state_known: bool,
}

impl ManagedGameLifecycle {
    pub fn memory() -> Self {
        Self {
            path: None,
            persisted: PersistedState::default(),
            bound_profile_id: None,
            active: None,
            pending_close_report: false,
            recovery_state_known: false,
        }
    }

    #[cfg(any(windows, test))]
    pub fn persistent(legacy_path: PathBuf, agent_id: &str) -> Self {
        let path = namespaced_path(&legacy_path, agent_id);
        let loaded =
            load(&path).filter(|persisted| persisted.agent_id.as_deref() == Some(agent_id));
        let recovery_state_known = loaded.is_some();
        let persisted = loaded.unwrap_or_else(|| PersistedState {
            agent_id: Some(agent_id.to_owned()),
            ..PersistedState::default()
        });
        let pending_close_report = persisted.pending_close_receipt.is_some();
        Self {
            path: Some(path),
            persisted,
            bound_profile_id: None,
            active: None,
            pending_close_report,
            recovery_state_known,
        }
    }

    pub fn released(&self) -> bool {
        self.recovery_state_known
            && self.bound_profile_id.is_none()
            && self.active.is_none()
            && self.persisted.closing.is_none()
            && self.persisted.pending_close_receipt.is_none()
            && self
                .persisted
                .policies
                .values()
                .all(|policy| !policy.occupied)
    }

    pub fn release_task_occupancy(&mut self) -> Result<(), AgentError> {
        if !self
            .persisted
            .policies
            .values()
            .any(|policy| policy.occupied)
        {
            return Ok(());
        }
        let previous = self.persisted.clone();
        for policy in self.persisted.policies.values_mut() {
            policy.occupied = false;
        }
        self.bump_sequence();
        if let Err(error) = self.persist() {
            self.persisted = previous;
            return Err(error);
        }
        if let Some(active) = self.active.as_mut() {
            active.policy.occupied = false;
        }
        Ok(())
    }

    pub fn bind_target(&mut self, profile_id: &str, now: Instant, now_unix_ms: i64) {
        self.bound_profile_id = Some(profile_id.to_owned());
        let mut matching = self
            .persisted
            .policies
            .values()
            .filter(|policy| policy.profile_id == profile_id);
        let policy = matching.next().cloned();
        self.active = if matching.next().is_some() {
            None
        } else {
            policy.map(|policy| {
                let (closing, close_failed) = self.closing_state(&policy);
                ActiveState {
                    policy,
                    last_activity: now,
                    last_activity_at_unix_ms: now_unix_ms,
                    closing,
                    close_failed,
                }
            })
        };
    }

    pub fn configure(
        &mut self,
        value: &v3::ConfigureIdleClose,
        now: Instant,
        now_unix_ms: i64,
    ) -> Result<(), AgentError> {
        validate(value)?;
        let incoming = PolicySnapshot::from(value);
        if self.persisted.closing.as_ref().is_some_and(|closing| {
            closing.game_session_id != incoming.game_session_id
                || closing.state_version != incoming.state_version
        }) {
            return Err(AgentError::new(
                "target.closing",
                "managed target remains in the closing gate",
            ));
        }
        if let Some(current) = self.persisted.policies.get(&incoming.game_id) {
            if incoming.state_version < current.state_version {
                return Err(AgentError::new(
                    "idle_close.state_stale",
                    "idle close state version is stale",
                ));
            }
            if incoming.state_version == current.state_version {
                if &incoming != current {
                    return Err(AgentError::new(
                        "idle_close.state_version_conflict",
                        "idle close state version has conflicting content",
                    ));
                }
                if self.active.is_none()
                    && self.bound_profile_id.as_deref() == Some(incoming.profile_id.as_str())
                {
                    let (closing, close_failed) = self.closing_state(&incoming);
                    self.active = Some(ActiveState {
                        policy: incoming,
                        last_activity: now,
                        last_activity_at_unix_ms: now_unix_ms,
                        closing,
                        close_failed,
                    });
                }
                return Ok(());
            }
        }
        self.persisted
            .policies
            .insert(incoming.game_id.clone(), incoming.clone());
        self.bump_sequence();
        self.persist()?;
        self.active = (self.bound_profile_id.as_deref() == Some(incoming.profile_id.as_str()))
            .then(|| {
                let (closing, close_failed) = self.closing_state(&incoming);
                ActiveState {
                    policy: incoming,
                    last_activity: now,
                    last_activity_at_unix_ms: now_unix_ms,
                    closing,
                    close_failed,
                }
            });
        Ok(())
    }

    pub fn mark_activity(&mut self, now: Instant, now_unix_ms: i64) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if !active.policy.enabled || active.policy.occupied || active.closing {
            return;
        }
        active.last_activity = now;
        active.last_activity_at_unix_ms = now_unix_ms;
        self.bump_sequence();
        let _ = self.persist();
    }

    pub fn due(&self, now: Instant) -> bool {
        self.active.as_ref().is_some_and(|active| {
            active.policy.enabled
                && !active.policy.occupied
                && !active.closing
                && !active.close_failed
                && now.duration_since(active.last_activity)
                    >= Duration::from_millis(active.policy.idle_timeout_ms)
        })
    }

    pub fn status(&self, now: Instant, now_unix_ms: i64) -> Option<v3::ManagedGameIdleStatus> {
        let active = self.active.as_ref()?;
        let (state, expected_close_at_unix_ms, reason_code) = if active.close_failed {
            (
                v3::ManagedGameIdleState::CloseFailed,
                None,
                Some("idle_close.close_failed".to_owned()),
            )
        } else if active.closing {
            (
                v3::ManagedGameIdleState::Paused,
                None,
                Some("target.closing".to_owned()),
            )
        } else if !active.policy.enabled {
            (v3::ManagedGameIdleState::Disabled, None, None)
        } else if active.policy.occupied {
            (v3::ManagedGameIdleState::Occupied, None, None)
        } else {
            let remaining = Duration::from_millis(active.policy.idle_timeout_ms)
                .saturating_sub(now.duration_since(active.last_activity));
            (
                v3::ManagedGameIdleState::Counting,
                Some(now_unix_ms.saturating_add(remaining.as_millis() as i64)),
                None,
            )
        };
        Some(v3::ManagedGameIdleStatus {
            session: None,
            game_session_id: active.policy.game_session_id.clone(),
            state_version: active.policy.state_version,
            status_sequence: self.persisted.status_sequence,
            state: state as i32,
            last_activity_at_unix_ms: active.last_activity_at_unix_ms,
            expected_close_at_unix_ms,
            reason_code,
        })
    }

    pub fn close_receipt(
        &mut self,
        trigger: v3::ManagedGameCloseTrigger,
        result: v3::ManagedGameCloseResult,
        occurred_at_unix_ms: i64,
        error_code: Option<String>,
    ) -> Option<v3::ManagedGameCloseReceipt> {
        let active = self.active.as_mut()?;
        let receipt = v3::ManagedGameCloseReceipt {
            game_session_id: active.policy.game_session_id.clone(),
            state_version: active.policy.state_version,
            trigger: trigger as i32,
            result: result as i32,
            occurred_at_unix_ms,
            error_code,
        };
        self.persisted.pending_close_receipt = Some(PendingCloseReceipt {
            game_session_id: receipt.game_session_id.clone(),
            state_version: receipt.state_version,
            trigger: receipt.trigger,
            result: receipt.result,
            occurred_at_unix_ms: receipt.occurred_at_unix_ms,
            error_code: receipt.error_code.clone(),
        });
        self.pending_close_report = true;
        if result == v3::ManagedGameCloseResult::Failed {
            active.closing = true;
            active.close_failed = true;
            self.persisted.closing = Some(ClosingSnapshot {
                game_session_id: receipt.game_session_id.clone(),
                state_version: receipt.state_version,
                failed: true,
            });
            self.bump_sequence();
        } else {
            self.persisted.policies.remove(&active.policy.game_id);
            self.persisted.closing = None;
            self.bound_profile_id = None;
            self.active = None;
        }
        let _ = self.persist();
        Some(receipt)
    }

    pub fn begin_close(&mut self) -> Result<(), AgentError> {
        let active = self.active.as_mut().ok_or_else(|| {
            AgentError::new(
                "target.identity_unavailable",
                "managed game identity has not been confirmed",
            )
        })?;
        active.closing = true;
        active.close_failed = false;
        self.persisted.closing = Some(ClosingSnapshot {
            game_session_id: active.policy.game_session_id.clone(),
            state_version: active.policy.state_version,
            failed: false,
        });
        self.bump_sequence();
        self.persist()
    }

    pub fn manual_close_failed(
        &mut self,
        error_code: &str,
        occurred_at_unix_ms: i64,
    ) -> Option<v3::ManagedGameCloseReceipt> {
        let active = self.active.as_mut()?;
        active.closing = true;
        active.close_failed = true;
        let game_session_id = active.policy.game_session_id.clone();
        let state_version = active.policy.state_version;
        self.persisted.closing = Some(ClosingSnapshot {
            game_session_id: game_session_id.clone(),
            state_version,
            failed: true,
        });
        self.bump_sequence();
        let _ = self.persist();
        Some(v3::ManagedGameCloseReceipt {
            game_session_id,
            state_version,
            trigger: v3::ManagedGameCloseTrigger::Manual as i32,
            result: v3::ManagedGameCloseResult::Failed as i32,
            occurred_at_unix_ms,
            error_code: Some(error_code.to_owned()),
        })
    }

    pub fn manual_close_receipt(
        &mut self,
        result: v3::ManagedGameCloseResult,
        occurred_at_unix_ms: i64,
    ) -> Option<v3::ManagedGameCloseReceipt> {
        let active = self.active.as_ref()?;
        let receipt = v3::ManagedGameCloseReceipt {
            game_session_id: active.policy.game_session_id.clone(),
            state_version: active.policy.state_version,
            trigger: v3::ManagedGameCloseTrigger::Manual as i32,
            result: result as i32,
            occurred_at_unix_ms,
            error_code: None,
        };
        self.persisted.policies.remove(&active.policy.game_id);
        self.persisted.closing = None;
        self.bound_profile_id = None;
        self.active = None;
        let _ = self.persist();
        Some(receipt)
    }

    pub fn prepare_close_replay(&mut self) {
        self.pending_close_report = self.persisted.pending_close_receipt.is_some();
    }

    pub fn pending_close_receipt(&self) -> Option<v3::ManagedGameCloseReceipt> {
        if !self.pending_close_report {
            return None;
        }
        self.persisted
            .pending_close_receipt
            .as_ref()
            .map(PendingCloseReceipt::to_proto)
    }

    pub fn mark_close_reported(&mut self) {
        self.pending_close_report = false;
    }

    pub fn acknowledge_close(
        &mut self,
        event_id: &str,
        game_session_id: &str,
        state_version: u64,
    ) -> Result<(), AgentError> {
        let receipt = self
            .persisted
            .pending_close_receipt
            .as_ref()
            .ok_or_else(|| {
                AgentError::new("idle_close.ack_stale", "close receipt is no longer pending")
            })?;
        let proto = receipt.to_proto();
        if proto.game_session_id != game_session_id
            || proto.state_version != state_version
            || close_event_id(&proto) != event_id
        {
            return Err(AgentError::new(
                "idle_close.ack_mismatch",
                "close acknowledgement does not match the pending receipt",
            ));
        }
        self.persisted.pending_close_receipt = None;
        self.pending_close_report = false;
        self.persist()
    }

    pub fn is_closing(&self) -> bool {
        self.active.as_ref().is_some_and(|active| active.closing)
    }

    pub fn current_identity(&self) -> Option<(&str, u64)> {
        self.active.as_ref().map(|active| {
            (
                active.policy.game_session_id.as_str(),
                active.policy.state_version,
            )
        })
    }

    fn closing_state(&self, policy: &PolicySnapshot) -> (bool, bool) {
        self.persisted
            .closing
            .as_ref()
            .map_or((false, false), |closing| {
                let matches = closing.game_session_id == policy.game_session_id
                    && closing.state_version == policy.state_version;
                (matches, matches && closing.failed)
            })
    }

    fn bump_sequence(&mut self) {
        self.persisted.status_sequence = self.persisted.status_sequence.saturating_add(1).max(1);
    }

    fn persist(&self) -> Result<(), AgentError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let parent = path.parent().ok_or_else(|| {
            AgentError::new(
                "idle_close.persistence_failed",
                "idle close state path is invalid",
            )
        })?;
        fs::create_dir_all(parent).map_err(persistence_error)?;
        let temporary = path.with_extension("tmp");
        fs::write(
            &temporary,
            serde_json::to_vec(&self.persisted).map_err(persistence_error)?,
        )
        .map_err(persistence_error)?;
        fs::rename(&temporary, path).map_err(persistence_error)
    }
}

pub fn close_event_id(receipt: &v3::ManagedGameCloseReceipt) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        receipt.game_session_id,
        receipt.state_version,
        receipt.trigger,
        receipt.result,
        receipt.occurred_at_unix_ms,
        receipt.error_code.as_deref().unwrap_or_default(),
    )
}

fn validate(value: &v3::ConfigureIdleClose) -> Result<(), AgentError> {
    if value.game_id.is_empty()
        || value.game_session_id.is_empty()
        || value.profile_id.is_empty()
        || value.state_version == 0
    {
        return Err(AgentError::new(
            "idle_close.state_invalid",
            "idle close identity is incomplete",
        ));
    }
    if value.enabled
        && !(MIN_IDLE_TIMEOUT_MS..=MAX_IDLE_TIMEOUT_MS).contains(&value.idle_timeout_ms)
    {
        return Err(AgentError::new(
            "idle_close.timeout_invalid",
            "idle close timeout must be between 5 minutes and 24 hours",
        ));
    }
    if !value.enabled && value.idle_timeout_ms != 0 {
        return Err(AgentError::new(
            "idle_close.timeout_invalid",
            "disabled idle close must use a zero timeout",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn load(path: &Path) -> Option<PersistedState> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[cfg(any(windows, test))]
fn namespaced_path(legacy_path: &Path, agent_id: &str) -> PathBuf {
    let digest = Sha256::digest(agent_id.as_bytes());
    legacy_path.with_file_name(format!("managed-game-lifecycle-{digest:x}.json"))
}

fn persistence_error(error: impl std::fmt::Display) -> AgentError {
    AgentError::new(
        "idle_close.persistence_failed",
        format!("idle close state could not be persisted: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn config(version: u64, enabled: bool, occupied: bool) -> v3::ConfigureIdleClose {
        v3::ConfigureIdleClose {
            game_id: "game-1".into(),
            game_session_id: "game-session-1".into(),
            profile_id: "genshin-impact".into(),
            state_version: version,
            enabled,
            idle_timeout_ms: if enabled { MIN_IDLE_TIMEOUT_MS } else { 0 },
            occupied,
            ..v3::ConfigureIdleClose::default()
        }
    }

    #[test]
    fn occupied_policy_never_becomes_due() {
        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::memory();
        lifecycle.bind_target("genshin-impact", start, 1_000);
        lifecycle
            .configure(&config(1, true, true), start, 1_000)
            .unwrap();

        assert!(!lifecycle.due(start + Duration::from_secs(24 * 60 * 60)));
        assert_eq!(
            lifecycle.status(start, 1_000).unwrap().state,
            v3::ManagedGameIdleState::Occupied as i32
        );
    }

    #[test]
    fn versions_are_scoped_by_game_not_profile() {
        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::memory();
        let mut first = config(5, false, true);
        let mut second = config(1, false, true);
        second.game_id = "game-2".into();
        second.game_session_id = "game-session-2".into();

        lifecycle.configure(&first, start, 1_000).unwrap();
        lifecycle.configure(&second, start, 1_000).unwrap();
        first.state_version = 4;
        assert_eq!(
            lifecycle
                .configure(&first, start, 1_000)
                .unwrap_err()
                .code(),
            "idle_close.state_stale"
        );
        first.state_version = 5;
        first.profile_id = "genshin-impact-v2".into();
        assert_eq!(
            lifecycle
                .configure(&first, start, 1_000)
                .unwrap_err()
                .code(),
            "idle_close.state_version_conflict"
        );
        first.state_version = 6;
        lifecycle.configure(&first, start, 1_000).unwrap();
        assert_eq!(lifecycle.persisted.policies.len(), 2);
    }

    #[test]
    fn game_identity_is_required() {
        let mut value = config(1, false, true);
        value.game_id.clear();
        assert_eq!(
            ManagedGameLifecycle::memory()
                .configure(&value, Instant::now(), 1_000)
                .unwrap_err()
                .code(),
            "idle_close.state_invalid"
        );
    }

    #[test]
    fn idle_policy_becomes_due_and_activity_resets_full_period() {
        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::memory();
        lifecycle.bind_target("genshin-impact", start, 1_000);
        lifecycle
            .configure(&config(1, true, false), start, 1_000)
            .unwrap();
        let almost_due = start + Duration::from_millis(MIN_IDLE_TIMEOUT_MS - 1);
        assert!(!lifecycle.due(almost_due));

        lifecycle.mark_activity(almost_due, 2_000);
        assert!(!lifecycle.due(start + Duration::from_millis(MIN_IDLE_TIMEOUT_MS)));
        assert!(lifecycle.due(almost_due + Duration::from_millis(MIN_IDLE_TIMEOUT_MS)));
    }

    #[test]
    fn version_replay_is_idempotent_and_conflict_fails_closed() {
        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::memory();
        lifecycle.bind_target("genshin-impact", start, 1_000);
        let original = config(2, true, false);
        lifecycle.configure(&original, start, 1_000).unwrap();
        let original_status = lifecycle.status(start, 1_000).unwrap();
        let sequence = original_status.status_sequence;
        let expected_close = original_status.expected_close_at_unix_ms;
        lifecycle
            .configure(&original, start + Duration::from_secs(10), 11_000)
            .unwrap();
        let replayed_status = lifecycle
            .status(start + Duration::from_secs(10), 11_000)
            .unwrap();
        assert_eq!(replayed_status.status_sequence, sequence);
        assert_eq!(replayed_status.expected_close_at_unix_ms, expected_close);

        let mut conflict = original;
        conflict.occupied = true;
        assert_eq!(
            lifecycle
                .configure(&conflict, start, 1_000)
                .unwrap_err()
                .code(),
            "idle_close.state_version_conflict"
        );
        assert_eq!(
            lifecycle
                .configure(&config(1, true, false), start, 1_000)
                .unwrap_err()
                .code(),
            "idle_close.state_stale"
        );
    }

    #[test]
    fn close_receipt_is_replayed_once_per_connection() {
        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::memory();
        lifecycle.bind_target("genshin-impact", start, 1_000);
        lifecycle
            .configure(&config(1, true, false), start, 1_000)
            .unwrap();
        let receipt = lifecycle
            .close_receipt(
                v3::ManagedGameCloseTrigger::Idle,
                v3::ManagedGameCloseResult::Graceful,
                2_000,
                None,
            )
            .unwrap();

        assert!(lifecycle.pending_close_receipt().is_some());
        lifecycle.mark_close_reported();
        assert!(lifecycle.pending_close_receipt().is_none());
        lifecycle
            .configure(&config(2, true, false), start, 2_500)
            .unwrap();
        lifecycle.prepare_close_replay();
        assert!(lifecycle.pending_close_receipt().is_some());
        lifecycle
            .acknowledge_close(
                &close_event_id(&receipt),
                &receipt.game_session_id,
                receipt.state_version,
            )
            .unwrap();
        lifecycle.prepare_close_replay();
        assert!(lifecycle.pending_close_receipt().is_none());
    }

    #[test]
    fn persistent_state_is_isolated_by_agent_identity() {
        let directory = tempdir().unwrap();
        let legacy_path = directory.path().join("managed-game-lifecycle.json");
        let legacy_bytes = br#"{"policies":{"genshin-impact":{"game_session_id":"old","profile_id":"genshin-impact","state_version":9,"enabled":true,"idle_timeout_ms":300000,"occupied":false}},"status_sequence":9}"#;
        fs::write(&legacy_path, legacy_bytes).unwrap();
        let start = Instant::now();

        let mut old_agent = ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a");
        old_agent.bind_target("genshin-impact", start, 1_000);
        old_agent
            .configure(&config(9, true, false), start, 1_000)
            .unwrap();
        old_agent
            .close_receipt(
                v3::ManagedGameCloseTrigger::Idle,
                v3::ManagedGameCloseResult::Failed,
                2_000,
                Some("target.close_failed".to_owned()),
            )
            .unwrap();

        let mut new_agent = ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-b");
        assert_eq!(new_agent.persisted.status_sequence, 0);
        assert!(new_agent.persisted.pending_close_receipt.is_none());
        assert!(new_agent.persisted.closing.is_none());
        new_agent.bind_target("genshin-impact", start, 3_000);
        new_agent
            .configure(&config(1, false, true), start, 3_000)
            .unwrap();
        new_agent
            .configure(&config(2, false, true), start, 3_500)
            .unwrap();

        let mut reopened = ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-b");
        reopened.bind_target("genshin-impact", start, 4_000);
        assert_eq!(
            reopened
                .configure(&config(1, false, true), start, 4_000)
                .unwrap_err()
                .code(),
            "idle_close.state_stale"
        );
        reopened
            .configure(&config(2, false, true), start, 4_000)
            .unwrap();
        assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);
    }

    #[test]
    fn lost_session_releases_persisted_occupancy_without_erasing_close_evidence() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("lifecycle.json");
        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::persistent(path.clone(), "agent-a");
        lifecycle
            .configure(&config(1, true, true), start, 1_000)
            .unwrap();
        let mut reopened = ManagedGameLifecycle::persistent(path.clone(), "agent-a");
        assert!(!reopened.released());
        reopened.release_task_occupancy().unwrap();
        assert!(reopened.released());
        let saved = ManagedGameLifecycle::persistent(path.clone(), "agent-a");
        assert!(saved.released());
        assert_eq!(
            saved.persisted.policies["game-1"],
            PolicySnapshot::from(&config(1, true, false))
        );
        assert!(saved.persisted.status_sequence > lifecycle.persisted.status_sequence);
        assert_eq!(
            reopened
                .configure(&config(1, true, true), start, 1_000)
                .unwrap_err()
                .code(),
            "idle_close.state_version_conflict"
        );
        reopened
            .configure(&config(2, true, false), start, 1_000)
            .unwrap();

        reopened.bind_target("genshin-impact", start, 1_000);
        reopened
            .configure(&config(3, true, true), start, 1_000)
            .unwrap();
        reopened.release_task_occupancy().unwrap();
        assert!(!reopened.active.as_ref().unwrap().policy.occupied);
        assert!(!reopened.released());
        reopened.begin_close().unwrap();
        reopened.release_task_occupancy().unwrap();
        assert!(!ManagedGameLifecycle::persistent(path.clone(), "agent-a").released());
        reopened
            .close_receipt(
                v3::ManagedGameCloseTrigger::Idle,
                v3::ManagedGameCloseResult::Graceful,
                2_000,
                None,
            )
            .unwrap();
        reopened.release_task_occupancy().unwrap();
        assert!(!ManagedGameLifecycle::persistent(path, "agent-a").released());
        assert!(reopened.pending_close_receipt().is_some());

        let unknown_path = directory.path().join("unknown.json");
        let mut unknown = ManagedGameLifecycle::persistent(unknown_path, "agent-a");
        unknown.release_task_occupancy().unwrap();
        assert!(!unknown.released());
    }

    #[test]
    fn lost_session_occupancy_persistence_failure_remains_retryable() {
        let directory = tempdir().unwrap();
        let legacy_path = directory.path().join("lifecycle.json");
        let path = namespaced_path(&legacy_path, "agent-a");
        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a");
        lifecycle
            .configure(&config(1, true, true), start, 1_000)
            .unwrap();
        let mut reopened = ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        for _ in 0..2 {
            assert_eq!(
                reopened.release_task_occupancy().unwrap_err().code(),
                "idle_close.persistence_failed"
            );
            assert!(!reopened.released());
        }
        fs::remove_dir(&path).unwrap();
        reopened.release_task_occupancy().unwrap();
        assert!(ManagedGameLifecycle::persistent(legacy_path, "agent-a").released());
    }

    #[test]
    fn released_requires_readable_matching_state_and_preserves_close_evidence() {
        let directory = tempdir().unwrap();
        let legacy_path = directory.path().join("lifecycle.json");
        let path = namespaced_path(&legacy_path, "agent-a");
        assert!(!ManagedGameLifecycle::memory().released());
        assert!(!ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a").released());
        fs::write(&path, b"broken json").unwrap();
        assert!(!ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a").released());
        fs::write(&path, br#"{"agent_id":"other-agent"}"#).unwrap();
        assert!(!ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a").released());

        let start = Instant::now();
        let mut lifecycle = ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a");
        lifecycle
            .configure(&config(1, true, true), start, 1_000)
            .unwrap();
        assert!(!ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a").released());
        lifecycle
            .configure(&config(2, true, false), start, 1_000)
            .unwrap();
        let mut reopened = ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a");
        assert!(!reopened.persisted.policies.is_empty());
        assert!(reopened.released());
        reopened.bind_target("genshin-impact", start, 1_000);
        assert!(!reopened.released());
        reopened.begin_close().unwrap();
        assert!(!ManagedGameLifecycle::persistent(legacy_path.clone(), "agent-a").released());
        let receipt = reopened
            .close_receipt(
                v3::ManagedGameCloseTrigger::Idle,
                v3::ManagedGameCloseResult::Graceful,
                2_000,
                None,
            )
            .unwrap();
        reopened.mark_close_reported();
        assert!(!reopened.released());
        let mut awaiting_ack = ManagedGameLifecycle::persistent(legacy_path, "agent-a");
        assert!(!awaiting_ack.released());
        awaiting_ack
            .acknowledge_close(
                &close_event_id(&receipt),
                &receipt.game_session_id,
                receipt.state_version,
            )
            .unwrap();
        assert!(awaiting_ack.released());
    }
}
