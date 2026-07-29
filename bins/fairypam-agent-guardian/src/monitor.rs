//! Guardian safety monitor.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use fairypam_agent_guardian_protocol::{
    GuardianRequest, GuardianResponse, PhysicalHold, ReleaseReason,
};

pub trait ReleaseDriver {
    fn release_all(&mut self, holds: &[PhysicalHold]) -> Result<(), String>;
}

pub struct GuardianMonitor<R> {
    release_driver: R,
    agent_pid: Option<u32>,
    heartbeat_timeout: Option<Duration>,
    heartbeat_deadline: Option<Instant>,
    last_sequence: u64,
    pending_intent: Option<(u64, Vec<PhysicalHold>)>,
    committed_holds: Vec<PhysicalHold>,
    last_release_reason: Option<ReleaseReason>,
}

impl<R: ReleaseDriver> GuardianMonitor<R> {
    pub fn new(release_driver: R) -> Self {
        Self {
            release_driver,
            agent_pid: None,
            heartbeat_timeout: None,
            heartbeat_deadline: None,
            last_sequence: 0,
            pending_intent: None,
            committed_holds: Vec::new(),
            last_release_reason: None,
        }
    }

    pub fn register_agent(
        &mut self,
        agent_pid: u32,
        heartbeat_timeout: Duration,
        now: Instant,
    ) -> Result<(), String> {
        if agent_pid == 0
            || heartbeat_timeout.is_zero()
            || heartbeat_timeout > Duration::from_secs(5)
        {
            return Err("guardian.registration_invalid".into());
        }
        if self.agent_pid.is_some() {
            return Err("guardian.agent_already_registered".into());
        }
        self.agent_pid = Some(agent_pid);
        self.heartbeat_timeout = Some(heartbeat_timeout);
        self.heartbeat_deadline = Some(now + heartbeat_timeout);
        Ok(())
    }

    pub fn register_intent(
        &mut self,
        sequence: u64,
        holds: Vec<PhysicalHold>,
    ) -> Result<(), String> {
        if self.pending_intent.is_some() {
            return Err("guardian.intent_pending".into());
        }
        if self.agent_pid.is_none() || sequence == 0 || sequence <= self.last_sequence {
            return Err("guardian.sequence_invalid".into());
        }
        let unique: BTreeSet<_> = holds.iter().map(PhysicalHold::action_id).collect();
        if unique.len() != holds.len() {
            return Err("guardian.duplicate_hold".into());
        }
        self.pending_intent = Some((sequence, holds));
        Ok(())
    }

    pub fn commit_holds(&mut self, sequence: u64) -> Result<(), String> {
        let Some((pending_sequence, holds)) = self.pending_intent.take() else {
            return Err("guardian.intent_missing".into());
        };
        if pending_sequence != sequence {
            self.pending_intent = Some((pending_sequence, holds));
            return Err("guardian.sequence_invalid".into());
        }
        self.last_sequence = sequence;
        self.committed_holds = holds;
        Ok(())
    }

    pub fn heartbeat(&mut self, sequence: u64, now: Instant) -> Result<(), String> {
        if sequence < self.last_sequence {
            return Err("guardian.sequence_invalid".into());
        }
        let timeout = self
            .heartbeat_timeout
            .ok_or_else(|| "guardian.agent_not_registered".to_string())?;
        self.heartbeat_deadline = Some(now + timeout);
        Ok(())
    }

    pub fn tick(&mut self, now: Instant, agent_alive: bool) -> Result<(), String> {
        if !agent_alive {
            self.release_all(ReleaseReason::AgentExited)?;
            self.agent_pid = None;
            self.heartbeat_deadline = None;
            return Ok(());
        }
        if self
            .heartbeat_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            self.release_all(ReleaseReason::HeartbeatExpired)?;
            self.heartbeat_deadline = None;
        }
        Ok(())
    }

    pub fn release_all(&mut self, reason: ReleaseReason) -> Result<(), String> {
        let mut releases: BTreeMap<_, _> = self
            .committed_holds
            .iter()
            .cloned()
            .map(|hold| (hold.action_id().clone(), hold))
            .collect();
        if let Some((_, pending)) = &self.pending_intent {
            for hold in pending {
                releases.insert(hold.action_id().clone(), hold.clone());
            }
        }
        self.release_driver
            .release_all(&releases.into_values().collect::<Vec<_>>())?;
        self.committed_holds.clear();
        self.pending_intent = None;
        self.last_release_reason = Some(reason);
        Ok(())
    }

    pub fn handle(&mut self, request: GuardianRequest, now: Instant) -> GuardianResponse {
        let result = match request {
            GuardianRequest::RegisterAgent {
                agent_pid,
                heartbeat_timeout_ms,
            } => self.register_agent(
                agent_pid,
                Duration::from_millis(u64::from(heartbeat_timeout_ms)),
                now,
            ),
            GuardianRequest::Heartbeat { sequence } => self.heartbeat(sequence, now),
            GuardianRequest::RegisterIntent { sequence, holds } => {
                self.register_intent(sequence, holds)
            }
            GuardianRequest::CommitHolds { sequence } => self.commit_holds(sequence),
            GuardianRequest::ReleaseAll { reason } => self.release_all(reason),
            GuardianRequest::Status {} => {
                return GuardianResponse::Status {
                    agent_pid: self.agent_pid,
                    committed_hold_count: self.committed_holds.len(),
                    last_sequence: self.last_sequence,
                };
            }
        };
        match result {
            Ok(()) => GuardianResponse::Ack {},
            Err(message) => GuardianResponse::Error {
                code: message.clone(),
                message,
            },
        }
    }

    pub const fn agent_pid(&self) -> Option<u32> {
        self.agent_pid
    }

    pub fn committed_holds(&self) -> &[PhysicalHold] {
        &self.committed_holds
    }

    pub const fn last_release_reason(&self) -> Option<ReleaseReason> {
        self.last_release_reason
    }

    pub const fn release_driver(&self) -> &R {
        &self.release_driver
    }
}
