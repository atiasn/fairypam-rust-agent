#![cfg(feature = "dev-automation")]

use std::path::PathBuf;
#[cfg(not(windows))]
use std::time::Instant;

use fairypam_agent_core::AgentError;
#[cfg(not(windows))]
use fairypam_agent_local_protocol::AutomationTarget;

use crate::profile_store::ProfileStore;

#[cfg(windows)]
mod platform {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use fairypam_agent_core::platform::{AuthorizationState, LocalAuthorization, TargetPlatform};
    use fairypam_agent_core::state::{Machine, SessionIdentity};
    use fairypam_agent_core::target::IntegrityLevel;
    use fairypam_agent_input::{
        ActionId, ActionMap, GuardianProcessClient, InputLease, InputPermit, ReleaseReason,
    };
    use fairypam_agent_local_protocol::AutomationTarget;
    use fairypam_agent_windows::{NativeWindows, WindowsInput, WindowsTargetPlatform};

    use super::{AgentError, PathBuf, ProfileStore};

    const TESTBED_PROFILE_ID: &str = "fairypam-test-window";
    const PULSE_ACTION_ID: &str = "input.pulse";
    const HOLD_ACTION_ID: &str = "move.forward";

    struct GrantedAuthorization {
        expires_at: Instant,
    }

    impl LocalAuthorization for GrantedAuthorization {
        fn current(&self, now: Instant) -> AuthorizationState {
            if now < self.expires_at {
                AuthorizationState::Granted {
                    expires_at: self.expires_at,
                }
            } else {
                AuthorizationState::Denied
            }
        }
    }

    struct HoldWorker {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl HoldWorker {
        fn release(mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[derive(Default)]
    pub struct DevInputController {
        hold: Option<HoldWorker>,
    }

    impl DevInputController {
        pub fn pulse(
            &mut self,
            profiles: &ProfileStore,
            target: &AutomationTarget,
            session_id: &str,
            expires_at: Instant,
            guardian_path: PathBuf,
        ) -> Result<(), AgentError> {
            self.release_all();
            let (mut input, session, mut machine, snapshot) =
                prepare(profiles, target, session_id, expires_at, guardian_path)?;
            let permit = InputPermit::from_capability(machine.issue_input_capability(
                Instant::now(),
                &snapshot,
                true,
            )?);
            input
                .apply_lease(
                    InputLease {
                        session: session.clone(),
                        sequence: 1,
                        expires_at,
                        desired_holds: BTreeSet::new(),
                    },
                    &permit,
                    Instant::now(),
                )
                .map_err(map_safety)?;
            input
                .execute_pulse(
                    &ActionId::new(PULSE_ACTION_ID.to_owned()).map_err(map_safety)?,
                    &session,
                    &permit,
                    Instant::now(),
                )
                .map_err(map_safety)?;
            input
                .release_all(ReleaseReason::EmergencyStop)
                .map_err(map_safety)
        }

        pub fn hold(
            &mut self,
            profiles: &ProfileStore,
            target: &AutomationTarget,
            session_id: &str,
            expires_at: Instant,
            hold_until: Instant,
            guardian_path: PathBuf,
        ) -> Result<(), AgentError> {
            self.release_all();
            let (mut input, session, mut machine, snapshot) =
                prepare(profiles, target, session_id, expires_at, guardian_path)?;
            let permit = InputPermit::from_capability(machine.issue_input_capability(
                Instant::now(),
                &snapshot,
                true,
            )?);
            input
                .apply_lease(
                    InputLease {
                        session,
                        sequence: 1,
                        expires_at: hold_until,
                        desired_holds: BTreeSet::from([
                            ActionId::new(HOLD_ACTION_ID.to_owned()).map_err(map_safety)?
                        ]),
                    },
                    &permit,
                    Instant::now(),
                )
                .map_err(map_safety)?;
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                while !worker_stop.load(Ordering::Acquire) && Instant::now() < hold_until {
                    if input.tick(Instant::now()).is_err() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                let _ = input.release_all(ReleaseReason::LeaseExpired);
            });
            self.hold = Some(HoldWorker {
                stop,
                thread: Some(thread),
            });
            Ok(())
        }

        pub fn release_all(&mut self) {
            if let Some(worker) = self.hold.take() {
                worker.release();
            }
        }
    }

    impl Drop for DevInputController {
        fn drop(&mut self) {
            self.release_all();
        }
    }

    fn prepare(
        profiles: &ProfileStore,
        target: &AutomationTarget,
        session_id: &str,
        expires_at: Instant,
        guardian_path: PathBuf,
    ) -> Result<
        (
            WindowsInput<GuardianProcessClient>,
            SessionIdentity,
            Machine,
            fairypam_agent_core::target::TargetSnapshot,
        ),
        AgentError,
    > {
        let expected_integrity = match target {
            AutomationTarget::TestbedNormal {} => IntegrityLevel::Medium,
            AutomationTarget::TestbedHigh {} => IntegrityLevel::High,
            AutomationTarget::LiveGame { .. } => {
                return Err(AgentError::new(
                    "automation.target_forbidden",
                    "unattended input is restricted to fairypam-agent-testbed",
                ))
            }
        };
        let profile = profiles.get(TESTBED_PROFILE_ID)?.clone();
        let mut targets = WindowsTargetPlatform::new(NativeWindows);
        let candidates = targets.enumerate(&profile)?;
        if candidates.len() != 1 {
            return Err(AgentError::new(
                "automation.testbed_ambiguous",
                format!(
                    "expected exactly one testbed target; found {}",
                    candidates.len()
                ),
            ));
        }
        let binding = targets.lock(&profile, candidates[0].selector.clone())?;
        if binding.integrity != expected_integrity {
            return Err(AgentError::new(
                "automation.testbed_integrity_mismatch",
                "testbed integrity does not match the fixed automation target",
            ));
        }
        let snapshot = targets.focus(&binding)?;
        let session = SessionIdentity {
            agent_id: "11111111-1111-1111-1111-111111111111".into(),
            session_id: session_id.to_owned(),
            generation: 1,
        };
        let authorization = GrantedAuthorization { expires_at };
        let mut machine = Machine::new();
        machine.start_completed()?;
        machine.control_connected(session.clone())?;
        machine.activate_profile(&profile)?;
        machine.lock_target(binding.clone())?;
        machine.preflight_passed(snapshot.clone())?;
        machine.enter_dry_run()?;
        machine.request_arm(&authorization, Instant::now(), expires_at)?;
        machine.begin_control(Instant::now())?;
        let action_map = ActionMap::from_verified_profile(&profile).map_err(map_safety)?;
        let guardian = GuardianProcessClient::spawn(
            &guardian_path,
            action_map.physical_holds(),
            Duration::from_millis(300),
        )
        .map_err(map_safety)?;
        let input = targets
            .start_input(&profile, binding, guardian)
            .map_err(map_safety)?;
        Ok((input, session, machine, snapshot))
    }

    fn map_safety(error: fairypam_agent_input::SafetyError) -> AgentError {
        AgentError::new(error.code(), error.to_string())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{AgentError, AutomationTarget, Instant, PathBuf, ProfileStore};

    #[derive(Default)]
    pub struct DevInputController;

    impl DevInputController {
        pub fn pulse(
            &mut self,
            _profiles: &ProfileStore,
            _target: &AutomationTarget,
            _session_id: &str,
            _expires_at: Instant,
            _guardian_path: PathBuf,
        ) -> Result<(), AgentError> {
            Err(AgentError::new(
                "automation.platform_unsupported",
                "testbed input requires Windows",
            ))
        }

        pub fn hold(
            &mut self,
            _profiles: &ProfileStore,
            _target: &AutomationTarget,
            _session_id: &str,
            _expires_at: Instant,
            _hold_until: Instant,
            _guardian_path: PathBuf,
        ) -> Result<(), AgentError> {
            Err(AgentError::new(
                "automation.platform_unsupported",
                "testbed input requires Windows",
            ))
        }

        pub fn release_all(&mut self) {}
    }
}

pub use platform::DevInputController;
