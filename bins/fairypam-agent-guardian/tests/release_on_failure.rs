use std::time::{Duration, Instant};

use fairypam_agent_guardian::monitor::{GuardianMonitor, ReleaseDriver};
use fairypam_agent_guardian_protocol::ReleaseReason;
use fairypam_agent_guardian_protocol::{ActionId, PhysicalHold};

#[derive(Default)]
struct FakeRelease {
    calls: usize,
    released: Vec<PhysicalHold>,
    failures_remaining: usize,
}

impl ReleaseDriver for FakeRelease {
    fn release_all(&mut self, holds: &[PhysicalHold]) -> Result<(), String> {
        self.calls += 1;
        if self.failures_remaining > 0 {
            self.failures_remaining -= 1;
            return Err("test release failure".into());
        }
        self.released.extend_from_slice(holds);
        Ok(())
    }
}

#[test]
fn second_intent_is_rejected_without_overwriting_first() {
    let now = Instant::now();
    let mut monitor = GuardianMonitor::new(FakeRelease::default());
    monitor
        .register_agent(42, Duration::from_millis(300), now)
        .unwrap();
    monitor.register_intent(1, vec![hold()]).unwrap();

    let replacement = PhysicalHold::ScanCode {
        action_id: ActionId::new("movement.backward").unwrap(),
        scan_code: 31,
    };
    assert_eq!(
        monitor.register_intent(2, vec![replacement]).unwrap_err(),
        "guardian.intent_pending"
    );
    monitor.tick(now + Duration::from_millis(1), false).unwrap();

    assert_eq!(monitor.release_driver().released, vec![hold()]);
}

#[test]
fn failed_release_preserves_holds_for_retry() {
    let now = Instant::now();
    let mut monitor = GuardianMonitor::new(FakeRelease {
        failures_remaining: 1,
        ..FakeRelease::default()
    });
    monitor
        .register_agent(42, Duration::from_millis(300), now)
        .unwrap();
    monitor.register_intent(1, vec![hold()]).unwrap();

    assert!(monitor.release_all(ReleaseReason::AgentExited).is_err());
    monitor.release_all(ReleaseReason::AgentExited).unwrap();

    assert_eq!(monitor.release_driver().calls, 2);
    assert_eq!(monitor.release_driver().released, vec![hold()]);
}

fn hold() -> PhysicalHold {
    PhysicalHold::ScanCode {
        action_id: ActionId::new("movement.forward").unwrap(),
        scan_code: 17,
    }
}

#[test]
fn guardian_releases_when_agent_pid_exits() {
    let now = Instant::now();
    let mut monitor = GuardianMonitor::new(FakeRelease::default());
    monitor
        .register_agent(42, Duration::from_millis(300), now)
        .unwrap();
    monitor.register_intent(1, vec![hold()]).unwrap();
    monitor.commit_holds(1).unwrap();

    monitor.tick(now + Duration::from_millis(1), false).unwrap();

    assert_eq!(monitor.release_driver().calls, 1);
    assert!(monitor.committed_holds().is_empty());
    assert_eq!(
        monitor.last_release_reason(),
        Some(ReleaseReason::AgentExited)
    );
}

#[test]
fn heartbeat_timeout_releases_committed_holds() {
    let now = Instant::now();
    let mut monitor = GuardianMonitor::new(FakeRelease::default());
    monitor
        .register_agent(42, Duration::from_millis(300), now)
        .unwrap();
    monitor.register_intent(1, vec![hold()]).unwrap();
    monitor.commit_holds(1).unwrap();

    monitor
        .tick(now + Duration::from_millis(301), true)
        .unwrap();

    assert_eq!(monitor.release_driver().calls, 1);
    assert_eq!(
        monitor.last_release_reason(),
        Some(ReleaseReason::HeartbeatExpired)
    );

    monitor
        .tick(now + Duration::from_millis(600), true)
        .unwrap();
    assert_eq!(monitor.release_driver().calls, 1);
}

#[test]
fn crash_between_intent_and_commit_releases_pending_hold() {
    let now = Instant::now();
    let mut monitor = GuardianMonitor::new(FakeRelease::default());
    monitor
        .register_agent(42, Duration::from_millis(300), now)
        .unwrap();
    monitor.register_intent(1, vec![hold()]).unwrap();

    monitor.tick(now + Duration::from_millis(1), false).unwrap();

    assert_eq!(monitor.release_driver().calls, 1);
    assert_eq!(monitor.release_driver().released, vec![hold()]);
}
