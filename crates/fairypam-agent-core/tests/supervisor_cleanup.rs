use std::time::Duration;

use fairypam_agent_core::supervisor::{SessionDriver, SessionSupervisor, SupervisorHooks};
use fairypam_agent_transport::CappedBackoff;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct RecordingHooks {
    effects: Vec<&'static str>,
    fail_guardian: bool,
}

impl SupervisorHooks for RecordingHooks {
    fn close_input_gate(&mut self) -> Result<(), String> {
        self.effects.push("close_input_gate");
        Ok(())
    }

    fn guardian_release_all(&mut self) -> Result<(), String> {
        self.effects.push("guardian_release_all");
        if self.fail_guardian {
            Err("release timeout".into())
        } else {
            Ok(())
        }
    }

    fn cancel_all_tasks(&mut self) {
        self.effects.push("cancel_all_tasks");
    }

    fn join_all_tasks(&mut self) -> Result<(), String> {
        self.effects.push("join_all_tasks");
        Ok(())
    }

    fn clear_target_session(&mut self) {
        self.effects.push("clear_target_session");
    }

    fn cancel_frame_pipeline(&mut self) {
        self.effects.push("cancel_frame_pipeline");
    }

    fn join_frame_pipeline(&mut self) -> Result<(), String> {
        self.effects.push("join_frame_pipeline");
        Ok(())
    }
}

#[test]
fn control_failure_releases_before_reconnect_backoff() {
    let hooks = RecordingHooks::default();
    let backoff = CappedBackoff::new(Duration::from_millis(10), Duration::from_secs(1)).unwrap();
    let mut supervisor = SessionSupervisor::new(hooks, backoff);

    let delay = supervisor.handle_control_failure().unwrap();

    assert!((Duration::from_millis(5)..=Duration::from_millis(10)).contains(&delay));
    assert_eq!(
        supervisor.hooks().effects,
        vec![
            "close_input_gate",
            "guardian_release_all",
            "cancel_all_tasks",
            "join_all_tasks",
            "clear_target_session",
        ]
    );
}

#[test]
fn frame_failure_does_not_release_control_session() {
    let hooks = RecordingHooks::default();
    let backoff = CappedBackoff::new(Duration::from_millis(10), Duration::from_secs(1)).unwrap();
    let mut supervisor = SessionSupervisor::new(hooks, backoff);

    let control_token = supervisor.cancellation();
    let old_frame_token = supervisor.frame_cancellation();
    supervisor.handle_frame_failure().unwrap();

    assert_eq!(
        supervisor.hooks().effects,
        vec!["cancel_frame_pipeline", "join_frame_pipeline"]
    );
    assert!(!control_token.is_cancelled());
    assert!(old_frame_token.is_cancelled());
    assert!(!supervisor.frame_cancellation().is_cancelled());
}

#[test]
fn release_timeout_fails_closed_after_completing_cleanup() {
    let hooks = RecordingHooks {
        fail_guardian: true,
        ..RecordingHooks::default()
    };
    let backoff = CappedBackoff::new(Duration::from_millis(10), Duration::from_secs(1)).unwrap();
    let mut supervisor = SessionSupervisor::new(hooks, backoff);

    let old_tree = supervisor.cancellation();
    let error = supervisor.handle_control_failure().unwrap_err();

    assert_eq!(error.code(), "supervisor.cleanup_failed");
    assert_eq!(
        supervisor.hooks().effects,
        vec![
            "close_input_gate",
            "guardian_release_all",
            "cancel_all_tasks",
            "join_all_tasks",
            "clear_target_session",
        ]
    );
    assert!(old_tree.is_cancelled());
    assert!(!supervisor.cancellation().is_cancelled());
}

struct FrameFailsOnce {
    frame_runs: std::sync::atomic::AtomicUsize,
}

impl SessionDriver for FrameFailsOnce {
    async fn establish_session(
        &self,
        _cancellation: CancellationToken,
    ) -> Result<(), fairypam_agent_core::AgentError> {
        Ok(())
    }

    async fn run_control_session(
        &self,
        cancellation: CancellationToken,
    ) -> Result<(), fairypam_agent_core::AgentError> {
        cancellation.cancelled().await;
        Err(fairypam_agent_core::AgentError::new(
            "test.control_cancelled",
            "cancelled",
        ))
    }

    async fn run_frame_session(
        &self,
        cancellation: CancellationToken,
    ) -> Result<(), fairypam_agent_core::AgentError> {
        if self
            .frame_runs
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            return Err(fairypam_agent_core::AgentError::new(
                "test.frame_failed",
                "failed",
            ));
        }
        cancellation.cancelled().await;
        Ok(())
    }
}

#[tokio::test]
async fn run_automatically_restarts_frame_without_dropping_control() {
    let hooks = RecordingHooks::default();
    let backoff = CappedBackoff::new(Duration::from_millis(10), Duration::from_secs(1)).unwrap();
    let mut supervisor = SessionSupervisor::new(hooks, backoff);
    let driver = FrameFailsOnce {
        frame_runs: std::sync::atomic::AtomicUsize::new(0),
    };

    tokio::time::timeout(
        Duration::from_millis(250),
        supervisor.run_one_session(&driver),
    )
    .await
    .unwrap_err();

    assert!(driver.frame_runs.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    assert_eq!(
        supervisor.hooks().effects,
        vec!["cancel_frame_pipeline", "join_frame_pipeline"]
    );
}

struct DropOrderHooks {
    effects: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl SupervisorHooks for DropOrderHooks {
    fn record_control_failure(&mut self, error: &fairypam_agent_core::AgentError) {
        assert_eq!(error.code(), "test.control_failed");
        self.effects.lock().unwrap().push("record_control_failure");
    }

    fn close_input_gate(&mut self) -> Result<(), String> {
        self.effects.lock().unwrap().push("close_input_gate");
        Ok(())
    }

    fn guardian_release_all(&mut self) -> Result<(), String> {
        self.effects.lock().unwrap().push("guardian_release_all");
        Ok(())
    }

    fn cancel_all_tasks(&mut self) {
        self.effects.lock().unwrap().push("cancel_all_tasks");
    }

    fn join_all_tasks(&mut self) -> Result<(), String> {
        self.effects.lock().unwrap().push("join_all_tasks");
        Ok(())
    }

    fn clear_target_session(&mut self) {
        self.effects.lock().unwrap().push("clear_target_session");
    }

    fn cancel_frame_pipeline(&mut self) {}
    fn join_frame_pipeline(&mut self) -> Result<(), String> {
        Ok(())
    }
}

struct ControlFailsWithLiveFrame {
    effects: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

struct PendingFrame {
    effects: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl std::future::Future for PendingFrame {
    type Output = Result<(), fairypam_agent_core::AgentError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl Drop for PendingFrame {
    fn drop(&mut self) {
        self.effects.lock().unwrap().push("frame_future_dropped");
    }
}

impl SessionDriver for ControlFailsWithLiveFrame {
    async fn establish_session(
        &self,
        _cancellation: CancellationToken,
    ) -> Result<(), fairypam_agent_core::AgentError> {
        Ok(())
    }

    async fn run_control_session(
        &self,
        _cancellation: CancellationToken,
    ) -> Result<(), fairypam_agent_core::AgentError> {
        Err(fairypam_agent_core::AgentError::new(
            "test.control_failed",
            "failed",
        ))
    }

    fn run_frame_session(
        &self,
        _cancellation: CancellationToken,
    ) -> impl std::future::Future<Output = Result<(), fairypam_agent_core::AgentError>> + Send {
        PendingFrame {
            effects: self.effects.clone(),
        }
    }
}

#[tokio::test]
async fn control_failure_releases_before_frame_future_is_dropped() {
    let effects = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let hooks = DropOrderHooks {
        effects: effects.clone(),
    };
    let driver = ControlFailsWithLiveFrame {
        effects: effects.clone(),
    };
    let backoff = CappedBackoff::new(Duration::from_millis(10), Duration::from_secs(1)).unwrap();
    let mut supervisor = SessionSupervisor::new(hooks, backoff);

    supervisor.run_one_session(&driver).await.unwrap();

    assert_eq!(
        *effects.lock().unwrap(),
        vec![
            "close_input_gate",
            "guardian_release_all",
            "cancel_all_tasks",
            "frame_future_dropped",
            "record_control_failure",
            "join_all_tasks",
            "clear_target_session",
        ]
    );
}
