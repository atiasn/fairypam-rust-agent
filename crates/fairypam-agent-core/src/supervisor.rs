use std::convert::Infallible;
use std::future::Future;
use std::time::Duration;

use fairypam_agent_transport::CappedBackoff;
use tokio_util::sync::CancellationToken;

use crate::AgentError;

pub trait SupervisorHooks {
    fn close_input_gate(&mut self) -> Result<(), String>;
    fn guardian_release_all(&mut self) -> Result<(), String>;
    fn cancel_all_tasks(&mut self);
    fn join_all_tasks(&mut self) -> Result<(), String>;
    fn clear_target_session(&mut self);
    fn cancel_frame_pipeline(&mut self);
    fn join_frame_pipeline(&mut self) -> Result<(), String>;
}

pub trait SessionDriver {
    fn establish_session(
        &self,
        cancellation: CancellationToken,
    ) -> impl Future<Output = Result<(), AgentError>> + Send;

    fn run_control_session(
        &self,
        cancellation: CancellationToken,
    ) -> impl Future<Output = Result<(), AgentError>> + Send;

    fn run_frame_session(
        &self,
        cancellation: CancellationToken,
    ) -> impl Future<Output = Result<(), AgentError>> + Send;
}

pub struct SessionSupervisor<H> {
    hooks: H,
    backoff: CappedBackoff,
    frame_backoff: CappedBackoff,
    cancellation: CancellationToken,
    frame_cancellation: CancellationToken,
}

impl<H: SupervisorHooks> SessionSupervisor<H> {
    pub fn new(hooks: H, backoff: CappedBackoff) -> Self {
        let cancellation = CancellationToken::new();
        let frame_cancellation = cancellation.child_token();
        Self {
            hooks,
            backoff,
            frame_backoff: CappedBackoff::new(Duration::from_millis(100), Duration::from_secs(5))
                .expect("fixed Frame backoff bounds are valid"),
            cancellation,
            frame_cancellation,
        }
    }

    pub fn handle_control_failure(&mut self) -> Result<Duration, AgentError> {
        let errors = self.begin_control_failure();
        self.finish_control_failure(errors)
    }

    fn begin_control_failure(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        if let Err(error) = self.hooks.close_input_gate() {
            errors.push(format!("close_input_gate: {error}"));
        }
        if let Err(error) = self.hooks.guardian_release_all() {
            errors.push(format!("guardian_release_all: {error}"));
        }
        self.cancellation.cancel();
        self.hooks.cancel_all_tasks();
        errors
    }

    fn finish_control_failure(&mut self, mut errors: Vec<String>) -> Result<Duration, AgentError> {
        if let Err(error) = self.hooks.join_all_tasks() {
            errors.push(format!("join_all_tasks: {error}"));
        }
        self.hooks.clear_target_session();
        self.cancellation = CancellationToken::new();
        self.frame_cancellation = self.cancellation.child_token();
        if errors.is_empty() {
            Ok(self.backoff.next_delay())
        } else {
            Err(cleanup_error(errors.join("; ")))
        }
    }

    pub fn handle_frame_failure(&mut self) -> Result<(), AgentError> {
        self.frame_cancellation.cancel();
        self.hooks.cancel_frame_pipeline();
        let result = self
            .hooks
            .join_frame_pipeline()
            .map_err(|error| cleanup_error(format!("join_frame_pipeline: {error}")));
        self.frame_cancellation = self.cancellation.child_token();
        result
    }

    pub fn session_established(&mut self) {
        self.backoff.reset();
        self.frame_backoff.reset();
    }

    pub async fn run<D: SessionDriver>(&mut self, driver: &D) -> Result<Infallible, AgentError> {
        loop {
            let session_end = self.run_one_session(driver).await?;
            tracing::warn!(
                error = %session_end.error,
                "control session ended; starting fail-closed cleanup"
            );
            tracing::info!(
                reconnect_delay_ms = session_end.reconnect_delay.as_millis(),
                "control cleanup completed; reconnect scheduled"
            );
            tokio::time::sleep(session_end.reconnect_delay).await;
        }
    }

    pub async fn run_one_session<D: SessionDriver>(
        &mut self,
        driver: &D,
    ) -> Result<SessionEnd, AgentError> {
        if let Err(error) = driver
            .establish_session(self.cancellation.child_token())
            .await
        {
            let reconnect_delay = self.handle_control_failure()?;
            return Ok(SessionEnd {
                error,
                reconnect_delay,
            });
        }
        self.session_established();
        tracing::info!("control session established; reconnect backoff reset");

        let mut control = Box::pin(driver.run_control_session(self.cancellation.child_token()));
        let mut frame = Some(Box::pin(
            driver.run_frame_session(self.frame_cancellation.clone()),
        ));
        loop {
            tokio::select! {
                biased;
                result = &mut control => {
                    let error = match result {
                        Ok(()) => AgentError::new(
                            "supervisor.control_ended",
                            "Control session ended without an error",
                        ),
                        Err(error) => error,
                    };
                    let errors = self.begin_control_failure();
                    // Frame remains alive until after CloseInputGate, Guardian
                    // ReleaseAll and cancellation have all happened.
                    drop(frame.take());
                    let reconnect_delay = self.finish_control_failure(errors)?;
                    return Ok(SessionEnd { error, reconnect_delay });
                },
                result = frame.as_mut().expect("Frame future is installed").as_mut() => {
                    tracing::warn!(
                        error = ?result.err(),
                        "frame session ended; reattaching without dropping Control"
                    );
                    drop(frame.take());
                    self.handle_frame_failure()?;
                    let delay = self.frame_backoff.next_delay();
                    tracing::info!(
                        frame_reconnect_delay_ms = delay.as_millis(),
                        "Frame cleanup completed; reattach scheduled"
                    );
                    tokio::time::sleep(delay).await;
                    frame = Some(Box::pin(
                        driver.run_frame_session(self.frame_cancellation.clone()),
                    ));
                }
            }
        }
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn frame_cancellation(&self) -> CancellationToken {
        self.frame_cancellation.clone()
    }

    pub const fn hooks(&self) -> &H {
        &self.hooks
    }

    pub const fn hooks_mut(&mut self) -> &mut H {
        &mut self.hooks
    }
}

#[derive(Debug)]
pub struct SessionEnd {
    pub error: AgentError,
    pub reconnect_delay: Duration,
}

fn cleanup_error(message: String) -> AgentError {
    AgentError::new(
        "supervisor.cleanup_failed",
        format!("session cleanup failed: {message}"),
    )
}
