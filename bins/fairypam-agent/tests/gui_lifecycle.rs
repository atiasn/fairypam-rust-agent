#[path = "../src/gui_lifecycle.rs"]
mod gui_lifecycle;

use gui_lifecycle::{GuiExitReason, GuiLifetime, LifecycleState};
use tokio_util::sync::CancellationToken;

#[test]
fn lifecycle_binds_once_and_rejects_another_gui_pid() {
    let mut lifecycle = LifecycleState::default();

    assert!(lifecycle.bind(100).is_ok());
    assert_eq!(
        lifecycle.bind(101).unwrap_err().code(),
        "local.lifecycle.already_bound"
    );
}

#[test]
fn lifecycle_requires_the_bound_gui_for_explicit_shutdown() {
    let mut lifecycle = LifecycleState::default();

    assert_eq!(
        lifecycle.request_shutdown(100).unwrap_err().code(),
        "local.lifecycle.not_bound"
    );
    lifecycle.bind(100).unwrap();
    assert_eq!(
        lifecycle.request_shutdown(101).unwrap_err().code(),
        "local.lifecycle.pid_mismatch"
    );
    assert_eq!(
        lifecycle.request_shutdown(100).unwrap(),
        GuiExitReason::ExplicitShutdown
    );
}

#[test]
fn lifecycle_records_gui_process_exit_for_the_bound_pid() {
    let mut lifecycle = LifecycleState::default();
    lifecycle.bind(100).unwrap();

    lifecycle.process_exited(101);
    assert_eq!(lifecycle.exit_reason(), None);
    lifecycle.process_exited(100);
    assert_eq!(lifecycle.exit_reason(), Some(GuiExitReason::ProcessExited));
}

#[test]
fn gui_lifetime_cancels_the_shared_shutdown_signal() {
    let shutdown = CancellationToken::new();
    let lifecycle = GuiLifetime::new(shutdown.clone());

    lifecycle.bind(100).unwrap();
    assert_eq!(
        lifecycle.request_shutdown(100).unwrap(),
        GuiExitReason::ExplicitShutdown
    );
    assert!(shutdown.is_cancelled());
}
