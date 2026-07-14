//! Fixed environment-check/v1 executor.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use data_encoding::BASE64;
use serde_json::json;

use crate::config::CaptureConfig;
use crate::input::InputController;
use crate::process::{is_launch_allowed, ProcessManager};
use crate::protocol::{
    EnvironmentCheckResult, EnvironmentCheckStart, EnvironmentCheckStepResult, InputFrame,
    MouseState,
};

pub trait EnvironmentCheckOps {
    fn launch_game(&mut self, command: &EnvironmentCheckStart) -> Result<serde_json::Value>;
    fn bind_window(&mut self) -> Result<serde_json::Value>;
    fn capture(&mut self, label: &str) -> Result<serde_json::Value>;
    fn input_probe(&mut self, session_id: &str) -> Result<serde_json::Value>;
    fn cleanup(&mut self, force: bool) -> Result<serde_json::Value>;
}

pub struct AgentEnvironmentCheckOps<'a> {
    pub process: &'a mut ProcessManager,
    pub input: &'a mut InputController,
    pub capture_config: &'a CaptureConfig,
    pub launch_allowlist: &'a [String],
}

impl EnvironmentCheckOps for AgentEnvironmentCheckOps<'_> {
    fn launch_game(&mut self, command: &EnvironmentCheckStart) -> Result<serde_json::Value> {
        let executable = command
            .resolved_executable
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("local game target was not resolved"))?;
        let pid = self.process.launch_game(
            "",
            executable,
            &[],
            command.resolved_working_dir.as_deref(),
        )?;
        let (_, resolved_executable) = self
            .process
            .active_target()
            .ok_or_else(|| anyhow::anyhow!("launch target missing after process start"))?;
        if !is_launch_allowed(&resolved_executable, self.launch_allowlist) {
            let _ = crate::target_operation::close_active_target(self.process, true);
            anyhow::bail!(
                "launch rejected: resolved executable not in allowlist ({})",
                resolved_executable
            );
        }
        Ok(json!({ "process_id": pid }))
    }

    fn bind_window(&mut self) -> Result<serde_json::Value> {
        let binding = self.process.active_binding_or_refresh()?;
        Ok(json!({
            "pid": binding.pid,
            "title": binding.title,
            "class_name": binding.class_name,
            "rect": {
                "left": binding.rect.left,
                "top": binding.rect.top,
                "right": binding.rect.right,
                "bottom": binding.rect.bottom
            }
        }))
    }

    fn capture(&mut self, label: &str) -> Result<serde_json::Value> {
        let capture = crate::capture::ScreenCapture::new(self.capture_config)?;
        let (binding, frame) =
            crate::target_operation::capture_active_target(self.process, &capture)?;
        Ok(json!({
            "artifact_ref": format!(
                "agent-local:{label}:{}x{}:{}",
                frame.width,
                frame.height,
                frame.jpeg.len()
            ),
            "pid": binding.pid,
            "width": frame.width,
            "height": frame.height,
            "jpeg_base64": BASE64.encode(&frame.jpeg)
        }))
    }

    fn input_probe(&mut self, session_id: &str) -> Result<serde_json::Value> {
        let binding = self.process.active_binding_or_refresh()?;
        let x = binding.rect.left + binding.rect.width() / 2;
        let y = binding.rect.top + binding.rect.height() / 2;
        let mut keyboard = HashMap::new();
        keyboard.insert("escape".to_string(), "down".to_string());
        let down = InputFrame {
            session_id: session_id.to_string(),
            game_id: String::new(),
            seq: 1,
            keyboard,
            mouse: MouseState {
                x,
                y,
                ..MouseState::default()
            },
            gamepad: None,
        };
        crate::target_operation::send_input_to_active_target(self.process, self.input, &down)?;

        let up = InputFrame {
            session_id: session_id.to_string(),
            game_id: String::new(),
            seq: 2,
            keyboard: HashMap::new(),
            mouse: MouseState {
                x,
                y,
                ..MouseState::default()
            },
            gamepad: None,
        };
        crate::target_operation::send_input_to_active_target(self.process, self.input, &up)?;
        Ok(json!({"keyboard": "escape", "mouse_probe": "move_only"}))
    }

    fn cleanup(&mut self, force: bool) -> Result<serde_json::Value> {
        self.input.emergency_stop()?;
        crate::target_operation::close_active_target(self.process, force)?;
        Ok(json!({"closed": true, "force": force}))
    }
}

pub fn run_environment_check<O: EnvironmentCheckOps>(
    command: &EnvironmentCheckStart,
    ops: &mut O,
    canceled: &AtomicBool,
) -> (Vec<EnvironmentCheckStepResult>, EnvironmentCheckResult) {
    let mut steps = Vec::new();
    let deadline = timeout_deadline(command.timeout_s);

    for (step_id, action) in [
        ("launch_game", Action::Launch),
        ("bind_window", Action::Bind),
        ("capture_before", Action::CaptureBefore),
        ("input_probe", Action::InputProbe),
        ("capture_after", Action::CaptureAfter),
    ] {
        if is_timed_out(deadline) {
            push_cleanup(command, ops, &mut steps);
            return final_result(
                command,
                "failed",
                &steps,
                Some("timeout"),
                Some("timeout"),
                Some("environment check timed out"),
            );
        }
        if canceled.load(Ordering::Relaxed) {
            push_cleanup(command, ops, &mut steps);
            return final_result(command, "canceled", &steps, None, None, None);
        }
        match run_step(action, command, ops) {
            Ok(result) => steps.push(step(command, step_id, "succeeded", result, None)),
            Err(err) => {
                let (step_error_code, final_error_code, message) =
                    if matches!(action, Action::InputProbe) {
                        let (code, message) = input_probe_failure(&err);
                        (Some(code), code, message)
                    } else {
                        (None, step_id, "environment check step failed")
                    };
                let mut failed_step = step(
                    command,
                    step_id,
                    "failed",
                    json!({}),
                    Some(message.to_string()),
                );
                if let Some(code) = step_error_code {
                    failed_step.error_code = Some(code.to_string());
                }
                steps.push(failed_step);
                push_cleanup(command, ops, &mut steps);
                return final_result(
                    command,
                    "failed",
                    &steps,
                    Some(step_id),
                    Some(final_error_code),
                    Some(message),
                );
            }
        }
    }

    push_cleanup(command, ops, &mut steps);
    steps.push(step(
        command,
        "summarize",
        "succeeded",
        json!({"ok": true}),
        None,
    ));
    final_result(command, "succeeded", &steps, None, None, None)
}

fn input_probe_failure(err: &anyhow::Error) -> (&'static str, &'static str) {
    let contains = |needle: &str| err.chain().any(|cause| cause.to_string().contains(needle));
    if contains("target-not-found")
        || contains("target-window-not-found")
        || contains("target privilege is higher")
    {
        (
            "input_probe_target",
            "input probe target unavailable or not permitted",
        )
    } else if contains("target-focus-failed")
        || contains("目标窗口聚焦失败")
        || contains("目标窗口未成为前台窗口")
        || contains("target window could not be focused")
        || contains("target window did not become foreground")
        || contains("target window input threads could not be attached")
        || contains("target window input threads could not be detached")
    {
        (
            "input_probe_focus",
            "input probe target could not be focused",
        )
    } else if contains("SendInput") {
        (
            "input_probe_input_rejected",
            "input probe input was rejected",
        )
    } else {
        ("input_probe_other", "input probe failed")
    }
}

fn timeout_deadline(timeout_s: u64) -> Option<Instant> {
    Some(Instant::now() + Duration::from_secs(timeout_s))
}

fn is_timed_out(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

#[derive(Clone, Copy)]
enum Action {
    Launch,
    Bind,
    CaptureBefore,
    InputProbe,
    CaptureAfter,
}

fn run_step<O: EnvironmentCheckOps>(
    action: Action,
    command: &EnvironmentCheckStart,
    ops: &mut O,
) -> Result<serde_json::Value> {
    match action {
        Action::Launch => ops.launch_game(command),
        Action::Bind => ops.bind_window(),
        Action::CaptureBefore => ops.capture("capture_before"),
        Action::InputProbe => ops.input_probe(&command.session_id),
        Action::CaptureAfter => ops.capture("capture_after"),
    }
}

fn push_cleanup<O: EnvironmentCheckOps>(
    command: &EnvironmentCheckStart,
    ops: &mut O,
    steps: &mut Vec<EnvironmentCheckStepResult>,
) {
    let result = ops.cleanup(command.force_close_on_cleanup);
    match result {
        Ok(value) => steps.push(step(command, "close_game", "succeeded", value, None)),
        Err(_) => steps.push(step(
            command,
            "close_game",
            "failed",
            json!({}),
            Some("environment check cleanup failed".to_string()),
        )),
    }
}

fn step(
    command: &EnvironmentCheckStart,
    step_id: &str,
    status: &str,
    result: serde_json::Value,
    error: Option<String>,
) -> EnvironmentCheckStepResult {
    EnvironmentCheckStepResult {
        task_run_id: command.task_run_id.clone(),
        trace_id: command.trace_id.clone(),
        session_id: command.session_id.clone(),
        step_id: step_id.to_string(),
        status: status.to_string(),
        result,
        error_code: error.as_ref().map(|_| format!("{step_id}_failed")),
        error_message: error,
    }
}

fn final_result(
    command: &EnvironmentCheckStart,
    status: &str,
    steps: &[EnvironmentCheckStepResult],
    failed_step: Option<&str>,
    error_code: Option<&str>,
    error: Option<&str>,
) -> (Vec<EnvironmentCheckStepResult>, EnvironmentCheckResult) {
    let step_values = steps
        .iter()
        .map(|item| serde_json::to_value(item).unwrap_or_else(|_| json!({})))
        .collect::<Vec<_>>();
    (
        steps.to_vec(),
        EnvironmentCheckResult {
            task_run_id: command.task_run_id.clone(),
            trace_id: command.trace_id.clone(),
            session_id: command.session_id.clone(),
            status: status.to_string(),
            result: json!({
                "failed_step": failed_step,
                "cleanup_attempted": steps.iter().any(|step| step.step_id == "close_game")
            }),
            steps: step_values,
            error_code: error_code.map(str::to_string),
            error_message: error.map(str::to_string),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeOps {
        calls: Vec<String>,
        fail_step: Option<&'static str>,
        fail_message: Option<&'static str>,
    }

    impl EnvironmentCheckOps for FakeOps {
        fn launch_game(&mut self, _command: &EnvironmentCheckStart) -> Result<serde_json::Value> {
            self.call("launch_game")
        }

        fn bind_window(&mut self) -> Result<serde_json::Value> {
            self.call("bind_window")
        }

        fn capture(&mut self, label: &str) -> Result<serde_json::Value> {
            self.call(label)
        }

        fn input_probe(&mut self, _session_id: &str) -> Result<serde_json::Value> {
            self.call("input_probe")
        }

        fn cleanup(&mut self, _force: bool) -> Result<serde_json::Value> {
            self.calls.push("close_game".into());
            Ok(json!({"closed": true}))
        }
    }

    impl FakeOps {
        fn call(&mut self, name: &str) -> Result<serde_json::Value> {
            self.calls.push(name.to_string());
            if self.fail_step == Some(name) {
                anyhow::bail!(self
                    .fail_message
                    .unwrap_or("environment check fake failure"));
            }
            Ok(json!({"artifact_ref": format!("artifact:{name}")}))
        }
    }

    fn command() -> EnvironmentCheckStart {
        EnvironmentCheckStart {
            _message_type: "environment_check_start".into(),
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            connection_id: uuid::Uuid::nil(),
            game_slug: "genshin".into(),
            session_id: "session-a".into(),
            timeout_s: 10,
            force_close_on_cleanup: false,
            resolved_executable: Some("YuanShen.exe".into()),
            resolved_working_dir: None,
        }
    }

    #[test]
    fn zero_timeout_fails_before_launch_and_attempts_cleanup() {
        let mut command = command();
        command.timeout_s = 0;
        let mut ops = FakeOps::default();
        let canceled = AtomicBool::new(false);
        let (steps, final_result) = run_environment_check(&command, &mut ops, &canceled);

        assert_eq!(ops.calls, vec!["close_game"]);
        assert_eq!(final_result.status, "failed");
        assert_eq!(final_result.error_code.as_deref(), Some("timeout"));
        assert!(steps.iter().any(|step| step.step_id == "close_game"));
    }

    #[test]
    fn final_launch_target_must_remain_allowlisted() {
        assert!(is_launch_allowed(
            r"C:\Games\YuanShen.exe",
            &["yuanshen.exe".to_string()]
        ));
        assert!(!is_launch_allowed(
            r"C:\Windows\System32\cmd.exe",
            &["yuanshen.exe".to_string()]
        ));
    }

    #[test]
    fn environment_check_runs_fixed_steps() {
        let mut ops = FakeOps::default();
        let canceled = AtomicBool::new(false);
        let (steps, final_result) = run_environment_check(&command(), &mut ops, &canceled);

        assert_eq!(
            ops.calls,
            vec![
                "launch_game",
                "bind_window",
                "capture_before",
                "input_probe",
                "capture_after",
                "close_game"
            ]
        );
        assert_eq!(final_result.status, "succeeded");
        assert_eq!(steps.last().unwrap().step_id, "summarize");
    }

    #[test]
    fn step_failure_stops_before_input_and_cleans_up() {
        let mut ops = FakeOps {
            fail_step: Some("capture_before"),
            ..Default::default()
        };
        let canceled = AtomicBool::new(false);
        let (steps, final_result) = run_environment_check(&command(), &mut ops, &canceled);

        assert!(!ops.calls.contains(&"input_probe".to_string()));
        assert!(ops.calls.contains(&"close_game".to_string()));
        assert_eq!(final_result.status, "failed");
        assert_eq!(steps[2].step_id, "capture_before");
        assert_eq!(steps[2].status, "failed");
    }

    #[test]
    fn step_failure_never_serializes_local_path_error() {
        let mut ops = FakeOps {
            fail_step: Some("capture_before"),
            fail_message: Some(r"C:\\private\\Genshin\\YuanShen.exe failed"),
            ..Default::default()
        };
        let canceled = AtomicBool::new(false);
        let (steps, final_result) = run_environment_check(&command(), &mut ops, &canceled);
        let wire = serde_json::to_string(&(steps, final_result)).unwrap();

        assert!(!wire.contains("private"));
        assert!(!wire.contains("YuanShen.exe failed"));
        assert!(wire.contains("environment check step failed"));
    }

    #[test]
    fn input_probe_failure_uses_safe_stable_error_code() {
        for (failure, expected_code, expected_message) in [
            (
                r"target-not-found: C:\\private\\Genshin\\YuanShen.exe",
                "input_probe_target",
                "input probe target unavailable or not permitted",
            ),
            (
                "target window input threads could not be attached",
                "input_probe_focus",
                "input probe target could not be focused",
            ),
            (
                "SendInput 只发送了 0/2 个事件",
                "input_probe_input_rejected",
                "input probe input was rejected",
            ),
            (
                "unexpected local failure",
                "input_probe_other",
                "input probe failed",
            ),
        ] {
            let mut ops = FakeOps {
                fail_step: Some("input_probe"),
                fail_message: Some(failure),
                ..Default::default()
            };
            let canceled = AtomicBool::new(false);
            let (steps, final_result) = run_environment_check(&command(), &mut ops, &canceled);
            let probe = steps
                .iter()
                .find(|step| step.step_id == "input_probe")
                .unwrap();
            let wire = serde_json::to_string(&(&steps, &final_result)).unwrap();

            assert_eq!(probe.error_code.as_deref(), Some(expected_code));
            assert_eq!(probe.error_message.as_deref(), Some(expected_message));
            assert_eq!(final_result.error_code.as_deref(), Some(expected_code));
            assert_eq!(
                final_result.error_message.as_deref(),
                Some(expected_message)
            );
            assert!(!wire.contains(failure));
            assert!(!wire.contains("private"));
        }
    }

    #[test]
    fn cancel_before_input_probe_prevents_input() {
        use std::sync::Arc;

        struct CancelBeforeInput {
            inner: FakeOps,
            cancel: Arc<AtomicBool>,
        }
        impl EnvironmentCheckOps for CancelBeforeInput {
            fn launch_game(&mut self, c: &EnvironmentCheckStart) -> Result<serde_json::Value> {
                self.inner.launch_game(c)
            }
            fn bind_window(&mut self) -> Result<serde_json::Value> {
                self.inner.bind_window()
            }
            fn capture(&mut self, label: &str) -> Result<serde_json::Value> {
                let result = self.inner.capture(label);
                if label == "capture_before" {
                    self.cancel.store(true, Ordering::Relaxed);
                }
                result
            }
            fn input_probe(&mut self, session_id: &str) -> Result<serde_json::Value> {
                self.inner.input_probe(session_id)
            }
            fn cleanup(&mut self, force: bool) -> Result<serde_json::Value> {
                self.inner.cleanup(force)
            }
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let mut ops = CancelBeforeInput {
            inner: FakeOps::default(),
            cancel: cancel.clone(),
        };
        let (steps, final_result) = run_environment_check(&command(), &mut ops, &cancel);

        assert!(!ops.inner.calls.contains(&"input_probe".to_string()));
        assert_eq!(final_result.status, "canceled");
        assert!(steps.iter().any(|step| step.step_id == "close_game"));
    }
}
