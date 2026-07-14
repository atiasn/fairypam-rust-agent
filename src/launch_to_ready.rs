//! Minimal trusted state for genshin/launch-to-ready@v1.

use anyhow::Result;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::process::TargetBinding;
use crate::protocol::{
    OwnedCleanup, TaskRunCancel, TaskRunCleanupReceipt, TaskRunClick, TaskRunFrame, TaskRunStart,
    TaskRunTerminal,
};
use crate::{
    capture::ScreenCapture, input::InputController, process::ProcessManager, target_operation,
};

// ponytail: two synchronous attempts; add backoff only if graceful-close churn is observed.
const CLEANUP_ATTEMPTS: usize = 2;

pub struct ActiveLaunchToReadyRun {
    task_run_id: String,
    trace_id: String,
    session_id: String,
    connection_id: Uuid,
    binding: TargetBinding,
    frame_width: u32,
    frame_height: u32,
    last_frame_seq: Option<u64>,
    target_process_alive: bool,
    target_window_alive: bool,
    accepted_click_source_frame_seq: Option<u64>,
    last_applied_click_source_frame_seq: Option<u64>,
}

impl ActiveLaunchToReadyRun {
    pub fn new(start: &TaskRunStart, binding: TargetBinding) -> Result<Self> {
        if start.game_slug != "genshin"
            || start.template_id != "genshin/launch-to-ready"
            || start.template_version != "v1"
            || binding.profile_id.as_deref() != Some("genshin")
        {
            anyhow::bail!("launch-to-ready only supports canonical genshin/v1");
        }
        Ok(Self {
            task_run_id: start.task_run_id.clone(),
            trace_id: start.trace_id.clone(),
            session_id: start.session_id.clone(),
            connection_id: start.connection_id,
            binding,
            frame_width: 0,
            frame_height: 0,
            last_frame_seq: None,
            target_process_alive: false,
            target_window_alive: false,
            accepted_click_source_frame_seq: None,
            last_applied_click_source_frame_seq: None,
        })
    }

    pub fn record_frame(&mut self, binding: &TargetBinding, frame: &TaskRunFrame) -> Result<u64> {
        let expected = self.last_frame_seq.map_or(0, |value| value + 1);
        if frame.task_run_id != self.task_run_id
            || frame.trace_id != self.trace_id
            || frame.session_id != self.session_id
            || frame.connection_id != self.connection_id
            || frame.frame_seq != expected
            || !same_binding(&self.binding, binding)
            || frame.window_width == 0
            || frame.window_height == 0
        {
            anyhow::bail!("target binding or frame dimensions changed");
        }
        self.frame_width = frame.window_width;
        self.frame_height = frame.window_height;
        self.last_frame_seq = Some(frame.frame_seq);
        self.target_process_alive = frame.target_process_alive;
        self.target_window_alive = frame.target_window_alive;
        Ok(frame.frame_seq)
    }

    pub fn authorize_click(
        &mut self,
        click: &TaskRunClick,
        binding: &TargetBinding,
        width: u32,
        height: u32,
        target_process_alive: bool,
        target_window_alive: bool,
    ) -> Result<(u32, u32)> {
        if click.task_run_id != self.task_run_id
            || click.trace_id != self.trace_id
            || click.session_id != self.session_id
            || click.connection_id != self.connection_id
            || !same_binding(&self.binding, binding)
            || self.last_frame_seq != Some(click.source_frame_seq)
            || self.frame_width != width
            || self.frame_height != height
            || !self.target_process_alive
            || !self.target_window_alive
            || !target_process_alive
            || !target_window_alive
        {
            anyhow::bail!("stale task-run click");
        }
        if self.accepted_click_source_frame_seq.is_some() {
            anyhow::bail!("task-run click already consumed");
        }
        // ponytail: registry records authorization only; the OS input slice reports an applied click.
        self.accepted_click_source_frame_seq = Some(click.source_frame_seq);
        Ok((
            (click.client_x_ratio * f64::from(width)) as u32,
            (click.client_y_ratio * f64::from(height)) as u32,
        ))
    }

    /// Record the source frame only after the caller has completed the OS click.
    pub fn mark_click_applied(&mut self, source_frame_seq: u64) -> Result<()> {
        if self.accepted_click_source_frame_seq != Some(source_frame_seq) {
            anyhow::bail!("task-run click was not authorized");
        }
        self.last_applied_click_source_frame_seq = Some(source_frame_seq);
        Ok(())
    }

    pub fn last_applied_click_source_frame_seq(&self) -> Option<u64> {
        self.last_applied_click_source_frame_seq
    }
}

fn same_binding(expected: &TargetBinding, current: &TargetBinding) -> bool {
    expected.hwnd == current.hwnd && expected.pid == current.pid
}

/// Narrow production boundary; tests provide the fake and the next slice provides OS wiring.
pub trait LaunchToReadyOps {
    fn launch_and_bind(&mut self, start: &TaskRunStart) -> Result<LaunchedTarget>;
    fn capture_target(&mut self) -> Result<CapturedTarget>;
    fn click_target(
        &mut self,
        binding: &TargetBinding,
        source_width: u32,
        source_height: u32,
        x: u32,
        y: u32,
    ) -> Result<()>;
    fn release_input(&mut self) -> Result<()>;
    fn close_owned_process(&mut self) -> Result<()>;
    fn force_close_owned_process(&mut self) -> Result<()>;
}

pub struct LaunchedTarget {
    pub binding: TargetBinding,
    pub client_version: String,
}

pub struct CapturedTarget {
    pub binding: TargetBinding,
    pub jpeg_base64: String,
    pub width: u32,
    pub height: u32,
    pub process_alive: bool,
    pub window_alive: bool,
}

/// Production adapter intentionally exposes no arbitrary desktop-input surface.
pub(crate) struct ProductionLaunchToReadyOps<'a> {
    pub process: &'a mut ProcessManager,
    pub input: &'a mut InputController,
    pub capture: &'a ScreenCapture,
    pub owned: &'a mut Option<TargetBinding>,
}

impl LaunchToReadyOps for ProductionLaunchToReadyOps<'_> {
    fn launch_and_bind(&mut self, start: &TaskRunStart) -> Result<LaunchedTarget> {
        if self.process.active_target().is_some() {
            anyhow::bail!("launch-to-ready rejects an existing active target");
        }
        let (executable, working_dir) = start
            .local_target()
            .ok_or_else(|| anyhow::anyhow!("launch-to-ready local target is unavailable"))?;
        self.process
            .launch_game("genshin", executable, &[], working_dir)?;
        let binding = self.process.active_binding_or_refresh()?;
        *self.owned = Some(binding.clone());
        let Some(client_version) = self.process.active_client_version() else {
            let _ = self.input.emergency_stop();
            let _ = self.close_owned_process();
            anyhow::bail!("game client version is unavailable");
        };
        Ok(LaunchedTarget {
            binding,
            client_version: client_version.to_string(),
        })
    }

    fn capture_target(&mut self) -> Result<CapturedTarget> {
        let (binding, frame) = target_operation::capture_active_target(self.process, self.capture)?;
        let owned = self
            .owned
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("task owns no target"))?;
        if binding.pid != owned.pid || binding.hwnd != owned.hwnd {
            anyhow::bail!("target binding changed during task capture");
        }
        Ok(CapturedTarget {
            binding,
            jpeg_base64: data_encoding::BASE64.encode(&frame.jpeg),
            width: frame.width,
            height: frame.height,
            process_alive: true,
            window_alive: true,
        })
    }

    fn click_target(
        &mut self,
        binding: &TargetBinding,
        source_width: u32,
        source_height: u32,
        x: u32,
        y: u32,
    ) -> Result<()> {
        let owned = self
            .owned
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("task owns no target"))?;
        if binding.pid != owned.pid || binding.hwnd != owned.hwnd {
            anyhow::bail!("target binding is not task-owned");
        }
        target_operation::click_active_target_once(
            self.process,
            self.input,
            binding,
            source_width,
            source_height,
            x,
            y,
        )
    }

    fn release_input(&mut self) -> Result<()> {
        self.input.emergency_stop()
    }

    fn close_owned_process(&mut self) -> Result<()> {
        let Some(owned) = self.owned.as_ref() else {
            return Ok(());
        };
        let current = self.process.active_binding_or_refresh()?;
        require_owned_binding(owned, &current)?;
        self.process.kill(Some(owned.pid), false)?;
        *self.owned = None;
        Ok(())
    }

    fn force_close_owned_process(&mut self) -> Result<()> {
        let Some(owned) = self.owned.as_ref() else {
            return Ok(());
        };
        let current = self.process.active_binding_or_refresh()?;
        require_owned_binding(owned, &current)?;
        self.process.kill(Some(owned.pid), true)?;
        *self.owned = None;
        Ok(())
    }
}

fn require_owned_binding(owned: &TargetBinding, current: &TargetBinding) -> Result<()> {
    if !same_binding(owned, current) {
        anyhow::bail!("refusing to close a target not owned by this task");
    }
    Ok(())
}

struct ActiveExecutor {
    start: TaskRunStart,
    registry: ActiveLaunchToReadyRun,
    deadline: Instant,
    leave_running: bool,
    client_version: String,
}

pub struct LaunchToReadyEngine {
    active: Option<ActiveExecutor>,
    cleanup_receipt_recorded: bool,
    pending_cleanup_receipt: Option<TaskRunCleanupReceipt>,
}

impl LaunchToReadyEngine {
    pub fn new() -> Self {
        Self {
            active: None,
            cleanup_receipt_recorded: false,
            pending_cleanup_receipt: None,
        }
    }

    pub(crate) fn active_identity(&self) -> Option<(String, String, String)> {
        self.active.as_ref().map(|active| {
            (
                active.start.task_run_id.clone(),
                active.start.trace_id.clone(),
                active.start.session_id.clone(),
            )
        })
    }

    pub(crate) fn take_cleanup_receipt(&mut self) -> Option<TaskRunCleanupReceipt> {
        self.pending_cleanup_receipt.take()
    }

    pub fn start<O: LaunchToReadyOps>(
        &mut self,
        start: TaskRunStart,
        now: Instant,
        ops: &mut O,
    ) -> Result<()> {
        if self.active.is_some() {
            anyhow::bail!("launch-to-ready executor busy");
        }
        let leave_running = parse_params(&start.params, start.timeout_s)?;
        if start.game_slug != "genshin"
            || start.template_id != "genshin/launch-to-ready"
            || start.template_version != "v1"
            || start.timeout_s == 0
            || start.local_target().is_none()
        {
            anyhow::bail!("unknown launch-to-ready template");
        }
        self.cleanup_receipt_recorded = false;
        self.pending_cleanup_receipt = None;
        let launched = ops.launch_and_bind(&start)?;
        let registry = ActiveLaunchToReadyRun::new(&start, launched.binding);
        let registry = match registry {
            Ok(registry) => registry,
            Err(err) => {
                let input_released = ops.release_input().is_ok();
                let owned_cleanup = if ops.close_owned_process().is_ok() {
                    OwnedCleanup::Completed
                } else {
                    OwnedCleanup::Failed
                };
                let error_code = cleanup_error_code(input_released, owned_cleanup);
                self.record_cleanup_receipt_for_identity(
                    &start,
                    input_released,
                    owned_cleanup,
                    error_code,
                );
                return Err(err);
            }
        };
        self.active = Some(ActiveExecutor {
            start,
            registry,
            deadline: now + Duration::from_secs(1),
            leave_running,
            client_version: launched.client_version,
        });
        if let Some(active) = self.active.as_mut() {
            active.deadline = now + Duration::from_secs(active.start.timeout_s);
        }
        Ok(())
    }

    pub fn tick<O: LaunchToReadyOps>(
        &mut self,
        now: Instant,
        ops: &mut O,
    ) -> Result<Option<TaskRunFrame>> {
        if self.active.is_none() {
            anyhow::bail!("no active executor");
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| now >= active.deadline)
        {
            self.cleanup(ops)?;
            return Ok(None);
        }
        let captured = ops.capture_target()?;
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no active executor"))?;
        let seq = active.registry.last_frame_seq.map_or(0, |seq| seq + 1);
        let frame = TaskRunFrame {
            task_run_id: active.start.task_run_id.clone(),
            trace_id: active.start.trace_id.clone(),
            session_id: active.start.session_id.clone(),
            connection_id: active.start.connection_id,
            client_version: active.client_version.clone(),
            frame_seq: seq,
            window_width: captured.width,
            window_height: captured.height,
            frame_jpeg_base64: captured.jpeg_base64,
            target_process_alive: captured.process_alive,
            target_window_alive: captured.window_alive,
            last_applied_click_source_frame_seq: active
                .registry
                .last_applied_click_source_frame_seq(),
        };
        active.registry.record_frame(&captured.binding, &frame)?;
        Ok(Some(frame))
    }

    pub fn click<O: LaunchToReadyOps>(&mut self, click: &TaskRunClick, ops: &mut O) -> Result<()> {
        self.require_identity(
            &click.task_run_id,
            &click.trace_id,
            &click.session_id,
            click.connection_id,
        )?;
        let result = (|| {
            if !(click.client_x_ratio.is_finite()
                && click.client_y_ratio.is_finite()
                && 0.0 < click.client_x_ratio
                && click.client_x_ratio < 1.0
                && 0.0 < click.client_y_ratio
                && click.client_y_ratio < 1.0)
            {
                anyhow::bail!("task-run click ratio outside source frame");
            }
            let captured = ops.capture_target()?;
            let active = self
                .active
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("no active executor"))?;
            let (x, y) = active.registry.authorize_click(
                click,
                &captured.binding,
                captured.width,
                captured.height,
                captured.process_alive,
                captured.window_alive,
            )?;
            ops.click_target(&captured.binding, captured.width, captured.height, x, y)?;
            active.registry.mark_click_applied(click.source_frame_seq)
        })();
        if result.is_err() {
            let _ = self.cleanup(ops);
        }
        result
    }

    pub fn cancel<O: LaunchToReadyOps>(
        &mut self,
        cancel: &TaskRunCancel,
        ops: &mut O,
    ) -> Result<()> {
        self.require_identity(
            &cancel.task_run_id,
            &cancel.trace_id,
            &cancel.session_id,
            cancel.connection_id,
        )?;
        self.cleanup(ops)
    }

    pub fn terminal<O: LaunchToReadyOps>(
        &mut self,
        terminal: &TaskRunTerminal,
        ops: &mut O,
    ) -> Result<()> {
        self.require_identity(
            &terminal.task_run_id,
            &terminal.trace_id,
            &terminal.session_id,
            terminal.connection_id,
        )?;
        let keep = terminal.outcome == "succeeded"
            && self
                .active
                .as_ref()
                .is_some_and(|active| active.leave_running);
        if keep {
            if ops.release_input().is_ok() {
                self.record_cleanup_receipt(true, OwnedCleanup::NotRequired, None);
                self.active = None;
                Ok(())
            } else {
                self.cleanup(ops)
            }
        } else {
            self.cleanup(ops)
        }
    }

    pub fn disconnect<O: LaunchToReadyOps>(&mut self, ops: &mut O) -> Result<()> {
        self.cleanup(ops)
    }

    fn require_identity(
        &self,
        task_run_id: &str,
        trace_id: &str,
        session_id: &str,
        connection_id: Uuid,
    ) -> Result<()> {
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active executor"))?;
        if active.start.task_run_id != task_run_id
            || active.start.trace_id != trace_id
            || active.start.session_id != session_id
            || active.start.connection_id != connection_id
        {
            anyhow::bail!("stale task-run identity");
        }
        Ok(())
    }

    fn cleanup<O: LaunchToReadyOps>(&mut self, ops: &mut O) -> Result<()> {
        if self.active.is_none() {
            return Ok(());
        }
        let mut release = ops.release_input();
        let mut close = ops.close_owned_process();
        for _ in 1..CLEANUP_ATTEMPTS {
            if release.is_ok() && close.is_ok() {
                break;
            }
            if release.is_err() {
                release = ops.release_input();
            }
            if close.is_err() {
                close = ops.close_owned_process();
            }
        }
        if close.is_err() {
            close = ops.force_close_owned_process();
        }
        let input_released = release.is_ok();
        let owned_cleanup = if close.is_ok() {
            OwnedCleanup::Completed
        } else {
            OwnedCleanup::Failed
        };
        let error_code = cleanup_error_code(input_released, owned_cleanup);
        self.record_cleanup_receipt(input_released, owned_cleanup, error_code);
        if release.is_ok() && close.is_ok() {
            self.active = None;
        }
        release.and(close)
    }

    fn record_cleanup_receipt(
        &mut self,
        input_released: bool,
        owned_cleanup: OwnedCleanup,
        error_code: Option<String>,
    ) {
        let Some((task_run_id, trace_id, session_id)) = self.active_identity() else {
            return;
        };
        self.record_cleanup_receipt_fields(
            task_run_id,
            trace_id,
            session_id,
            input_released,
            owned_cleanup,
            error_code,
        );
    }

    fn record_cleanup_receipt_for_identity(
        &mut self,
        start: &TaskRunStart,
        input_released: bool,
        owned_cleanup: OwnedCleanup,
        error_code: Option<String>,
    ) {
        self.record_cleanup_receipt_fields(
            start.task_run_id.clone(),
            start.trace_id.clone(),
            start.session_id.clone(),
            input_released,
            owned_cleanup,
            error_code,
        );
    }

    fn record_cleanup_receipt_fields(
        &mut self,
        task_run_id: String,
        trace_id: String,
        session_id: String,
        input_released: bool,
        owned_cleanup: OwnedCleanup,
        error_code: Option<String>,
    ) {
        if self.cleanup_receipt_recorded {
            return;
        }
        self.pending_cleanup_receipt = Some(TaskRunCleanupReceipt {
            task_run_id,
            trace_id,
            session_id,
            input_released,
            owned_cleanup,
            error_code,
        });
        self.cleanup_receipt_recorded = true;
    }
}

fn cleanup_error_code(input_released: bool, owned_cleanup: OwnedCleanup) -> Option<String> {
    if input_released && owned_cleanup == OwnedCleanup::Completed {
        None
    } else if !input_released && owned_cleanup == OwnedCleanup::Failed {
        Some("cleanup_failed".into())
    } else if !input_released {
        Some("input_release_failed".into())
    } else {
        Some("owned_cleanup_failed".into())
    }
}

impl Default for LaunchToReadyEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_params(params: &serde_json::Value, timeout_s: u64) -> Result<bool> {
    if timeout_s == 0 || timeout_s > 600 {
        anyhow::bail!("task-run timeout outside supported range");
    }
    let object = params
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("task-run params must be an object"))?;
    for key in object.keys() {
        if key != "leave_running" && key != "timeout_s" {
            anyhow::bail!("unknown launch-to-ready parameter");
        }
    }
    if let Some(value) = object.get("timeout_s") {
        if value.as_u64() != Some(timeout_s) {
            anyhow::bail!("task-run timeout parameter conflicts with command");
        }
    }
    match object.get("leave_running") {
        None => Ok(true),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("leave_running must be boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeOps {
        launch_binding: TargetBinding,
        captured_binding: TargetBinding,
        jpeg_base64: String,
        width: u32,
        height: u32,
        process_alive: bool,
        window_alive: bool,
        launch_count: usize,
        click_attempts: usize,
        clicks: Vec<(u32, u32)>,
        release_count: usize,
        close_count: usize,
        fail_capture: bool,
        fail_click: bool,
        fail_release_once: bool,
        fail_close_once: bool,
        fail_close_always: bool,
        fail_force_once: bool,
        force_close_count: usize,
    }

    impl LaunchToReadyOps for FakeOps {
        fn launch_and_bind(&mut self, _start: &TaskRunStart) -> Result<LaunchedTarget> {
            self.launch_count += 1;
            Ok(LaunchedTarget {
                binding: self.launch_binding.clone(),
                client_version: "5.7.0".into(),
            })
        }

        fn capture_target(&mut self) -> Result<CapturedTarget> {
            if self.fail_capture {
                anyhow::bail!("fake capture failure");
            }
            Ok(CapturedTarget {
                binding: self.captured_binding.clone(),
                jpeg_base64: self.jpeg_base64.clone(),
                width: self.width,
                height: self.height,
                process_alive: self.process_alive,
                window_alive: self.window_alive,
            })
        }

        fn click_target(
            &mut self,
            _binding: &TargetBinding,
            _source_width: u32,
            _source_height: u32,
            x: u32,
            y: u32,
        ) -> Result<()> {
            self.click_attempts += 1;
            if self.fail_click {
                anyhow::bail!("fake OS click failure");
            }
            self.clicks.push((x, y));
            Ok(())
        }

        fn release_input(&mut self) -> Result<()> {
            self.release_count += 1;
            if self.fail_release_once {
                self.fail_release_once = false;
                anyhow::bail!("fake release failure");
            }
            Ok(())
        }

        fn close_owned_process(&mut self) -> Result<()> {
            self.close_count += 1;
            if self.fail_close_once || self.fail_close_always {
                self.fail_close_once = false;
                anyhow::bail!("fake close failure");
            }
            Ok(())
        }

        fn force_close_owned_process(&mut self) -> Result<()> {
            self.force_close_count += 1;
            if self.fail_force_once {
                self.fail_force_once = false;
                anyhow::bail!("fake force close failure");
            }
            Ok(())
        }
    }

    fn connection_id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn binding() -> TargetBinding {
        TargetBinding {
            profile_id: Some("genshin".into()),
            resolved_executable: "YuanShen.exe".into(),
            process_name: "YuanShen.exe".into(),
            hwnd: 1,
            pid: 2,
            title: "原神".into(),
            class_name: Some("UnityWndClass".into()),
            rect: crate::window::WindowRect {
                left: 0,
                top: 0,
                right: 100,
                bottom: 200,
            },
        }
    }

    fn fake_ops() -> FakeOps {
        let binding = binding();
        FakeOps {
            launch_binding: binding.clone(),
            captured_binding: binding,
            jpeg_base64: "transient-frame".into(),
            width: 100,
            height: 200,
            process_alive: true,
            window_alive: true,
            launch_count: 0,
            click_attempts: 0,
            clicks: Vec::new(),
            release_count: 0,
            close_count: 0,
            fail_capture: false,
            fail_click: false,
            fail_release_once: false,
            fail_close_once: false,
            fail_close_always: false,
            fail_force_once: false,
            force_close_count: 0,
        }
    }

    fn start(params: serde_json::Value) -> TaskRunStart {
        TaskRunStart {
            message_type: "task_run_start".into(),
            task_run_id: "task".into(),
            trace_id: "trace".into(),
            session_id: "session".into(),
            connection_id: connection_id(),
            game_slug: "genshin".into(),
            template_id: "genshin/launch-to-ready".into(),
            template_version: "v1".into(),
            params,
            timeout_s: 30,
            resolved_executable: Some("YuanShen.exe".into()),
            resolved_working_dir: None,
        }
    }

    fn cancel() -> TaskRunCancel {
        TaskRunCancel {
            message_type: "task_run_cancel".into(),
            task_run_id: "task".into(),
            trace_id: "trace".into(),
            session_id: "session".into(),
            connection_id: connection_id(),
        }
    }

    fn terminal(outcome: &str) -> TaskRunTerminal {
        TaskRunTerminal {
            message_type: "task_run_terminal".into(),
            task_run_id: "task".into(),
            trace_id: "trace".into(),
            session_id: "session".into(),
            connection_id: connection_id(),
            outcome: outcome.into(),
        }
    }

    fn started_engine(
        ops: &mut FakeOps,
        params: serde_json::Value,
    ) -> (LaunchToReadyEngine, Instant) {
        let now = Instant::now();
        let mut engine = LaunchToReadyEngine::new();
        engine.start(start(params), now, ops).unwrap();
        (engine, now)
    }
    fn click(seq: u64) -> TaskRunClick {
        TaskRunClick {
            message_type: "task_run_click".into(),
            task_run_id: "task".into(),
            trace_id: "trace".into(),
            session_id: "session".into(),
            connection_id: connection_id(),
            click_id: "click".into(),
            source_frame_seq: seq,
            client_x_ratio: 0.5,
            client_y_ratio: 0.25,
            button: "left".into(),
            click_count: 1,
        }
    }
    fn frame(seq: u64) -> TaskRunFrame {
        TaskRunFrame {
            task_run_id: "task".into(),
            trace_id: "trace".into(),
            session_id: "session".into(),
            connection_id: connection_id(),
            client_version: "0.1.0".into(),
            frame_seq: seq,
            window_width: 100,
            window_height: 200,
            frame_jpeg_base64: "frame".into(),
            target_process_alive: true,
            target_window_alive: true,
            last_applied_click_source_frame_seq: None,
        }
    }
    #[test]
    fn genshin_frame_identity_and_one_click_are_strict() {
        let binding = binding();
        let mut run =
            ActiveLaunchToReadyRun::new(&start(serde_json::json!({})), binding.clone()).unwrap();
        assert_eq!(run.record_frame(&binding, &frame(0)).unwrap(), 0);
        assert_eq!(
            run.authorize_click(&click(0), &binding, 100, 200, true, true)
                .unwrap(),
            (50, 50)
        );
        assert!(run
            .authorize_click(&click(0), &binding, 100, 200, true, true)
            .is_err());
        assert_eq!(run.accepted_click_source_frame_seq, Some(0));
        assert_eq!(run.last_applied_click_source_frame_seq(), None);
        run.mark_click_applied(0).unwrap();
        assert_eq!(run.last_applied_click_source_frame_seq(), Some(0));
        let next_frame = frame(1);
        assert_eq!(next_frame.last_applied_click_source_frame_seq, None);
        assert_eq!(run.record_frame(&binding, &next_frame).unwrap(), 1);
    }

    #[test]
    fn rejected_frame_identity_or_sequence_does_not_advance_state() {
        let binding = binding();
        let mut run =
            ActiveLaunchToReadyRun::new(&start(serde_json::json!({})), binding.clone()).unwrap();
        assert!(run.record_frame(&binding, &frame(1)).is_err());
        assert_eq!(run.record_frame(&binding, &frame(0)).unwrap(), 0);
        assert!(run.record_frame(&binding, &frame(0)).is_err());
        assert_eq!(run.record_frame(&binding, &frame(1)).unwrap(), 1);
    }

    #[test]
    fn click_requires_matching_connection_and_live_source_frame() {
        let binding = binding();
        let mut run =
            ActiveLaunchToReadyRun::new(&start(serde_json::json!({})), binding.clone()).unwrap();
        let mut stale_frame = frame(0);
        stale_frame.target_window_alive = false;
        assert_eq!(run.record_frame(&binding, &stale_frame).unwrap(), 0);
        assert!(run
            .authorize_click(&click(0), &binding, 100, 200, true, true)
            .is_err());

        assert_eq!(run.record_frame(&binding, &frame(1)).unwrap(), 1);
        let mut wrong_connection = click(0);
        wrong_connection.connection_id =
            Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap();
        wrong_connection.source_frame_seq = 1;
        assert!(run
            .authorize_click(&wrong_connection, &binding, 100, 200, true, true)
            .is_err());
        assert_eq!(
            run.authorize_click(&click(1), &binding, 100, 200, true, true)
                .unwrap(),
            (50, 50)
        );
    }

    #[test]
    fn start_defaults_leave_running_and_rejects_invalid_params_before_ops() {
        let mut ops = fake_ops();
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({}));
        assert!(engine.active.as_ref().unwrap().leave_running);
        engine.terminal(&terminal("succeeded"), &mut ops).unwrap();
        assert_eq!((ops.release_count, ops.close_count), (1, 0));

        for params in [
            serde_json::json!({"leave_running": "true"}),
            serde_json::json!({"unexpected": true}),
            serde_json::json!({"executable": "untrusted.exe"}),
            serde_json::json!({"executable_path": "C:\\private"}),
            serde_json::json!({"working_dir": "C:\\private"}),
            serde_json::json!({"timeout_s": 29}),
        ] {
            let mut engine = LaunchToReadyEngine::new();
            assert!(engine
                .start(start(params), Instant::now(), &mut ops)
                .is_err());
        }
        let mut unknown_template = start(serde_json::json!({}));
        unknown_template.template_id = "unknown".into();
        let mut engine = LaunchToReadyEngine::new();
        assert!(engine
            .start(unknown_template, Instant::now(), &mut ops)
            .is_err());
        assert_eq!(ops.launch_count, 1);
    }

    #[test]
    fn start_requires_agent_local_target_before_launch() {
        let mut ops = fake_ops();
        let mut start = start(serde_json::json!({}));
        start.resolved_executable = None;
        start.resolved_working_dir = None;

        assert!(LaunchToReadyEngine::new()
            .start(start, Instant::now(), &mut ops)
            .is_err());
        assert_eq!(ops.launch_count, 0);
    }

    #[test]
    fn start_conflict_and_post_bind_registry_failure_cleanup_once() {
        let mut ops = fake_ops();
        let (mut engine, now) = started_engine(&mut ops, serde_json::json!({}));
        assert!(engine
            .start(start(serde_json::json!({})), now, &mut ops)
            .is_err());
        assert_eq!(ops.launch_count, 1);
        engine.disconnect(&mut ops).unwrap();

        let mut failing_ops = fake_ops();
        failing_ops.launch_binding.profile_id = None;
        let mut engine = LaunchToReadyEngine::new();
        assert!(engine
            .start(
                start(serde_json::json!({})),
                Instant::now(),
                &mut failing_ops
            )
            .is_err());
        assert_eq!(failing_ops.launch_count, 1);
        assert_eq!((failing_ops.release_count, failing_ops.close_count), (1, 1));
        assert!(engine.active.is_none());
        let receipt = engine
            .take_cleanup_receipt()
            .expect("post-bind failure cleanup receipt");
        assert!(receipt.input_released);
        assert_eq!(receipt.owned_cleanup, OwnedCleanup::Completed);
        assert!(receipt.error_code.is_none());
    }

    #[test]
    fn tick_preserves_identity_sequence_liveness_and_transient_payload() {
        let mut ops = fake_ops();
        ops.jpeg_base64 = "ephemeral-jpeg".into();
        ops.process_alive = false;
        let (mut engine, now) = started_engine(&mut ops, serde_json::json!({}));
        let first = engine.tick(now, &mut ops).unwrap().unwrap();
        assert_eq!(first.task_run_id, "task");
        assert_eq!(first.trace_id, "trace");
        assert_eq!(first.session_id, "session");
        assert_eq!(first.connection_id, connection_id());
        assert_eq!(first.client_version, "5.7.0");
        assert_eq!(first.frame_seq, 0);
        assert_eq!(first.frame_jpeg_base64, "ephemeral-jpeg");
        assert!(!first.target_process_alive);
        assert!(first.target_window_alive);
        assert_eq!(first.last_applied_click_source_frame_seq, None);
        assert_eq!(engine.tick(now, &mut ops).unwrap().unwrap().frame_seq, 1);
    }

    #[test]
    fn invalid_programmatic_ratios_never_call_click() {
        let mut ops = fake_ops();
        let (mut engine, now) = started_engine(&mut ops, serde_json::json!({}));
        engine.tick(now, &mut ops).unwrap();
        for ratio in [f64::NAN, f64::INFINITY, 0.0, 1.0, -0.1, 1.1] {
            let mut invalid = click(0);
            invalid.client_x_ratio = ratio;
            assert!(engine.click(&invalid, &mut ops).is_err());
        }
        assert_eq!(ops.click_attempts, 0);
        assert_eq!((ops.release_count, ops.close_count), (1, 1));
    }

    #[test]
    fn valid_click_is_applied_once_and_replay_cleans_up() {
        let mut ops = fake_ops();
        let (mut engine, now) = started_engine(&mut ops, serde_json::json!({}));
        engine.tick(now, &mut ops).unwrap();
        engine.click(&click(0), &mut ops).unwrap();
        assert_eq!(ops.clicks, vec![(50, 50)]);
        assert_eq!(
            engine
                .tick(now, &mut ops)
                .unwrap()
                .unwrap()
                .last_applied_click_source_frame_seq,
            Some(0)
        );
        assert!(engine.click(&click(1), &mut ops).is_err());
        assert_eq!(ops.clicks, vec![(50, 50)]);
        assert_eq!((ops.release_count, ops.close_count), (1, 1));
    }

    #[test]
    fn stale_click_identity_frame_binding_and_os_failure_cleanup() {
        let mut identity_ops = fake_ops();
        let (mut engine, now) = started_engine(&mut identity_ops, serde_json::json!({}));
        engine.tick(now, &mut identity_ops).unwrap();
        let mut stale_identity = click(0);
        stale_identity.trace_id = "stale".into();
        assert!(engine.click(&stale_identity, &mut identity_ops).is_err());
        assert_eq!(
            (identity_ops.release_count, identity_ops.close_count),
            (0, 0)
        );

        let mut frame_ops = fake_ops();
        let (mut engine, now) = started_engine(&mut frame_ops, serde_json::json!({}));
        engine.tick(now, &mut frame_ops).unwrap();
        assert!(engine.click(&click(1), &mut frame_ops).is_err());
        assert_eq!((frame_ops.release_count, frame_ops.close_count), (1, 1));

        let mut binding_ops = fake_ops();
        let (mut engine, now) = started_engine(&mut binding_ops, serde_json::json!({}));
        engine.tick(now, &mut binding_ops).unwrap();
        binding_ops.captured_binding.hwnd = 9;
        assert!(engine.click(&click(0), &mut binding_ops).is_err());
        assert_eq!((binding_ops.release_count, binding_ops.close_count), (1, 1));

        let mut os_failure_ops = fake_ops();
        os_failure_ops.fail_click = true;
        let (mut engine, now) = started_engine(&mut os_failure_ops, serde_json::json!({}));
        engine.tick(now, &mut os_failure_ops).unwrap();
        assert!(engine.click(&click(0), &mut os_failure_ops).is_err());
        assert_eq!(os_failure_ops.click_attempts, 1);
        assert!(os_failure_ops.clicks.is_empty());
        assert_eq!(
            (os_failure_ops.release_count, os_failure_ops.close_count),
            (1, 1)
        );
        assert!(engine.active.is_none());
    }

    #[test]
    fn terminal_requires_full_identity_and_obeys_leave_running() {
        let mut ops = fake_ops();
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({"leave_running": true}));
        let mut stale = terminal("succeeded");
        stale.connection_id = Uuid::new_v4();
        assert!(engine.terminal(&stale, &mut ops).is_err());
        assert_eq!((ops.release_count, ops.close_count), (0, 0));
        engine.terminal(&terminal("succeeded"), &mut ops).unwrap();
        assert_eq!((ops.release_count, ops.close_count), (1, 0));

        for outcome in ["succeeded", "failed", "canceled", "interrupted"] {
            let mut ops = fake_ops();
            let leave_running = outcome != "succeeded";
            let (mut engine, _) = started_engine(
                &mut ops,
                serde_json::json!({"leave_running": leave_running}),
            );
            engine.terminal(&terminal(outcome), &mut ops).unwrap();
            assert_eq!((ops.release_count, ops.close_count), (1, 1));
        }
    }

    #[test]
    fn successful_leave_running_terminal_records_one_typed_cleanup_receipt() {
        let mut ops = fake_ops();
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({"leave_running": true}));

        engine.terminal(&terminal("succeeded"), &mut ops).unwrap();

        let receipt = engine.take_cleanup_receipt().expect("cleanup receipt");
        assert_eq!(receipt.task_run_id, "task");
        assert_eq!(receipt.trace_id, "trace");
        assert_eq!(receipt.session_id, "session");
        assert!(receipt.input_released);
        assert_eq!(
            receipt.owned_cleanup,
            crate::protocol::OwnedCleanup::NotRequired
        );
        assert!(receipt.error_code.is_none());
        assert!(engine.take_cleanup_receipt().is_none());
    }

    #[test]
    fn failed_leave_running_input_release_falls_back_to_owned_cleanup_receipt() {
        let mut ops = fake_ops();
        ops.fail_release_once = true;
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({"leave_running": true}));

        engine.terminal(&terminal("succeeded"), &mut ops).unwrap();

        let receipt = engine.take_cleanup_receipt().expect("cleanup receipt");
        assert!(receipt.input_released);
        assert_eq!(receipt.owned_cleanup, OwnedCleanup::Completed);
        assert!(receipt.error_code.is_none());
        assert_eq!((ops.release_count, ops.close_count), (2, 1));
    }

    #[test]
    fn timeout_cancel_disconnect_and_reconnect_cleanup_are_idempotent() {
        let mut ops = fake_ops();
        let now = Instant::now();
        let mut engine = LaunchToReadyEngine::new();
        let mut timed = start(serde_json::json!({}));
        timed.timeout_s = 1;
        engine.start(timed, now, &mut ops).unwrap();
        assert!(engine
            .tick(now + Duration::from_secs(1), &mut ops)
            .unwrap()
            .is_none());
        let receipt = engine
            .take_cleanup_receipt()
            .expect("timeout cleanup receipt");
        assert!(receipt.input_released);
        assert_eq!(receipt.owned_cleanup, OwnedCleanup::Completed);
        engine.disconnect(&mut ops).unwrap();
        assert!(engine.take_cleanup_receipt().is_none());
        assert_eq!((ops.release_count, ops.close_count), (1, 1));

        engine
            .start(start(serde_json::json!({})), now, &mut ops)
            .unwrap();
        engine.cancel(&cancel(), &mut ops).unwrap();
        let receipt = engine
            .take_cleanup_receipt()
            .expect("cancel cleanup receipt");
        assert!(receipt.input_released);
        assert_eq!(receipt.owned_cleanup, OwnedCleanup::Completed);
        engine.disconnect(&mut ops).unwrap();
        assert_eq!((ops.release_count, ops.close_count), (2, 2));

        engine
            .start(start(serde_json::json!({})), now, &mut ops)
            .unwrap();
        engine.disconnect(&mut ops).unwrap();
        assert_eq!((ops.release_count, ops.close_count), (3, 3));
        assert!(engine
            .start(start(serde_json::json!({})), now, &mut ops)
            .is_ok());
    }

    #[test]
    fn cleanup_keeps_active_run_until_release_and_close_can_be_retried() {
        let mut ops = fake_ops();
        ops.fail_release_once = true;
        ops.fail_close_always = true;
        ops.fail_force_once = true;
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({}));

        assert!(engine.disconnect(&mut ops).is_err());
        assert!(engine.active.is_some());
        assert_eq!(
            (ops.release_count, ops.close_count, ops.force_close_count),
            (2, 2, 1)
        );
        let receipt = engine
            .take_cleanup_receipt()
            .expect("failed cleanup receipt");
        assert!(receipt.input_released);
        assert_eq!(receipt.owned_cleanup, OwnedCleanup::Failed);
        assert_eq!(receipt.error_code.as_deref(), Some("owned_cleanup_failed"));

        engine.disconnect(&mut ops).unwrap();
        assert!(engine.active.is_none());
        assert_eq!(
            (ops.release_count, ops.close_count, ops.force_close_count),
            (3, 4, 2)
        );
        assert!(engine.take_cleanup_receipt().is_none());
    }

    #[test]
    fn disconnect_retries_failed_release_and_owned_close_automatically() {
        let mut ops = fake_ops();
        ops.fail_release_once = true;
        ops.fail_close_once = true;
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({}));

        engine.disconnect(&mut ops).unwrap();

        assert!(engine.active.is_none());
        assert_eq!((ops.release_count, ops.close_count), (2, 2));
    }

    #[test]
    fn disconnect_force_closes_only_after_bounded_owned_close_retries() {
        let mut ops = fake_ops();
        ops.fail_close_always = true;
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({}));

        engine.disconnect(&mut ops).unwrap();

        assert!(engine.active.is_none());
        assert_eq!(ops.release_count, 1);
        assert_eq!(ops.close_count, CLEANUP_ATTEMPTS);
        assert_eq!(ops.force_close_count, 1);
    }

    #[test]
    fn stale_cancel_never_retries_or_closes_current_owned_run() {
        let mut ops = fake_ops();
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({}));
        let mut stale = cancel();
        stale.connection_id = Uuid::new_v4();

        assert!(engine.cancel(&stale, &mut ops).is_err());
        assert!(engine.active.is_some());
        assert_eq!((ops.release_count, ops.close_count), (0, 0));
        assert!(engine.take_cleanup_receipt().is_none());
    }

    #[test]
    fn force_close_rejects_binding_identity_mismatch() {
        let owned = binding();
        let mut current = binding();
        current.hwnd = 99;

        assert!(require_owned_binding(&owned, &current).is_err());
    }

    #[test]
    fn stale_click_never_touches_current_run_but_current_capture_failure_cleans() {
        let mut ops = fake_ops();
        let (mut engine, now) = started_engine(&mut ops, serde_json::json!({}));
        engine.tick(now, &mut ops).unwrap();
        let mut stale = click(0);
        stale.trace_id = "old".into();
        assert!(engine.click(&stale, &mut ops).is_err());
        assert_eq!(
            (ops.click_attempts, ops.release_count, ops.close_count),
            (0, 0, 0)
        );
        engine.click(&click(0), &mut ops).unwrap();

        let mut ops = fake_ops();
        ops.fail_capture = true;
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({}));
        assert!(engine.click(&click(0), &mut ops).is_err());
        assert_eq!((ops.release_count, ops.close_count), (1, 1));
        assert!(engine.active.is_none());
    }

    #[test]
    fn only_current_invalid_ratio_cleans() {
        let mut ops = fake_ops();
        let (mut engine, _) = started_engine(&mut ops, serde_json::json!({}));
        let mut stale = click(0);
        stale.task_run_id = "old".into();
        stale.client_x_ratio = f64::NAN;
        assert!(engine.click(&stale, &mut ops).is_err());
        assert_eq!((ops.release_count, ops.close_count), (0, 0));
        let mut invalid = click(0);
        invalid.client_x_ratio = f64::NAN;
        assert!(engine.click(&invalid, &mut ops).is_err());
        assert_eq!((ops.release_count, ops.close_count), (1, 1));
    }
}
