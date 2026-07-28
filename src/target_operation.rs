//! Shared target-window operations for runtime and GUI.

use anyhow::{Context, Result};

use crate::capture::{CapturedFrame, ScreenCapture};
use crate::input::InputController;
use crate::process::{
    current_process_privilege_level, process_privilege_level, PrivilegeLevel, ProcessManager,
    TargetBinding,
};
use crate::protocol::InputFrame;
use crate::window::{self, TargetWindow};

pub(crate) fn focus_active_target(process: &mut ProcessManager) -> Result<TargetBinding> {
    let binding = process
        .active_binding_or_refresh()
        .context("target-not-found")?;
    ensure_target_control_allowed(
        current_process_privilege_level(),
        process_privilege_level(binding.pid)?,
    )?;
    window::focus_window(&target_window_from_binding(&binding))?;
    Ok(binding)
}

pub fn capture_active_target(
    process: &mut ProcessManager,
    capture: &ScreenCapture,
) -> Result<(TargetBinding, CapturedFrame)> {
    let binding = process
        .active_binding_or_refresh()
        .context("target-not-found")?;
    let frame = capture
        .capture_window(binding.hwnd)
        .with_context(|| format!("target capture failed for PID {}", binding.pid))?;
    Ok((binding, frame))
}

pub fn send_input_to_active_target(
    process: &mut ProcessManager,
    input: &mut InputController,
    frame: &InputFrame,
) -> Result<TargetBinding> {
    let binding = focus_active_target(process)?;
    input.apply_frame(frame)?;
    Ok(binding)
}

pub fn close_active_target(process: &mut ProcessManager, force: bool) -> Result<()> {
    process
        .active_binding_or_refresh()
        .context("target-not-found")?;
    match process.kill(None, false) {
        Ok(()) => Ok(()),
        Err(graceful_err) if force => process
            .kill(None, true)
            .with_context(|| format!("target graceful close failed: {graceful_err}")),
        Err(err) => Err(err),
    }
}

pub(crate) fn target_window_from_binding(binding: &TargetBinding) -> TargetWindow {
    TargetWindow {
        hwnd: binding.hwnd,
        pid: binding.pid,
        title: binding.title.clone(),
        class_name: binding.class_name.clone(),
        rect: binding.rect.clone(),
    }
}

fn ensure_target_control_allowed(agent: PrivilegeLevel, target: PrivilegeLevel) -> Result<()> {
    if agent == PrivilegeLevel::Standard && target == PrivilegeLevel::Elevated {
        anyhow::bail!("target privilege is higher than agent; restart agent as administrator");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> TargetBinding {
        TargetBinding {
            profile_id: Some("genshin".to_string()),
            resolved_executable: r"C:\Games\YuanShen.exe".to_string(),
            process_name: "YuanShen.exe".to_string(),
            hwnd: 7,
            pid: 42,
            title: "原神".to_string(),
            class_name: Some("UnityWndClass".to_string()),
            rect: crate::window::WindowRect {
                left: 1,
                top: 2,
                right: 101,
                bottom: 202,
            },
        }
    }

    #[test]
    fn target_window_keeps_binding_identity() {
        let binding = binding();
        let window = target_window_from_binding(&binding);

        assert_eq!(window.hwnd, 7);
        assert_eq!(window.pid, 42);
        assert_eq!(window.title, "原神");
        assert_eq!(window.class_name.as_deref(), Some("UnityWndClass"));
        assert_eq!(window.rect.width(), 100);
    }

    #[test]
    fn elevated_target_is_rejected_for_standard_agent() {
        let err = ensure_target_control_allowed(PrivilegeLevel::Standard, PrivilegeLevel::Elevated)
            .unwrap_err()
            .to_string();

        assert!(err.contains("target privilege is higher"));
        assert!(
            ensure_target_control_allowed(PrivilegeLevel::Elevated, PrivilegeLevel::Elevated)
                .is_ok()
        );
    }

    #[test]
    fn focus_without_active_target_fails() {
        let mut process = ProcessManager::new();
        let err = focus_active_target(&mut process).unwrap_err().to_string();

        assert!(err.contains("target-not-found"));
    }

    #[test]
    fn close_without_active_target_fails() {
        let mut process = ProcessManager::new();
        let err = close_active_target(&mut process, true)
            .unwrap_err()
            .to_string();

        assert!(err.contains("target-not-found"));
    }
}
