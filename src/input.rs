//! 抢占式输入控制器。
//!
//! 全量语义：input_frame 中的键盘/鼠标字段包含当前目标状态。
//! - 帧中存在的键 = 目标状态（"down" 按住, "up" 松开）
//! - 帧中缺失的键 = 视为 "up"（松开）
//! - Agent diff 当前状态 vs 目标状态，仅对差异执行 SendInput。

use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::protocol::{InputFrame, MouseState};

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VirtualDesktop {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn virtual_desktop_absolute_point(
    desktop: VirtualDesktop,
    screen_x: i32,
    screen_y: i32,
) -> Result<(i32, i32)> {
    if desktop.width <= 0
        || desktop.height <= 0
        || screen_x < desktop.left
        || screen_y < desktop.top
        || i64::from(screen_x) >= i64::from(desktop.left) + i64::from(desktop.width)
        || i64::from(screen_y) >= i64::from(desktop.top) + i64::from(desktop.height)
    {
        anyhow::bail!("target point is outside the virtual desktop");
    }
    let scale = |offset: i32, size: i32| -> i32 {
        ((i64::from(offset) * 65_535) / i64::from((size - 1).max(1))) as i32
    };
    Ok((
        scale(screen_x - desktop.left, desktop.width),
        scale(screen_y - desktop.top, desktop.height),
    ))
}

/// 输入差异（需要变更的操作）。
#[derive(Debug, Default)]
pub struct InputDiff {
    /// 需要按下的键
    pub key_down: Vec<String>,
    /// 需要松开的键
    pub key_up: Vec<String>,
    /// 鼠标是否需要移动
    pub mouse_move: Option<(i32, i32)>,
    /// 鼠标按键变更: (button, down/up)
    pub mouse_buttons: Vec<(String, bool)>,
}

impl InputDiff {
    /// 计算当前状态与目标状态的差异。
    pub fn compute(
        current_kb: &HashMap<String, String>,
        target_kb: &HashMap<String, String>,
        current_mouse: &MouseState,
        target_mouse: &MouseState,
    ) -> Self {
        let mut diff = InputDiff::default();

        // 键盘 diff
        for (key, target_state) in target_kb {
            let current = current_kb.get(key).map(|s| s.as_str()).unwrap_or("up");
            if current != target_state {
                match target_state.as_str() {
                    "down" => diff.key_down.push(key.clone()),
                    "up" => diff.key_up.push(key.clone()),
                    _ => {}
                }
            }
        }
        // 当前状态存在但目标帧缺失的键 → 松开
        for key in current_kb.keys() {
            if !target_kb.contains_key(key) {
                diff.key_up.push(key.clone());
            }
        }

        // 鼠标 diff。keyboard-only 路径可能把省略的 mouse 补成默认 (0, 0)，
        // 不应因此把光标拖到屏幕左上角。
        let suppress_default_mouse_move = target_mouse.x == 0
            && target_mouse.y == 0
            && (current_mouse.x != 0 || current_mouse.y != 0);
        if !suppress_default_mouse_move
            && (current_mouse.x != target_mouse.x || current_mouse.y != target_mouse.y)
        {
            diff.mouse_move = Some((target_mouse.x, target_mouse.y));
        }
        for (btn, current, target) in [
            (
                "left",
                &current_mouse.buttons.left,
                &target_mouse.buttons.left,
            ),
            (
                "right",
                &current_mouse.buttons.right,
                &target_mouse.buttons.right,
            ),
            (
                "middle",
                &current_mouse.buttons.middle,
                &target_mouse.buttons.middle,
            ),
        ] {
            if current != target {
                diff.mouse_buttons.push((btn.to_string(), target == "down"));
            }
        }

        diff
    }
}

/// 抢占式输入控制器。
pub struct InputController {
    /// 当前键盘状态
    current_kb: HashMap<String, String>,
    /// 当前鼠标状态
    current_mouse: MouseState,
}

impl InputController {
    /// 创建新的输入控制器。
    pub fn new() -> Self {
        Self {
            current_kb: HashMap::new(),
            current_mouse: MouseState::default(),
        }
    }

    /// 应用一帧输入状态。
    ///
    /// Diff 当前状态 vs 目标状态，仅对差异调用 SendInput。
    pub fn apply_frame(&mut self, frame: &InputFrame) -> Result<()> {
        let diff = InputDiff::compute(
            &self.current_kb,
            &frame.keyboard,
            &self.current_mouse,
            &frame.mouse,
        );

        if diff.key_down.is_empty()
            && diff.key_up.is_empty()
            && diff.mouse_move.is_none()
            && diff.mouse_buttons.is_empty()
        {
            return Ok(()); // 无变化
        }

        debug!(
            "input diff: key_down_count={}, key_up_count={}, mouse_move={}, mouse_button_count={}",
            diff.key_down.len(),
            diff.key_up.len(),
            diff.mouse_move.is_some(),
            diff.mouse_buttons.len()
        );

        // Windows SendInput 调用
        #[cfg(target_os = "windows")]
        self.apply_diff_win32(&diff)?;

        // 更新当前状态。若本帧因默认 mouse=(0,0) 被视为 keyboard-only，
        // 保留本地鼠标坐标，避免后续 diff 与真实光标状态脱节。
        self.current_kb = frame.keyboard.clone();
        let mut next_mouse = frame.mouse.clone();
        if diff.mouse_move.is_none()
            && (self.current_mouse.x != frame.mouse.x || self.current_mouse.y != frame.mouse.y)
        {
            next_mouse.x = self.current_mouse.x;
            next_mouse.y = self.current_mouse.y;
        }
        self.current_mouse = next_mouse;

        Ok(())
    }

    /// 紧急停止 — 松开所有按键和鼠标按钮。
    #[allow(dead_code)]
    pub fn emergency_stop(&mut self) -> Result<()> {
        warn!("紧急停止: 松开所有按键");
        let _all_up = InputDiff {
            key_down: vec![],
            key_up: self.current_kb.keys().cloned().collect(),
            mouse_move: None,
            mouse_buttons: vec![
                ("left".into(), false),
                ("right".into(), false),
                ("middle".into(), false),
            ],
        };

        #[cfg(target_os = "windows")]
        let result = self.apply_diff_win32(&_all_up);
        #[cfg(not(target_os = "windows"))]
        let result = Ok(());

        self.apply_emergency_stop_result(result)
    }

    /// Crate-private primitive for one validated target-bound left click.
    pub(crate) fn click_left_once(&mut self, x: i32, y: i32) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::UI::Input::KeyboardAndMouse::{
                SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN,
                MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_VIRTUALDESK, MOUSEINPUT,
            };
            use windows::Win32::UI::WindowsAndMessaging::{
                GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
                SM_YVIRTUALSCREEN,
            };
            let desktop = VirtualDesktop {
                left: unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) },
                top: unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) },
                width: unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) },
                height: unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) },
            };
            let (absolute_x, absolute_y) = virtual_desktop_absolute_point(desktop, x, y)?;
            let inputs = [
                mouse_input(
                    absolute_x,
                    absolute_y,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                ),
                mouse_input(0, 0, MOUSEEVENTF_LEFTDOWN),
                mouse_input(0, 0, MOUSEEVENTF_LEFTUP),
            ];
            let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            if sent != inputs.len() as u32 {
                anyhow::bail!("SendInput only sent {sent}/{} click events", inputs.len());
            }
            fn mouse_input(
                dx: i32,
                dy: i32,
                flags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS,
            ) -> INPUT {
                INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dx,
                            dy,
                            mouseData: 0,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            }
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (x, y);
            anyhow::bail!("target-bound click only supports Windows")
        }
    }

    fn apply_emergency_stop_result(&mut self, result: Result<()>) -> Result<()> {
        result?;
        self.current_kb.clear();
        self.current_mouse = MouseState::default();
        Ok(())
    }

    /// Windows SendInput 实现。
    #[cfg(target_os = "windows")]
    fn apply_diff_win32(&self, diff: &InputDiff) -> Result<()> {
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
            KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
            MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
            MOUSEEVENTF_RIGHTUP, MOUSEINPUT, VIRTUAL_KEY,
        };
        use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

        let mut inputs = Vec::new();

        for key in &diff.key_down {
            if let Some(scan) = key_to_scan_code(key) {
                inputs.push(keyboard_input(scan, false));
            } else {
                warn!("未知按键（忽略）");
            }
        }

        for key in &diff.key_up {
            if let Some(scan) = key_to_scan_code(key) {
                inputs.push(keyboard_input(scan, true));
            } else {
                warn!("未知按键（忽略）");
            }
        }

        if let Some((x, y)) = diff.mouse_move {
            let width = unsafe { GetSystemMetrics(SM_CXSCREEN) }.max(1);
            let height = unsafe { GetSystemMetrics(SM_CYSCREEN) }.max(1);
            let abs_x = (x.clamp(0, width - 1) * 65535) / (width - 1).max(1);
            let abs_y = (y.clamp(0, height - 1) * 65535) / (height - 1).max(1);

            inputs.push(INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: abs_x,
                        dy: abs_y,
                        mouseData: 0,
                        dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            });
        }

        for (button, is_down) in &diff.mouse_buttons {
            let flags = match (button.as_str(), *is_down) {
                ("left", true) => MOUSEEVENTF_LEFTDOWN,
                ("left", false) => MOUSEEVENTF_LEFTUP,
                ("right", true) => MOUSEEVENTF_RIGHTDOWN,
                ("right", false) => MOUSEEVENTF_RIGHTUP,
                ("middle", true) => MOUSEEVENTF_MIDDLEDOWN,
                ("middle", false) => MOUSEEVENTF_MIDDLEUP,
                _ => {
                    warn!("未知鼠标按键（忽略）: {button}");
                    continue;
                }
            };

            inputs.push(INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: 0,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            });
        }

        if inputs.is_empty() {
            return Ok(());
        }

        let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent != inputs.len() as u32 {
            anyhow::bail!("SendInput 只发送了 {sent}/{} 个事件", inputs.len());
        }

        fn keyboard_input(scan_code: u16, key_up: bool) -> INPUT {
            let mut flags = KEYEVENTF_SCANCODE;
            if key_up {
                flags |= KEYEVENTF_KEYUP;
            }

            INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: VIRTUAL_KEY(0),
                        wScan: scan_code,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            }
        }

        fn key_to_scan_code(key: &str) -> Option<u16> {
            let key = key.trim().to_ascii_lowercase();
            match key.as_str() {
                "a" => Some(0x1e),
                "b" => Some(0x30),
                "c" => Some(0x2e),
                "d" => Some(0x20),
                "e" => Some(0x12),
                "f" => Some(0x21),
                "g" => Some(0x22),
                "h" => Some(0x23),
                "i" => Some(0x17),
                "j" => Some(0x24),
                "k" => Some(0x25),
                "l" => Some(0x26),
                "m" => Some(0x32),
                "n" => Some(0x31),
                "o" => Some(0x18),
                "p" => Some(0x19),
                "q" => Some(0x10),
                "r" => Some(0x13),
                "s" => Some(0x1f),
                "t" => Some(0x14),
                "u" => Some(0x16),
                "v" => Some(0x2f),
                "w" => Some(0x11),
                "x" => Some(0x2d),
                "y" => Some(0x15),
                "z" => Some(0x2c),
                "0" => Some(0x0b),
                "1" => Some(0x02),
                "2" => Some(0x03),
                "3" => Some(0x04),
                "4" => Some(0x05),
                "5" => Some(0x06),
                "6" => Some(0x07),
                "7" => Some(0x08),
                "8" => Some(0x09),
                "9" => Some(0x0a),
                "space" => Some(0x39),
                "enter" | "return" => Some(0x1c),
                "escape" | "esc" => Some(0x01),
                "tab" => Some(0x0f),
                "backspace" => Some(0x0e),
                "lshift" | "shift" => Some(0x2a),
                "rshift" => Some(0x36),
                "lctrl" | "ctrl" | "control" => Some(0x1d),
                "lalt" | "alt" => Some(0x38),
                "capslock" => Some(0x3a),
                "f1" => Some(0x3b),
                "f2" => Some(0x3c),
                "f3" => Some(0x3d),
                "f4" => Some(0x3e),
                "f5" => Some(0x3f),
                "f6" => Some(0x40),
                "f7" => Some(0x41),
                "f8" => Some(0x42),
                "f9" => Some(0x43),
                "f10" => Some(0x44),
                "f11" => Some(0x57),
                "f12" => Some(0x58),
                _ => None,
            }
        }

        Ok(())
    }

    /// 非 Windows 平台的空实现（测试用）。
    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn apply_diff_win32(&self, _diff: &InputDiff) -> Result<()> {
        Ok(())
    }
}

impl Default for InputController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MouseButtons;
    use std::collections::HashMap;

    #[test]
    fn test_diff_new_key_down() {
        let current: HashMap<String, String> = HashMap::new();
        let target: HashMap<String, String> = [("w".into(), "down".into())].into();

        let diff = InputDiff::compute(
            &current,
            &target,
            &MouseState::default(),
            &MouseState::default(),
        );
        assert_eq!(diff.key_down, vec!["w"]);
        assert!(diff.key_up.is_empty());
    }

    #[test]
    fn test_diff_missing_key_becomes_up() {
        let current: HashMap<String, String> =
            [("w".into(), "down".into()), ("a".into(), "down".into())].into();
        let target: HashMap<String, String> = [("w".into(), "down".into())].into();

        let diff = InputDiff::compute(
            &current,
            &target,
            &MouseState::default(),
            &MouseState::default(),
        );
        assert!(diff.key_down.is_empty());
        assert_eq!(diff.key_up, vec!["a"]);
    }

    #[test]
    fn test_diff_unchanged_noop() {
        let current: HashMap<String, String> = [("w".into(), "down".into())].into();
        let target: HashMap<String, String> = [("w".into(), "down".into())].into();

        let diff = InputDiff::compute(
            &current,
            &target,
            &MouseState::default(),
            &MouseState::default(),
        );
        assert!(diff.key_down.is_empty());
        assert!(diff.key_up.is_empty());
    }

    #[test]
    fn test_emergency_stop_all_up() {
        let current: HashMap<String, String> =
            [("w".into(), "down".into()), ("space".into(), "down".into())].into();
        let target: HashMap<String, String> = HashMap::new(); // 空 = 全 up

        let diff = InputDiff::compute(
            &current,
            &target,
            &MouseState::default(),
            &MouseState::default(),
        );
        assert_eq!(diff.key_up.len(), 2);
        assert!(diff.key_down.is_empty());
    }

    #[test]
    fn emergency_stop_only_clears_state_after_successful_release() {
        let mut controller = InputController::new();
        controller.current_kb.insert("w".into(), "down".into());
        controller.current_mouse.buttons.left = "down".into();

        assert!(controller
            .apply_emergency_stop_result(Err(anyhow::anyhow!("release failed")))
            .is_err());
        assert_eq!(
            controller.current_kb.get("w").map(String::as_str),
            Some("down")
        );
        assert_eq!(controller.current_mouse.buttons.left, "down");

        controller.apply_emergency_stop_result(Ok(())).unwrap();
        assert!(controller.current_kb.is_empty());
        assert_eq!(controller.current_mouse.x, 0);
        assert_eq!(controller.current_mouse.y, 0);
        assert_eq!(controller.current_mouse.buttons.left, "up");
    }

    #[test]
    fn keyboard_only_default_mouse_does_not_move_from_current_position() {
        let current: HashMap<String, String> = HashMap::new();
        let target: HashMap<String, String> = [("w".into(), "down".into())].into();
        let current_mouse = MouseState {
            x: 640,
            y: 360,
            ..Default::default()
        };

        let diff = InputDiff::compute(&current, &target, &current_mouse, &MouseState::default());

        assert_eq!(diff.key_down, vec!["w"]);
        assert_eq!(diff.mouse_move, None);
    }

    #[test]
    fn non_default_mouse_position_moves() {
        let current: HashMap<String, String> = HashMap::new();
        let target: HashMap<String, String> = HashMap::new();
        let target_mouse = MouseState {
            x: 320,
            y: 240,
            ..Default::default()
        };

        let diff = InputDiff::compute(&current, &target, &MouseState::default(), &target_mouse);

        assert_eq!(diff.mouse_move, Some((320, 240)));
    }

    #[test]
    fn emergency_stop_state_tracks_platform_release_result() {
        let mut ctrl = InputController::new();
        ctrl.current_kb = [("w".into(), "down".into())].into();
        ctrl.current_mouse = MouseState {
            x: 10,
            y: 20,
            buttons: MouseButtons {
                left: "down".into(),
                ..MouseButtons::default()
            },
            scroll_delta: 0,
        };

        let result = ctrl.emergency_stop();

        if result.is_ok() {
            assert!(ctrl.current_kb.is_empty());
            assert_eq!(ctrl.current_mouse.x, 0);
            assert_eq!(ctrl.current_mouse.y, 0);
            assert_eq!(ctrl.current_mouse.buttons.left, "up");
        } else {
            assert_eq!(ctrl.current_kb.get("w").map(String::as_str), Some("down"));
            assert_eq!(ctrl.current_mouse.buttons.left, "down");
        }
    }

    #[test]
    fn virtual_desktop_coordinates_support_negative_secondary_monitor() {
        let desktop = VirtualDesktop {
            left: -1920,
            top: -180,
            width: 3840,
            height: 1260,
        };

        assert_eq!(
            virtual_desktop_absolute_point(desktop, -1920, -180).unwrap(),
            (0, 0)
        );
        assert_eq!(
            virtual_desktop_absolute_point(desktop, 1919, 1079).unwrap(),
            (65_535, 65_535)
        );
        assert!(virtual_desktop_absolute_point(desktop, -1921, 0).is_err());
    }
}
