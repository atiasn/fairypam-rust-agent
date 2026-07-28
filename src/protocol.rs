//! WebSocket 协议消息类型定义。
//!
//! 与 `protocol/ws-messages.json` 对齐的 Rust struct 定义。
//! v3 协议，Agent ↔ Hub 双向 16 种消息序列化。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================
// 共享子类型
// ============================================================

/// 系统信息（agent_hello 中发送）。
/// 字段与 protocol/ws-messages.json definitions/SystemInfo 对齐。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    #[serde(default)]
    pub os_version: String,
    #[serde(default)]
    pub os_build: String,
    #[serde(default)]
    pub os_arch: String,
    #[serde(default)]
    pub net_version: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub last_boot_time: String,
    pub cpu_name: String,
    #[serde(default)]
    pub cpu_cores: u32,
    #[serde(default)]
    pub cpu_threads: u32,
    #[serde(rename = "memory_total_gb")]
    pub memory_total_gb: f64,
    #[serde(default)]
    pub disks: Vec<DiskInfo>,
    #[serde(default)]
    pub network_adapters: Vec<NetworkAdapter>,
    #[serde(default)]
    pub displays: Vec<DisplayInfo>,
    #[serde(default)]
    pub agent_version: String,
}

/// 磁盘信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub mount_point: String,
    pub total_gb: f64,
    #[serde(default)]
    pub free_gb: f64,
}

/// 网络适配器信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub name: String,
    #[serde(default)]
    pub mac_address: String,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
}

/// 显示器信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
    #[serde(default)]
    pub refresh_rate: u32,
    #[serde(default)]
    pub is_primary: bool,
}

/// 鼠标按钮状态（嵌套结构，与 schema definitions/MouseState/buttons 对齐）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseButtons {
    #[serde(default = "default_button_state")]
    pub left: String,
    #[serde(default = "default_button_state")]
    pub right: String,
    #[serde(default = "default_button_state")]
    pub middle: String,
}

impl Default for MouseButtons {
    fn default() -> Self {
        Self {
            left: default_button_state(),
            right: default_button_state(),
            middle: default_button_state(),
        }
    }
}

/// 鼠标状态。
/// 与 protocol/ws-messages.json definitions/MouseState 对齐。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MouseState {
    #[serde(default)]
    pub x: i32,
    #[serde(default)]
    pub y: i32,
    #[serde(default)]
    pub buttons: MouseButtons,
    #[serde(default)]
    pub scroll_delta: i32,
}

fn default_button_state() -> String {
    "up".into()
}

/// Hub 下发的 Agent 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubAgentConfig {
    pub heartbeat_interval_s: u64,
    pub command_timeout_s: u64,
    pub auto_update: bool,
    pub auto_start: bool,
    pub launch_allowlist: Vec<String>,
}

/// 游戏进程事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameProcessEvent {
    pub session_id: String,
    pub game_id: String,
    pub executable: String,
    pub event: String,
    pub process_id: u32,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ============================================================
// Hub → Agent (入站消息)
// ============================================================

/// Hub 欢迎消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubWelcome {
    pub protocol_version: u32,
    pub agent_id: String,
    pub agent_name_effective: String,
    pub config: HubAgentConfig,
    pub accepted_capabilities: Vec<String>,
}

/// 抢占式输入状态帧。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFrame {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub game_id: String,
    pub seq: u64,
    #[serde(default)]
    pub keyboard: HashMap<String, String>,
    pub mouse: MouseState,
    #[serde(default)]
    pub gamepad: Option<serde_json::Value>,
}

/// 断连恢复帧。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFrameResume {
    pub session_id: String,
    pub seq: u64,
    #[serde(default)]
    pub keyboard: HashMap<String, String>,
    pub mouse: MouseState,
}

/// 启动游戏指令。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameLaunch {
    pub session_id: String,
    pub game_id: String,
    pub trace_id: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
}

/// 终止游戏指令。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameKill {
    pub session_id: String,
    #[serde(default)]
    pub game_id: String,
    #[serde(default)]
    pub force: bool,
}

/// Hub 下发的设置更新。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SettingsUpdate {
    #[serde(default)]
    pub auto_update: Option<bool>,
    #[serde(default)]
    pub auto_start: Option<bool>,
    #[serde(default)]
    pub command_timeout_s: Option<u64>,
    #[serde(default)]
    pub launch_allowlist: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Hub 请求 Agent 重新扫描本机米哈游游戏。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MihoyoGameDiscoveryRescan {
    pub request_id: String,
}

/// Hub 下发的固定 environment-check/v1 任务。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentCheckStart {
    pub task_run_id: String,
    pub trace_id: String,
    pub template_id: String,
    pub template_version: String,
    pub game_id: String,
    pub session_id: String,
    pub executable: String,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_s: u64,
    #[serde(default)]
    pub force_close_on_cleanup: bool,
}

/// Hub 下发的 environment-check/v1 取消信号。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentCheckCancel {
    pub task_run_id: String,
    pub trace_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

/// 暂停 AI 指令。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseAI {
    pub session_id: String,
}

/// 恢复 AI 指令。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeAI {
    pub session_id: String,
}

/// 心跳确认。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAck {
    pub server_time: String,
}

/// 错误消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

/// 入站消息枚举（Hub → Agent）。
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AgentMessage {
    HubWelcome(HubWelcome),
    HeartbeatAck(HeartbeatAck),
    InputFrame(InputFrame),
    InputFrameResume(InputFrameResume),
    GameLaunch(GameLaunch),
    GameKill(GameKill),
    SettingsUpdate(SettingsUpdate),
    MihoyoGameDiscoveryRescan(MihoyoGameDiscoveryRescan),
    EnvironmentCheckStart(EnvironmentCheckStart),
    EnvironmentCheckCancel(EnvironmentCheckCancel),
    PauseAI(PauseAI),
    ResumeAI(ResumeAI),
    Error(ErrorMessage),
}

// ============================================================
// Agent → Hub (出站消息)
// ============================================================

/// Agent 握手消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHello {
    pub api_key: String,
    pub agent_name: String,
    pub protocol_version: u32,
    pub system_info: SystemInfo,
    pub capabilities: Vec<String>,
}

/// 心跳消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub cpu_usage: f64,
    #[serde(rename = "memory_available_gb")]
    pub memory_available_gb: f64,
    pub active_processes: u32,
    #[serde(default)]
    pub game_process_events: Vec<GameProcessEvent>,
}

/// 启动确认。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameLaunchAck {
    pub session_id: String,
    pub process_id: u32,
    #[serde(default = "default_success")]
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
}

/// 终止确认。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameKillAck {
    pub session_id: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default = "default_success")]
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
}

/// 输入帧确认。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFrameAck {
    pub session_id: String,
    pub seq: u64,
}

/// 游戏运行时事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameEvent {
    pub session_id: String,
    pub event: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// CV 调试可视化数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugOverlay {
    pub session_id: String,
    #[serde(default)]
    pub detection_boxes: Vec<serde_json::Value>,
    #[serde(default)]
    pub ocr_regions: Vec<serde_json::Value>,
    #[serde(default)]
    pub template_matches: Vec<serde_json::Value>,
    #[serde(default)]
    pub perf: Option<serde_json::Value>,
}

/// Agent 上报的米哈游游戏发现项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MihoyoGameDiscoveryItem {
    pub discovery_id: String,
    #[serde(default)]
    pub game_id: Option<String>,
    pub display_name: String,
    #[serde(default)]
    pub display_version: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub install_path: Option<String>,
    #[serde(default)]
    pub launch_path: Option<String>,
    pub exists_on_disk: bool,
    pub supported: bool,
    #[serde(default)]
    pub last_scanned_at: Option<String>,
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

/// Agent 上报的米哈游游戏发现快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MihoyoGameDiscoverySnapshot {
    #[serde(default)]
    pub request_id: Option<String>,
    pub status: String,
    #[serde(default)]
    pub last_scanned_at: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub games: Vec<MihoyoGameDiscoveryItem>,
}

/// Agent 回传环境检查步骤结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentCheckStepResult {
    pub task_run_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub step_id: String,
    pub status: String,
    #[serde(default)]
    pub result: serde_json::Value,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Agent 回传环境检查最终结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentCheckResult {
    pub task_run_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub status: String,
    #[serde(default)]
    pub result: serde_json::Value,
    #[serde(default)]
    pub steps: Vec<serde_json::Value>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

fn default_success() -> bool {
    true
}

/// 出站消息枚举（Agent → Hub）。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub enum HubMessage {
    #[serde(rename = "agent_hello")]
    AgentHello(AgentHello),
    #[serde(rename = "heartbeat")]
    Heartbeat(Heartbeat),
    #[serde(rename = "game_launch_ack")]
    GameLaunchAck(GameLaunchAck),
    #[serde(rename = "game_kill_ack")]
    GameKillAck(GameKillAck),
    #[serde(rename = "input_frame_ack")]
    InputFrameAck(InputFrameAck),
    #[serde(rename = "game_event")]
    GameEvent(GameEvent),
    #[serde(rename = "debug_overlay")]
    DebugOverlay(DebugOverlay),
    #[serde(rename = "mihoyo_game_discovery_snapshot")]
    MihoyoGameDiscoverySnapshot(MihoyoGameDiscoverySnapshot),
    #[serde(rename = "environment_check_step_result")]
    EnvironmentCheckStepResult(EnvironmentCheckStepResult),
    #[serde(rename = "environment_check_result")]
    EnvironmentCheckResult(EnvironmentCheckResult),
}

// ============================================================
// 解析
// ============================================================

/// 解析入站 JSON 消息。
pub fn parse_message(text: &str) -> Result<AgentMessage, serde_json::Error> {
    let raw: serde_json::Value = serde_json::from_str(text)?;
    let msg_type = raw["type"]
        .as_str()
        .ok_or_else(|| serde::de::Error::custom("缺少 type 字段"))?;

    match msg_type {
        "hub_welcome" => Ok(AgentMessage::HubWelcome(serde_json::from_value(raw)?)),
        "heartbeat_ack" => Ok(AgentMessage::HeartbeatAck(serde_json::from_value(raw)?)),
        "input_frame" => Ok(AgentMessage::InputFrame(serde_json::from_value(raw)?)),
        "input_frame_resume" => Ok(AgentMessage::InputFrameResume(serde_json::from_value(raw)?)),
        "game_launch" => Ok(AgentMessage::GameLaunch(serde_json::from_value(raw)?)),
        "game_kill" => Ok(AgentMessage::GameKill(serde_json::from_value(raw)?)),
        "settings_update" => Ok(AgentMessage::SettingsUpdate(serde_json::from_value(raw)?)),
        "mihoyo_game_discovery_rescan" => Ok(AgentMessage::MihoyoGameDiscoveryRescan(
            serde_json::from_value(raw)?,
        )),
        "environment_check_start" => Ok(AgentMessage::EnvironmentCheckStart(
            serde_json::from_value(raw)?,
        )),
        "environment_check_cancel" => Ok(AgentMessage::EnvironmentCheckCancel(
            serde_json::from_value(raw)?,
        )),
        "pause_ai" => Ok(AgentMessage::PauseAI(serde_json::from_value(raw)?)),
        "resume_ai" => Ok(AgentMessage::ResumeAI(serde_json::from_value(raw)?)),
        "error" => Ok(AgentMessage::Error(serde_json::from_value(raw)?)),
        _ => Err(serde::de::Error::custom(format!(
            "未知消息类型: {}",
            msg_type
        ))),
    }
}

// ============================================================
// thiserror 自定义错误类型
// ============================================================

/// Agent 自定义错误类型。
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum AgentError {
    /// 配置加载失败
    #[error("配置加载失败: {0}")]
    ConfigLoad(String),

    /// WebSocket 连接失败
    #[error("WebSocket 连接失败: {0}")]
    ConnectionFailed(String),

    /// 协议解析错误
    #[error("协议解析错误: {0}")]
    ProtocolParse(String),

    /// 进程操作错误
    #[error("进程操作失败: {0}")]
    ProcessError(String),

    /// 屏幕捕获错误
    #[error("屏幕捕获失败: {0}")]
    CaptureError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_snapshot_serializes_snake_case_contract() {
        let snapshot = HubMessage::MihoyoGameDiscoverySnapshot(MihoyoGameDiscoverySnapshot {
            request_id: Some("req-1".to_string()),
            status: "ready".to_string(),
            last_scanned_at: Some("2026-07-04T00:00:00Z".to_string()),
            error: None,
            games: vec![MihoyoGameDiscoveryItem {
                discovery_id: "hk4e_cn:c:/games".to_string(),
                game_id: Some("hk4e_cn".to_string()),
                display_name: "原神".to_string(),
                display_version: Some("5.7.0".to_string()),
                publisher: Some("miHoYo".to_string()),
                install_path: Some(r"C:\HoYoPlay".to_string()),
                launch_path: Some(
                    r"C:\HoYoPlay\games\Genshin Impact Game\YuanShen.exe".to_string(),
                ),
                exists_on_disk: true,
                supported: true,
                last_scanned_at: Some("2026-07-04T00:00:00Z".to_string()),
                status: "ok".to_string(),
                error: None,
            }],
        });

        let json = serde_json::to_string(&snapshot).unwrap();

        assert!(json.contains(r#""type":"mihoyo_game_discovery_snapshot""#));
        assert!(json.contains(r#""request_id":"req-1""#));
        assert!(json.contains(r#""discovery_id":"hk4e_cn:c:/games""#));
        assert!(json.contains(r#""exists_on_disk":true"#));
        assert!(!json.contains("requestId"));
        assert!(!json.contains("existsOnDisk"));
    }

    #[test]
    fn discovery_rescan_message_parses_request_id() {
        let msg = parse_message(r#"{"type":"mihoyo_game_discovery_rescan","request_id":"req-2"}"#)
            .unwrap();

        match msg {
            AgentMessage::MihoyoGameDiscoveryRescan(request) => {
                assert_eq!(request.request_id, "req-2");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn environment_check_start_parses_fixed_wire_shape() {
        let msg = parse_message(
            r#"{
                "type":"environment_check_start",
                "task_run_id":"task-a",
                "trace_id":"trace-a",
                "template_id":"environment-check/v1",
                "template_version":"v1",
                "game_id":"game-a",
                "session_id":"session-a",
                "executable":"game.exe",
                "timeout_s":10
            }"#,
        )
        .unwrap();

        match msg {
            AgentMessage::EnvironmentCheckStart(command) => {
                assert_eq!(command.template_id, "environment-check/v1");
                assert_eq!(command.executable, "game.exe");
                assert!(command.args.is_empty());
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn environment_check_result_serializes_snake_case_contract() {
        let msg = HubMessage::EnvironmentCheckResult(EnvironmentCheckResult {
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            session_id: "session-a".into(),
            status: "succeeded".into(),
            result: serde_json::json!({"summary": "ok"}),
            steps: vec![],
            error_code: None,
            error_message: None,
        });

        let json = serde_json::to_string(&msg).unwrap();

        assert!(json.contains(r#""type":"environment_check_result""#));
        assert!(json.contains(r#""task_run_id":"task-a""#));
        assert!(!json.contains("taskRunId"));
    }
}
