//! WebSocket 协议消息类型定义。
//!
//! 与 `protocol/ws-messages.json` 对齐的 Rust struct 定义。
//! v3 协议，Agent ↔ Hub 双向 16 种消息序列化。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    pub connection_id: Uuid,
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GameLaunch {
    #[serde(rename = "type", deserialize_with = "deserialize_game_launch_type")]
    pub message_type: String,
    pub session_id: Uuid,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub trace_id: String,
    #[serde(deserialize_with = "deserialize_game_slug")]
    pub game_slug: String,
    pub connection_id: Uuid,
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

/// Hub 请求 Agent 重新扫描系统游戏目录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameDiscoveryRequest {
    pub request_id: String,
}

/// Hub 下发的固定 environment-check/v1 任务。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCheckStart {
    #[serde(rename = "type")]
    pub(crate) _message_type: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub task_run_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub trace_id: String,
    pub connection_id: Uuid,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub game_slug: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub session_id: String,
    pub timeout_s: u64,
    pub force_close_on_cleanup: bool,
    #[serde(skip)]
    pub(crate) resolved_executable: Option<String>,
    #[serde(skip)]
    pub(crate) resolved_working_dir: Option<String>,
}

impl EnvironmentCheckStart {
    pub(crate) fn with_local_target(
        mut self,
        executable: String,
        working_dir: Option<String>,
    ) -> Self {
        self.resolved_executable = Some(executable);
        self.resolved_working_dir = working_dir;
        self
    }
}

/// Hub 下发的 environment-check/v1 取消信号。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentCheckCancel {
    pub task_run_id: String,
    pub trace_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Hub 下发的版本化 TaskRun executor 启动请求。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRunStart {
    #[serde(rename = "type", deserialize_with = "deserialize_task_run_start_type")]
    pub message_type: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub task_run_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub trace_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub session_id: String,
    pub connection_id: Uuid,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub game_slug: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub template_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub template_version: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub timeout_s: u64,
    #[serde(skip)]
    pub(crate) resolved_executable: Option<String>,
    #[serde(skip)]
    pub(crate) resolved_working_dir: Option<String>,
}

impl TaskRunStart {
    pub(crate) fn with_local_target(
        mut self,
        executable: String,
        working_dir: Option<String>,
    ) -> Self {
        self.resolved_executable = Some(executable);
        self.resolved_working_dir = working_dir;
        self
    }

    pub(crate) fn local_target(&self) -> Option<(&str, Option<&str>)> {
        self.resolved_executable
            .as_deref()
            .map(|executable| (executable, self.resolved_working_dir.as_deref()))
    }
}

/// Hub 取消当前 TaskRun。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRunCancel {
    #[serde(rename = "type", deserialize_with = "deserialize_task_run_cancel_type")]
    pub message_type: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub task_run_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub trace_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub session_id: String,
    pub connection_id: Uuid,
}

/// Hub 对当前 TaskRun 的最终判定。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRunTerminal {
    #[serde(
        rename = "type",
        deserialize_with = "deserialize_task_run_terminal_type"
    )]
    pub message_type: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub task_run_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub trace_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub session_id: String,
    pub connection_id: Uuid,
    #[serde(deserialize_with = "deserialize_terminal_outcome")]
    pub outcome: String,
}

/// Hub 下发的受限 TaskRun 单次左键点击。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRunClick {
    #[serde(rename = "type", deserialize_with = "deserialize_task_run_click_type")]
    pub message_type: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub task_run_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub trace_id: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub session_id: String,
    pub connection_id: Uuid,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub click_id: String,
    pub source_frame_seq: u64,
    #[serde(deserialize_with = "deserialize_client_ratio")]
    pub client_x_ratio: f64,
    #[serde(deserialize_with = "deserialize_client_ratio")]
    pub client_y_ratio: f64,
    #[serde(deserialize_with = "deserialize_left_button")]
    pub button: String,
    #[serde(deserialize_with = "deserialize_single_click")]
    pub click_count: u8,
}

fn deserialize_nonempty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom("value must not be empty"));
    }
    Ok(value)
}

fn deserialize_left_button<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_nonempty_string(deserializer)?;
    if value != "left" {
        return Err(serde::de::Error::custom("button must be left"));
    }
    Ok(value)
}

fn deserialize_task_run_click_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value != "task_run_click" {
        return Err(serde::de::Error::custom("type must be task_run_click"));
    }
    Ok(value)
}

fn deserialize_game_launch_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_message_type(deserializer, "game_launch")
}

fn deserialize_agent_update_request_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_message_type(deserializer, "agent_update_request")
}

fn deserialize_build_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_nonempty_string(deserializer)?;
    if value.len() > 128 {
        return Err(serde::de::Error::custom("build_id is too long"));
    }
    Ok(value)
}

fn deserialize_attempt_nonce<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_nonempty_string(deserializer)?;
    if !(16..=128).contains(&value.len()) {
        return Err(serde::de::Error::custom("attempt_nonce length is invalid"));
    }
    Ok(value)
}

fn deserialize_agent_update_artifact_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_nonempty_string(deserializer)?;
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() != 8
        || !parts[0].is_empty()
        || parts[1..4] != ["api", "v1", "agents"]
        || parts[5] != "updates"
        || parts[7] != "artifact"
        || Uuid::parse_str(parts[4]).is_err()
        || Uuid::parse_str(parts[6]).is_err()
    {
        return Err(serde::de::Error::custom("invalid update artifact path"));
    }
    Ok(value)
}

fn deserialize_sha256<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(serde::de::Error::custom(
            "sha256 must be lowercase hexadecimal",
        ));
    }
    Ok(value)
}

fn deserialize_positive_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if value == 0 {
        return Err(serde::de::Error::custom("size_bytes must be positive"));
    }
    Ok(value)
}

fn deserialize_game_slug<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_nonempty_string(deserializer)?;
    if matches!(value.as_str(), "genshin" | "star-rail" | "zenless") {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("unsupported canonical game slug"))
    }
}

fn deserialize_message_type<'de, D>(deserializer: D, expected: &str) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value != expected {
        return Err(serde::de::Error::custom(format!("type must be {expected}")));
    }
    Ok(value)
}

fn deserialize_task_run_start_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_message_type(deserializer, "task_run_start")
}
fn deserialize_task_run_cancel_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_message_type(deserializer, "task_run_cancel")
}
fn deserialize_task_run_terminal_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_message_type(deserializer, "task_run_terminal")
}
fn deserialize_terminal_outcome<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_nonempty_string(deserializer)?;
    if matches!(
        value.as_str(),
        "succeeded" | "failed" | "canceled" | "interrupted"
    ) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("unknown terminal outcome"))
    }
}

fn deserialize_single_click<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    if value != 1 {
        return Err(serde::de::Error::custom("click_count must be 1"));
    }
    Ok(value)
}

fn deserialize_client_ratio<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = f64::deserialize(deserializer)?;
    if !(value.is_finite() && 0.0 < value && value < 1.0) {
        return Err(serde::de::Error::custom(
            "client ratio must be finite and within (0,1)",
        ));
    }
    Ok(value)
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

/// Hub 下发的、与当前连接和目标候选精确绑定的更新请求。
///
/// 该 wire 从不携带 URL、命令或本地路径；`artifact_path` 只能是当前
/// Agent 的固定 Hub artifact endpoint。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentUpdateRequest {
    #[serde(
        rename = "type",
        deserialize_with = "deserialize_agent_update_request_type"
    )]
    pub message_type: String,
    pub connection_id: Uuid,
    pub update_id: Uuid,
    pub promotion_id: Uuid,
    #[serde(deserialize_with = "deserialize_build_id")]
    pub source_build_id: String,
    #[serde(deserialize_with = "deserialize_build_id")]
    pub target_build_id: String,
    #[serde(deserialize_with = "deserialize_attempt_nonce")]
    pub attempt_nonce: String,
    #[serde(deserialize_with = "deserialize_agent_update_artifact_path")]
    pub artifact_path: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    pub sha256: String,
    #[serde(deserialize_with = "deserialize_positive_size")]
    pub size_bytes: u64,
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
    GameDiscoveryRequest(GameDiscoveryRequest),
    EnvironmentCheckStart(EnvironmentCheckStart),
    EnvironmentCheckCancel(EnvironmentCheckCancel),
    TaskRunStart(TaskRunStart),
    TaskRunCancel(TaskRunCancel),
    TaskRunClick(TaskRunClick),
    TaskRunTerminal(TaskRunTerminal),
    AgentUpdateRequest(AgentUpdateRequest),
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
    #[serde(default)]
    pub supported_task_templates: Vec<SupportedTaskTemplate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_handoff: Option<AgentUpdateHandoff>,
}

/// 仅在更新后的新进程首次握手中携带的重启证明。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentUpdateHandoff {
    pub update_id: Uuid,
    #[serde(deserialize_with = "deserialize_attempt_nonce")]
    pub attempt_nonce: String,
    #[serde(deserialize_with = "deserialize_build_id")]
    pub source_build_id: String,
    #[serde(deserialize_with = "deserialize_build_id")]
    pub target_build_id: String,
    pub prior_connection_id: Uuid,
    #[serde(deserialize_with = "deserialize_build_id")]
    pub running_build_id: String,
}

/// Update 的非终态进度。每条消息均携带完整五元身份。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentUpdateProgress {
    pub connection_id: Uuid,
    pub update_id: Uuid,
    pub source_build_id: String,
    pub target_build_id: String,
    pub attempt_nonce: String,
    pub status: AgentUpdateProgressStatus,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpdateProgressStatus {
    Downloading,
    Staged,
    Restarting,
}

/// Update 的终态结果；错误码只能是稳定、脱敏的固定 code。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentUpdateResult {
    pub connection_id: Uuid,
    pub update_id: Uuid,
    pub source_build_id: String,
    pub target_build_id: String,
    pub attempt_nonce: String,
    pub status: AgentUpdateResultStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpdateResultStatus {
    Succeeded,
    Failed,
    RolledBack,
}

/// 已编译进 Agent 的公开 TaskRun 模板键。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupportedTaskTemplate {
    pub template_id: String,
    pub template_version: String,
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

/// Agent 上报的 canonical 游戏发现项。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GameDiscoveryItem {
    pub game_slug: String,
    pub discovered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_discovered_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Agent 上报的 canonical 游戏发现结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GameDiscoveryResult {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub games: Vec<GameDiscoveryItem>,
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

/// Agent 上报的临时 TaskRun JPEG 帧；仅供 Hub 当前请求处理。
#[derive(Debug, Clone, Serialize)]
pub struct TaskRunFrame {
    pub task_run_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub connection_id: Uuid,
    pub client_version: String,
    pub frame_seq: u64,
    pub window_width: u32,
    pub window_height: u32,
    pub frame_jpeg_base64: String,
    pub target_process_alive: bool,
    pub target_window_alive: bool,
    pub last_applied_click_source_frame_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskRunStep {
    pub task_run_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub step_id: String,
    pub status: String,
    pub result: serde_json::Value,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskRunResult {
    pub task_run_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub status: String,
    pub result: serde_json::Value,
    pub steps: Vec<serde_json::Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

/// 任务清理中 Agent 自有进程的最终处置结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedCleanup {
    Completed,
    NotRequired,
    Failed,
}

/// Agent 在本地清理完成后上报的可信 TaskRun 清理回执。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskRunCleanupReceipt {
    pub task_run_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub input_released: bool,
    pub owned_cleanup: OwnedCleanup,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
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
    #[serde(rename = "game_discovery_result")]
    GameDiscoveryResult(GameDiscoveryResult),
    #[serde(rename = "environment_check_step_result")]
    EnvironmentCheckStepResult(EnvironmentCheckStepResult),
    #[serde(rename = "environment_check_result")]
    EnvironmentCheckResult(EnvironmentCheckResult),
    #[serde(rename = "task_run_frame")]
    TaskRunFrame(TaskRunFrame),
    #[serde(rename = "task_run_step")]
    TaskRunStep(TaskRunStep),
    #[serde(rename = "task_run_result")]
    TaskRunResult(TaskRunResult),
    #[serde(rename = "task_run_cleanup_receipt")]
    TaskRunCleanupReceipt(TaskRunCleanupReceipt),
    #[serde(rename = "agent_update_progress")]
    AgentUpdateProgress(AgentUpdateProgress),
    #[serde(rename = "agent_update_result")]
    AgentUpdateResult(AgentUpdateResult),
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
        "game_discovery_request" => Ok(AgentMessage::GameDiscoveryRequest(serde_json::from_value(
            raw,
        )?)),
        "environment_check_start" => Ok(AgentMessage::EnvironmentCheckStart(
            serde_json::from_value(raw)?,
        )),
        "environment_check_cancel" => Ok(AgentMessage::EnvironmentCheckCancel(
            serde_json::from_value(raw)?,
        )),
        "task_run_start" => Ok(AgentMessage::TaskRunStart(serde_json::from_value(raw)?)),
        "task_run_cancel" => Ok(AgentMessage::TaskRunCancel(serde_json::from_value(raw)?)),
        "task_run_click" => Ok(AgentMessage::TaskRunClick(serde_json::from_value(raw)?)),
        "task_run_terminal" => Ok(AgentMessage::TaskRunTerminal(serde_json::from_value(raw)?)),
        "agent_update_request" => Ok(AgentMessage::AgentUpdateRequest(serde_json::from_value(
            raw,
        )?)),
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
    fn task_run_frame_serializes_ephemeral_wire_contract() {
        let connection_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let frame = HubMessage::TaskRunFrame(TaskRunFrame {
            task_run_id: "task-a".into(),
            trace_id: "trace-a".into(),
            session_id: "session-a".into(),
            connection_id,
            client_version: "0.1.0".into(),
            frame_seq: 7,
            window_width: 1920,
            window_height: 1080,
            frame_jpeg_base64: "ZmFrZS1qcGVn".into(),
            target_process_alive: true,
            target_window_alive: true,
            last_applied_click_source_frame_seq: None,
        });

        let json = serde_json::to_value(frame).unwrap();

        assert_eq!(json["type"], "task_run_frame");
        assert_eq!(json["task_run_id"], "task-a");
        assert_eq!(json["trace_id"], "trace-a");
        assert_eq!(json["session_id"], "session-a");
        assert_eq!(
            json["connection_id"],
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(json["frame_seq"], 7);
        assert_eq!(json["window_width"], 1920);
        assert_eq!(json["window_height"], 1080);
        assert_eq!(json["target_process_alive"], true);
        assert_eq!(json["target_window_alive"], true);
        assert!(json["last_applied_click_source_frame_seq"].is_null());
    }

    #[test]
    fn task_run_cleanup_receipt_serializes_typed_safe_contract() {
        let receipt = HubMessage::TaskRunCleanupReceipt(TaskRunCleanupReceipt {
            task_run_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            trace_id: "660e8400-e29b-41d4-a716-446655440000".into(),
            session_id: "770e8400-e29b-41d4-a716-446655440000".into(),
            input_released: false,
            owned_cleanup: OwnedCleanup::Failed,
            error_code: Some("owned_cleanup_failed".into()),
        });

        let json = serde_json::to_value(receipt).unwrap();

        assert_eq!(json["type"], "task_run_cleanup_receipt");
        assert_eq!(json["input_released"], false);
        assert_eq!(json["owned_cleanup"], "failed");
        assert_eq!(json["error_code"], "owned_cleanup_failed");
        assert!(json.get("connection_id").is_none());
    }

    #[test]
    fn task_run_click_parses_exact_left_single_click_contract() {
        let msg = parse_message(
            r#"{
                "type":"task_run_click",
                "task_run_id":"task-a",
                "trace_id":"trace-a",
                "session_id":"session-a",
                "connection_id":"550e8400-e29b-41d4-a716-446655440000",
                "click_id":"click-a",
                "source_frame_seq":7,
                "client_x_ratio":0.5,
                "client_y_ratio":0.25,
                "button":"left",
                "click_count":1
            }"#,
        )
        .unwrap();

        match msg {
            AgentMessage::TaskRunClick(click) => {
                assert_eq!(click.message_type, "task_run_click");
                assert_eq!(click.task_run_id, "task-a");
                assert_eq!(click.trace_id, "trace-a");
                assert_eq!(click.session_id, "session-a");
                assert_eq!(
                    click.connection_id,
                    Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
                );
                assert_eq!(click.click_id, "click-a");
                assert_eq!(click.source_frame_seq, 7);
                assert_eq!(click.client_x_ratio, 0.5);
                assert_eq!(click.client_y_ratio, 0.25);
                assert_eq!(click.button, "left");
                assert_eq!(click.click_count, 1);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn task_run_click_rejects_missing_unknown_and_non_left_single_click_values() {
        for payload in [
            r#"{"type":"task_run_click","task_run_id":"task-a","trace_id":"trace-a","session_id":"session-a","source_frame_seq":1,"client_x_ratio":0.5,"client_y_ratio":0.5,"button":"left","click_count":1}"#,
            r#"{"type":"task_run_click","task_run_id":"task-a","trace_id":"trace-a","session_id":"session-a","click_id":"click-a","source_frame_seq":1,"client_x_ratio":0.5,"client_y_ratio":0.5,"button":"left","click_count":1}"#,
            r#"{"type":"task_run_click","task_run_id":"task-a","trace_id":"trace-a","session_id":"session-a","click_id":"click-a","source_frame_seq":1,"client_x_ratio":0.5,"client_y_ratio":0.5,"button":"right","click_count":1}"#,
            r#"{"type":"task_run_click","task_run_id":"task-a","trace_id":"trace-a","session_id":"session-a","click_id":"click-a","source_frame_seq":1,"client_x_ratio":0.5,"client_y_ratio":0.5,"button":"left","click_count":2}"#,
            r#"{"type":"task_run_click","task_run_id":"task-a","trace_id":"trace-a","session_id":"session-a","click_id":"click-a","source_frame_seq":1,"client_x_ratio":0.5,"client_y_ratio":0.5,"button":"left","click_count":1,"extra":"forbidden"}"#,
            r#"{"type":"task_run_click","task_run_id":"","trace_id":"trace-a","session_id":"session-a","click_id":"click-a","source_frame_seq":1,"client_x_ratio":0.5,"client_y_ratio":0.5,"button":"left","click_count":1}"#,
            r#"{"type":"other","task_run_id":"task-a","trace_id":"trace-a","session_id":"session-a","click_id":"click-a","source_frame_seq":1,"client_x_ratio":0.5,"client_y_ratio":0.5,"button":"left","click_count":1}"#,
        ] {
            assert!(parse_message(payload).is_err(), "payload must be rejected");
        }
    }

    #[test]
    fn task_run_click_rejects_malformed_connection_id() {
        let payload = r#"{
            "type":"task_run_click",
            "task_run_id":"task-a",
            "trace_id":"trace-a",
            "session_id":"session-a",
            "connection_id":"not-a-uuid",
            "click_id":"click-a",
            "source_frame_seq":7,
            "client_x_ratio":0.5,
            "client_y_ratio":0.25,
            "button":"left",
            "click_count":1
        }"#;

        assert!(parse_message(payload).is_err());

        let empty_connection_id = r#"{
            "type":"task_run_click",
            "task_run_id":"task-a",
            "trace_id":"trace-a",
            "session_id":"session-a",
            "connection_id":"",
            "click_id":"click-a",
            "source_frame_seq":7,
            "client_x_ratio":0.5,
            "client_y_ratio":0.25,
            "button":"left",
            "click_count":1
        }"#;

        assert!(parse_message(empty_connection_id).is_err());
    }

    #[test]
    fn game_discovery_request_parses_and_private_rescan_is_rejected() {
        let msg =
            parse_message(r#"{"type":"game_discovery_request","request_id":"req-3"}"#).unwrap();

        assert!(matches!(
            msg,
            AgentMessage::GameDiscoveryRequest(GameDiscoveryRequest { request_id }) if request_id == "req-3"
        ));
        assert!(
            parse_message(r#"{"type":"mihoyo_game_discovery_rescan","request_id":"req-3"}"#)
                .is_err()
        );
        assert!(parse_message(r#"{"type":"game_discovery_request"}"#).is_err());
    }

    #[test]
    fn game_discovery_result_serializes_canonical_contract_without_paths() {
        let result = HubMessage::GameDiscoveryResult(GameDiscoveryResult {
            request_id: "req-3".to_string(),
            status: "ready".to_string(),
            error: None,
            games: vec![GameDiscoveryItem {
                game_slug: "genshin".to_string(),
                discovered: true,
                discovery_source: Some("registry".to_string()),
                last_discovered_at: Some("2026-07-04T00:00:00Z".to_string()),
                error: None,
            }],
        });

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""type":"game_discovery_result""#));
        assert!(json.contains(r#""game_slug":"genshin""#));
        assert!(json.contains(r#""discovered":true"#), "{json}");
        assert!(!json.contains(r#"C:\\HoYoPlay"#));
        assert!(!json.contains("executable_path"));
        assert!(!json.contains("working_dir"));
        assert!(!json.contains("mihoyo_game_discovery_snapshot"));
    }

    #[test]
    fn game_discovery_item_rejects_removed_path_properties() {
        assert!(serde_json::from_str::<GameDiscoveryItem>(
            r#"{"game_slug":"genshin","discovered":true,"executable_path":"C:\\private"}"#
        )
        .is_err());
    }

    #[test]
    fn task_run_start_accepts_only_pathless_canonical_wire() {
        let canonical = r#"{
            "type":"task_run_start",
            "task_run_id":"task-a",
            "trace_id":"trace-a",
            "session_id":"session-a",
            "connection_id":"550e8400-e29b-41d4-a716-446655440002",
            "game_slug":"genshin",
            "template_id":"genshin/launch-to-ready",
            "template_version":"v1",
            "params":{"leave_running":true},
            "timeout_s":30
        }"#;

        assert!(matches!(
            parse_message(canonical),
            Ok(AgentMessage::TaskRunStart(TaskRunStart { game_slug, .. })) if game_slug == "genshin"
        ));

        for removed_field in ["game_id", "executable", "executable_path", "working_dir"] {
            let payload = canonical.replacen(
                "\n        }",
                &format!(",\n            \"{removed_field}\":\"private-value\"\n        }}"),
                1,
            );
            assert!(
                parse_message(&payload).is_err(),
                "{removed_field} must be rejected"
            );
        }
    }

    #[test]
    fn environment_check_start_accepts_only_pathless_canonical_wire() {
        let msg = parse_message(
            r#"{
                "type":"environment_check_start",
                "task_run_id":"550e8400-e29b-41d4-a716-446655440001",
                "trace_id":"trace-a",
                "connection_id":"550e8400-e29b-41d4-a716-446655440002",
                "game_slug":"genshin",
                "session_id":"550e8400-e29b-41d4-a716-446655440003",
                "timeout_s":10,
                "force_close_on_cleanup":false
            }"#,
        )
        .unwrap();

        match msg {
            AgentMessage::EnvironmentCheckStart(command) => {
                assert_eq!(command.game_slug, "genshin");
                assert_eq!(
                    command.connection_id,
                    Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap()
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }

        for removed_field in ["game_id", "executable", "working_dir"] {
            let payload = format!(
                r#"{{
                    "type":"environment_check_start",
                    "task_run_id":"550e8400-e29b-41d4-a716-446655440001",
                    "trace_id":"trace-a",
                    "connection_id":"550e8400-e29b-41d4-a716-446655440002",
                    "game_slug":"genshin",
                    "session_id":"550e8400-e29b-41d4-a716-446655440003",
                    "timeout_s":10,
                    "force_close_on_cleanup":false,
                    "{removed_field}":"private-value"
                }}"#,
            );
            assert!(
                parse_message(&payload).is_err(),
                "{removed_field} must be rejected"
            );
        }
    }

    #[test]
    fn game_launch_accepts_only_pathless_canonical_wire() {
        let canonical = r#"{
            "type":"game_launch",
            "session_id":"550e8400-e29b-41d4-a716-446655440001",
            "trace_id":"trace-a",
            "game_slug":"genshin",
            "connection_id":"550e8400-e29b-41d4-a716-446655440002"
        }"#;

        let message = parse_message(canonical).expect("canonical game launch parses");
        assert!(matches!(
            message,
            AgentMessage::GameLaunch(GameLaunch { game_slug, .. }) if game_slug == "genshin"
        ));

        for removed_field in ["game_id", "executable", "working_dir", "unexpected"] {
            let payload = format!(
                r#"{{
                    "type":"game_launch",
                    "session_id":"550e8400-e29b-41d4-a716-446655440001",
                    "trace_id":"trace-a",
                    "game_slug":"genshin",
                    "connection_id":"550e8400-e29b-41d4-a716-446655440002",
                    "{removed_field}":"private-value"
                }}"#,
            );
            assert!(
                parse_message(&payload).is_err(),
                "{removed_field} must be rejected"
            );
        }

        assert!(parse_message(&canonical.replace("genshin", "unsupported")).is_err());
        assert!(parse_message(
            &canonical.replace("550e8400-e29b-41d4-a716-446655440001", "not-a-uuid",)
        )
        .is_err());
        assert!(parse_message(&canonical.replace("\"trace-a\"", "\"\"")).is_err());
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

    #[test]
    fn agent_update_request_accepts_only_canonical_bound_wire() {
        let payload = r#"{
            "type":"agent_update_request",
            "connection_id":"550e8400-e29b-41d4-a716-446655440001",
            "update_id":"550e8400-e29b-41d4-a716-446655440002",
            "promotion_id":"550e8400-e29b-41d4-a716-446655440003",
            "source_build_id":"build-old",
            "target_build_id":"build-new",
            "attempt_nonce":"0123456789abcdef",
            "artifact_path":"/api/v1/agents/550e8400-e29b-41d4-a716-446655440004/updates/550e8400-e29b-41d4-a716-446655440002/artifact",
            "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size_bytes":123
        }"#;
        assert!(matches!(
            parse_message(payload),
            Ok(AgentMessage::AgentUpdateRequest(AgentUpdateRequest { target_build_id, .. }))
                if target_build_id == "build-new"
        ));

        for invalid in [
            payload.replace("/artifact\"", "/artifact\",\"url\":\"https://unsafe\""),
            payload.replace("/api/v1/agents/", "/api/v1/other/"),
            payload.replace(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            payload.replace("\"size_bytes\":123", "\"size_bytes\":0"),
        ] {
            assert!(
                parse_message(&invalid).is_err(),
                "unsafe update wire must reject"
            );
        }
    }

    #[test]
    fn update_messages_and_hello_handoff_serialize_typed_identity() {
        let connection_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
        let update_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap();
        let handoff = AgentUpdateHandoff {
            update_id,
            attempt_nonce: "0123456789abcdef".into(),
            source_build_id: "build-old".into(),
            target_build_id: "build-new".into(),
            prior_connection_id: connection_id,
            running_build_id: "build-new".into(),
        };
        let progress = serde_json::to_value(HubMessage::AgentUpdateProgress(AgentUpdateProgress {
            connection_id,
            update_id,
            source_build_id: "build-old".into(),
            target_build_id: "build-new".into(),
            attempt_nonce: "0123456789abcdef".into(),
            status: AgentUpdateProgressStatus::Staged,
        }))
        .unwrap();
        assert_eq!(progress["type"], "agent_update_progress");
        assert_eq!(progress["status"], "staged");
        let result = serde_json::to_value(HubMessage::AgentUpdateResult(AgentUpdateResult {
            connection_id,
            update_id,
            source_build_id: "build-old".into(),
            target_build_id: "build-new".into(),
            attempt_nonce: "0123456789abcdef".into(),
            status: AgentUpdateResultStatus::Failed,
            error_code: Some("agent_update_artifact_digest_mismatch".into()),
        }))
        .unwrap();
        assert_eq!(result["type"], "agent_update_result");
        assert_eq!(
            result["error_code"],
            "agent_update_artifact_digest_mismatch"
        );
        let json = serde_json::to_value(AgentHello {
            api_key: "redacted".into(),
            agent_name: "agent".into(),
            protocol_version: 3,
            system_info: SystemInfo {
                hostname: "host".into(),
                os_name: "Windows".into(),
                os_version: String::new(),
                os_build: String::new(),
                os_arch: "x64".into(),
                net_version: String::new(),
                timezone: String::new(),
                locale: String::new(),
                last_boot_time: String::new(),
                cpu_name: "cpu".into(),
                cpu_cores: 1,
                cpu_threads: 1,
                memory_total_gb: 1.0,
                disks: vec![],
                network_adapters: vec![],
                displays: vec![],
                agent_version: "0".into(),
            },
            capabilities: vec![],
            supported_task_templates: vec![],
            build_id: Some("build-new".into()),
            update_handoff: Some(handoff),
        })
        .unwrap();
        assert_eq!(json["build_id"], "build-new");
        assert_eq!(json["update_handoff"]["running_build_id"], "build-new");
    }
}
