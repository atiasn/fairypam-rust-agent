//! WebSocket client for JSON protocol messages and binary JPEG frames.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, info};

use crate::protocol::{
    parse_message, AgentHello, AgentMessage, AgentUpdateHandoff, HubMessage, SupportedTaskTemplate,
    SystemInfo,
};

const CONTROL_QUEUE_CAPACITY: usize = 32;
const VIDEO_QUEUE_CAPACITY: usize = 2;

type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// WebSocket receive message type.
pub enum RecvMessage {
    /// JSON protocol message.
    Json(Box<AgentMessage>),
    /// Binary frame, such as a JPEG video frame.
    #[allow(dead_code)]
    Binary(Vec<u8>),
}

/// WebSocket client used during the initial handshake.
pub struct WsClient {
    reader: WsReader,
    writer: WsWriter,
}

/// Writable half of the WebSocket connection.
pub struct WsWriter {
    writer: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
}

/// Readable half of the WebSocket connection.
pub struct WsReader {
    reader: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

/// Queueing handle for outbound WebSocket messages.
#[derive(Clone)]
pub struct OutboundWriter {
    control_tx: mpsc::Sender<ControlMessage>,
    video_queue: Arc<VideoFrameQueue>,
    closed: Arc<AtomicBool>,
}

struct ControlMessage {
    msg: HubMessage,
    enqueued_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlSendLatency {
    message_type: &'static str,
    queue_wait_ms: u64,
    socket_send_ms: u64,
    total_elapsed_ms: u64,
}

struct VideoFrameQueue {
    capacity: usize,
    frames: Mutex<VecDeque<Vec<u8>>>,
    dropped: AtomicU64,
    notify: Notify,
}

trait OutboundSink {
    fn send_control<'a>(&'a mut self, msg: &'a HubMessage) -> SendFuture<'a>;
    fn send_video<'a>(&'a mut self, data: Vec<u8>) -> SendFuture<'a>;
}

#[derive(Debug, PartialEq, Eq)]
enum OutboundSent {
    Control(ControlSendLatency),
    Video,
}

impl WsClient {
    /// Connect to the Hub and complete the agent_hello handshake.
    pub async fn connect(
        url: &str,
        api_key: &str,
        agent_name: &str,
        system_info: SystemInfo,
        build_id: Option<String>,
        update_handoff: Option<AgentUpdateHandoff>,
    ) -> Result<(Self, crate::protocol::HubWelcome)> {
        info!("Connecting to Hub: {}", url);
        let (ws, _) = connect_async(url)
            .await
            .with_context(|| format!("WebSocket connection failed: {}", url))?;
        info!("WebSocket connected");

        let (writer, reader) = ws.split();
        let mut client = Self {
            reader: WsReader { reader },
            writer: WsWriter { writer },
        };

        let hello = HubMessage::AgentHello(agent_hello(
            api_key,
            agent_name,
            system_info,
            build_id,
            update_handoff,
        ));
        client.send_json(&hello).await?;
        debug!("agent_hello sent");

        match client.recv_json().await? {
            AgentMessage::HubWelcome(welcome) => {
                info!("Handshake complete: agent_id={}", welcome.agent_id);
                Ok((client, welcome))
            }
            other => anyhow::bail!("expected hub_welcome but received {:?}", other),
        }
    }

    /// Send a JSON protocol message.
    pub async fn send_json(&mut self, msg: &HubMessage) -> Result<()> {
        self.writer.send_json(msg).await
    }

    /// Receive JSON protocol messages, skipping binary frames.
    pub async fn recv_json(&mut self) -> Result<AgentMessage> {
        self.reader.recv_json().await
    }

    /// Split read and write halves so receiving cannot block frame or heartbeat sends.
    pub fn into_split(self) -> (WsWriter, WsReader) {
        (self.writer, self.reader)
    }
}

fn agent_hello(
    api_key: &str,
    agent_name: &str,
    system_info: SystemInfo,
    build_id: Option<String>,
    update_handoff: Option<AgentUpdateHandoff>,
) -> AgentHello {
    AgentHello {
        api_key: api_key.to_string(),
        agent_name: agent_name.to_string(),
        protocol_version: 3,
        system_info,
        capabilities: vec![
            "launch".to_string(),
            "window_bind".to_string(),
            "capture".to_string(),
            "scene_detection".to_string(),
            "game_discovery".to_string(),
            "restricted_input".to_string(),
        ],
        supported_task_templates: vec![SupportedTaskTemplate {
            template_id: "genshin/launch-to-ready".to_string(),
            template_version: "v1".to_string(),
        }],
        build_id,
        update_handoff,
    }
}

impl OutboundWriter {
    #[cfg(test)]
    pub(crate) fn closed_for_test() -> Self {
        let (control_tx, control_rx) = mpsc::channel(1);
        drop(control_rx);
        Self {
            control_tx,
            video_queue: Arc::new(VideoFrameQueue::new(1)),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn spawn(writer: WsWriter) -> (Self, JoinHandle<Result<()>>) {
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
        let video_queue = Arc::new(VideoFrameQueue::new(VIDEO_QUEUE_CAPACITY));
        let task_video_queue = video_queue.clone();
        let closed = Arc::new(AtomicBool::new(false));
        let task_closed = closed.clone();
        let handle = tokio::spawn(async move {
            let result = run_outbound_writer_loop(writer, control_rx, task_video_queue).await;
            task_closed.store(true, Ordering::Relaxed);
            result
        });
        (
            Self {
                control_tx,
                video_queue,
                closed,
            },
            handle,
        )
    }

    pub async fn send_control(&self, msg: HubMessage) -> Result<()> {
        let permit = self
            .control_tx
            .reserve()
            .await
            .map_err(|_| anyhow::anyhow!("outbound control queue closed"))?;
        permit.send(ControlMessage::new(msg));
        Ok(())
    }

    pub fn try_send_control(&self, msg: HubMessage) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            anyhow::bail!("outbound writer closed");
        }
        self.control_tx
            .try_send(ControlMessage::new(msg))
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => {
                    anyhow::anyhow!("outbound control queue full")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    anyhow::anyhow!("outbound control queue closed")
                }
            })
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn send_video(&self, data: Vec<u8>) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            anyhow::bail!("outbound writer closed");
        }
        self.video_queue.push_latest(data);
        Ok(())
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn dropped_video_frames(&self) -> u64 {
        self.video_queue.dropped_count()
    }
}

impl ControlMessage {
    fn new(msg: HubMessage) -> Self {
        Self {
            msg,
            enqueued_at: Instant::now(),
        }
    }
}

impl VideoFrameQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            frames: Mutex::new(VecDeque::with_capacity(capacity)),
            dropped: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    fn push_latest(&self, data: Vec<u8>) {
        if self.capacity == 0 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut frames = self.frames.lock().expect("video queue mutex poisoned");
        while frames.len() >= self.capacity {
            frames.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        frames.push_back(data);
        self.notify.notify_one();
    }

    async fn pop(&self) -> Vec<u8> {
        loop {
            let notified = self.notify.notified();
            if let Some(frame) = self
                .frames
                .lock()
                .expect("video queue mutex poisoned")
                .pop_front()
            {
                return frame;
            }
            notified.await;
        }
    }

    fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl OutboundSink for WsWriter {
    fn send_control<'a>(&'a mut self, msg: &'a HubMessage) -> SendFuture<'a> {
        Box::pin(async move { self.send_json(msg).await })
    }

    fn send_video<'a>(&'a mut self, data: Vec<u8>) -> SendFuture<'a> {
        Box::pin(async move { self.send_binary(data).await })
    }
}

async fn run_outbound_writer_loop<W: OutboundSink>(
    mut writer: W,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    video_queue: Arc<VideoFrameQueue>,
) -> Result<()> {
    loop {
        send_next_outbound(&mut writer, &mut control_rx, &video_queue).await?;
    }
}

async fn send_next_outbound<W: OutboundSink>(
    writer: &mut W,
    control_rx: &mut mpsc::Receiver<ControlMessage>,
    video_queue: &VideoFrameQueue,
) -> Result<OutboundSent> {
    if let Ok(item) = control_rx.try_recv() {
        return send_control_item(writer, item)
            .await
            .map(OutboundSent::Control);
    }

    tokio::select! {
        biased;
        msg = control_rx.recv() => {
            if let Some(item) = msg {
                send_control_item(writer, item).await.map(OutboundSent::Control)
            } else {
                let frame = video_queue.pop().await;
                writer.send_video(frame).await?;
                Ok(OutboundSent::Video)
            }
        }
        frame = video_queue.pop() => {
            writer.send_video(frame).await?;
            Ok(OutboundSent::Video)
        }
    }
}

async fn send_control_item<W: OutboundSink>(
    writer: &mut W,
    item: ControlMessage,
) -> Result<ControlSendLatency> {
    let message_type = control_message_type(&item.msg);
    let send_started = Instant::now();
    let queue_wait = send_started.duration_since(item.enqueued_at);
    writer.send_control(&item.msg).await?;
    let socket_send = send_started.elapsed();
    let total_elapsed = item.enqueued_at.elapsed();
    let latency = ControlSendLatency {
        message_type,
        queue_wait_ms: duration_millis(queue_wait),
        socket_send_ms: duration_millis(socket_send),
        total_elapsed_ms: duration_millis(total_elapsed),
    };
    info!(
        message_type = latency.message_type,
        queue_wait_ms = latency.queue_wait_ms,
        socket_send_ms = latency.socket_send_ms,
        total_elapsed_ms = latency.total_elapsed_ms,
        "outbound control message sent"
    );
    Ok(latency)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn control_message_type(msg: &HubMessage) -> &'static str {
    match msg {
        HubMessage::AgentHello(_) => "agent_hello",
        HubMessage::Heartbeat(_) => "heartbeat",
        HubMessage::GameLaunchAck(_) => "game_launch_ack",
        HubMessage::GameKillAck(_) => "game_kill_ack",
        HubMessage::InputFrameAck(_) => "input_frame_ack",
        HubMessage::GameEvent(_) => "game_event",
        HubMessage::DebugOverlay(_) => "debug_overlay",
        HubMessage::GameDiscoveryResult(_) => "game_discovery_result",
        HubMessage::EnvironmentCheckStepResult(_) => "environment_check_step_result",
        HubMessage::EnvironmentCheckResult(_) => "environment_check_result",
        HubMessage::TaskRunFrame(_) => "task_run_frame",
        HubMessage::TaskRunStep(_) => "task_run_step",
        HubMessage::TaskRunResult(_) => "task_run_result",
        HubMessage::TaskRunCleanupReceipt(_) => "task_run_cleanup_receipt",
        HubMessage::AgentUpdateProgress(_) => "agent_update_progress",
        HubMessage::AgentUpdateResult(_) => "agent_update_result",
    }
}

impl WsWriter {
    /// Send a JSON protocol message.
    pub async fn send_json(&mut self, msg: &HubMessage) -> Result<()> {
        let text = serde_json::to_string(msg)?;
        self.writer.send(Message::Text(text)).await?;
        Ok(())
    }

    /// Send binary data, such as a JPEG video frame.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub async fn send_binary(&mut self, data: Vec<u8>) -> Result<()> {
        self.writer.send(Message::Binary(data)).await?;
        Ok(())
    }
}

impl WsReader {
    /// Receive JSON protocol messages, skipping binary frames.
    pub async fn recv_json(&mut self) -> Result<AgentMessage> {
        loop {
            match self.recv_raw().await? {
                RecvMessage::Json(msg) => return Ok(*msg),
                RecvMessage::Binary(_) => continue,
            }
        }
    }

    /// Receive any WebSocket message.
    pub async fn recv_raw(&mut self) -> Result<RecvMessage> {
        loop {
            match self.reader.next().await {
                Some(Ok(Message::Text(text))) => match parse_message(&text) {
                    Ok(msg) => return Ok(RecvMessage::Json(Box::new(msg))),
                    Err(e) => {
                        error!("message parse failed: {}", e);
                        continue;
                    }
                },
                Some(Ok(Message::Binary(data))) => {
                    return Ok(RecvMessage::Binary(data.to_vec()));
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) => {
                    anyhow::bail!("Hub closed the connection");
                }
                Some(Err(e)) => {
                    anyhow::bail!("WebSocket error: {}", e);
                }
                None => {
                    anyhow::bail!("WebSocket connection closed");
                }
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::*;
    use crate::protocol::{Heartbeat, HubMessage, SystemInfo};

    #[derive(Default)]
    struct RecordingSink {
        sent: Vec<&'static str>,
    }

    impl OutboundSink for RecordingSink {
        fn send_control<'a>(&'a mut self, _msg: &'a HubMessage) -> SendFuture<'a> {
            self.sent.push("control");
            Box::pin(async { Ok(()) })
        }

        fn send_video<'a>(&'a mut self, _data: Vec<u8>) -> SendFuture<'a> {
            self.sent.push("video");
            Box::pin(async { Ok(()) })
        }
    }

    fn heartbeat() -> HubMessage {
        HubMessage::Heartbeat(Heartbeat {
            cpu_usage: 0.0,
            memory_available_gb: 1.0,
            active_processes: 1,
            game_process_events: vec![],
        })
    }

    #[test]
    fn test_ws_client_hello_serialization() {
        let hello = HubMessage::AgentHello(agent_hello(
            "test",
            "test",
            SystemInfo {
                hostname: "test-host".into(),
                os_name: "Windows".into(),
                os_version: "11".into(),
                os_build: String::new(),
                os_arch: "x86_64".into(),
                net_version: String::new(),
                timezone: String::new(),
                locale: String::new(),
                last_boot_time: String::new(),
                cpu_name: "Intel".into(),
                cpu_cores: 8,
                cpu_threads: 16,
                memory_total_gb: 16.0,
                disks: vec![],
                network_adapters: vec![],
                displays: vec![],
                agent_version: "0.1.0".into(),
            },
            Some("build-test".into()),
            None,
        ));
        let HubMessage::AgentHello(hello) = hello else {
            unreachable!()
        };
        assert_eq!(
            hello.capabilities,
            [
                "launch",
                "window_bind",
                "capture",
                "scene_detection",
                "game_discovery",
                "restricted_input",
            ]
        );
        assert_eq!(
            hello.supported_task_templates,
            vec![SupportedTaskTemplate {
                template_id: "genshin/launch-to-ready".into(),
                template_version: "v1".into(),
            }]
        );
        let json = serde_json::to_string(&HubMessage::AgentHello(hello)).unwrap();
        assert!(json.contains("agent_hello"));
        assert!(json.contains("genshin/launch-to-ready"));
        assert!(json.contains("scene_detection"));
        assert!(json.contains("game_discovery"));
        assert!(json.contains("build-test"));
    }

    #[tokio::test]
    async fn outbound_writer_prioritizes_control_over_queued_video() {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let video_queue = Arc::new(VideoFrameQueue::new(2));
        let mut sink = RecordingSink::default();

        video_queue.push_latest(vec![1]);
        assert!(control_tx
            .try_send(ControlMessage::new(heartbeat()))
            .is_ok());

        let sent = send_next_outbound(&mut sink, &mut control_rx, &video_queue)
            .await
            .unwrap();

        assert!(matches!(
            sent,
            OutboundSent::Control(ControlSendLatency {
                message_type: "heartbeat",
                ..
            })
        ));
        assert_eq!(sink.sent, vec!["control"]);
    }

    #[tokio::test]
    async fn outbound_writer_records_control_send_latency() {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let video_queue = Arc::new(VideoFrameQueue::new(2));
        let mut sink = RecordingSink::default();
        let item = ControlMessage {
            msg: heartbeat(),
            enqueued_at: Instant::now() - std::time::Duration::from_millis(7),
        };
        control_tx.try_send(item).unwrap();

        let sent = send_next_outbound(&mut sink, &mut control_rx, &video_queue)
            .await
            .unwrap();

        let OutboundSent::Control(latency) = sent else {
            panic!("expected control send latency");
        };
        assert_eq!(latency.message_type, "heartbeat");
        assert!(latency.queue_wait_ms >= 7);
        assert!(latency.total_elapsed_ms >= latency.queue_wait_ms);
        assert!(latency.total_elapsed_ms >= latency.socket_send_ms);
        assert_eq!(sink.sent, vec!["control"]);
    }

    #[tokio::test]
    async fn control_enqueue_is_not_blocked_by_full_video_queue() {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let outbound = OutboundWriter {
            control_tx,
            video_queue: Arc::new(VideoFrameQueue::new(1)),
            closed: Arc::new(AtomicBool::new(false)),
        };

        outbound.send_video(vec![1]).unwrap();
        outbound.send_video(vec![2]).unwrap();

        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            outbound.send_control(heartbeat()),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(matches!(
            control_rx.try_recv().unwrap().msg,
            HubMessage::Heartbeat(_)
        ));
        assert_eq!(outbound.dropped_video_frames(), 1);
    }

    #[test]
    fn full_control_queue_rejects_without_waiting() {
        let (control_tx, _control_rx) = mpsc::channel(1);
        let outbound = OutboundWriter {
            control_tx,
            video_queue: Arc::new(VideoFrameQueue::new(1)),
            closed: Arc::new(AtomicBool::new(false)),
        };

        outbound.try_send_control(heartbeat()).unwrap();
        let err = outbound
            .try_send_control(heartbeat())
            .unwrap_err()
            .to_string();

        assert!(err.contains("outbound control queue full"));
    }

    #[test]
    fn full_video_queue_drops_old_frames_and_counts_them() {
        let queue = VideoFrameQueue::new(2);

        queue.push_latest(vec![1]);
        queue.push_latest(vec![2]);
        queue.push_latest(vec![3]);

        assert_eq!(queue.dropped_count(), 1);
    }
}
