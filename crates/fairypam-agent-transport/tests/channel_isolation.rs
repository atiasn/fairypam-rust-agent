use std::time::{Duration, Instant};

use fairypam_agent_protocol::v3::{AgentControlEvent, FramePacket};
use fairypam_agent_transport::{control_queue, LatestFrameSlot};

#[tokio::test]
async fn full_frame_slot_does_not_delay_control_heartbeat() {
    let frames = LatestFrameSlot::new();
    for sequence in 1..=100 {
        frames.publish(FramePacket {
            frame_sequence: sequence,
            ..FramePacket::default()
        });
    }
    let (control, mut receiver) = control_queue();

    let started = Instant::now();
    control.try_send(AgentControlEvent::default()).unwrap();
    let heartbeat = receiver.recv().await.unwrap();

    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(heartbeat, AgentControlEvent::default());
    assert_eq!(frames.latest().unwrap().frame_sequence, 100);
    assert_eq!(frames.overwritten_frames(), 99);
}

#[tokio::test]
async fn control_queue_is_bounded_to_declared_capacity() {
    let (control, _receiver) = control_queue();
    for _ in 0..64 {
        control.try_send(AgentControlEvent::default()).unwrap();
    }

    let error = control.try_send(AgentControlEvent::default()).unwrap_err();

    assert_eq!(error.code(), "transport.control_queue_full");
}

#[tokio::test]
async fn consumed_frame_is_not_reported_as_overwritten() {
    use tokio_stream::StreamExt;

    let frames = LatestFrameSlot::new();
    let mut stream = Box::pin(frames.stream());
    frames.publish(FramePacket {
        frame_sequence: 1,
        ..FramePacket::default()
    });
    assert_eq!(stream.next().await.unwrap().frame_sequence, 1);

    frames.publish(FramePacket {
        frame_sequence: 2,
        ..FramePacket::default()
    });

    assert_eq!(frames.overwritten_frames(), 0);
}
