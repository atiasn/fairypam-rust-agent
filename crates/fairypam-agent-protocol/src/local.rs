use std::fmt;

use prost::Message;
use sha2::{Digest, Sha256};

use crate::worker_v1::{LocalEnvelope, RealtimeProgramMetrics, WorkerRequest};

pub const LOCAL_PROTOCOL_MAJOR: u32 = 1;
pub const LOCAL_PROTOCOL_MINOR: u32 = 1;
pub const MAX_LOCAL_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalProtocolError(&'static str);

impl LocalProtocolError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for LocalProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for LocalProtocolError {}

pub fn encode_local_envelope(envelope: &LocalEnvelope) -> Result<Vec<u8>, LocalProtocolError> {
    let payload = envelope.encode_to_vec();
    if payload.len() > MAX_LOCAL_MESSAGE_BYTES {
        return Err(LocalProtocolError("worker.message_too_large"));
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| LocalProtocolError("worker.message_too_large"))?;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&length.to_le_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

pub fn decode_local_envelope(framed: &[u8]) -> Result<LocalEnvelope, LocalProtocolError> {
    let length = framed
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(LocalProtocolError("worker.frame_invalid"))? as usize;
    if length > MAX_LOCAL_MESSAGE_BYTES || framed.len() != length + 4 {
        return Err(LocalProtocolError("worker.frame_invalid"));
    }
    let envelope = LocalEnvelope::decode(&framed[4..])
        .map_err(|_| LocalProtocolError("worker.protobuf_invalid"))?;
    if envelope.protocol_major != LOCAL_PROTOCOL_MAJOR
        || envelope.protocol_minor > LOCAL_PROTOCOL_MINOR
        || envelope.payload.is_none()
    {
        return Err(LocalProtocolError("worker.protocol_incompatible"));
    }
    Ok(envelope)
}

pub fn worker_request_digest(request: &WorkerRequest) -> String {
    let payload_only = WorkerRequest {
        identity: None,
        payload: request.payload.clone(),
    };
    format!("{:x}", Sha256::digest(payload_only.encode_to_vec()))
}

pub fn worker_realtime_metrics_digest(metrics: &RealtimeProgramMetrics) -> String {
    let canonical = format!(
        "v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        metrics.sample_count,
        metrics.transition_count,
        metrics.missed_deadlines,
        metrics.stale_events,
        metrics.queue_overflows,
        metrics.sample_interval_p50_us,
        metrics.sample_interval_p95_us,
        metrics.sample_interval_p99_us,
        metrics.scheduler_lateness_p99_us,
        metrics.detection_to_input_p99_us,
        metrics.chord_skew_p99_us,
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

pub fn verify_worker_request(
    request: &WorkerRequest,
    expected_worker_generation: &str,
    expected_target_generation: u64,
    expected_input_owner_epoch: u64,
    now_unix_ms: i64,
) -> Result<(), LocalProtocolError> {
    let identity = request
        .identity
        .as_ref()
        .ok_or(LocalProtocolError("worker.identity_missing"))?;
    if identity.worker_generation != expected_worker_generation {
        return Err(LocalProtocolError("worker.generation_stale"));
    }
    if identity.target_generation != expected_target_generation {
        return Err(LocalProtocolError("worker.target_generation_stale"));
    }
    if identity.input_owner_epoch != expected_input_owner_epoch {
        return Err(LocalProtocolError("worker.input_owner_stale"));
    }
    if identity.local_command_id.is_empty() {
        return Err(LocalProtocolError("worker.command_id_invalid"));
    }
    if identity.deadline_unix_ms <= now_unix_ms {
        return Err(LocalProtocolError("worker.deadline_expired"));
    }
    if request.payload.is_none() || identity.request_digest != worker_request_digest(request) {
        return Err(LocalProtocolError("worker.request_digest_invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::worker_v1::{
        local_envelope, worker_request, GenericClickKey, GetHealth, LocalEnvelope,
        WorkerCommandIdentity, WorkerRequest,
    };

    use super::*;

    fn request() -> WorkerRequest {
        let mut request = WorkerRequest {
            identity: Some(WorkerCommandIdentity {
                worker_generation: "worker-7".into(),
                local_command_id: "command-1".into(),
                deadline_unix_ms: 2_000,
                target_generation: 9,
                input_owner_epoch: 4,
                request_digest: String::new(),
            }),
            payload: Some(worker_request::Payload::GetHealth(GetHealth {})),
        };
        request.identity.as_mut().unwrap().request_digest = worker_request_digest(&request);
        request
    }

    #[test]
    fn framed_protobuf_round_trips() {
        let envelope = LocalEnvelope {
            protocol_major: LOCAL_PROTOCOL_MAJOR,
            protocol_minor: LOCAL_PROTOCOL_MINOR,
            payload: Some(local_envelope::Payload::Request(request())),
        };
        assert_eq!(
            decode_local_envelope(&encode_local_envelope(&envelope).unwrap()).unwrap(),
            envelope
        );
    }

    #[test]
    fn atomic_click_key_round_trips_as_one_payload() {
        let mut request = request();
        request.payload = Some(worker_request::Payload::GenericClickKey(GenericClickKey {
            action_id: "gadget.quick_use".into(),
        }));
        request.identity.as_mut().unwrap().request_digest = worker_request_digest(&request);
        let envelope = LocalEnvelope {
            protocol_major: LOCAL_PROTOCOL_MAJOR,
            protocol_minor: LOCAL_PROTOCOL_MINOR,
            payload: Some(local_envelope::Payload::Request(request)),
        };
        assert_eq!(
            decode_local_envelope(&encode_local_envelope(&envelope).unwrap()).unwrap(),
            envelope
        );
    }

    #[test]
    fn rejects_stale_generation_deadline_and_digest() {
        let request = request();
        assert_eq!(
            verify_worker_request(&request, "worker-8", 9, 4, 1_000)
                .unwrap_err()
                .code(),
            "worker.generation_stale"
        );
        assert_eq!(
            verify_worker_request(&request, "worker-7", 9, 4, 2_000)
                .unwrap_err()
                .code(),
            "worker.deadline_expired"
        );
        let mut tampered = request;
        tampered.payload = Some(worker_request::Payload::GetCapabilities(
            crate::worker_v1::GetCapabilities {},
        ));
        assert_eq!(
            verify_worker_request(&tampered, "worker-7", 9, 4, 1_000)
                .unwrap_err()
                .code(),
            "worker.request_digest_invalid"
        );
    }

    #[test]
    fn realtime_metrics_digest_binds_every_metric() {
        let metrics = RealtimeProgramMetrics {
            sample_count: 1,
            transition_count: 2,
            missed_deadlines: 3,
            stale_events: 4,
            queue_overflows: 5,
            sample_interval_p50_us: 6,
            sample_interval_p95_us: 7,
            sample_interval_p99_us: 8,
            scheduler_lateness_p99_us: 9,
            detection_to_input_p99_us: 10,
            chord_skew_p99_us: 11,
        };
        let digest = worker_realtime_metrics_digest(&metrics);
        let mut changed = metrics;
        changed.chord_skew_p99_us += 1;
        assert_ne!(worker_realtime_metrics_digest(&changed), digest);
        assert_eq!(
            digest,
            "b14d65885d427a5d1f2a9d00ba282970249ac7b2b4ceb1a31a0363e8f6c0a1ef"
        );
    }
}
