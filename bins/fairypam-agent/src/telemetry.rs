#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fairypam_agent_core::AgentError;
use fairypam_agent_protocol::v2::{
    agent_telemetry_event, agent_telemetry_record, command_identity, hub_telemetry_command,
    telemetry_attribute, AgentLogChunk, AgentLogReadRequest, AgentTelemetryBatch,
    AgentTelemetryEvent, AgentTelemetryRecord, DiagnosticLease, DiagnosticLeaseDisposition,
    DiagnosticLeaseReceipt, DiagnosticTargetType, HubTelemetryCommand, RevokeDiagnosticLease,
    TelemetryAttribute, TelemetryDisposition, TelemetryEventSignal, TelemetryMetricKind,
    TelemetryMetricSignal, TelemetryRecordReceipt, TelemetrySeverity, TelemetrySpanSignal,
    TelemetrySpanStatus,
};
use fairypam_agent_protocol::{
    canonical_telemetry_record, decode_telemetry_record, encode_telemetry_record,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::observability::FixedLog;

const MAX_RECORDS: usize = 10_000;
const MAX_BYTES: usize = 5 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_LOG_READ_BYTES: usize = 1024 * 1024;
pub const MAX_LOG_CHUNK_BYTES: usize = 32 * 1024;
const MAX_LEASE_RECEIPTS: usize = 10_000;
const BUFFER_FILE: &str = "telemetry-buffer.json";
const BUFFER_TEMP_FILE: &str = "telemetry-buffer.tmp";
const PROCESS_MARKER_FILE: &str = "agent-process.running";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredRecord {
    queued_at_unix_ms: u64,
    encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredLeaseReceipt {
    recorded_at_unix_ms: u64,
    diagnostic_session_id: String,
    lease_instance_id: String,
    target_type: i32,
    target_id: String,
    agent_process_generation_id: String,
    control_generation: u64,
    disposition: i32,
    source_sequence_boundary: u64,
    source_monotonic_ns: u64,
    expires_monotonic_ns: u64,
    error_code: Option<String>,
}

impl StoredLeaseReceipt {
    fn from_message(value: &DiagnosticLeaseReceipt) -> Self {
        Self {
            recorded_at_unix_ms: now_unix_ms(),
            diagnostic_session_id: value.diagnostic_session_id.clone(),
            lease_instance_id: value.lease_instance_id.clone(),
            target_type: value.target_type,
            target_id: value.target_id.clone(),
            agent_process_generation_id: value.agent_process_generation_id.clone(),
            control_generation: value.control_generation,
            disposition: value.disposition,
            source_sequence_boundary: value.source_sequence_boundary,
            source_monotonic_ns: value.source_monotonic_ns,
            expires_monotonic_ns: value.expires_monotonic_ns,
            error_code: value.error_code.clone(),
        }
    }

    fn message(&self) -> DiagnosticLeaseReceipt {
        DiagnosticLeaseReceipt {
            diagnostic_session_id: self.diagnostic_session_id.clone(),
            lease_instance_id: self.lease_instance_id.clone(),
            target_type: self.target_type,
            target_id: self.target_id.clone(),
            agent_process_generation_id: self.agent_process_generation_id.clone(),
            control_generation: self.control_generation,
            disposition: self.disposition,
            source_sequence_boundary: self.source_sequence_boundary,
            source_monotonic_ns: self.source_monotonic_ns,
            expires_monotonic_ns: self.expires_monotonic_ns,
            error_code: self.error_code.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredLeaseClaim {
    claimed_at_unix_ms: u64,
    lease_instance_id: String,
    agent_process_generation_id: String,
    source_sequence: u64,
    source_monotonic_ns: u64,
    record_digest_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredBuffer {
    schema_version: u32,
    records: VecDeque<StoredRecord>,
    lease_receipts: VecDeque<StoredLeaseReceipt>,
    lease_claims: VecDeque<StoredLeaseClaim>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredBufferFile {
    Current(StoredBuffer),
    Legacy(VecDeque<StoredRecord>),
}

impl StoredRecord {
    fn decode(&self) -> Result<AgentTelemetryRecord, AgentError> {
        decode_telemetry_record(&decode_hex(&self.encoded_hex)?).map_err(|_| buffer_invalid())
    }

    fn byte_len(&self) -> usize {
        self.encoded_hex.len() / 2
    }
}

#[derive(Clone, Debug)]
struct ActiveLease {
    value: DiagnosticLease,
    applied: DiagnosticLeaseReceipt,
    deadline: Instant,
}

pub struct TelemetryState {
    records: VecDeque<StoredRecord>,
    dropped: BTreeMap<String, u64>,
    rejected: BTreeMap<String, u64>,
    root: Option<PathBuf>,
    private: bool,
    process_generation_id: String,
    process_started: Instant,
    source_sequence: u64,
    batch_sequence: u64,
    active_leases: BTreeMap<String, ActiveLease>,
    lease_receipts: VecDeque<StoredLeaseReceipt>,
    lease_claims: VecDeque<StoredLeaseClaim>,
    last_queue_depth: Option<usize>,
    queue_capacity_reported: bool,
}

impl TelemetryState {
    pub fn memory(process_generation_id: String) -> Self {
        Self {
            records: VecDeque::new(),
            dropped: BTreeMap::new(),
            rejected: BTreeMap::new(),
            root: None,
            private: false,
            process_generation_id,
            process_started: Instant::now(),
            source_sequence: 0,
            batch_sequence: 0,
            active_leases: BTreeMap::new(),
            lease_receipts: VecDeque::new(),
            lease_claims: VecDeque::new(),
            last_queue_depth: None,
            queue_capacity_reported: false,
        }
    }

    #[cfg(windows)]
    pub fn production(process_generation_id: String) -> Result<Self, AgentError> {
        let root = PathBuf::from(crate::enrollment::AUDIT_ROOT);
        crate::enrollment::ensure_private_directory(&root)?;
        let marker = root.join(PROCESS_MARKER_FILE);
        let previous_exit_ungraceful = match marker.symlink_metadata() {
            Ok(_) => {
                crate::enrollment::verify_private_file(&marker)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::enrollment::write_private(&marker, process_generation_id.as_bytes())?;
                false
            }
            Err(_) => return Err(buffer_unavailable()),
        };
        let mut state = Self::load(root, true, process_generation_id)?;
        if previous_exit_ungraceful {
            state.record_event(
                "agent.process.previous_exit_ungraceful",
                TelemetrySeverity::Warn,
                Some("previous Agent process did not clear its protected running marker"),
                None,
                None,
                None,
            )?;
        }
        state.record_event(
            "agent.process.started",
            TelemetrySeverity::Info,
            None,
            None,
            None,
            None,
        )?;
        Ok(state)
    }

    #[cfg(any(test, not(windows)))]
    pub fn open(root: PathBuf, process_generation_id: String) -> Result<Self, AgentError> {
        if !root.is_dir()
            || root
                .symlink_metadata()
                .is_ok_and(|value| value.file_type().is_symlink())
        {
            return Err(buffer_unavailable());
        }
        Self::load(root, false, process_generation_id)
    }

    fn load(
        root: PathBuf,
        private: bool,
        process_generation_id: String,
    ) -> Result<Self, AgentError> {
        let path = root.join(BUFFER_FILE);
        let mut bytes = Vec::new();
        let exists = path.exists();
        if exists {
            let file = if private {
                #[cfg(windows)]
                {
                    crate::enrollment::open_private_read(&path)?
                }
                #[cfg(not(windows))]
                unreachable!("private telemetry storage is Windows-only")
            } else {
                fs::File::open(&path).map_err(|_| buffer_unavailable())?
            };
            file.take((MAX_BYTES * 3) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| buffer_unavailable())?;
            if private {
                #[cfg(windows)]
                crate::enrollment::verify_private_file(&path)?;
            }
        }
        let stored = if bytes.is_empty() {
            StoredBuffer {
                schema_version: 2,
                records: VecDeque::new(),
                lease_receipts: VecDeque::new(),
                lease_claims: VecDeque::new(),
            }
        } else {
            match serde_json::from_slice(&bytes).map_err(|_| buffer_invalid())? {
                StoredBufferFile::Current(value) if value.schema_version == 2 => value,
                StoredBufferFile::Current(_) => return Err(buffer_invalid()),
                StoredBufferFile::Legacy(records) => StoredBuffer {
                    schema_version: 2,
                    records,
                    lease_receipts: VecDeque::new(),
                    lease_claims: VecDeque::new(),
                },
            }
        };
        let mut state = Self::memory(process_generation_id.clone());
        state.records = stored.records;
        state.lease_receipts = stored.lease_receipts;
        state.lease_claims = stored.lease_claims;
        state.root = Some(root);
        state.private = private;
        state.source_sequence = state
            .records
            .iter()
            .filter_map(|item| item.decode().ok())
            .filter(|record| record.agent_process_generation_id == process_generation_id)
            .map(|record| record.source_sequence)
            .max()
            .unwrap_or(0);
        state.prune()?;
        state.validate_lease_claims()?;
        Ok(state)
    }

    pub fn record_event(
        &mut self,
        event_name: &str,
        severity: TelemetrySeverity,
        message: Option<&str>,
        task_run_id: Option<String>,
        attempt_id: Option<String>,
        command_id: Option<String>,
    ) -> Result<(), AgentError> {
        self.source_sequence = self
            .source_sequence
            .checked_add(1)
            .ok_or_else(buffer_invalid)?;
        let diagnostic = self.matching_lease(task_run_id.as_deref());
        let mut record = AgentTelemetryRecord {
            schema_version: 1,
            event_id: crate::v2_adapter::new_uuid(),
            agent_process_generation_id: self.process_generation_id.clone(),
            source_sequence: self.source_sequence,
            occurred_at_unix_nano: now_unix_nano(),
            task_run_id,
            attempt_id,
            command_id,
            signal: Some(agent_telemetry_record::Signal::Event(
                TelemetryEventSignal {
                    message: message.map(str::to_owned),
                    ..Default::default()
                },
            )),
            severity: severity as i32,
            event_name: event_name.to_owned(),
            ..Default::default()
        };
        if severity == TelemetrySeverity::Debug {
            let lease = diagnostic.ok_or_else(|| {
                AgentError::new(
                    "telemetry.diagnostic_lease_missing",
                    "debug telemetry requires an active diagnostic lease",
                )
            })?;
            record.control_generation = Some(lease.value.control_generation);
            record.diagnostic_session_id = Some(lease.value.diagnostic_session_id.clone());
            record.source_monotonic_ns = Some(self.monotonic_ns());
            record.diagnostic_lease_instance_id = Some(lease.value.lease_instance_id.clone());
        }
        record.record_digest = Sha256::digest(
            canonical_telemetry_record(&record)
                .map_err(|error| AgentError::new(error.code(), error.to_string()))?,
        )
        .to_vec();
        self.enqueue(record)
    }

    pub fn record_command_span(
        &mut self,
        name: &str,
        identity: &fairypam_agent_protocol::v2::CommandIdentity,
        started_at_unix_nano: i64,
        ended_at_unix_nano: i64,
        error_code: Option<&str>,
    ) -> Result<(), AgentError> {
        let (command, task_run_id, attempt_id) = match identity.value.as_ref() {
            Some(command_identity::Value::Command(command)) => (command, None, None),
            Some(command_identity::Value::Task(task)) => (
                task.command.as_ref().ok_or_else(buffer_invalid)?,
                task.attempt
                    .as_ref()
                    .map(|attempt| attempt.task_run_id.clone()),
                task.attempt
                    .as_ref()
                    .map(|attempt| attempt.attempt_id.clone()),
            ),
            None => return Err(buffer_invalid()),
        };
        if self.matching_lease(task_run_id.as_deref()).is_some() {
            self.record_event(
                "agent.command.detail",
                TelemetrySeverity::Debug,
                Some(name),
                task_run_id.clone(),
                attempt_id.clone(),
                Some(command.command_id.clone()),
            )?;
        }
        let Some(context) = command.trace_context.as_ref() else {
            return Ok(());
        };
        let parts = context.traceparent.split('-').collect::<Vec<_>>();
        if parts.len() != 4 {
            return Ok(());
        }
        let trace_id = decode_hex(parts[1])?;
        let parent_span_id = decode_hex(parts[2])?;
        let trace_flags = u32::from_str_radix(parts[3], 16).map_err(|_| buffer_invalid())?;
        self.source_sequence = self
            .source_sequence
            .checked_add(1)
            .ok_or_else(buffer_invalid)?;
        let event_id = crate::v2_adapter::new_uuid();
        let span_id = Sha256::digest(event_id.as_bytes())[..8].to_vec();
        let mut record = AgentTelemetryRecord {
            schema_version: 1,
            event_id,
            agent_process_generation_id: self.process_generation_id.clone(),
            source_sequence: self.source_sequence,
            occurred_at_unix_nano: ended_at_unix_nano,
            task_run_id,
            attempt_id,
            command_id: Some(command.command_id.clone()),
            signal: Some(agent_telemetry_record::Signal::Span(TelemetrySpanSignal {
                trace_id,
                span_id,
                parent_span_id: Some(parent_span_id),
                name: format!("agent.command.{name}"),
                started_at_unix_nano,
                ended_at_unix_nano,
                status: if error_code.is_some() {
                    TelemetrySpanStatus::Error as i32
                } else {
                    TelemetrySpanStatus::Ok as i32
                },
                error_code: error_code.map(str::to_owned),
                trace_flags,
                tracestate: context.tracestate.clone(),
                ..Default::default()
            })),
            severity: if error_code.is_some() {
                TelemetrySeverity::Error as i32
            } else {
                TelemetrySeverity::Info as i32
            },
            event_name: "agent.command.completed".to_owned(),
            ..Default::default()
        };
        record.record_digest = Sha256::digest(
            canonical_telemetry_record(&record)
                .map_err(|error| AgentError::new(error.code(), error.to_string()))?,
        )
        .to_vec();
        self.enqueue(record)
    }

    pub fn next_batch(
        &mut self,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Option<AgentTelemetryEvent>, AgentError> {
        self.prune()?;
        self.flush_counter_metrics()?;
        self.mark_delayed_backfill()?;
        self.validate_lease_claims()?;
        let mut records = Vec::new();
        let mut bytes: usize = 0;
        for item in &self.records {
            if records.len() >= max_records || bytes.saturating_add(item.byte_len()) > max_bytes {
                break;
            }
            records.push(item.decode()?);
            bytes += item.byte_len();
        }
        if records.is_empty() {
            return Ok(None);
        }
        self.batch_sequence = self.batch_sequence.saturating_add(1).max(1);
        Ok(Some(AgentTelemetryEvent {
            payload: Some(agent_telemetry_event::Payload::Batch(AgentTelemetryBatch {
                batch_sequence: self.batch_sequence,
                records,
            })),
        }))
    }

    pub fn refresh_queue_metrics(&mut self) -> Result<(), AgentError> {
        let depth = self
            .records
            .iter()
            .filter(|item| !item.decode().is_ok_and(|record| is_queue_gauge(&record)))
            .count();
        if self.last_queue_depth != Some(depth)
            && !self.has_metric("fairypam.telemetry.queue.depth")
        {
            self.record_gauge_metric("fairypam.telemetry.queue.depth", depth as f64)?;
            self.last_queue_depth = Some(depth);
        }
        if !self.queue_capacity_reported && !self.has_metric("fairypam.telemetry.queue.capacity") {
            self.record_gauge_metric("fairypam.telemetry.queue.capacity", MAX_RECORDS as f64)?;
            self.queue_capacity_reported = true;
        }
        Ok(())
    }

    pub fn apply_receipts(
        &mut self,
        receipts: &[TelemetryRecordReceipt],
    ) -> Result<(), AgentError> {
        for receipt in receipts {
            let removable = matches!(
                TelemetryDisposition::try_from(receipt.disposition),
                Ok(TelemetryDisposition::Accepted
                    | TelemetryDisposition::Duplicate
                    | TelemetryDisposition::PermanentReject)
            );
            if !removable {
                continue;
            }
            if let Some(index) = self.records.iter().position(|item| {
                item.decode().is_ok_and(|record| {
                    record.agent_process_generation_id == receipt.agent_process_generation_id
                        && record.source_sequence == receipt.source_sequence
                        && record.event_id == receipt.event_id
                })
            }) {
                let removed_record = self.records[index].decode().ok();
                let signal = removed_record.as_ref().map_or("invalid", telemetry_signal);
                self.records.remove(index);
                if let Some(record) = removed_record.as_ref() {
                    self.remove_claim(record);
                }
                if receipt.disposition == TelemetryDisposition::PermanentReject as i32 {
                    *self
                        .rejected
                        .entry(format!("{signal}:permanent_reject"))
                        .or_default() += 1;
                }
            }
        }
        self.persist()
    }

    pub fn handle_lease(
        &mut self,
        lease: &DiagnosticLease,
        agent_id: &str,
        control_generation: u64,
    ) -> Result<DiagnosticLeaseReceipt, AgentError> {
        if let Some(receipt) = self.stored_lease_receipt(&lease.lease_instance_id) {
            return Ok(receipt.message());
        }
        let now_ms = now_unix_ms() as i64;
        let target_valid = match DiagnosticTargetType::try_from(lease.target_type) {
            Ok(DiagnosticTargetType::Agent) => lease.target_id == agent_id,
            Ok(DiagnosticTargetType::TaskRun) => !lease.target_id.is_empty(),
            _ => false,
        };
        let valid = target_valid
            && self.root.is_some()
            && lease.detail_level
                == fairypam_agent_protocol::v2::DiagnosticDetailLevel::Debug as i32
            && lease.agent_process_generation_id == self.process_generation_id
            && lease.control_generation == control_generation
            && lease.expires_at_unix_ms > now_ms;
        let now_mono = self.monotonic_ns();
        let duration_ms =
            u64::try_from(lease.expires_at_unix_ms.saturating_sub(now_ms)).unwrap_or(0);
        let expires_mono = now_mono.saturating_add(duration_ms.saturating_mul(1_000_000));
        let receipt = DiagnosticLeaseReceipt {
            diagnostic_session_id: lease.diagnostic_session_id.clone(),
            lease_instance_id: lease.lease_instance_id.clone(),
            target_type: lease.target_type,
            target_id: lease.target_id.clone(),
            agent_process_generation_id: self.process_generation_id.clone(),
            control_generation,
            disposition: if valid {
                DiagnosticLeaseDisposition::Applied as i32
            } else {
                DiagnosticLeaseDisposition::Rejected as i32
            },
            source_sequence_boundary: self.source_sequence.saturating_add(1),
            source_monotonic_ns: now_mono,
            expires_monotonic_ns: expires_mono,
            error_code: (!valid).then(|| {
                if self.root.is_none() {
                    "telemetry.buffer_unavailable".to_owned()
                } else {
                    "diagnostic.lease_invalid".to_owned()
                }
            }),
        };
        if valid {
            self.active_leases.insert(
                lease.lease_instance_id.clone(),
                ActiveLease {
                    value: lease.clone(),
                    applied: receipt.clone(),
                    deadline: Instant::now() + Duration::from_millis(duration_ms),
                },
            );
        }
        if let Err(error) = self.remember_receipt(receipt.clone()) {
            self.active_leases.remove(&lease.lease_instance_id);
            return Err(error);
        }
        if let Err(error) = self.persist() {
            self.active_leases.remove(&lease.lease_instance_id);
            self.remove_receipt(&lease.lease_instance_id);
            return Err(error);
        }
        Ok(receipt)
    }

    pub fn handle_revoke(
        &mut self,
        revoke: &RevokeDiagnosticLease,
    ) -> Result<DiagnosticLeaseReceipt, AgentError> {
        let stored = self
            .stored_lease_receipt(&revoke.lease_instance_id)
            .cloned();
        if let Some(receipt) = stored.as_ref() {
            if receipt.disposition == DiagnosticLeaseDisposition::Revoked as i32 {
                return Ok(receipt.message());
            }
        }
        let active = self.active_leases.get(&revoke.lease_instance_id);
        let valid = active.is_some_and(|lease| {
            lease.value.diagnostic_session_id == revoke.diagnostic_session_id
                && lease.value.lease_instance_id == revoke.lease_instance_id
                && lease.value.target_type == revoke.target_type
                && lease.value.target_id == revoke.target_id
                && lease.value.agent_process_generation_id == revoke.agent_process_generation_id
                && lease.value.control_generation == revoke.control_generation
        }) || stored.as_ref().is_some_and(|receipt| {
            receipt.disposition == DiagnosticLeaseDisposition::Applied as i32
                && receipt.diagnostic_session_id == revoke.diagnostic_session_id
                && receipt.target_type == revoke.target_type
                && receipt.target_id == revoke.target_id
                && receipt.agent_process_generation_id == revoke.agent_process_generation_id
                && receipt.control_generation == revoke.control_generation
        });
        let receipt = self.terminal_lease_receipt(
            revoke.diagnostic_session_id.clone(),
            revoke.lease_instance_id.clone(),
            revoke.target_type,
            revoke.target_id.clone(),
            revoke.control_generation,
            if valid {
                DiagnosticLeaseDisposition::Revoked
            } else {
                DiagnosticLeaseDisposition::Rejected
            },
            (!valid).then(|| "diagnostic.revoke_invalid".to_owned()),
            active
                .map(|lease| lease.applied.expires_monotonic_ns)
                .or_else(|| stored.as_ref().map(|receipt| receipt.expires_monotonic_ns)),
        );
        let previous_receipts = self.lease_receipts.clone();
        self.remember_receipt(receipt.clone())?;
        if let Err(error) = self.persist() {
            self.lease_receipts = previous_receipts;
            return Err(error);
        }
        if valid {
            self.active_leases.remove(&revoke.lease_instance_id);
        }
        Ok(receipt)
    }

    pub fn expire_leases(&mut self) -> Result<Vec<DiagnosticLeaseReceipt>, AgentError> {
        let expired = self
            .active_leases
            .iter()
            .filter(|(_, lease)| lease_expired(lease))
            .map(|(lease_instance_id, lease)| (lease_instance_id.clone(), lease.value.clone()))
            .collect::<Vec<_>>();
        let mut receipts = Vec::with_capacity(expired.len());
        let previous_receipts = self.lease_receipts.clone();
        for (_, value) in &expired {
            let receipt = self.terminal_lease_receipt(
                value.diagnostic_session_id.clone(),
                value.lease_instance_id.clone(),
                value.target_type,
                value.target_id.clone(),
                value.control_generation,
                DiagnosticLeaseDisposition::Expired,
                None,
                self.active_leases
                    .get(&value.lease_instance_id)
                    .map(|lease| lease.applied.expires_monotonic_ns),
            );
            if let Err(error) = self.remember_receipt(receipt.clone()) {
                self.lease_receipts = previous_receipts;
                return Err(error);
            }
            receipts.push(receipt);
        }
        if !receipts.is_empty() {
            if let Err(error) = self.persist() {
                self.lease_receipts = previous_receipts;
                return Err(error);
            }
            for (lease_instance_id, _) in expired {
                self.active_leases.remove(&lease_instance_id);
            }
        }
        Ok(receipts)
    }

    pub fn cancel_detail_on_disconnect(&mut self) {
        self.active_leases.clear();
    }

    pub fn log_read_allowed(&self, request: &AgentLogReadRequest, agent_id: &str) -> bool {
        request.max_total_bytes > 0
            && request.max_total_bytes <= MAX_LOG_READ_BYTES as u64
            && request.target_type == DiagnosticTargetType::Agent as i32
            && request.target_id == agent_id
            && self.active_leases.values().any(|lease| {
                !lease_expired(lease)
                    && lease.value.diagnostic_session_id == request.diagnostic_session_id
                    && lease.value.target_type == DiagnosticTargetType::Agent as i32
                    && lease.value.target_id == request.target_id
            })
    }

    pub fn lease_receipts(&self) -> Vec<DiagnosticLeaseReceipt> {
        self.lease_receipts
            .iter()
            .map(StoredLeaseReceipt::message)
            .collect()
    }

    #[cfg(windows)]
    pub fn mark_clean_shutdown(&mut self) -> Result<(), AgentError> {
        let Some(root) = self.root.as_ref() else {
            return Ok(());
        };
        let marker = root.join(PROCESS_MARKER_FILE);
        match marker.symlink_metadata() {
            Ok(_) => {
                crate::enrollment::verify_private_file(&marker)?;
                fs::remove_file(marker).map_err(|_| buffer_unavailable())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(buffer_unavailable()),
        }
    }

    fn enqueue(&mut self, record: AgentTelemetryRecord) -> Result<(), AgentError> {
        let encoded = encode_telemetry_record(&record);
        if encoded.len() > 16 * 1024 {
            return Err(AgentError::new(
                "telemetry.record_too_large",
                "telemetry record exceeds the local protocol limit",
            ));
        }
        if let Some(claim) = lease_claim(&record)? {
            self.lease_claims.push_back(claim);
        }
        self.records.push_back(StoredRecord {
            queued_at_unix_ms: now_unix_ms(),
            encoded_hex: encode_hex(&encoded),
        });
        while self.records.len() > MAX_RECORDS || self.total_bytes() > MAX_BYTES {
            let index = self
                .records
                .iter()
                .position(|item| {
                    item.decode().is_ok_and(|value| {
                        value.diagnostic_session_id.is_some()
                            || value.severity <= TelemetrySeverity::Info as i32
                    })
                })
                .unwrap_or(0);
            if let Some(removed) = self.records.remove(index) {
                let removed_record = removed.decode().ok();
                let signal = removed_record
                    .as_ref()
                    .and_then(|value| {
                        value.signal.as_ref().map(|signal| match signal {
                            agent_telemetry_record::Signal::Event(_) => "event",
                            agent_telemetry_record::Signal::Span(_) => "span",
                            agent_telemetry_record::Signal::Metric(_) => "metric",
                        })
                    })
                    .unwrap_or("invalid");
                *self
                    .dropped
                    .entry(format!("{signal}:capacity"))
                    .or_default() += 1;
                if let Some(record) = removed_record.as_ref() {
                    self.remove_claim(record);
                }
            }
        }
        self.persist()
    }

    fn prune(&mut self) -> Result<(), AgentError> {
        let cutoff = now_unix_ms().saturating_sub(MAX_AGE.as_millis() as u64);
        let mut removed = BTreeMap::<String, u64>::new();
        self.records.retain(|item| match item.decode() {
            Ok(_) if item.queued_at_unix_ms >= cutoff => true,
            Ok(record) => {
                *removed
                    .entry(format!("{}:expired", telemetry_signal(&record)))
                    .or_default() += 1;
                false
            }
            Err(_) => {
                *removed.entry("invalid:expired".to_owned()).or_default() += 1;
                false
            }
        });
        let before_receipts = self.lease_receipts.len();
        let before_claims = self.lease_claims.len();
        self.lease_receipts
            .retain(|receipt| receipt.recorded_at_unix_ms >= cutoff);
        let records = &self.records;
        self.lease_claims.retain(|claim| {
            claim.claimed_at_unix_ms >= cutoff
                && records.iter().any(|item| {
                    item.decode()
                        .is_ok_and(|record| claim_matches_record(claim, &record))
                })
        });
        if !removed.is_empty()
            || before_receipts != self.lease_receipts.len()
            || before_claims != self.lease_claims.len()
        {
            for (key, value) in removed {
                *self.dropped.entry(key).or_default() += value;
            }
            self.persist()?;
        }
        Ok(())
    }

    fn validate_lease_claims(&self) -> Result<(), AgentError> {
        for item in &self.records {
            let record = item.decode()?;
            if record.diagnostic_lease_instance_id.is_some()
                && !self
                    .lease_claims
                    .iter()
                    .any(|claim| claim_matches_record(claim, &record))
            {
                return Err(buffer_invalid());
            }
        }
        Ok(())
    }

    fn remove_claim(&mut self, record: &AgentTelemetryRecord) {
        self.lease_claims.retain(|claim| {
            record.diagnostic_lease_instance_id.as_deref() != Some(claim.lease_instance_id.as_str())
                || record.agent_process_generation_id != claim.agent_process_generation_id
                || record.source_sequence != claim.source_sequence
        });
    }

    fn flush_counter_metrics(&mut self) -> Result<(), AgentError> {
        for (key, value) in self.dropped.clone() {
            let (signal, reason) = key.split_once(':').ok_or_else(buffer_invalid)?;
            self.record_counter_metric(
                "fairypam.telemetry.records.dropped",
                reason,
                signal,
                value,
            )?;
            subtract_counter(&mut self.dropped, &key, value);
        }
        for (key, value) in self.rejected.clone() {
            let (signal, reason) = key.split_once(':').ok_or_else(buffer_invalid)?;
            self.record_counter_metric(
                "fairypam.telemetry.records.rejected",
                reason,
                signal,
                value,
            )?;
            subtract_counter(&mut self.rejected, &key, value);
        }
        Ok(())
    }

    fn record_counter_metric(
        &mut self,
        name: &str,
        reason: &str,
        signal: &str,
        value: u64,
    ) -> Result<(), AgentError> {
        self.source_sequence = self
            .source_sequence
            .checked_add(1)
            .ok_or_else(buffer_invalid)?;
        let mut record = AgentTelemetryRecord {
            schema_version: 1,
            event_id: crate::v2_adapter::new_uuid(),
            agent_process_generation_id: self.process_generation_id.clone(),
            source_sequence: self.source_sequence,
            occurred_at_unix_nano: now_unix_nano(),
            signal: Some(agent_telemetry_record::Signal::Metric(
                TelemetryMetricSignal {
                    name: name.to_owned(),
                    kind: TelemetryMetricKind::CounterDelta as i32,
                    sum: value as f64,
                    attributes: vec![
                        string_attribute("reason", reason),
                        string_attribute("signal", signal),
                    ],
                    ..Default::default()
                },
            )),
            severity: TelemetrySeverity::Info as i32,
            event_name: "agent.telemetry.metric".to_owned(),
            ..Default::default()
        };
        record.record_digest = Sha256::digest(
            canonical_telemetry_record(&record)
                .map_err(|error| AgentError::new(error.code(), error.to_string()))?,
        )
        .to_vec();
        self.enqueue(record)
    }

    fn record_gauge_metric(&mut self, name: &str, value: f64) -> Result<(), AgentError> {
        self.source_sequence = self
            .source_sequence
            .checked_add(1)
            .ok_or_else(buffer_invalid)?;
        let mut record = AgentTelemetryRecord {
            schema_version: 1,
            event_id: crate::v2_adapter::new_uuid(),
            agent_process_generation_id: self.process_generation_id.clone(),
            source_sequence: self.source_sequence,
            occurred_at_unix_nano: now_unix_nano(),
            signal: Some(agent_telemetry_record::Signal::Metric(
                TelemetryMetricSignal {
                    name: name.to_owned(),
                    kind: TelemetryMetricKind::Gauge as i32,
                    sum: value,
                    ..Default::default()
                },
            )),
            severity: TelemetrySeverity::Info as i32,
            event_name: "agent.telemetry.metric".to_owned(),
            ..Default::default()
        };
        record.record_digest = Sha256::digest(
            canonical_telemetry_record(&record)
                .map_err(|error| AgentError::new(error.code(), error.to_string()))?,
        )
        .to_vec();
        self.enqueue(record)
    }

    fn has_metric(&self, name: &str) -> bool {
        self.records.iter().any(|item| {
            item.decode().is_ok_and(|record| {
                matches!(
                    record.signal,
                    Some(agent_telemetry_record::Signal::Metric(ref metric)) if metric.name == name
                )
            })
        })
    }

    fn mark_delayed_backfill(&mut self) -> Result<(), AgentError> {
        let cutoff = now_unix_ms().saturating_sub(5_000);
        let mut changed = false;
        let mut claim_updates = Vec::new();
        for item in &mut self.records {
            if item.queued_at_unix_ms > cutoff {
                continue;
            }
            let mut record = item.decode()?;
            if record.delayed_backfill {
                continue;
            }
            record.delayed_backfill = true;
            record.record_digest = Sha256::digest(
                canonical_telemetry_record(&record)
                    .map_err(|error| AgentError::new(error.code(), error.to_string()))?,
            )
            .to_vec();
            item.encoded_hex = encode_hex(&encode_telemetry_record(&record));
            if record.diagnostic_lease_instance_id.is_some() {
                claim_updates.push(record);
            }
            changed = true;
        }
        for record in &claim_updates {
            self.remove_claim(record);
            if let Some(claim) = lease_claim(record)? {
                self.lease_claims.push_back(claim);
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    fn total_bytes(&self) -> usize {
        self.records.iter().map(StoredRecord::byte_len).sum()
    }

    fn monotonic_ns(&self) -> u64 {
        (self
            .process_started
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128) as u64)
            .max(1)
    }

    fn matching_lease(&self, task_run_id: Option<&str>) -> Option<&ActiveLease> {
        self.active_leases
            .values()
            .filter(|lease| {
                !lease_expired(lease)
                    && (lease.value.target_type == DiagnosticTargetType::Agent as i32
                        || (lease.value.target_type == DiagnosticTargetType::TaskRun as i32
                            && task_run_id == Some(lease.value.target_id.as_str())))
            })
            .min_by_key(|lease| {
                if lease.value.target_type == DiagnosticTargetType::TaskRun as i32 {
                    0
                } else {
                    1
                }
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn terminal_lease_receipt(
        &self,
        diagnostic_session_id: String,
        lease_instance_id: String,
        target_type: i32,
        target_id: String,
        control_generation: u64,
        disposition: DiagnosticLeaseDisposition,
        error_code: Option<String>,
        expires_monotonic_ns: Option<u64>,
    ) -> DiagnosticLeaseReceipt {
        let now_mono = self.monotonic_ns();
        DiagnosticLeaseReceipt {
            diagnostic_session_id,
            lease_instance_id,
            target_type,
            target_id,
            agent_process_generation_id: self.process_generation_id.clone(),
            control_generation,
            disposition: disposition as i32,
            source_sequence_boundary: self.source_sequence.saturating_add(1),
            source_monotonic_ns: now_mono,
            expires_monotonic_ns: expires_monotonic_ns.unwrap_or(now_mono),
            error_code,
        }
    }

    fn remember_receipt(&mut self, receipt: DiagnosticLeaseReceipt) -> Result<(), AgentError> {
        self.remove_receipt(&receipt.lease_instance_id);
        if self.lease_receipts.len() >= MAX_LEASE_RECEIPTS {
            let Some(index) = self
                .lease_receipts
                .iter()
                .position(|known| known.disposition != DiagnosticLeaseDisposition::Applied as i32)
            else {
                return Err(buffer_unavailable());
            };
            self.lease_receipts.remove(index);
        }
        self.lease_receipts
            .push_back(StoredLeaseReceipt::from_message(&receipt));
        Ok(())
    }

    fn stored_lease_receipt(&self, lease_instance_id: &str) -> Option<&StoredLeaseReceipt> {
        self.lease_receipts
            .iter()
            .find(|receipt| receipt.lease_instance_id == lease_instance_id)
    }

    fn remove_receipt(&mut self, lease_instance_id: &str) {
        self.lease_receipts
            .retain(|receipt| receipt.lease_instance_id != lease_instance_id);
    }

    fn persist(&self) -> Result<(), AgentError> {
        let Some(root) = self.root.as_ref() else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(&StoredBuffer {
            schema_version: 2,
            records: self.records.clone(),
            lease_receipts: self.lease_receipts.clone(),
            lease_claims: self.lease_claims.clone(),
        })
        .map_err(|_| buffer_invalid())?;
        let temporary = root.join(BUFFER_TEMP_FILE);
        let destination = root.join(BUFFER_FILE);
        if self.private {
            #[cfg(windows)]
            {
                if temporary.exists() {
                    crate::enrollment::verify_private_file(&temporary)?;
                    fs::remove_file(&temporary).map_err(|_| buffer_unavailable())?;
                }
                if destination.exists() {
                    crate::enrollment::verify_private_file(&destination)?;
                }
                crate::enrollment::write_private(&temporary, &bytes)?;
                return crate::enrollment::replace_private(&temporary, &destination);
            }
            #[cfg(not(windows))]
            unreachable!("private telemetry storage is Windows-only")
        }
        fs::write(&temporary, bytes).map_err(|_| buffer_unavailable())?;
        fs::rename(temporary, destination).map_err(|_| buffer_unavailable())
    }
}

fn telemetry_signal(record: &AgentTelemetryRecord) -> &'static str {
    match record.signal.as_ref() {
        Some(agent_telemetry_record::Signal::Event(_)) => "event",
        Some(agent_telemetry_record::Signal::Span(_)) => "span",
        Some(agent_telemetry_record::Signal::Metric(_)) => "metric",
        None => "invalid",
    }
}

fn is_queue_gauge(record: &AgentTelemetryRecord) -> bool {
    matches!(
        record.signal.as_ref(),
        Some(agent_telemetry_record::Signal::Metric(metric))
            if metric.kind == TelemetryMetricKind::Gauge as i32
                && matches!(
                    metric.name.as_str(),
                    "fairypam.telemetry.queue.depth" | "fairypam.telemetry.queue.capacity"
                )
    )
}

fn lease_claim(record: &AgentTelemetryRecord) -> Result<Option<StoredLeaseClaim>, AgentError> {
    let Some(lease_instance_id) = record.diagnostic_lease_instance_id.as_ref() else {
        return Ok(None);
    };
    let source_monotonic_ns = record.source_monotonic_ns.ok_or_else(buffer_invalid)?;
    if record.diagnostic_session_id.is_none()
        || record.control_generation.is_none()
        || record.record_digest.is_empty()
    {
        return Err(buffer_invalid());
    }
    Ok(Some(StoredLeaseClaim {
        claimed_at_unix_ms: now_unix_ms(),
        lease_instance_id: lease_instance_id.clone(),
        agent_process_generation_id: record.agent_process_generation_id.clone(),
        source_sequence: record.source_sequence,
        source_monotonic_ns,
        record_digest_hex: encode_hex(&record.record_digest),
    }))
}

fn claim_matches_record(claim: &StoredLeaseClaim, record: &AgentTelemetryRecord) -> bool {
    record.diagnostic_lease_instance_id.as_deref() == Some(claim.lease_instance_id.as_str())
        && record.agent_process_generation_id == claim.agent_process_generation_id
        && record.source_sequence == claim.source_sequence
        && record.source_monotonic_ns == Some(claim.source_monotonic_ns)
        && encode_hex(&record.record_digest) == claim.record_digest_hex
}

fn string_attribute(key: &str, value: &str) -> TelemetryAttribute {
    TelemetryAttribute {
        key: key.to_owned(),
        value: Some(telemetry_attribute::Value::StringValue(value.to_owned())),
    }
}

fn subtract_counter(counters: &mut BTreeMap<String, u64>, key: &str, value: u64) {
    let remove = counters.get_mut(key).is_some_and(|current| {
        *current = current.saturating_sub(value);
        *current == 0
    });
    if remove {
        counters.remove(key);
    }
}

pub fn log_chunks(
    request: &AgentLogReadRequest,
    state: &TelemetryState,
    agent_id: &str,
    log: Result<FixedLog, AgentError>,
) -> Vec<AgentTelemetryEvent> {
    let result = if !state.log_read_allowed(request, agent_id) {
        Err("diagnostic.log_read_not_authorized")
    } else if request.max_total_bytes as usize > MAX_LOG_READ_BYTES {
        Err("diagnostic.log_read_too_large")
    } else {
        log.and_then(|log| log.snapshot(request.max_total_bytes as usize))
            .map_err(|_| "diagnostic.log_read_unavailable")
    };
    match result {
        Ok(bytes) => {
            let chunks = bytes.chunks(MAX_LOG_CHUNK_BYTES).collect::<Vec<_>>();
            if chunks.is_empty() {
                return vec![log_chunk(request, 0, &[], true, None)];
            }
            let last = chunks.len() - 1;
            chunks
                .into_iter()
                .enumerate()
                .map(|(index, bytes)| log_chunk(request, index as u32, bytes, index == last, None))
                .collect()
        }
        Err(code) => vec![log_chunk(request, 0, &[], true, Some(code))],
    }
}

pub fn log_read_error(request: &AgentLogReadRequest, code: &str) -> AgentTelemetryEvent {
    log_chunk(request, 0, &[], true, Some(code))
}

pub fn command_payload(command: &HubTelemetryCommand) -> Option<&hub_telemetry_command::Payload> {
    command.payload.as_ref()
}

pub fn lease_receipt_event(receipt: DiagnosticLeaseReceipt) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        payload: Some(agent_telemetry_event::Payload::DiagnosticLeaseReceipt(
            receipt,
        )),
    }
}

fn log_chunk(
    request: &AgentLogReadRequest,
    sequence: u32,
    payload: &[u8],
    eof: bool,
    error_code: Option<&str>,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        payload: Some(agent_telemetry_event::Payload::LogChunk(AgentLogChunk {
            request_id: request.request_id.clone(),
            chunk_sequence: sequence,
            payload: payload.to_vec(),
            eof,
            error_code: error_code.map(str::to_owned),
        })),
    }
}

fn lease_expired(lease: &ActiveLease) -> bool {
    Instant::now() >= lease.deadline
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn now_unix_nano() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(i64::MAX as u128) as i64
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AgentError> {
    if !value.len().is_multiple_of(2) {
        return Err(buffer_invalid());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| buffer_invalid())?;
            u8::from_str_radix(pair, 16).map_err(|_| buffer_invalid())
        })
        .collect()
}

fn buffer_unavailable() -> AgentError {
    AgentError::new(
        "telemetry.buffer_unavailable",
        "protected telemetry buffer is unavailable",
    )
}

fn buffer_invalid() -> AgentError {
    AgentError::new(
        "telemetry.buffer_invalid",
        "protected telemetry buffer is invalid",
    )
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn diagnostic_lease(
        lease_instance_id: &str,
        target_type: DiagnosticTargetType,
        target_id: &str,
    ) -> DiagnosticLease {
        DiagnosticLease {
            diagnostic_session_id: crate::v2_adapter::new_uuid(),
            expires_at_unix_ms: now_unix_ms() as i64 + 60_000,
            detail_level: fairypam_agent_protocol::v2::DiagnosticDetailLevel::Debug as i32,
            target_type: target_type as i32,
            target_id: target_id.to_owned(),
            lease_instance_id: lease_instance_id.to_owned(),
            agent_process_generation_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            control_generation: 7,
        }
    }

    #[test]
    fn buffer_persists_and_only_acks_terminal_receipts() {
        let root = tempdir().unwrap();
        let generation = "11111111-1111-4111-8111-111111111111".to_owned();
        let mut state =
            TelemetryState::open(root.path().to_path_buf(), generation.clone()).unwrap();
        state
            .record_event(
                "agent.process.started",
                TelemetrySeverity::Info,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let event = state.next_batch(64, 256 * 1024).unwrap().unwrap();
        let agent_telemetry_event::Payload::Batch(batch) = event.payload.unwrap() else {
            panic!("expected batch")
        };
        let record = &batch.records[0];
        state
            .apply_receipts(&[TelemetryRecordReceipt {
                agent_process_generation_id: generation.clone(),
                source_sequence: record.source_sequence,
                event_id: record.event_id.clone(),
                disposition: TelemetryDisposition::Unspecified as i32,
                ..Default::default()
            }])
            .unwrap();
        assert!(state.next_batch(64, 256 * 1024).unwrap().is_some());
        state
            .apply_receipts(&[TelemetryRecordReceipt {
                agent_process_generation_id: generation.clone(),
                source_sequence: record.source_sequence,
                event_id: record.event_id.clone(),
                disposition: TelemetryDisposition::Accepted as i32,
                timeline_sequence: Some(1),
                ..Default::default()
            }])
            .unwrap();
        assert!(state.next_batch(64, 256 * 1024).unwrap().is_none());
        let reloaded = TelemetryState::open(root.path().to_path_buf(), generation).unwrap();
        assert!(reloaded.records.is_empty());
    }

    #[test]
    fn dropped_and_rejected_counters_are_flushed_as_metric_deltas() {
        let mut state = TelemetryState::memory("11111111-1111-4111-8111-111111111111".to_owned());
        state.dropped.insert("event:capacity".to_owned(), 2);
        state.rejected.insert("span:permanent_reject".to_owned(), 1);

        let event = state.next_batch(64, 256 * 1024).unwrap().unwrap();
        let agent_telemetry_event::Payload::Batch(batch) = event.payload.unwrap() else {
            panic!("expected batch")
        };
        let values = batch
            .records
            .iter()
            .map(|record| {
                let agent_telemetry_record::Signal::Metric(metric) =
                    record.signal.as_ref().unwrap()
                else {
                    panic!("expected metric")
                };
                (metric.name.as_str(), metric.sum)
            })
            .collect::<Vec<_>>();

        assert_eq!(
            values,
            vec![
                ("fairypam.telemetry.records.dropped", 2.0),
                ("fairypam.telemetry.records.rejected", 1.0),
            ]
        );
        assert!(state.dropped.is_empty());
        assert!(state.rejected.is_empty());
    }

    #[test]
    fn queue_gauges_are_bounded_and_only_refresh_after_depth_changes() {
        let mut state = TelemetryState::memory("11111111-1111-4111-8111-111111111111".to_owned());

        state.refresh_queue_metrics().unwrap();
        state.refresh_queue_metrics().unwrap();

        let metrics = state
            .records
            .iter()
            .filter_map(|item| item.decode().ok())
            .filter_map(|record| match record.signal {
                Some(agent_telemetry_record::Signal::Metric(metric)) => {
                    Some((metric.name, metric.kind, metric.sum))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(metrics.len(), 2);
        assert!(metrics.contains(&(
            "fairypam.telemetry.queue.depth".to_owned(),
            TelemetryMetricKind::Gauge as i32,
            0.0,
        )));
        assert!(metrics.contains(&(
            "fairypam.telemetry.queue.capacity".to_owned(),
            TelemetryMetricKind::Gauge as i32,
            MAX_RECORDS as f64,
        )));
    }

    #[test]
    fn concurrent_agent_and_task_leases_are_isolated() {
        let root = tempdir().unwrap();
        let agent_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let task_run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let mut state = TelemetryState::open(
            root.path().to_path_buf(),
            "11111111-1111-4111-8111-111111111111".to_owned(),
        )
        .unwrap();
        let agent = diagnostic_lease(
            "22222222-2222-4222-8222-222222222222",
            DiagnosticTargetType::Agent,
            agent_id,
        );
        let task = diagnostic_lease(
            "33333333-3333-4333-8333-333333333333",
            DiagnosticTargetType::TaskRun,
            task_run_id,
        );

        state.handle_lease(&agent, agent_id, 7).unwrap();
        state.handle_lease(&task, agent_id, 7).unwrap();
        state
            .record_event(
                "agent.process.started",
                TelemetrySeverity::Debug,
                None,
                Some(task_run_id.to_owned()),
                None,
                None,
            )
            .unwrap();
        let record = state.records.back().unwrap().decode().unwrap();
        assert_eq!(
            record.diagnostic_lease_instance_id.as_deref(),
            Some(task.lease_instance_id.as_str())
        );

        state
            .handle_revoke(&RevokeDiagnosticLease {
                diagnostic_session_id: task.diagnostic_session_id.clone(),
                lease_instance_id: task.lease_instance_id.clone(),
                target_type: task.target_type,
                target_id: task.target_id.clone(),
                agent_process_generation_id: task.agent_process_generation_id.clone(),
                control_generation: task.control_generation,
            })
            .unwrap();
        assert_eq!(state.active_leases.len(), 1);
        assert!(state.active_leases.contains_key(&agent.lease_instance_id));
    }

    #[test]
    fn task_lease_adds_claimed_debug_detail_only_for_the_matching_command() {
        use fairypam_agent_protocol::v2::{
            AttemptRef, CommandIdentity, CommandRef, TaskCommandRef,
        };

        let root = tempdir().unwrap();
        let agent_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let task_run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let mut state = TelemetryState::open(
            root.path().to_path_buf(),
            "11111111-1111-4111-8111-111111111111".to_owned(),
        )
        .unwrap();
        let lease = diagnostic_lease(
            "22222222-2222-4222-8222-222222222222",
            DiagnosticTargetType::TaskRun,
            task_run_id,
        );
        state.handle_lease(&lease, agent_id, 7).unwrap();
        let identity = CommandIdentity {
            value: Some(command_identity::Value::Task(TaskCommandRef {
                command: Some(CommandRef {
                    command_id: "44444444-4444-4444-8444-444444444444".to_owned(),
                    ..Default::default()
                }),
                attempt: Some(AttemptRef {
                    task_run_id: task_run_id.to_owned(),
                    attempt_id: "55555555-5555-4555-8555-555555555555".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        };

        state
            .record_command_span(
                "capture_frame",
                &identity,
                now_unix_nano(),
                now_unix_nano(),
                None,
            )
            .unwrap();

        let detail = state.records.back().unwrap().decode().unwrap();
        assert_eq!(detail.event_name, "agent.command.detail");
        assert_eq!(detail.severity, TelemetrySeverity::Debug as i32);
        assert_eq!(detail.task_run_id.as_deref(), Some(task_run_id));
        assert_eq!(
            detail.diagnostic_lease_instance_id.as_deref(),
            Some(lease.lease_instance_id.as_str())
        );
        assert_eq!(state.lease_claims.len(), 1);
    }

    #[test]
    fn memory_fallback_rejects_diagnostic_leases_without_disrupting_normal_telemetry() {
        let agent_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut state = TelemetryState::memory("11111111-1111-4111-8111-111111111111".to_owned());
        let lease = diagnostic_lease(
            "22222222-2222-4222-8222-222222222222",
            DiagnosticTargetType::Agent,
            agent_id,
        );

        let receipt = state.handle_lease(&lease, agent_id, 7).unwrap();

        assert_eq!(
            receipt.disposition,
            DiagnosticLeaseDisposition::Rejected as i32
        );
        assert_eq!(
            receipt.error_code.as_deref(),
            Some("telemetry.buffer_unavailable")
        );
        assert!(state.active_leases.is_empty());
        state
            .record_event(
                "agent.process.started",
                TelemetrySeverity::Info,
                None,
                None,
                None,
                None,
            )
            .unwrap();
    }

    #[test]
    fn expired_lease_is_rejected_without_wrapping_the_monotonic_deadline() {
        let root = tempdir().unwrap();
        let agent_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut state = TelemetryState::open(
            root.path().to_path_buf(),
            "11111111-1111-4111-8111-111111111111".to_owned(),
        )
        .unwrap();
        let mut lease = diagnostic_lease(
            "22222222-2222-4222-8222-222222222222",
            DiagnosticTargetType::Agent,
            agent_id,
        );
        lease.expires_at_unix_ms = now_unix_ms() as i64 - 100;

        let receipt = state.handle_lease(&lease, agent_id, 7).unwrap();

        assert_eq!(
            receipt.disposition,
            DiagnosticLeaseDisposition::Rejected as i32
        );
        assert_eq!(receipt.expires_monotonic_ns, receipt.source_monotonic_ns);
        assert!(state.active_leases.is_empty());
    }

    #[test]
    fn revoke_after_disconnect_is_durable_before_it_is_replayed() {
        let root = tempdir().unwrap();
        let generation = "11111111-1111-4111-8111-111111111111".to_owned();
        let agent_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let lease = diagnostic_lease(
            "22222222-2222-4222-8222-222222222222",
            DiagnosticTargetType::Agent,
            agent_id,
        );
        let revoke = RevokeDiagnosticLease {
            diagnostic_session_id: lease.diagnostic_session_id.clone(),
            lease_instance_id: lease.lease_instance_id.clone(),
            target_type: lease.target_type,
            target_id: lease.target_id.clone(),
            agent_process_generation_id: lease.agent_process_generation_id.clone(),
            control_generation: lease.control_generation,
        };
        let mut state =
            TelemetryState::open(root.path().to_path_buf(), generation.clone()).unwrap();
        state.handle_lease(&lease, agent_id, 7).unwrap();
        state.cancel_detail_on_disconnect();

        let blocked_temporary = root.path().join(BUFFER_TEMP_FILE);
        fs::create_dir(&blocked_temporary).unwrap();
        assert_eq!(
            state.handle_revoke(&revoke).unwrap_err().code(),
            "telemetry.buffer_unavailable"
        );
        assert_eq!(
            state
                .stored_lease_receipt(&lease.lease_instance_id)
                .unwrap()
                .disposition,
            DiagnosticLeaseDisposition::Applied as i32
        );

        fs::remove_dir(blocked_temporary).unwrap();
        let receipt = state.handle_revoke(&revoke).unwrap();
        assert_eq!(
            receipt.disposition,
            DiagnosticLeaseDisposition::Revoked as i32
        );
        drop(state);

        let reloaded = TelemetryState::open(root.path().to_path_buf(), generation).unwrap();
        assert_eq!(
            reloaded
                .stored_lease_receipt(&lease.lease_instance_id)
                .unwrap()
                .disposition,
            DiagnosticLeaseDisposition::Revoked as i32
        );
    }

    #[test]
    fn lease_journal_capacity_never_evicts_applied_receipts() {
        let generation = "11111111-1111-4111-8111-111111111111".to_owned();
        let agent_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut state = TelemetryState::memory(generation.clone());
        for index in 0..MAX_LEASE_RECEIPTS {
            state
                .lease_receipts
                .push_back(StoredLeaseReceipt::from_message(&DiagnosticLeaseReceipt {
                    diagnostic_session_id: format!("session-{index}"),
                    lease_instance_id: format!("lease-{index}"),
                    agent_process_generation_id: generation.clone(),
                    control_generation: 7,
                    disposition: DiagnosticLeaseDisposition::Applied as i32,
                    ..DiagnosticLeaseReceipt::default()
                }));
        }

        let lease = diagnostic_lease(
            "22222222-2222-4222-8222-222222222222",
            DiagnosticTargetType::Agent,
            agent_id,
        );
        assert_eq!(
            state.handle_lease(&lease, agent_id, 7).unwrap_err().code(),
            "telemetry.buffer_unavailable"
        );
        assert_eq!(state.lease_receipts.len(), MAX_LEASE_RECEIPTS);
        assert!(state
            .lease_receipts
            .iter()
            .all(|receipt| receipt.disposition == DiagnosticLeaseDisposition::Applied as i32));
        assert!(!state.active_leases.contains_key(&lease.lease_instance_id));
    }

    #[test]
    fn lease_receipt_and_detail_claim_survive_reload_and_expire_after_seven_days() {
        let root = tempdir().unwrap();
        let generation = "11111111-1111-4111-8111-111111111111".to_owned();
        let agent_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let lease = diagnostic_lease(
            "22222222-2222-4222-8222-222222222222",
            DiagnosticTargetType::Agent,
            agent_id,
        );
        let mut state =
            TelemetryState::open(root.path().to_path_buf(), generation.clone()).unwrap();
        state.handle_lease(&lease, agent_id, 7).unwrap();
        state
            .record_event(
                "agent.process.started",
                TelemetrySeverity::Debug,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        drop(state);

        let mut reloaded = TelemetryState::open(root.path().to_path_buf(), generation).unwrap();
        assert_eq!(reloaded.lease_receipts.len(), 1);
        assert_eq!(reloaded.lease_claims.len(), 1);
        assert!(reloaded.active_leases.is_empty());
        reloaded.lease_receipts[0].recorded_at_unix_ms = 0;
        reloaded.lease_claims[0].claimed_at_unix_ms = 0;
        reloaded.records[0].queued_at_unix_ms = 0;
        reloaded.prune().unwrap();
        assert!(reloaded.lease_receipts.is_empty());
        assert!(reloaded.lease_claims.is_empty());
        assert!(reloaded.records.is_empty());
    }
}
