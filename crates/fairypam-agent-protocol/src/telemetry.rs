use std::collections::{BTreeMap, HashSet};
use std::fmt;

use prost::Message;
use serde_json::{json, Value};

use crate::v2::{
    agent_telemetry_record, telemetry_attribute, AgentTelemetryRecord, TelemetryAttribute,
    TelemetryEventSignal, TelemetryMetricSignal, TelemetrySpanSignal, W3cTraceContext,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelemetryCanonicalError(&'static str);

impl TelemetryCanonicalError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for TelemetryCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TelemetryCanonicalError {}

pub fn canonical_telemetry_record(
    record: &AgentTelemetryRecord,
) -> Result<Vec<u8>, TelemetryCanonicalError> {
    let mut value = BTreeMap::from([
        (
            "agent_process_generation_id".to_owned(),
            json!(record.agent_process_generation_id),
        ),
        (
            "delayed_backfill".to_owned(),
            json!(record.delayed_backfill),
        ),
        ("event_id".to_owned(), json!(record.event_id)),
        ("event_name".to_owned(), json!(record.event_name)),
        (
            "occurred_at_unix_nano".to_owned(),
            json!(record.occurred_at_unix_nano),
        ),
        ("schema_version".to_owned(), json!(record.schema_version)),
        ("severity".to_owned(), json!(record.severity)),
        ("source_sequence".to_owned(), json!(record.source_sequence)),
    ]);
    optional(&mut value, "task_run_id", record.task_run_id.as_ref());
    optional(&mut value, "attempt_id", record.attempt_id.as_ref());
    optional(&mut value, "command_id", record.command_id.as_ref());
    optional(
        &mut value,
        "control_generation",
        record.control_generation.as_ref(),
    );
    optional(
        &mut value,
        "diagnostic_session_id",
        record.diagnostic_session_id.as_ref(),
    );
    optional(
        &mut value,
        "source_monotonic_ns",
        record.source_monotonic_ns.as_ref(),
    );
    optional(
        &mut value,
        "diagnostic_lease_instance_id",
        record.diagnostic_lease_instance_id.as_ref(),
    );
    if let Some(context) = record.trace_context.as_ref() {
        value.insert("trace_context".to_owned(), trace_context(context));
    }
    match record.signal.as_ref() {
        Some(agent_telemetry_record::Signal::Event(event)) => {
            value.insert("event".to_owned(), event_signal(event)?);
        }
        Some(agent_telemetry_record::Signal::Span(span)) => {
            value.insert("span".to_owned(), span_signal(span)?);
        }
        Some(agent_telemetry_record::Signal::Metric(metric)) => {
            value.insert("metric".to_owned(), metric_signal(metric)?);
        }
        None => return Err(TelemetryCanonicalError("telemetry.signal_missing")),
    }
    serde_json::to_vec(&value).map_err(|_| TelemetryCanonicalError("telemetry.canonical_invalid"))
}

pub fn encode_telemetry_record(record: &AgentTelemetryRecord) -> Vec<u8> {
    record.encode_to_vec()
}

pub fn decode_telemetry_record(bytes: &[u8]) -> Result<AgentTelemetryRecord, prost::DecodeError> {
    AgentTelemetryRecord::decode(bytes)
}

fn optional<T: serde::Serialize>(
    value: &mut BTreeMap<String, Value>,
    name: &str,
    item: Option<&T>,
) {
    if let Some(item) = item {
        value.insert(name.to_owned(), json!(item));
    }
}

fn trace_context(value: &W3cTraceContext) -> Value {
    let mut result = BTreeMap::from([("traceparent".to_owned(), json!(value.traceparent))]);
    optional(&mut result, "tracestate", value.tracestate.as_ref());
    json!(result)
}

fn event_signal(value: &TelemetryEventSignal) -> Result<Value, TelemetryCanonicalError> {
    let mut result = BTreeMap::from([("attributes".to_owned(), attributes(&value.attributes)?)]);
    optional(&mut result, "message", value.message.as_ref());
    optional(&mut result, "error_code", value.error_code.as_ref());
    Ok(json!(result))
}

fn span_signal(value: &TelemetrySpanSignal) -> Result<Value, TelemetryCanonicalError> {
    let mut result = BTreeMap::from([
        ("attributes".to_owned(), attributes(&value.attributes)?),
        (
            "ended_at_unix_nano".to_owned(),
            json!(value.ended_at_unix_nano),
        ),
        ("name".to_owned(), json!(value.name)),
        ("span_id".to_owned(), json!(hex(&value.span_id))),
        (
            "started_at_unix_nano".to_owned(),
            json!(value.started_at_unix_nano),
        ),
        ("status".to_owned(), json!(value.status)),
        ("trace_flags".to_owned(), json!(value.trace_flags)),
        ("trace_id".to_owned(), json!(hex(&value.trace_id))),
    ]);
    if let Some(parent) = value.parent_span_id.as_ref() {
        result.insert("parent_span_id".to_owned(), json!(hex(parent)));
    }
    optional(&mut result, "error_code", value.error_code.as_ref());
    optional(&mut result, "tracestate", value.tracestate.as_ref());
    Ok(json!(result))
}

fn metric_signal(value: &TelemetryMetricSignal) -> Result<Value, TelemetryCanonicalError> {
    Ok(json!(BTreeMap::from([
        ("attributes".to_owned(), attributes(&value.attributes)?),
        ("bucket_counts".to_owned(), json!(value.bucket_counts)),
        ("count".to_owned(), json!(value.count)),
        (
            "explicit_bounds".to_owned(),
            Value::Array(
                value
                    .explicit_bounds
                    .iter()
                    .map(|value| double_hex(*value).map(Value::String))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        ("kind".to_owned(), json!(value.kind)),
        ("name".to_owned(), json!(value.name)),
        ("sum".to_owned(), Value::String(double_hex(value.sum)?)),
    ])))
}

fn attributes(values: &[TelemetryAttribute]) -> Result<Value, TelemetryCanonicalError> {
    let mut seen = HashSet::new();
    let mut attributes = values
        .iter()
        .map(|attribute| {
            if attribute.key.is_empty() || !seen.insert(attribute.key.as_str()) {
                return Err(TelemetryCanonicalError("telemetry.attribute_invalid"));
            }
            let (kind, value) = match attribute.value.as_ref() {
                Some(telemetry_attribute::Value::StringValue(value)) => {
                    ("string_value", json!(value))
                }
                Some(telemetry_attribute::Value::IntValue(value)) => ("int_value", json!(value)),
                Some(telemetry_attribute::Value::DoubleValue(value)) => {
                    ("double_value", Value::String(double_hex(*value)?))
                }
                Some(telemetry_attribute::Value::BoolValue(value)) => ("bool_value", json!(value)),
                None => return Err(TelemetryCanonicalError("telemetry.attribute_invalid")),
            };
            Ok(BTreeMap::from([
                ("key".to_owned(), json!(attribute.key)),
                (kind.to_owned(), value),
            ]))
        })
        .collect::<Result<Vec<_>, _>>()?;
    attributes.sort_by(|left, right| left["key"].as_str().cmp(&right["key"].as_str()));
    Ok(json!(attributes))
}

fn double_hex(value: f64) -> Result<String, TelemetryCanonicalError> {
    if !value.is_finite() {
        return Err(TelemetryCanonicalError("telemetry.double_invalid"));
    }
    Ok(if value == 0.0 { 0.0 } else { value }
        .to_bits()
        .to_be_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::v2::{agent_telemetry_record, AgentTelemetryRecord, TelemetrySeverity};

    #[test]
    fn event_canonicalization_is_stable_and_normalizes_negative_zero() {
        let mut record = AgentTelemetryRecord {
            schema_version: 1,
            event_id: "11111111-1111-4111-8111-111111111111".into(),
            agent_process_generation_id: "22222222-2222-4222-8222-222222222222".into(),
            source_sequence: 1,
            occurred_at_unix_nano: 1,
            severity: TelemetrySeverity::Info as i32,
            event_name: "agent.process.started".into(),
            signal: Some(agent_telemetry_record::Signal::Event(
                TelemetryEventSignal {
                    attributes: vec![TelemetryAttribute {
                        key: "value".into(),
                        value: Some(telemetry_attribute::Value::DoubleValue(-0.0)),
                    }],
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        let canonical = canonical_telemetry_record(&record).unwrap();
        assert!(String::from_utf8(canonical.clone())
            .unwrap()
            .contains("0000000000000000"));
        record.record_digest = Sha256::digest(&canonical).to_vec();
        assert_eq!(
            decode_telemetry_record(&encode_telemetry_record(&record)).unwrap(),
            record
        );
    }

    #[test]
    fn rust_matches_shared_canonical_vector() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../../proto/fairypam/agent/v2/testdata/telemetry-canonical-vectors.json"
        ))
        .unwrap();
        let expected = &vector[0];
        let record = AgentTelemetryRecord {
            schema_version: 1,
            event_id: "33333333-3333-4333-8333-333333333333".into(),
            agent_process_generation_id: "22222222-2222-4222-8222-222222222222".into(),
            source_sequence: 7,
            occurred_at_unix_nano: 1_700_000_000_123_456_789,
            task_run_id: Some("55555555-5555-4555-8555-555555555555".into()),
            trace_context: Some(W3cTraceContext {
                traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01".into(),
                tracestate: Some("vendor=value".into()),
            }),
            signal: Some(agent_telemetry_record::Signal::Event(
                TelemetryEventSignal {
                    message: Some("quote\" slash/ line\n中文\u{2028}😀".into()),
                    error_code: Some("command.failed".into()),
                    attributes: vec![
                        TelemetryAttribute {
                            key: "z".into(),
                            value: Some(telemetry_attribute::Value::IntValue(-2)),
                        },
                        TelemetryAttribute {
                            key: "a".into(),
                            value: Some(telemetry_attribute::Value::DoubleValue(-0.0)),
                        },
                        TelemetryAttribute {
                            key: "ok".into(),
                            value: Some(telemetry_attribute::Value::BoolValue(true)),
                        },
                    ],
                },
            )),
            severity: TelemetrySeverity::Info as i32,
            event_name: "agent.command.completed".into(),
            delayed_backfill: true,
            ..Default::default()
        };
        let canonical = canonical_telemetry_record(&record).unwrap();
        assert_eq!(
            String::from_utf8(canonical.clone()).unwrap(),
            expected["canonical_json"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical)),
            expected["sha256"].as_str().unwrap()
        );
    }
}
