using System.Text.Json;
using System.Text.Json.Serialization;

namespace FairyPam.Agent.Core;

public enum AttemptLedgerState
{
    Unspecified = 0,
    Claimed = 1,
    TargetReady = 2,
    Active = 3,
    Stopping = 4,
    Terminal = 5,
}

public enum LedgerSideEffectState
{
    Unspecified = 0,
    None = 1,
    IntentRecorded = 2,
    Applied = 3,
    NotApplied = 4,
    Uncertain = 5,
}

public enum LedgerResourceState
{
    Unspecified = 0,
    NotStarted = 1,
    Active = 2,
    Released = 3,
    Stopped = 4,
    Closed = 5,
    Unknown = 6,
}

public enum LedgerCommandOutcome
{
    Unspecified = 0,
    Applied = 1,
    NotApplied = 2,
    Uncertain = 3,
}

public sealed record AttemptLedgerRecord(
    [property: JsonPropertyName("attempt_id")] string AttemptId,
    [property: JsonPropertyName("attempt_state")] AttemptLedgerState AttemptState,
    [property: JsonPropertyName("capture_state")] LedgerResourceState CaptureState,
    [property: JsonPropertyName("cleanup_complete")] bool? CleanupComplete,
    [property: JsonPropertyName("command_id")] string CommandId,
    [property: JsonPropertyName("command_sequence")] ulong CommandSequence,
    [property: JsonPropertyName("contract_digest")] string ContractDigest,
    [property: JsonPropertyName("contract_version")] int ContractVersion,
    [property: JsonPropertyName("error_code")] string? ErrorCode,
    [property: JsonPropertyName("generation")] ulong Generation,
    [property: JsonPropertyName("input_state")] LedgerResourceState InputState,
    [property: JsonPropertyName("observed_at_unix_ms")] long ObservedAtUnixMs,
    [property: JsonPropertyName("owned_target_state")] LedgerResourceState OwnedTargetState,
    [property: JsonPropertyName("outcome")] LedgerCommandOutcome Outcome,
    [property: JsonPropertyName("payload_digest")] string PayloadDigest,
    [property: JsonPropertyName("record_sequence")] ulong RecordSequence,
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("side_effect_state")] LedgerSideEffectState SideEffectState,
    [property: JsonPropertyName("task_run_id")] string TaskRunId);

public sealed record LedgerRecovery(bool IsBlocked, IReadOnlyList<string> UnsafeAttemptIds);

public sealed class AttemptLedger(string root)
{
    public const int MaximumRecordBytes = 64 * 1024;

    public void Append(AttemptLedgerRecord record)
    {
        ValidateRecord(record);
        Directory.CreateDirectory(root);
        string path = PathFor(record.AttemptId);
        if (File.Exists(path))
        {
            AttemptLedgerRecord previous = ReadAll(path).Last();
            ValidateContinuation(previous, record);
        }
        else if (record.RecordSequence != 1)
        {
            throw Invalid("ledger.sequence_invalid");
        }

        byte[] json = StrictJson.Canonicalize(record);
        if (json.Length + 1 > MaximumRecordBytes)
        {
            throw Invalid("ledger.record_too_large");
        }

        using FileStream stream = new(
            path,
            FileMode.Append,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough);
        stream.Write(json);
        stream.WriteByte((byte)'\n');
        stream.Flush(flushToDisk: true);
    }

    public LedgerRecovery Recover()
    {
        if (!Directory.Exists(root))
        {
            return new(false, []);
        }

        List<string> unsafeAttempts = [];
        foreach (string path in Directory.EnumerateFiles(root, "*.jsonl").Order(StringComparer.Ordinal))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw Invalid("ledger.path_invalid");
            }
            AttemptLedgerRecord last = ReadAll(path).Last();
            if (!IsSafeTerminal(last))
            {
                unsafeAttempts.Add(last.AttemptId);
            }
        }
        return new(unsafeAttempts.Count > 0, unsafeAttempts);
    }

    private IReadOnlyList<AttemptLedgerRecord> ReadAll(string path)
    {
        List<AttemptLedgerRecord> records = [];
        using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using MemoryStream line = new(MaximumRecordBytes);
        int next;
        while ((next = stream.ReadByte()) != -1)
        {
            if (next == '\n')
            {
                if (line.Length == 0)
                {
                    throw Invalid("ledger.record_invalid");
                }
                AttemptLedgerRecord record = ParseRecord(
                    line.ToArray(),
                    Path.GetFileNameWithoutExtension(path));
                if (record.RecordSequence != (ulong)records.Count + 1)
                {
                    throw Invalid("ledger.sequence_invalid");
                }
                if (records.Count > 0)
                {
                    ValidateContinuation(records[^1], record);
                }
                records.Add(record);
                line.SetLength(0);
                continue;
            }
            if (line.Length >= MaximumRecordBytes - 1)
            {
                throw Invalid("ledger.record_too_large");
            }
            line.WriteByte((byte)next);
        }
        if (line.Length != 0 || records.Count == 0)
        {
            throw Invalid("ledger.truncated");
        }
        return records;
    }

    private static AttemptLedgerRecord ParseRecord(byte[] json, string expectedAttemptId)
    {
        AttemptLedgerRecord record;
        try
        {
            record = JsonSerializer.Deserialize<AttemptLedgerRecord>(json, StrictJson.Options)
                ?? throw Invalid("ledger.record_invalid");
        }
        catch (JsonException error)
        {
            throw new AgentContractException("ledger.record_invalid", error.Message);
        }
        if (!json.AsSpan().SequenceEqual(StrictJson.Canonicalize(record))
            || record.AttemptId != expectedAttemptId)
        {
            throw Invalid("ledger.record_invalid");
        }
        ValidateRecord(record);
        return record;
    }

    private static void ValidateRecord(AttemptLedgerRecord record)
    {
        if (record.SchemaVersion != 1
            || !IsCanonicalGuid(record.TaskRunId)
            || !IsCanonicalGuid(record.AttemptId)
            || record.RecordSequence == 0
            || record.CommandSequence == 0
            || record.Generation == 0
            || string.IsNullOrWhiteSpace(record.CommandId)
            || !IsDigest(record.ContractDigest)
            || record.ContractVersion != 2
            || !IsDigest(record.PayloadDigest)
            || record.ObservedAtUnixMs <= 0
            || record.AttemptState == AttemptLedgerState.Unspecified
            || record.SideEffectState == LedgerSideEffectState.Unspecified
            || record.InputState == LedgerResourceState.Unspecified
            || record.CaptureState == LedgerResourceState.Unspecified
            || record.OwnedTargetState == LedgerResourceState.Unspecified
            || record.Outcome == LedgerCommandOutcome.Unspecified)
        {
            throw Invalid("ledger.record_invalid");
        }
    }

    private static bool IsSafeTerminal(AttemptLedgerRecord record) =>
        record.AttemptState == AttemptLedgerState.Terminal
        && record.CleanupComplete is true
        && record.InputState == LedgerResourceState.Released
        && record.CaptureState is LedgerResourceState.NotStarted or LedgerResourceState.Stopped
        && record.OwnedTargetState is LedgerResourceState.NotStarted or LedgerResourceState.Closed
        && record.Outcome is LedgerCommandOutcome.Applied or LedgerCommandOutcome.NotApplied
        && record.SideEffectState is not (
            LedgerSideEffectState.IntentRecorded or LedgerSideEffectState.Uncertain);

    private static void ValidateContinuation(
        AttemptLedgerRecord previous,
        AttemptLedgerRecord current)
    {
        if (current.RecordSequence != previous.RecordSequence + 1
            || current.TaskRunId != previous.TaskRunId
            || current.AttemptId != previous.AttemptId
            || current.ContractDigest != previous.ContractDigest
            || current.ContractVersion != previous.ContractVersion)
        {
            throw Invalid("ledger.continuation_invalid");
        }
    }

    private string PathFor(string attemptId) => Path.Combine(root, $"{attemptId}.jsonl");

    private static bool IsCanonicalGuid(string value) =>
        Guid.TryParseExact(value, "D", out Guid parsed)
        && parsed.ToString("D") == value;

    private static bool IsDigest(string value) => value.Length == 64
        && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');

    private static AgentContractException Invalid(string code) =>
        new(code, "Attempt ledger is invalid.");
}
