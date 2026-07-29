using System.Security.Cryptography;
using Google.Protobuf;
using FairyPam.Agent.Protocol.V2;

namespace FairyPam.Agent.Core;

public enum CommandAdmission
{
    New,
    Replay,
    PayloadDigestInvalid,
    PayloadDigestConflict,
}

public sealed class HubSessionContract
{
    private const uint ProtocolMinor = 0;
    private readonly string agentId;
    private readonly string agentBuildId;
    private readonly IReadOnlyDictionary<string, string> profileDigests;
    private readonly Dictionary<ulong, CommandIdentitySnapshot> commands = [];
    private readonly HashSet<string> commandIds = new(StringComparer.Ordinal);
    private readonly Dictionary<(string AttemptId, string CommandId), string> taskDigests = [];
    private ulong lastGeneration;
    private ulong lastSequence;
    private uint maxInputLeaseMs;
    private SessionRef? session;

    public HubSessionContract(
        string agentId,
        string agentBuildId,
        IReadOnlyDictionary<string, string> profileDigests)
    {
        if (!IsCanonicalGuid(agentId)
            || string.IsNullOrWhiteSpace(agentBuildId)
            || profileDigests is null
            || profileDigests.Any(profile => string.IsNullOrWhiteSpace(profile.Key)
                || !IsLowerHex(profile.Value)))
        {
            throw Invalid("hub.agent_id_invalid");
        }
        this.agentId = agentId;
        this.agentBuildId = agentBuildId;
        this.profileDigests = new Dictionary<string, string>(profileDigests, StringComparer.Ordinal);
    }

    public SessionRef AcceptHello(HubHello hello)
    {
        if (hello is null || !HasOnlyKnownFields(hello))
        {
            throw Invalid("hub.hello_invalid");
        }
        SessionRef candidate = hello.Session
            ?? throw Invalid("hub.hello_invalid");
        if (session is not null
            || candidate.AgentId != agentId
            || string.IsNullOrWhiteSpace(candidate.SessionId)
            || candidate.Generation == 0
            || candidate.Generation <= lastGeneration
            || hello.HeartbeatIntervalMs == 0
            || hello.MaxInputLeaseMs == 0
            || hello.MaxFrameBytes == 0
            || hello.AcceptedProtocolMinor > ProtocolMinor)
        {
            throw Invalid("hub.hello_invalid");
        }

        session = candidate.Clone();
        lastGeneration = candidate.Generation;
        commands.Clear();
        commandIds.Clear();
        taskDigests.Clear();
        lastSequence = 0;
        maxInputLeaseMs = hello.MaxInputLeaseMs;
        return session.Clone();
    }

    public CommandAdmission Validate(HubControlCommand command, long receivedAtUnixMs)
    {
        if (session is null || receivedAtUnixMs <= 0)
        {
            throw Invalid("hub.session_inactive");
        }
        if (command is null || !HasOnlyKnownFields(command))
        {
            throw Invalid("hub.command_payload_invalid");
        }

        (CommandIdentity identity, IdentityKind identityKind) = Identity(command);
        CommandIdentitySnapshot candidate = ValidateIdentity(identity, identityKind, session, receivedAtUnixMs);
        if (candidate.AttemptId is not null
            && taskDigests.TryGetValue((candidate.AttemptId, candidate.CommandId), out string? acceptedDigest)
            && candidate.PayloadDigest != acceptedDigest)
        {
            return CommandAdmission.PayloadDigestConflict;
        }

        string payloadHash = PayloadHash(command, candidate, receivedAtUnixMs, maxInputLeaseMs);
        if (candidate.PayloadDigest is not null && candidate.PayloadDigest != payloadHash)
        {
            return CommandAdmission.PayloadDigestInvalid;
        }
        candidate = candidate with { PayloadHash = payloadHash };
        if (commands.TryGetValue(candidate.Sequence, out CommandIdentitySnapshot? accepted))
        {
            if (candidate == accepted)
            {
                return CommandAdmission.Replay;
            }
            throw Invalid("hub.command_sequence_invalid");
        }
        if (candidate.Sequence <= lastSequence || !commandIds.Add(candidate.CommandId))
        {
            throw Invalid("hub.command_sequence_invalid");
        }
        commands.Add(candidate.Sequence, candidate);
        if (candidate.AttemptId is not null)
        {
            taskDigests.Add((candidate.AttemptId, candidate.CommandId), candidate.PayloadDigest!);
        }
        lastSequence = candidate.Sequence;
        return CommandAdmission.New;
    }

    public void Disconnect()
    {
        session = null;
        commands.Clear();
        commandIds.Clear();
        taskDigests.Clear();
        lastSequence = 0;
        maxInputLeaseMs = 0;
    }

    private static (CommandIdentity Identity, IdentityKind IdentityKind) Identity(HubControlCommand command) =>
        command.PayloadCase switch
        {
            HubControlCommand.PayloadOneofCase.LaunchTarget => (command.LaunchTarget.Reference, IdentityKind.Command),
            HubControlCommand.PayloadOneofCase.CloseTarget => (command.CloseTarget.Reference, IdentityKind.Command),
            HubControlCommand.PayloadOneofCase.BeginAttempt => (command.BeginAttempt.Reference, IdentityKind.Task),
            HubControlCommand.PayloadOneofCase.StartAttemptTarget => (command.StartAttemptTarget.Reference, IdentityKind.Task),
            HubControlCommand.PayloadOneofCase.StartCapture => (command.StartCapture.Reference, IdentityKind.Task),
            HubControlCommand.PayloadOneofCase.StopCapture => (command.StopCapture.Reference, IdentityKind.Task),
            HubControlCommand.PayloadOneofCase.InputFrame => (command.InputFrame.Reference, IdentityKind.Task),
            HubControlCommand.PayloadOneofCase.ReleaseAll => (command.ReleaseAll.Reference, IdentityKind.Either),
            HubControlCommand.PayloadOneofCase.FinishAttempt => (command.FinishAttempt.Reference, IdentityKind.Task),
            HubControlCommand.PayloadOneofCase.InspectAttempt => (command.InspectAttempt.Reference, IdentityKind.Task),
            HubControlCommand.PayloadOneofCase.StopSession => (command.StopSession.Reference, IdentityKind.Command),
            _ => throw Invalid("hub.command_kind_invalid"),
        };

    private static CommandIdentitySnapshot ValidateIdentity(
        CommandIdentity identity,
        IdentityKind identityKind,
        SessionRef current,
        long receivedAtUnixMs)
    {
        if (identity is null
            || (identityKind == IdentityKind.Command && identity.ValueCase != CommandIdentity.ValueOneofCase.Command)
            || (identityKind == IdentityKind.Task && identity.ValueCase != CommandIdentity.ValueOneofCase.Task)
            || identity.ValueCase == CommandIdentity.ValueOneofCase.None)
        {
            throw Invalid("hub.command_identity_invalid");
        }

        TaskCommandRef? task = identity.ValueCase == CommandIdentity.ValueOneofCase.Task
            ? identity.Task
            : null;
        CommandRef? reference = identity.ValueCase switch
        {
            CommandIdentity.ValueOneofCase.Command => identity.Command,
            CommandIdentity.ValueOneofCase.Task => task?.Command,
            _ => throw Invalid("hub.command_identity_invalid"),
        };
        if (reference?.Session is null
            || reference.Session.AgentId != current.AgentId
            || reference.Session.SessionId != current.SessionId
            || reference.Session.Generation != current.Generation
            || string.IsNullOrWhiteSpace(reference.CommandId)
            || reference.Sequence == 0
            || reference.ExpiresAtUnixMs <= receivedAtUnixMs)
        {
            throw Invalid("hub.command_identity_invalid");
        }

        if (task is null)
        {
            return new(
                reference.Sequence,
                reference.CommandId,
                reference.ExpiresAtUnixMs,
                null,
                null,
                null,
                null,
                null);
        }
        AttemptRef attempt = task.Attempt
            ?? throw Invalid("hub.task_identity_invalid");
        if (!IsCanonicalGuid(attempt.TaskRunId)
            || !IsCanonicalGuid(attempt.AttemptId)
            || attempt.ContractVersion != 2
            || !IsLowerHex(attempt.ContractDigest)
            || !IsLowerHex(task.PayloadDigest))
        {
            throw Invalid("hub.task_identity_invalid");
        }
        return new(
            reference.Sequence,
            reference.CommandId,
            reference.ExpiresAtUnixMs,
            attempt.TaskRunId,
            attempt.AttemptId,
            attempt.ContractDigest,
            null,
            task.PayloadDigest);
    }

    private string PayloadHash(
        HubControlCommand command,
        CommandIdentitySnapshot identity,
        long receivedAtUnixMs,
        uint maxInputLeaseMs)
    {
        (string kind, Dictionary<string, object?> payload) = command.PayloadCase switch
        {
            HubControlCommand.PayloadOneofCase.LaunchTarget => LaunchPayload(command.LaunchTarget),
            HubControlCommand.PayloadOneofCase.CloseTarget => ClosePayload(command.CloseTarget),
            HubControlCommand.PayloadOneofCase.BeginAttempt => BeginPayload(
                command.BeginAttempt,
                identity,
                receivedAtUnixMs,
                maxInputLeaseMs),
            HubControlCommand.PayloadOneofCase.StartAttemptTarget => EmptyPayload("StartAttemptTarget"),
            HubControlCommand.PayloadOneofCase.StartCapture => CapturePayload(command.StartCapture),
            HubControlCommand.PayloadOneofCase.StopCapture => StopCapturePayload(command.StopCapture),
            HubControlCommand.PayloadOneofCase.InputFrame => InputPayload(command.InputFrame, maxInputLeaseMs),
            HubControlCommand.PayloadOneofCase.ReleaseAll => ReleasePayload(command.ReleaseAll),
            HubControlCommand.PayloadOneofCase.FinishAttempt => EmptyPayload("FinishAttempt"),
            HubControlCommand.PayloadOneofCase.InspectAttempt => EmptyPayload("InspectAttempt"),
            HubControlCommand.PayloadOneofCase.StopSession => StopSessionPayload(command.StopSession),
            _ => throw Invalid("hub.command_kind_invalid"),
        };
        Dictionary<string, object?> envelope = new()
        {
            ["kind"] = $"fairypam.agent.v2.{kind}",
            ["payload"] = payload,
        };
        if (identity.AttemptId is not null)
        {
            envelope["attempt"] = new Dictionary<string, object?>
            {
                ["task_run_id"] = identity.TaskRunId,
                ["attempt_id"] = identity.AttemptId,
                ["contract_version"] = 2,
                ["contract_digest"] = identity.ContractDigest,
            };
        }
        return Digest(envelope);
    }

    private static (string, Dictionary<string, object?>) LaunchPayload(LaunchTarget command)
    {
        if (string.IsNullOrWhiteSpace(command.ProfileId))
        {
            throw Invalid("hub.command_payload_invalid");
        }
        return ("LaunchTarget", new() { ["profile_id"] = command.ProfileId });
    }

    private static (string, Dictionary<string, object?>) ClosePayload(CloseTarget command)
    {
        if (command.TimeoutMs == 0)
        {
            throw Invalid("hub.command_payload_invalid");
        }
        return ("CloseTarget", new() { ["timeout_ms"] = command.TimeoutMs });
    }

    private (string, Dictionary<string, object?>) BeginPayload(
        BeginAttempt command,
        CommandIdentitySnapshot identity,
        long receivedAtUnixMs,
        uint maxInputLeaseMs)
    {
        ExecutionContract contract = command.Contract
            ?? throw Invalid("hub.execution_contract_invalid");
        int[] capabilities = contract.AllowedCapabilities.Select(value => (int)value).ToArray();
        if (contract.TaskRunId != identity.TaskRunId
            || contract.AttemptId != identity.AttemptId
            || contract.ContractVersion != 2
            || contract.ContractDigest != identity.ContractDigest
            || contract.AgentBuildId != agentBuildId
            || !profileDigests.TryGetValue(contract.ProfileId, out string? profileDigest)
            || contract.ProfileDigest != profileDigest
            || contract.DeadlineUnixMs <= receivedAtUnixMs
            || contract.MaxInputLeaseMs == 0
            || contract.MaxInputLeaseMs > maxInputLeaseMs
            || contract.CleanupPolicy != CleanupPolicy.ReleaseInputAndCloseOwnedTarget
            || capabilities.Length == 0
            || capabilities.Any(value => value is < 1 or > 6)
            || !capabilities.SequenceEqual(capabilities.Order())
            || capabilities.Distinct().Count() != capabilities.Length)
        {
            throw Invalid("hub.execution_contract_invalid");
        }

        Dictionary<string, object?> canonical = ContractPayload(contract, capabilities, includeDigest: false);
        if (Digest(canonical) != contract.ContractDigest)
        {
            throw Invalid("hub.execution_contract_invalid");
        }
        return ("BeginAttempt", new()
        {
            ["contract"] = ContractPayload(contract, capabilities, includeDigest: true),
        });
    }

    private static Dictionary<string, object?> ContractPayload(
        ExecutionContract contract,
        int[] capabilities,
        bool includeDigest)
    {
        Dictionary<string, object?> result = new()
        {
            ["task_run_id"] = contract.TaskRunId,
            ["attempt_id"] = contract.AttemptId,
            ["agent_build_id"] = contract.AgentBuildId,
            ["profile_id"] = contract.ProfileId,
            ["profile_digest"] = contract.ProfileDigest,
            ["allowed_capabilities"] = capabilities,
            ["deadline_unix_ms"] = contract.DeadlineUnixMs,
            ["max_input_lease_ms"] = contract.MaxInputLeaseMs,
            ["cleanup_policy"] = (int)contract.CleanupPolicy,
            ["contract_version"] = contract.ContractVersion,
        };
        if (includeDigest)
        {
            result["contract_digest"] = contract.ContractDigest;
        }
        return result;
    }

    private static (string, Dictionary<string, object?>) CapturePayload(StartCapture command)
    {
        if (string.IsNullOrWhiteSpace(command.CaptureSourceId)
            || command.Fps is < 1 or > 30
            || command.Encoding != "jpeg"
            || command.Quality is < 1 or > 100)
        {
            throw Invalid("hub.command_payload_invalid");
        }
        return ("StartCapture", new()
        {
            ["capture_source_id"] = command.CaptureSourceId,
            ["fps"] = command.Fps,
            ["encoding"] = command.Encoding,
            ["quality"] = command.Quality,
        });
    }

    private static (string, Dictionary<string, object?>) StopCapturePayload(StopCapture command)
    {
        if (string.IsNullOrWhiteSpace(command.CaptureSourceId))
        {
            throw Invalid("hub.command_payload_invalid");
        }
        return ("StopCapture", new() { ["capture_source_id"] = command.CaptureSourceId });
    }

    private static (string, Dictionary<string, object?>) InputPayload(InputFrame command, uint maxInputLeaseMs)
    {
        (uint ScanCode, bool Extended)[] keys = command.HeldKeys
            .Select(key => (key.ScanCode, key.Extended))
            .ToArray();
        int[] buttons = command.HeldMouseButtons.Select(value => (int)value).ToArray();
        if (command.InputSequence == 0
            || command.LeaseMs == 0
            || command.LeaseMs > maxInputLeaseMs
            || keys.Any(key => key.ScanCode is < 1 or > 255)
            || !keys.SequenceEqual(keys.OrderBy(key => key.ScanCode).ThenBy(key => key.Extended))
            || keys.Distinct().Count() != keys.Length
            || buttons.Any(value => value is < 1 or > 5)
            || !buttons.SequenceEqual(buttons.Order())
            || buttons.Distinct().Count() != buttons.Length
            || command.WheelDelta is < -1200 or > 1200
            || command.WheelDelta % 120 != 0)
        {
            throw Invalid("hub.command_payload_invalid");
        }

        Dictionary<string, object?> payload = new()
        {
            ["input_sequence"] = command.InputSequence,
            ["lease_ms"] = command.LeaseMs,
            ["held_keys"] = command.HeldKeys.Select(key => new Dictionary<string, object?>
            {
                ["scan_code"] = key.ScanCode,
                ["extended"] = key.Extended,
            }).ToArray(),
            ["held_mouse_buttons"] = buttons,
            ["wheel_delta"] = command.WheelDelta,
        };
        if (command.HasSourceFrameSequence)
        {
            payload["source_frame_sequence"] = command.SourceFrameSequence;
        }
        return ("InputFrame", payload);
    }

    private static (string, Dictionary<string, object?>) ReleasePayload(ReleaseAll command)
    {
        if (string.IsNullOrWhiteSpace(command.ReasonCode))
        {
            throw Invalid("hub.command_payload_invalid");
        }
        return ("ReleaseAll", new() { ["reason_code"] = command.ReasonCode });
    }

    private static (string, Dictionary<string, object?>) StopSessionPayload(StopSession command)
    {
        if (string.IsNullOrWhiteSpace(command.ReasonCode))
        {
            throw Invalid("hub.command_payload_invalid");
        }
        return ("StopSession", new() { ["reason_code"] = command.ReasonCode });
    }

    private static (string, Dictionary<string, object?>) EmptyPayload(string kind) => (kind, []);

    private static string Digest(object value) =>
        Convert.ToHexStringLower(SHA256.HashData(StrictJson.Canonicalize(value)));

    private static bool HasOnlyKnownFields(IMessage message)
    {
        try
        {
            IMessage known = message.Descriptor.Parser.ParseJson(JsonFormatter.Default.Format(message));
            return message.Equals(known);
        }
        catch (Exception error) when (error is InvalidProtocolBufferException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsCanonicalGuid(string value) =>
        Guid.TryParseExact(value, "D", out Guid parsed)
        && parsed.ToString("D") == value;

    private static bool IsLowerHex(string value) =>
        value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static AgentContractException Invalid(string code) =>
        new(code, "Hub session contract is invalid.");

    private sealed record CommandIdentitySnapshot(
        ulong Sequence,
        string CommandId,
        long ExpiresAtUnixMs,
        string? TaskRunId,
        string? AttemptId,
        string? ContractDigest,
        string? PayloadHash,
        string? PayloadDigest)
    { }

    private enum IdentityKind
    {
        Command,
        Task,
        Either,
    }
}
