using System.Security.Cryptography;
using System.Text.Json.Serialization;
using FairyPam.Agent.Protocol.V2;

namespace FairyPam.Agent.Core;

public static class DiscoveryContract
{
    public static DiscoverySnapshot Create(
        SessionRef session,
        string scanId,
        long observedAtUnixMs,
        IEnumerable<DiscoveredGame> discoveredGames)
    {
        if (session is null
            || !IsCanonicalGuid(session.AgentId)
            || string.IsNullOrWhiteSpace(session.SessionId)
            || session.Generation == 0
            || !IsCanonicalGuid(scanId)
            || observedAtUnixMs <= 0)
        {
            throw Invalid();
        }

        DiscoveredGame[] games = discoveredGames
            .Select(game => game.Clone())
            .OrderBy(game => game.ProfileId, StringComparer.Ordinal)
            .ThenBy(game => game.NormalizedInstallRoot, StringComparer.OrdinalIgnoreCase)
            .ThenBy(game => game.ExecutableName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (games.Any(game => !IsValid(game))
            || games.Select(GameKey).Distinct().Count() != games.Length)
        {
            throw Invalid();
        }

        DiscoveryDigestDocument digestDocument = new(
            games.Select(game => new DiscoveryDigestGame(
                game.Available,
                game.ExecutableName,
                game.HasExecutableSha256 ? game.ExecutableSha256 : null,
                game.NormalizedInstallRoot,
                game.ProcessName,
                game.ProfileId,
                string.IsNullOrEmpty(game.PublisherSubject) ? null : game.PublisherSubject)).ToArray());
        DiscoverySnapshot snapshot = new()
        {
            Session = session.Clone(),
            ScanId = scanId,
            ObservedAtUnixMs = observedAtUnixMs,
            PayloadDigest = Convert.ToHexStringLower(
                SHA256.HashData(StrictJson.Canonicalize(digestDocument))),
        };
        snapshot.Games.Add(games);
        return snapshot;
    }

    private static bool IsValid(DiscoveredGame game)
    {
        bool signerIsValid = !string.IsNullOrWhiteSpace(game.PublisherSubject)
            ^ (game.HasExecutableSha256 && IsLowerSha256(game.ExecutableSha256));
        return game.Available
            && !string.IsNullOrWhiteSpace(game.ProfileId)
            && IsWindowsAbsoluteDirectory(game.NormalizedInstallRoot)
            && IsExecutableName(game.ExecutableName)
            && game.ProcessName == Path.GetFileNameWithoutExtension(game.ExecutableName)
            && signerIsValid;
    }

    private static string GameKey(DiscoveredGame game) => string.Join(
        '\n',
        game.ProfileId,
        game.NormalizedInstallRoot.ToUpperInvariant(),
        game.ExecutableName.ToUpperInvariant());

    private static bool IsWindowsAbsoluteDirectory(string value) =>
        value.Length >= 3
        && char.IsAsciiLetter(value[0])
        && value[1] == ':'
        && value[2] == '\\'
        && !value.EndsWith('\\')
        && !value.Contains("..", StringComparison.Ordinal)
        && value.IndexOfAny(['<', '>', '"', '|', '?', '*']) < 0;

    private static bool IsExecutableName(string value) =>
        value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
        && Path.GetFileName(value) == value;

    private static bool IsCanonicalGuid(string value) =>
        Guid.TryParseExact(value, "D", out Guid parsed)
        && parsed.ToString("D") == value;

    private static bool IsLowerSha256(string value) => value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static AgentContractException Invalid() =>
        new("discovery.snapshot_invalid", "Discovery snapshot is invalid.");

    private sealed record DiscoveryDigestDocument(
        [property: JsonPropertyName("games")] DiscoveryDigestGame[] Games);

    private sealed record DiscoveryDigestGame(
        [property: JsonPropertyName("available")] bool Available,
        [property: JsonPropertyName("executable_name")] string ExecutableName,
        [property: JsonPropertyName("executable_sha256")] string? ExecutableSha256,
        [property: JsonPropertyName("normalized_install_root")] string NormalizedInstallRoot,
        [property: JsonPropertyName("process_name")] string ProcessName,
        [property: JsonPropertyName("profile_id")] string ProfileId,
        [property: JsonPropertyName("publisher_subject")] string? PublisherSubject);
}

public sealed class SafeCommandResponder
{
    private readonly Dictionary<string, CommandResult> completed = new(StringComparer.Ordinal);
    private readonly HashSet<string> blockedAttempts = new(StringComparer.Ordinal);

    public CommandResult Respond(HubControlCommand command, CommandAdmission admission)
    {
        CommandIdentity identity = Identity(command).Clone();
        string commandId = Command(identity).CommandId;
        if (admission == CommandAdmission.Replay)
        {
            return completed.TryGetValue(commandId, out CommandResult? result)
                ? result.Clone()
                : throw Invalid();
        }

        TaskCommandRef? task = identity.ValueCase == CommandIdentity.ValueOneofCase.Task
            ? identity.Task
            : null;
        string errorCode;
        CommandOutcome outcome;
        if (task is not null && blockedAttempts.Contains(task.Attempt.AttemptId))
        {
            errorCode = "attempt.recovery_blocked";
            outcome = CommandOutcome.Uncertain;
        }
        else if (admission == CommandAdmission.PayloadDigestConflict)
        {
            errorCode = "command.payload_digest_conflict";
            outcome = CommandOutcome.Uncertain;
            blockedAttempts.Add(task?.Attempt.AttemptId ?? throw Invalid());
        }
        else if (admission == CommandAdmission.PayloadDigestInvalid)
        {
            errorCode = "command.payload_digest_invalid";
            outcome = CommandOutcome.NotApplied;
        }
        else if (command.PayloadCase == HubControlCommand.PayloadOneofCase.StopSession)
        {
            errorCode = "session.stopped";
            outcome = CommandOutcome.Applied;
        }
        else
        {
            errorCode = "command.capability_not_ready";
            outcome = CommandOutcome.NotApplied;
        }

        CommandResult response = new()
        {
            Reference = identity,
            Outcome = outcome,
            ErrorCode = errorCode,
        };
        if (task is not null)
        {
            response.AttemptReceipt = Receipt(task, outcome, errorCode);
        }
        if (admission == CommandAdmission.New)
        {
            completed.Add(commandId, response.Clone());
        }
        return response;
    }

    private static AttemptReceipt Receipt(
        TaskCommandRef task,
        CommandOutcome outcome,
        string errorCode) => new()
        {
            ReceiptVersion = 1,
            Attempt = task.Attempt.Clone(),
            AttemptState = AttemptState.NotFound,
            LastCommand = task.Clone(),
            LastCommandOutcome = outcome,
            SideEffectState = outcome == CommandOutcome.Uncertain
                ? SideEffectState.Uncertain
                : SideEffectState.NotApplied,
            InputState = InputState.Released,
            CaptureState = CaptureState.NotStarted,
            OwnedTargetState = OwnedTargetState.NotStarted,
            CleanupComplete = false,
            ErrorCode = errorCode,
        };

    private static CommandIdentity Identity(HubControlCommand command) => command.PayloadCase switch
    {
        HubControlCommand.PayloadOneofCase.LaunchTarget => command.LaunchTarget.Reference,
        HubControlCommand.PayloadOneofCase.CloseTarget => command.CloseTarget.Reference,
        HubControlCommand.PayloadOneofCase.BeginAttempt => command.BeginAttempt.Reference,
        HubControlCommand.PayloadOneofCase.StartAttemptTarget => command.StartAttemptTarget.Reference,
        HubControlCommand.PayloadOneofCase.StartCapture => command.StartCapture.Reference,
        HubControlCommand.PayloadOneofCase.StopCapture => command.StopCapture.Reference,
        HubControlCommand.PayloadOneofCase.InputFrame => command.InputFrame.Reference,
        HubControlCommand.PayloadOneofCase.ReleaseAll => command.ReleaseAll.Reference,
        HubControlCommand.PayloadOneofCase.FinishAttempt => command.FinishAttempt.Reference,
        HubControlCommand.PayloadOneofCase.InspectAttempt => command.InspectAttempt.Reference,
        HubControlCommand.PayloadOneofCase.StopSession => command.StopSession.Reference,
        _ => throw Invalid(),
    };

    private static CommandRef Command(CommandIdentity identity) => identity.ValueCase switch
    {
        CommandIdentity.ValueOneofCase.Command => identity.Command,
        CommandIdentity.ValueOneofCase.Task => identity.Task.Command,
        _ => throw Invalid(),
    };

    private static AgentContractException Invalid() =>
        new("hub.command_result_invalid", "Command result cannot be formed safely.");
}
