using FairyPam.Agent.Core;
using FairyPam.Agent.Protocol.V2;
using Google.Protobuf;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace FairyPam.Agent.Tests;

[TestClass]
public sealed class Slice2ContractTests
{
    private const string AgentId = "11111111-1111-4111-8111-111111111111";
    private const string TaskRunId = "11111111-1111-4111-8111-111111111111";
    private const string AttemptId = "22222222-2222-4222-8222-222222222222";
    private const string ContractDigest = "e447a21dcd69b86c73d16fd6f0b998251b3b9e78ad6c1c546b0754ecb1e521b8";
    private const string BuildId = "build-2026.07.28";
    private const string ProfileId = "genshin-impact";
    private static readonly string ProfileDigest = new('b', 64);

    [TestMethod]
    public void HubSessionRequiresNewGenerationAndExactCommandIdentity()
    {
        HubSessionContract contract = SessionContract();
        SessionRef session = contract.AcceptHello(Hello(generation: 2));
        HubControlCommand command = Launch(session, "command-1", sequence: 1);

        Assert.AreEqual(CommandAdmission.New, contract.Validate(command, receivedAtUnixMs: 1));
        Assert.AreEqual(CommandAdmission.Replay, contract.Validate(command, receivedAtUnixMs: 1));
        HubControlCommand changedPayload = command.Clone();
        changedPayload.LaunchTarget.ProfileId = "different-profile";
        ExpectContractError(() => contract.Validate(changedPayload, receivedAtUnixMs: 1));
        HubControlCommand changedDeadline = command.Clone();
        changedDeadline.LaunchTarget.Reference.Command.ExpiresAtUnixMs++;
        ExpectContractError(() => contract.Validate(changedDeadline, receivedAtUnixMs: 1));
        ExpectContractError(() => contract.Validate(Launch(session, "command-2", sequence: 1), 1));

        HubControlCommand stop = new()
        {
            StopSession = new StopSession
            {
                Reference = new CommandIdentity { Command = Command(session, "command-2", 2) },
                ReasonCode = "user.requested",
            },
        };
        Assert.AreEqual(CommandAdmission.New, contract.Validate(stop, receivedAtUnixMs: 1));
        Assert.AreEqual(CommandAdmission.Replay, contract.Validate(stop, receivedAtUnixMs: 1));
        HubControlCommand changedReason = stop.Clone();
        changedReason.StopSession.ReasonCode = "different.reason";
        ExpectContractError(() => contract.Validate(changedReason, receivedAtUnixMs: 1));
        HubControlCommand emptyReason = stop.Clone();
        emptyReason.StopSession.Reference.Command.Sequence = 3;
        emptyReason.StopSession.Reference.Command.CommandId = "command-3";
        emptyReason.StopSession.ReasonCode = "";
        ExpectContractError(() => contract.Validate(emptyReason, receivedAtUnixMs: 1));

        contract.Disconnect();
        ExpectContractError(() => contract.AcceptHello(Hello(generation: 2)));
        contract.AcceptHello(Hello(generation: 3));
        ExpectContractError(() => contract.Validate(command, receivedAtUnixMs: 1));
    }

    [TestMethod]
    public void TaskCommandsRequireCurrentSessionAttemptAndDigest()
    {
        HubSessionContract contract = SessionContract();
        SessionRef session = contract.AcceptHello(Hello(generation: 1));
        HubControlCommand command = BeginAttemptCommand(session);

        HubControlCommand wrongBuild = command.Clone();
        wrongBuild.BeginAttempt.Contract.AgentBuildId = "different-build";
        RecomputeBeginAttemptDigests(wrongBuild);
        ExpectContractError(() => contract.Validate(wrongBuild, receivedAtUnixMs: 1));
        HubControlCommand unknownProfile = command.Clone();
        unknownProfile.BeginAttempt.Contract.ProfileId = "unknown-profile";
        RecomputeBeginAttemptDigests(unknownProfile);
        ExpectContractError(() => contract.Validate(unknownProfile, receivedAtUnixMs: 1));
        HubControlCommand wrongProfileDigest = command.Clone();
        wrongProfileDigest.BeginAttempt.Contract.ProfileDigest = new string('c', 64);
        RecomputeBeginAttemptDigests(wrongProfileDigest);
        ExpectContractError(() => contract.Validate(wrongProfileDigest, receivedAtUnixMs: 1));
        Assert.AreEqual(CommandAdmission.New, contract.Validate(command, receivedAtUnixMs: 1));
        HubControlCommand changedPayload = command.Clone();
        changedPayload.BeginAttempt.Contract.MaxInputLeaseMs++;
        ExpectContractError(() => contract.Validate(changedPayload, receivedAtUnixMs: 1));

        HubControlCommand changedDigestAndSequence = command.Clone();
        changedDigestAndSequence.BeginAttempt.Reference.Task.Command.Sequence++;
        changedDigestAndSequence.BeginAttempt.Reference.Task.PayloadDigest = new string('c', 64);
        Assert.AreEqual(
            CommandAdmission.PayloadDigestConflict,
            contract.Validate(changedDigestAndSequence, receivedAtUnixMs: 1));

        HubControlCommand missingCommand = command.Clone();
        missingCommand.BeginAttempt.Reference.Task.Command = null;
        ExpectContractError(() => contract.Validate(missingCommand, receivedAtUnixMs: 1));
    }

    [TestMethod]
    public void AllTaskGoldenVectorsAndUnknownFieldsAreValidated()
    {
        HubSessionContract contract = SessionContract();
        SessionRef session = contract.AcceptHello(Hello(generation: 1));
        HubControlCommand[] commands =
        [
            BeginAttemptCommand(session, "vector-1", 1),
            new()
            {
                StartAttemptTarget = new StartAttemptTarget
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-2",
                        2,
                        "cc4c89e7b1ed12da2b37a5144160cf6b6db66f9e2c3ab5c0dc09dfcc08a6f58e"),
                },
            },
            new()
            {
                StartCapture = new StartCapture
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-3",
                        3,
                        "8a1fb05f4e0f87c9fe77281f8e00f57baa9be92f9dcea915d9720a173a9c8bd0"),
                    CaptureSourceId = "main",
                    Fps = 5,
                    Encoding = "jpeg",
                    Quality = 80,
                },
            },
            new()
            {
                StopCapture = new StopCapture
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-4",
                        4,
                        "387c82ead12dc9c581a27fe9f8eae91f9bd53f2bed43e26e3f1316eb43c0a1a0"),
                    CaptureSourceId = "main",
                },
            },
            new()
            {
                InputFrame = new InputFrame
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-5",
                        5,
                        "8b6ed3cddad56b25e5b135a88c6dcd9bfa44a16d459bb2f57f88b6f5057d9218"),
                    InputSequence = 1,
                    LeaseMs = 500,
                    WheelDelta = 0,
                    HeldKeys =
                    {
                        new PhysicalKey { ScanCode = 30, Extended = false },
                        new PhysicalKey { ScanCode = 44, Extended = false },
                        new PhysicalKey { ScanCode = 72, Extended = true },
                    },
                    HeldMouseButtons = { MouseButton.Left, MouseButton.Right, MouseButton.X2 },
                },
            },
            new()
            {
                InputFrame = new InputFrame
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-6",
                        6,
                        "c2b1e4479b47ca07499cd8b98fafd11120f5e636da61db54f544b7082784d561"),
                    InputSequence = 2,
                    LeaseMs = 500,
                    WheelDelta = 120,
                },
            },
            new()
            {
                ReleaseAll = new ReleaseAll
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-7",
                        7,
                        "ba8f33c67e0168e9ebaf9e3257f61b1782c996d85d389d6059524909ecadd371"),
                    ReasonCode = "lease.expired",
                },
            },
            new()
            {
                FinishAttempt = new FinishAttempt
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-8",
                        8,
                        "3b316c0c5bfd995ea71a6a32f7bc3de6d06e2a12b5847686cb95a753fda004e1"),
                },
            },
            new()
            {
                InspectAttempt = new InspectAttempt
                {
                    Reference = TaskIdentity(
                        session,
                        "vector-9",
                        9,
                        "392207c1bf0033402ad354bf6af72beb2b5a4a43fc4944b685a2541bf0b8b8b0"),
                },
            },
        ];

        foreach (HubControlCommand command in commands)
        {
            Assert.AreEqual(CommandAdmission.New, contract.Validate(command, receivedAtUnixMs: 1));
        }

        HubControlCommand changedCapture = commands[2].Clone();
        changedCapture.StartCapture.Quality = 81;
        Assert.AreEqual(
            CommandAdmission.PayloadDigestInvalid,
            contract.Validate(changedCapture, receivedAtUnixMs: 1));

        byte[] withUnknownField = Launch(session, "unknown-field", 10).ToByteArray()
            .Concat(new byte[] { 0xa0, 0x06, 0x01 })
            .ToArray();
        HubControlCommand unknown = HubControlCommand.Parser.ParseFrom(withUnknownField);
        ExpectContractError(() => contract.Validate(unknown, receivedAtUnixMs: 1));

        HubControlCommand unknownEnum = new()
        {
            InputFrame = new InputFrame
            {
                Reference = TaskIdentity(session, "unknown-enum", 10, new string('d', 64)),
                InputSequence = 3,
                LeaseMs = 500,
                HeldMouseButtons = { (MouseButton)99 },
            },
        };
        ExpectContractError(() => contract.Validate(unknownEnum, receivedAtUnixMs: 1));
    }

    [TestMethod]
    public void EnrollmentResponseRejectsPrivateKeyAndCertificateIdentityMismatch()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        (byte[] valid, byte[] publicKey) = EnrollmentResponse(now, AgentId);
        EnrollmentCandidate candidate = EnrollmentContract.ParseResponse(valid, now, publicKey);

        Assert.AreEqual(Guid.Parse(AgentId), candidate.AgentId);
        Assert.AreEqual("https://hub.example.test:50051/", candidate.ControlEndpoint.AbsoluteUri);

        string withPrivateKey = Encoding.UTF8.GetString(valid).Replace(
            "\"expires_at\":",
            "\"client_key_pem\":\"forbidden\",\"expires_at\":",
            StringComparison.Ordinal);
        ExpectContractError(() => EnrollmentContract.ParseResponse(
            Encoding.UTF8.GetBytes(withPrivateKey),
            now,
            publicKey));
        ExpectContractError(() => EnrollmentContract.ParseResponse(
            EnrollmentResponse(
                now,
                AgentId,
                certificateAgentId: "22222222-2222-4222-8222-222222222222").Json,
            now,
            publicKey));
        ExpectContractError(() => EnrollmentContract.ParseResponse(
            EnrollmentResponse(now, AgentId, addUnexpectedUriSan: true).Json,
            now,
            publicKey));
        using RSA wrongKey = RSA.Create(2048);
        ExpectContractError(() => EnrollmentContract.ParseResponse(
            valid,
            now,
            wrongKey.ExportSubjectPublicKeyInfo()));
    }

    [TestMethod]
    public void DiscoveryDigestIsStableAndDoesNotCarryBusinessGameSlug()
    {
        SessionRef session = Hello(generation: 1).Session;
        DiscoveredGame first = new()
        {
            ProfileId = "genshin-impact",
            NormalizedInstallRoot = "C:\\Games\\Genshin Impact",
            ExecutableName = "YuanShen.exe",
            ProcessName = "YuanShen",
            PublisherSubject = "miHoYo Co., Ltd.",
            Available = true,
        };
        DiscoveredGame second = new()
        {
            ProfileId = "fairypam-test-window",
            NormalizedInstallRoot = "C:\\FairyPam\\Testbed",
            ExecutableName = "FairyPam.Testbed.exe",
            ProcessName = "FairyPam.Testbed",
            ExecutableSha256 = new string('a', 64),
            Available = true,
        };

        DiscoverySnapshot left = DiscoveryContract.Create(
            session,
            "33333333-3333-4333-8333-333333333333",
            100,
            [first, second]);
        DiscoverySnapshot right = DiscoveryContract.Create(
            session,
            "44444444-4444-4444-8444-444444444444",
            200,
            [second, first]);

        Assert.AreEqual(left.PayloadDigest, right.PayloadDigest);
        Assert.AreEqual("fairypam-test-window", left.Games[0].ProfileId);
        Assert.AreEqual("genshin-impact", left.Games[1].ProfileId);
        DiscoveredGame invalid = first.Clone();
        invalid.ExecutableSha256 = new string('b', 64);
        ExpectContractError(() => DiscoveryContract.Create(
            session,
            "55555555-5555-4555-8555-555555555555",
            300,
            [invalid]));
    }

    [TestMethod]
    public void SafeResponderReplaysTypedNotAppliedAndBlocksDigestConflict()
    {
        HubSessionContract contract = SessionContract();
        SessionRef session = contract.AcceptHello(Hello(generation: 1));
        SafeCommandResponder responder = new();
        HubControlCommand command = BeginAttemptCommand(session);

        CommandResult first = responder.Respond(command, contract.Validate(command, 1));
        Assert.AreEqual(CommandOutcome.NotApplied, first.Outcome);
        Assert.IsNotNull(first.AttemptReceipt);
        Assert.AreEqual(SideEffectState.NotApplied, first.AttemptReceipt.SideEffectState);
        Assert.IsFalse(first.AttemptReceipt.CleanupComplete);
        Assert.AreEqual(first, responder.Respond(command, contract.Validate(command, 1)));

        HubControlCommand conflict = command.Clone();
        conflict.BeginAttempt.Reference.Task.Command.Sequence = 2;
        conflict.BeginAttempt.Reference.Task.PayloadDigest = new string('c', 64);
        CommandResult uncertain = responder.Respond(conflict, contract.Validate(conflict, 1));
        Assert.AreEqual(CommandOutcome.Uncertain, uncertain.Outcome);
        Assert.AreEqual("command.payload_digest_conflict", uncertain.ErrorCode);

        HubControlCommand afterConflict = new()
        {
            StartAttemptTarget = new StartAttemptTarget
            {
                Reference = TaskIdentity(
                    session,
                    "after-conflict",
                    3,
                    "cc4c89e7b1ed12da2b37a5144160cf6b6db66f9e2c3ab5c0dc09dfcc08a6f58e"),
            },
        };
        CommandResult blocked = responder.Respond(
            afterConflict,
            contract.Validate(afterConflict, 1));
        Assert.AreEqual(CommandOutcome.Uncertain, blocked.Outcome);
        Assert.AreEqual("attempt.recovery_blocked", blocked.ErrorCode);
    }

    private static HubHello Hello(ulong generation) => new()
    {
        Session = new SessionRef
        {
            AgentId = AgentId,
            SessionId = $"session-{generation}",
            Generation = generation,
        },
        HeartbeatIntervalMs = 10_000,
        MaxInputLeaseMs = 1_000,
        MaxFrameBytes = 8 * 1024 * 1024,
        AcceptedProtocolMinor = 0,
    };

    private static HubControlCommand Launch(SessionRef session, string id, ulong sequence) => new()
    {
        LaunchTarget = new LaunchTarget
        {
            Reference = new CommandIdentity { Command = Command(session, id, sequence) },
            ProfileId = "genshin-impact",
        },
    };

    private static CommandRef Command(SessionRef session, string id, ulong sequence) => new()
    {
        Session = session.Clone(),
        CommandId = id,
        Sequence = sequence,
        ExpiresAtUnixMs = 10_000,
    };

    private static CommandIdentity TaskIdentity(
        SessionRef session,
        string commandId,
        ulong sequence,
        string payloadDigest) => new()
        {
            Task = new TaskCommandRef
            {
                Command = Command(session, commandId, sequence),
                Attempt = new AttemptRef
                {
                    TaskRunId = TaskRunId,
                    AttemptId = AttemptId,
                    ContractVersion = 2,
                    ContractDigest = ContractDigest,
                },
                PayloadDigest = payloadDigest,
            },
        };

    private static HubControlCommand BeginAttemptCommand(
        SessionRef session,
        string commandId = "command-1",
        ulong sequence = 1)
    {
        return new()
        {
            BeginAttempt = new BeginAttempt
            {
                Reference = TaskIdentity(
                    session,
                    commandId,
                    sequence,
                    "4f0ff748296bc675a134017b14fcfd6bd3adbb97dc10686c53bd3bae2c4110d0"),
                Contract = new ExecutionContract
                {
                    TaskRunId = TaskRunId,
                    AttemptId = AttemptId,
                    AgentBuildId = BuildId,
                    ProfileId = ProfileId,
                    ProfileDigest = ProfileDigest,
                    DeadlineUnixMs = 1785258000000,
                    MaxInputLeaseMs = 1000,
                    CleanupPolicy = CleanupPolicy.ReleaseInputAndCloseOwnedTarget,
                    ContractVersion = 2,
                    ContractDigest = ContractDigest,
                    AllowedCapabilities =
                    {
                        ExecutionCapability.TargetStart,
                        ExecutionCapability.TargetClose,
                        ExecutionCapability.Capture,
                        ExecutionCapability.InputKeyboard,
                    },
                },
            },
        };
    }

    private static (byte[] Json, byte[] PublicKey) EnrollmentResponse(
        DateTimeOffset now,
        string responseAgentId,
        string? certificateAgentId = null,
        bool addUnexpectedUriSan = false)
    {
        certificateAgentId ??= responseAgentId;
        using RSA caKey = RSA.Create(2048);
        CertificateRequest caRequest = new("CN=FairyPam Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            true));
        using X509Certificate2 ca = caRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));

        using RSA clientKey = RSA.Create(2048);
        CertificateRequest clientRequest = new(
            $"CN={certificateAgentId}",
            clientKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        clientRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        clientRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        OidCollection usages = new() { new Oid("1.3.6.1.5.5.7.3.2") };
        clientRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
        SubjectAlternativeNameBuilder names = new();
        names.AddUri(new Uri($"spiffe://fairypam/agent/{certificateAgentId}"));
        if (addUnexpectedUriSan)
        {
            names.AddUri(new Uri("spiffe://fairypam/agent/44444444-4444-4444-8444-444444444444"));
        }
        clientRequest.CertificateExtensions.Add(names.Build());
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        using X509Certificate2 client = clientRequest.Create(ca, now.AddMinutes(-1), now.AddHours(1), serial);

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["agent_id"] = responseAgentId,
            ["control_endpoint"] = "https://hub.example.test:50051",
            ["frame_endpoint"] = "https://hub.example.test:50052",
            ["hub_server_name"] = "hub.example.test",
            ["profile_root_public_key_hex"] = new string('1', 64),
            ["ca_pem"] = ca.ExportCertificatePem(),
            ["client_cert_pem"] = client.ExportCertificatePem(),
            ["expires_at"] = new DateTimeOffset(client.NotAfter.ToUniversalTime()),
        });
        return (json, clientKey.ExportSubjectPublicKeyInfo());
    }

    private static void ExpectContractError(Action action)
    {
        try
        {
            action();
            Assert.Fail("Expected AgentContractException.");
        }
        catch (AgentContractException)
        {
        }
    }

    private static HubSessionContract SessionContract() => new(
        AgentId,
        BuildId,
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [ProfileId] = ProfileDigest,
        });

    private static void RecomputeBeginAttemptDigests(HubControlCommand command)
    {
        ExecutionContract contract = command.BeginAttempt.Contract;
        TaskCommandRef reference = command.BeginAttempt.Reference.Task;
        int[] capabilities = contract.AllowedCapabilities.Select(value => (int)value).ToArray();
        Dictionary<string, object?> Contract(bool includeDigest)
        {
            Dictionary<string, object?> value = new()
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
                value["contract_digest"] = contract.ContractDigest;
            }
            return value;
        }

        contract.ContractDigest = Digest(Contract(includeDigest: false));
        reference.Attempt.ContractDigest = contract.ContractDigest;
        reference.PayloadDigest = Digest(new Dictionary<string, object?>
        {
            ["attempt"] = new Dictionary<string, object?>
            {
                ["task_run_id"] = reference.Attempt.TaskRunId,
                ["attempt_id"] = reference.Attempt.AttemptId,
                ["contract_version"] = reference.Attempt.ContractVersion,
                ["contract_digest"] = reference.Attempt.ContractDigest,
            },
            ["kind"] = "fairypam.agent.v2.BeginAttempt",
            ["payload"] = new Dictionary<string, object?>
            {
                ["contract"] = Contract(includeDigest: true),
            },
        });
    }

    private static string Digest(object value) => Convert.ToHexStringLower(
        SHA256.HashData(StrictJson.Canonicalize(value)));
}
