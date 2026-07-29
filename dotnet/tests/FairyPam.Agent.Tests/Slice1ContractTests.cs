using System.Text;
using FairyPam.Agent.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FairyPam.Agent.Tests;

[TestClass]
public sealed class Slice1ContractTests
{
    private const string PublicKey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    private const string BootstrapJson = """{"enrollment_base_url":"https://hub.example.test/api/v1/agent-enrollment/","schema_version":1}""";
    private const string BootstrapSignature = "1066cdaeded8979f535c28e090bedd892ab643ccd74e73db5e822ccc0bb1bc97f115c9d8bd8e13340dc89b88fd8d8ea8d59d4f25fc909a239736f23fb4273c0b";
    private const string ProfileEnvelopeJson = """{"content":{"allowed_install_roots":["C:\\Games\\Genshin"],"capabilities":[1,2,3,4],"input_policy":{"keys":[{"extended":false,"scan_code":44},{"extended":true,"scan_code":72}],"maximum_wheel_delta":120,"minimum_wheel_delta":-120,"mouse_buttons":[1,2]},"process_names":["YuanShen.exe"],"profile_id":"genshin-impact","profile_version":"1.0.0","publisher_subject":"miHoYo Co., Ltd.","schema_version":1,"unsigned_executable_sha256":null,"window_rules":{"classes":["UnityWndClass"],"minimum_client_height":720,"minimum_client_width":1280,"minimum_dpi":96,"title_patterns":["Genshin Impact"]}},"content_sha256":"828b18f6ef76da356f26aea6131f06f00c7d21ed63aaddb19ebd99fac9172134","signature":"88a067368e9895dcb12c0b5466e8e6588553b476219126a92dd55b7f172c6ce7b772cd53effee16e67c773e019cb92648de51a9afa637c89b007a219476b0c0c"}""";

    [TestMethod]
    public void BootstrapRequiresCanonicalStrictJsonAndValidDetachedSignature()
    {
        using TemporaryDirectory temporary = new();
        string document = temporary.Write("agent-bootstrap.json", BootstrapJson + "\n");
        string signature = temporary.Write("agent-bootstrap.json.sig", BootstrapSignature + "\n");

        VerifiedBootstrap verified = BootstrapLoader.Load(document, signature, PublicKey);

        Assert.AreEqual("https://hub.example.test/api/v1/agent-enrollment/", verified.EnrollmentBaseUri.AbsoluteUri);

        temporary.Write(
            "agent-bootstrap.json",
            """{"enrollment_base_url":"https://hub.example.test/","schema_version":1,"schema_version":1}""" + "\n");
        ExpectContractError(() => BootstrapLoader.Load(document, signature, PublicKey));
    }

    [TestMethod]
    public void ProfileRequiresCanonicalPolicyDigestAndSignature()
    {
        using TemporaryDirectory temporary = new();
        string path = temporary.Write("profile.json", ProfileEnvelopeJson + "\n");

        VerifiedProfile profile = ProfileLoader.Load(path, PublicKey);

        Assert.AreEqual("genshin-impact", profile.Content.ProfileId);
        Assert.AreEqual("828b18f6ef76da356f26aea6131f06f00c7d21ed63aaddb19ebd99fac9172134", profile.ContentSha256);

        temporary.Write("profile.json", ProfileEnvelopeJson.Replace("[1,2]", "[2,1]", StringComparison.Ordinal) + "\n");
        ExpectContractError(() => ProfileLoader.Load(path, PublicKey));
    }

    [TestMethod]
    public void LedgerFlushesAppendOnlyRecordsAndBlocksUnsafeRecovery()
    {
        using TemporaryDirectory temporary = new();
        AttemptLedger ledger = new(temporary.Path);
        AttemptLedgerRecord safe = Record(
            "22222222-2222-4222-8222-222222222222",
            AttemptLedgerState.Terminal,
            LedgerSideEffectState.NotApplied,
            LedgerResourceState.Released,
            LedgerResourceState.Stopped,
            LedgerResourceState.Closed,
            LedgerCommandOutcome.NotApplied,
            cleanupComplete: true);
        ledger.Append(safe);
        Assert.IsFalse(ledger.Recover().IsBlocked);
        ExpectContractError(() => ledger.Append(safe with
        {
            RecordSequence = 2,
            TaskRunId = "44444444-4444-4444-8444-444444444444",
        }));
        ExpectContractError(() => ledger.Append(safe with
        {
            ContractVersion = 1,
            RecordSequence = 2,
        }));
        ExpectContractError(() => ledger.Append(safe with
        {
            Outcome = LedgerCommandOutcome.Unspecified,
            RecordSequence = 2,
        }));

        ledger.Append(Record(
            "33333333-3333-4333-8333-333333333333",
            AttemptLedgerState.Active,
            LedgerSideEffectState.IntentRecorded,
            LedgerResourceState.Active,
            LedgerResourceState.NotStarted,
            LedgerResourceState.NotStarted,
            LedgerCommandOutcome.Uncertain,
            cleanupComplete: null));
        LedgerRecovery recovery = ledger.Recover();
        Assert.IsTrue(recovery.IsBlocked);
        CollectionAssert.Contains(recovery.UnsafeAttemptIds.ToArray(), "33333333-3333-4333-8333-333333333333");
    }

    [TestMethod]
    public void LedgerRejectsTruncatedRecords()
    {
        using TemporaryDirectory temporary = new();
        File.WriteAllText(
            System.IO.Path.Combine(temporary.Path, "22222222-2222-4222-8222-222222222222.jsonl"),
            "{}");

        ExpectContractError(() => new AttemptLedger(temporary.Path).Recover());
    }

    [TestMethod]
    public void GuardianFramesAreBoundedTypedAndCanonical()
    {
        using MemoryStream stream = new();
        GuardianWire.Write(
            stream,
            GuardianMessageType.Hello,
            new GuardianHello(AgentPid: 42, HeartbeatTimeoutMs: 1000, SchemaVersion: 1));
        stream.Position = 0;

        GuardianFrame frame = GuardianWire.Read(stream)!;
        GuardianHello hello = GuardianWire.Decode<GuardianHello>(frame);

        Assert.AreEqual(GuardianMessageType.Hello, frame.Type);
        Assert.AreEqual(42, hello.AgentPid);

        byte[] invalid = stream.ToArray();
        invalid[0] = 0;
        ExpectContractError(() => GuardianWire.Read(new MemoryStream(invalid)));
        ExpectContractError(() => GuardianWire.Read(new MemoryStream(invalid.AsSpan(0, 5).ToArray())));
    }

    private static AttemptLedgerRecord Record(
        string attemptId,
        AttemptLedgerState attemptState,
        LedgerSideEffectState sideEffectState,
        LedgerResourceState inputState,
        LedgerResourceState captureState,
        LedgerResourceState ownedTargetState,
        LedgerCommandOutcome outcome,
        bool? cleanupComplete) => new(
            AttemptId: attemptId,
            AttemptState: attemptState,
            CaptureState: captureState,
            CleanupComplete: cleanupComplete,
            CommandId: "command-1",
            CommandSequence: 1,
            ContractDigest: new string('a', 64),
            ContractVersion: 2,
            ErrorCode: null,
            Generation: 1,
            InputState: inputState,
            ObservedAtUnixMs: 1,
            OwnedTargetState: ownedTargetState,
            Outcome: outcome,
            PayloadDigest: new string('b', 64),
            RecordSequence: 1,
            SchemaVersion: 1,
            SideEffectState: sideEffectState,
            TaskRunId: "11111111-1111-4111-8111-111111111111");

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

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"fairypam-dotnet-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public string Write(string name, string content)
        {
            string path = System.IO.Path.Combine(Path, name);
            File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            return path;
        }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
