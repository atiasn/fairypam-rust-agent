using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FairyPam.Agent.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FairyPam.Agent.Windows.Tests;

[TestClass]
public sealed class RuntimeRecoveryTests
{
    [TestMethod]
    public void RetiredCleanupStopsBeforeKeyWhenCertificateRemovalFails()
    {
        string root = Path.Combine(
            WindowsProtectedPath.AgentStateRoot,
            $"identity-certificate-test-{Guid.NewGuid():N}");
        WindowsProtectedPath.EnsurePrivateDirectory(root);
        int keyAttempts = 0;
        using HttpClient client = new();
        DeviceIdentityStore store = new(
            client,
            root,
            _ => throw new CryptographicException("injected certificate cleanup failure"),
            _ => keyAttempts++,
            File.Delete);
        string retiredPath = Path.Combine(root, "device-identity.retired.json");
        try
        {
            store.WriteRecord(Path.Combine(root, "device-identity.json"), Record('a'));
            store.WriteRecord(retiredPath, Record('b'));

            Assert.IsFalse(store.TryFinalizeRetired());
            Assert.IsTrue(File.Exists(retiredPath));
            Assert.AreEqual(0, keyAttempts);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public void RetiredCleanupRetriesPartialFailuresWithoutLosingJournal()
    {
        string root = Path.Combine(
            WindowsProtectedPath.AgentStateRoot,
            $"identity-recovery-test-{Guid.NewGuid():N}");
        WindowsProtectedPath.EnsurePrivateDirectory(root);
        List<string> removedCertificates = [];
        List<string> deletedKeys = [];
        int keyAttempts = 0;
        using HttpClient client = new();
        DeviceIdentityStore store = new(
            client,
            root,
            removedCertificates.Add,
            key =>
            {
                keyAttempts++;
                if (keyAttempts == 1)
                {
                    throw new CryptographicException("injected key cleanup failure");
                }
                deletedKeys.Add(key);
            },
            File.Delete);
        DeviceIdentityRecord active = Record('a');
        DeviceIdentityRecord retired = Record('b');
        string activePath = Path.Combine(root, "device-identity.json");
        string retiredPath = Path.Combine(root, "device-identity.retired.json");
        try
        {
            store.WriteRecord(activePath, active);
            store.WriteRecord(retiredPath, retired);

            Assert.IsFalse(store.TryFinalizeRetired());
            Assert.IsTrue(File.Exists(retiredPath));
            CollectionAssert.AreEqual(
                new[] { retired.CertificateStoreThumbprint },
                removedCertificates);
            Assert.AreEqual(1, keyAttempts);

            Assert.IsTrue(store.TryFinalizeRetired());
            Assert.IsFalse(File.Exists(retiredPath));
            CollectionAssert.AreEqual(
                new[] { retired.CertificateStoreThumbprint, retired.CertificateStoreThumbprint },
                removedCertificates);
            CollectionAssert.AreEqual(new[] { retired.KeyName }, deletedKeys);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public void RetiredJournalBeforePromotionDoesNotDeleteActiveIdentity()
    {
        string root = Path.Combine(
            WindowsProtectedPath.AgentStateRoot,
            $"identity-journal-test-{Guid.NewGuid():N}");
        WindowsProtectedPath.EnsurePrivateDirectory(root);
        List<string> cleanup = [];
        using HttpClient client = new();
        DeviceIdentityStore store = new(
            client,
            root,
            thumbprint => cleanup.Add("certificate:" + thumbprint),
            key => cleanup.Add("key:" + key),
            File.Delete);
        DeviceIdentityRecord active = Record('a');
        string retiredPath = Path.Combine(root, "device-identity.retired.json");
        try
        {
            store.WriteRecord(Path.Combine(root, "device-identity.json"), active);
            store.WriteRecord(retiredPath, active);

            Assert.IsTrue(store.TryFinalizeRetired());
            Assert.IsFalse(File.Exists(retiredPath));
            Assert.AreEqual(0, cleanup.Count);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public void RetiredJournalDeletionFailureKeepsRetryableReference()
    {
        string root = Path.Combine(
            WindowsProtectedPath.AgentStateRoot,
            $"identity-journal-delete-test-{Guid.NewGuid():N}");
        WindowsProtectedPath.EnsurePrivateDirectory(root);
        List<string> cleanup = [];
        int deleteAttempts = 0;
        string retiredPath = Path.Combine(root, "device-identity.retired.json");
        using HttpClient client = new();
        DeviceIdentityStore store = new(
            client,
            root,
            thumbprint => cleanup.Add("certificate:" + thumbprint),
            key => cleanup.Add("key:" + key),
            path =>
            {
                if (path == retiredPath && ++deleteAttempts == 1)
                {
                    throw new IOException("injected journal delete failure");
                }
                File.Delete(path);
            });
        try
        {
            store.WriteRecord(Path.Combine(root, "device-identity.json"), Record('a'));
            store.WriteRecord(retiredPath, Record('b'));

            Assert.IsFalse(store.TryFinalizeRetired());
            Assert.IsTrue(File.Exists(retiredPath));
            Assert.AreEqual(2, cleanup.Count);

            Assert.IsTrue(store.TryFinalizeRetired());
            Assert.IsFalse(File.Exists(retiredPath));
            Assert.AreEqual(4, cleanup.Count);
            Assert.AreEqual(2, deleteAttempts);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public async Task HungConnectionRemainsBlockedUntilOriginalSupervisorCompletes()
    {
        using DeviceIdentity identity = Identity();
        TaskCompletionSource first = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource second = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int starts = 0;
        LocalRuntime runtime = new(
            new("已注册", "未连接", "未连接", "输入已禁用", false),
            identity: identity,
            connectionRunner: (_, _, _) => ++starts == 1 ? first.Task : second.Task,
            connectionStopTimeout: TimeSpan.FromMilliseconds(10));

        await runtime.StartAsync();
        InvalidOperationException timeout = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => runtime.RescanAsync(CancellationToken.None));
        Assert.AreEqual("hub.shutdown_failed", timeout.Message);
        Assert.IsTrue(runtime.Status.RecoveryBlocked);

        await runtime.StartAsync();
        Assert.AreEqual(1, starts);

        first.SetResult();
        await runtime.RescanAsync(CancellationToken.None);
        Assert.AreEqual(2, starts);
        Assert.IsFalse(runtime.Status.RecoveryBlocked);

        second.SetResult();
        Assert.IsTrue(await runtime.TryShutdownAsync());
    }

    private static DeviceIdentityRecord Record(char value) => new(
        new string(value, 40),
        Convert.ToBase64String(Encoding.UTF8.GetBytes("enrollment")),
        "FairyPam.Agent." + new string(value, 32),
        SchemaVersion: 1);

    private static DeviceIdentity Identity()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=FairyPam Recovery Test",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 source = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(5));
        X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(
            source.Export(X509ContentType.Cert));
        X509Certificate2 authority = X509CertificateLoader.LoadCertificate(
            source.Export(X509ContentType.Cert));
        EnrollmentCandidate enrollment = new(
            Guid.NewGuid(),
            new Uri("https://localhost:7443"),
            new Uri("https://localhost:7444"),
            "localhost",
            new string('a', 64),
            source.ExportCertificatePem(),
            source.ExportCertificatePem(),
            DateTimeOffset.UtcNow.AddMinutes(5),
            new string('a', 64));
        return new(Record('c'), enrollment, certificate, authority);
    }
}
