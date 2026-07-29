using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using FairyPam.Agent;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FairyPam.Agent.Windows.Tests;

[TestClass]
public sealed class WindowsSecurityTests
{
    [TestMethod]
    public async Task PreCanceledRegistrationClearsEnrollmentCode()
    {
        LocalRuntime runtime = new(new("未注册", "未连接", "未连接", "输入已禁用", false));
        char[] code = "one-time-code".ToCharArray();
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            runtime.RegisterAsync(code, cancellation.Token));

        Assert.IsTrue(code.All(character => character == '\0'));
    }

    [TestMethod]
    public void MachineLockRejectsSecondProcessSlot()
    {
        Assert.IsTrue(SingleInstance.TryAcquire(out SingleInstance? first));
        using (first)
        {
            Assert.IsFalse(SingleInstance.TryAcquire(out _));
        }
        Assert.IsTrue(SingleInstance.TryAcquire(out SingleInstance? reacquired));
        reacquired!.Dispose();
    }

    [TestMethod]
    public void ProtectedFilesRejectUntrustedWriterParentOwnerAndReparsePoint()
    {
        string root = Path.Combine(WindowsProtectedPath.AgentStateRoot, $"security-test-{Guid.NewGuid():N}");
        WindowsProtectedPath.EnsurePrivateDirectory(root);
        try
        {
            string file = Path.Combine(root, "bootstrap.json");
            File.WriteAllText(file, "{}\n");
            ProtectFile(file);
            SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);
            FileSecurity readable = new FileInfo(file).GetAccessControl();
            readable.AddAccessRule(new FileSystemAccessRule(
                users,
                FileSystemRights.ReadAndExecute,
                AccessControlType.Allow));
            new FileInfo(file).SetAccessControl(readable);
            WindowsProtectedPath.VerifyProtectedFile(file, root);

            FileSecurity writable = new FileInfo(file).GetAccessControl();
            writable.AddAccessRule(new FileSystemAccessRule(
                users,
                FileSystemRights.Write,
                AccessControlType.Allow));
            new FileInfo(file).SetAccessControl(writable);
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                WindowsProtectedPath.VerifyProtectedFile(file, root));

            ProtectFile(file);
            DirectorySecurity parent = new DirectoryInfo(root).GetAccessControl();
            parent.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.Write,
                AccessControlType.Allow));
            new DirectoryInfo(root).SetAccessControl(parent);
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                WindowsProtectedPath.VerifyProtectedFile(file, root));

            ProtectDirectory(root);
            ProtectFile(file);
            FileSecurity untrustedOwner = new FileInfo(file).GetAccessControl();
            untrustedOwner.SetOwner(WindowsIdentity.GetCurrent().User!);
            new FileInfo(file).SetAccessControl(untrustedOwner);
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                WindowsProtectedPath.VerifyProtectedFile(file, root));

            string target = Path.Combine(root, "target.json");
            File.WriteAllText(target, "{}\n");
            string link = Path.Combine(root, "link.json");
            File.CreateSymbolicLink(link, target);
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                WindowsProtectedPath.VerifyProtectedFile(link, root));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public void MachineCngKeyIsNonExportableAndInstalledCertificateCanSign()
    {
        string keyName = $"FairyPam.Agent.{Guid.NewGuid():N}";
        string? thumbprint = null;
        try
        {
            using (CngKey created = DeviceIdentityStore.CreateKey(keyName))
            {
                Assert.AreEqual(CngExportPolicies.None, created.ExportPolicy);
            }
            using CngKey key = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.MachineKey);
            Assert.AreEqual(CngExportPolicies.None, key.ExportPolicy);
            using RSACng rsa = new(key);
            Assert.ThrowsExactly<CryptographicException>(() => rsa.ExportPkcs8PrivateKey());

            byte[] securityDescriptor = key
                .GetProperty("Security Descr", DeviceIdentityStore.DaclSecurityInformation)
                .GetValue()
                ?? throw new AssertFailedException("CNG security descriptor is missing.");
            RawSecurityDescriptor descriptor = new(securityDescriptor, 0);
            SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User!;
            SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);
            SecurityIdentifier[] allowed = descriptor.DiscretionaryAcl!
                .OfType<CommonAce>()
                .Where(ace => ace.AceQualifier == AceQualifier.AccessAllowed)
                .Select(ace => ace.SecurityIdentifier)
                .ToArray();
            CollectionAssert.AreEquivalent(
                new[] { system.Value, currentUser.Value },
                allowed.Select(sid => sid.Value).ToArray());
            Assert.IsFalse(allowed.Contains(users));

            CertificateRequest request = new(
                "CN=FairyPam CNG Test",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            using X509Certificate2 issued = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddMinutes(5));
            using X509Certificate2 publicCertificate = X509CertificateLoader.LoadCertificate(
                issued.Export(X509ContentType.Cert));
            thumbprint = publicCertificate.Thumbprint.ToLowerInvariant();
            DeviceIdentityStore.InstallCertificate(publicCertificate.ExportCertificatePem(), rsa);
            using X509Certificate2 installed = DeviceIdentityStore.OpenCertificate(thumbprint);
            Assert.IsTrue(installed.HasPrivateKey);
            Assert.IsTrue(DeviceIdentityStore.CanSign(installed));
        }
        finally
        {
            if (thumbprint is not null)
            {
                DeviceIdentityStore.RemoveCertificate(thumbprint);
            }
            DeviceIdentityStore.DeleteKey(keyName);
        }
    }

    private static void ProtectFile(string path)
    {
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        FileSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            administrators,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static void ProtectDirectory(string path)
    {
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        DirectorySecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            administrators,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }
}
