using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FairyPam.Agent.Core;

namespace FairyPam.Agent;

internal sealed class DeviceIdentity(
    DeviceIdentityRecord record,
    EnrollmentCandidate enrollment,
    X509Certificate2 certificate,
    X509Certificate2 certificateAuthority) : IDisposable
{
    public DeviceIdentityRecord Record { get; } = record;
    public EnrollmentCandidate Enrollment { get; } = enrollment;
    public X509Certificate2 Certificate { get; } = certificate;
    public X509Certificate2 CertificateAuthority { get; } = certificateAuthority;

    public void Dispose()
    {
        Certificate.Dispose();
        CertificateAuthority.Dispose();
    }
}

internal sealed record DeviceIdentityRecord(
    [property: JsonPropertyName("certificate_store_thumbprint")] string CertificateStoreThumbprint,
    [property: JsonPropertyName("enrollment_response_base64")] string EnrollmentResponseBase64,
    [property: JsonPropertyName("key_name")] string KeyName,
    [property: JsonPropertyName("schema_version")] int SchemaVersion);

internal sealed class DeviceIdentityStore
{
    internal const CngPropertyOptions DaclSecurityInformation = (CngPropertyOptions)4;
    private const int MaximumIdentityBytes = 128 * 1024;
    private const string KeyPrefix = "FairyPam.Agent.";
    private const string SecurityDescriptorProperty = "Security Descr";
    private static readonly byte[] ClaimCodePrefix = Encoding.UTF8.GetBytes("{\"code\":\"");
    private static readonly byte[] ClaimCsrPrefix = Encoding.UTF8.GetBytes("\",\"csr_pem\":");
    private static readonly CngProvider Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
    private readonly Action<string> deleteFile;
    private readonly Action<string> deleteKey;
    private readonly HttpClient enrollmentClient;
    private readonly Action<string> removeCertificate;
    private readonly string root;

    public DeviceIdentityStore(HttpClient enrollmentClient)
        : this(
            enrollmentClient,
            Path.Combine(WindowsProtectedPath.AgentStateRoot, "identity"),
            RemoveCertificate,
            DeleteKey,
            File.Delete)
    {
    }

    internal DeviceIdentityStore(
        HttpClient enrollmentClient,
        string root,
        Action<string> removeCertificate,
        Action<string> deleteKey,
        Action<string> deleteFile)
    {
        this.enrollmentClient = enrollmentClient;
        this.root = root;
        this.removeCertificate = removeCertificate;
        this.deleteKey = deleteKey;
        this.deleteFile = deleteFile;
    }

    private string ActivePath => Path.Combine(root, "device-identity.json");
    private string PendingPath => Path.Combine(root, "device-identity.pending.json");
    private string RetiredPath => Path.Combine(root, "device-identity.retired.json");

    public DeviceIdentity? Load()
    {
        WindowsProtectedPath.EnsurePrivateDirectory(root);
        if (!TryFinalizeRetired())
        {
            throw new InvalidOperationException("identity.retired_cleanup_failed");
        }
        DeviceIdentity? pending = TryLoad(PendingPath);
        if (pending is not null)
        {
            DeviceIdentityRecord? previous = TryReadRecord(ActivePath);
            if (previous is not null)
            {
                WriteRecord(RetiredPath, previous);
            }
            File.Move(PendingPath, ActivePath, overwrite: true);
            if (!TryFinalizeRetired())
            {
                pending.Dispose();
                throw new InvalidOperationException("identity.retired_cleanup_failed");
            }
            return pending;
        }
        CleanupInvalidPending();
        return TryLoad(ActivePath);
    }

    public async Task<(DeviceIdentity Identity, bool CleanupComplete)> EnrollAsync(
        VerifiedBootstrap bootstrap,
        char[] enrollmentCode,
        CancellationToken cancellationToken)
    {
        ValidateCode(enrollmentCode);
        WindowsProtectedPath.EnsurePrivateDirectory(root);
        if (!TryFinalizeRetired())
        {
            throw new InvalidOperationException("identity.retired_cleanup_failed");
        }
        DeviceIdentityRecord? previous = TryReadRecord(ActivePath);
        string keyName = KeyPrefix + Guid.NewGuid().ToString("N");
        DeviceIdentityRecord? candidateRecord = null;
        DeviceIdentity? verified = null;
        bool installed = false;
        bool promoted = false;
        try
        {
            using CngKey key = CreateKey(keyName);
            using RSACng rsa = new(key);
            string csrPem = CreateCsrPem(rsa);
            byte[] response = await ClaimAsync(
                bootstrap.EnrollmentBaseUri,
                enrollmentCode,
                csrPem,
                cancellationToken);
            EnrollmentCandidate candidate = EnrollmentContract.ParseResponse(
                response,
                DateTimeOffset.UtcNow,
                rsa.ExportSubjectPublicKeyInfo());
            using X509Certificate2 publicCertificate = X509Certificate2.CreateFromPem(
                candidate.ClientCertificatePem);
            candidateRecord = new(
                publicCertificate.Thumbprint.ToLowerInvariant(),
                Convert.ToBase64String(response),
                keyName,
                SchemaVersion: 1);
            WriteRecord(PendingPath, candidateRecord);
            InstallCertificate(candidate.ClientCertificatePem, rsa);
            installed = true;

            verified = LoadRecord(PendingPath, candidateRecord);
            if (previous is not null)
            {
                WriteRecord(RetiredPath, previous);
            }
            File.Move(PendingPath, ActivePath, overwrite: true);
            promoted = true;
            return (verified, TryFinalizeRetired());
        }
        catch
        {
            if (!promoted && installed && candidateRecord is not null)
            {
                removeCertificate(candidateRecord.CertificateStoreThumbprint);
            }
            if (!promoted)
            {
                verified?.Dispose();
                deleteKey(keyName);
                deleteFile(PendingPath);
                _ = TryFinalizeRetired();
            }
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(enrollmentCode.AsSpan()));
        }
    }

    public void Delete(DeviceIdentityRecord record)
    {
        Cleanup(record);
        deleteFile(ActivePath);
    }

    private DeviceIdentity? TryLoad(string path)
    {
        try
        {
            DeviceIdentityRecord? record = TryReadRecord(path);
            if (record is null)
            {
                return null;
            }
            return LoadRecord(path, record);
        }
        catch (Exception error) when (error is CryptographicException
            or IOException
            or InvalidOperationException
            or AgentContractException
            or FormatException)
        {
            return null;
        }
    }

    private static DeviceIdentity LoadRecord(string path, DeviceIdentityRecord record)
    {
        ValidateRecord(record);
        WindowsProtectedPath.VerifyProtectedFile(path, Path.GetDirectoryName(path)!);
        byte[] response = Convert.FromBase64String(record.EnrollmentResponseBase64);
        if (response.Length == 0 || response.Length > 64 * 1024)
        {
            throw new InvalidOperationException("identity.response_invalid");
        }

        using CngKey key = CngKey.Open(record.KeyName, Provider, CngKeyOpenOptions.MachineKey);
        using RSACng rsa = new(key);
        EnrollmentCandidate enrollment = EnrollmentContract.ParseResponse(
            response,
            DateTimeOffset.UtcNow,
            rsa.ExportSubjectPublicKeyInfo());
        X509Certificate2 certificate = OpenCertificate(record.CertificateStoreThumbprint);
        X509Certificate2 certificateAuthority = X509Certificate2.CreateFromPem(enrollment.CaPem);
        try
        {
            using X509Certificate2 expected = X509Certificate2.CreateFromPem(
                enrollment.ClientCertificatePem);
            if (!certificate.RawData.AsSpan().SequenceEqual(expected.RawData)
                || !certificate.HasPrivateKey
                || !CanSign(certificate))
            {
                throw new InvalidOperationException("identity.certificate_invalid");
            }
            return new(record, enrollment, certificate, certificateAuthority);
        }
        catch
        {
            certificate.Dispose();
            certificateAuthority.Dispose();
            throw;
        }
    }

    private DeviceIdentityRecord? TryReadRecord(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        return StrictJson.ReadCanonical<DeviceIdentityRecord>(path, MaximumIdentityBytes);
    }

    internal void WriteRecord(string path, DeviceIdentityRecord record)
    {
        ValidateRecord(record);
        byte[] json = StrictJson.Canonicalize(record);
        if (json.Length + 1 > MaximumIdentityBytes)
        {
            throw new InvalidOperationException("identity.record_too_large");
        }
        string temporary = path + ".tmp";
        using (FileStream stream = new(
                   temporary,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None,
                   4096,
                   FileOptions.WriteThrough))
        {
            stream.Write(json);
            stream.WriteByte((byte)'\n');
            stream.Flush(flushToDisk: true);
        }
        WindowsProtectedPath.VerifyProtectedFile(temporary, root);
        File.Move(temporary, path, overwrite: true);
        WindowsProtectedPath.VerifyProtectedFile(path, root);
    }

    internal static CngKey CreateKey(string keyName)
    {
        SecurityIdentifier user = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("identity.user_sid_missing");
        RawSecurityDescriptor descriptor = new(
            $"O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{user.Value})");
        byte[] binaryDescriptor = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(binaryDescriptor, 0);
        CngKeyCreationParameters parameters = new()
        {
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            KeyUsage = CngKeyUsages.Signing,
            Provider = Provider,
        };
        parameters.Parameters.Add(new CngProperty(
            "Length",
            BitConverter.GetBytes(2048),
            CngPropertyOptions.None));
        parameters.Parameters.Add(new CngProperty(
            SecurityDescriptorProperty,
            binaryDescriptor,
            CngPropertyOptions.Persist | DaclSecurityInformation));
        CngKey key = CngKey.Create(CngAlgorithm.Rsa, keyName, parameters);
        if (key.ExportPolicy != CngExportPolicies.None || key.KeySize < 2048)
        {
            key.Delete();
            key.Dispose();
            throw new InvalidOperationException("identity.key_policy_invalid");
        }
        return key;
    }

    internal static string CreateCsrPem(RSA rsa)
    {
        CertificateRequest request = new(
            "CN=FairyPam Agent Enrollment",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        string pem = PemEncoding.WriteString("CERTIFICATE REQUEST", request.CreateSigningRequest());
        return pem.EndsWith('\n') ? pem : pem + '\n';
    }

    private async Task<byte[]> ClaimAsync(
        Uri baseUri,
        char[] code,
        string csrPem,
        CancellationToken cancellationToken)
    {
        byte[] encodedCsr = JsonSerializer.SerializeToUtf8Bytes(csrPem);
        int codeLength = Encoding.UTF8.GetByteCount(code);
        int requestLength = checked(
            ClaimCodePrefix.Length + codeLength + ClaimCsrPrefix.Length + encodedCsr.Length + 1);
        byte[] requestBuffer = new byte[requestLength];
        try
        {
            int offset = 0;
            ClaimCodePrefix.CopyTo(requestBuffer, offset);
            offset += ClaimCodePrefix.Length;
            offset += Encoding.UTF8.GetBytes(code, requestBuffer.AsSpan(offset, codeLength));
            ClaimCsrPrefix.CopyTo(requestBuffer, offset);
            offset += ClaimCsrPrefix.Length;
            encodedCsr.CopyTo(requestBuffer, offset);
            requestBuffer[^1] = (byte)'}';
            using ByteArrayContent content = new(requestBuffer, 0, requestLength);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using HttpRequestMessage request = new(
                HttpMethod.Post,
                new Uri(baseUri, "/api/v1/agent-enrollment/claim"))
            {
                Content = content,
            };
            using HttpResponseMessage response = await enrollmentClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException("enrollment.claim_failed");
            }
            await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using MemoryStream bounded = new(capacity: 64 * 1024);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken)) != 0)
            {
                if (bounded.Length + read > 64 * 1024)
                {
                    throw new InvalidOperationException("enrollment.response_too_large");
                }
                bounded.Write(buffer, 0, read);
            }
            return bounded.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBuffer);
            CryptographicOperations.ZeroMemory(encodedCsr);
        }
    }

    internal static void InstallCertificate(string certificatePem, RSA rsa)
    {
        using X509Certificate2 publicCertificate = X509Certificate2.CreateFromPem(certificatePem);
        using X509Certificate2 certificate = publicCertificate.CopyWithPrivateKey(rsa);
        using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
    }

    internal static X509Certificate2 OpenCertificate(string thumbprint)
    {
        using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint,
            validOnly: false);
        if (matches.Count != 1)
        {
            foreach (X509Certificate2 match in matches)
            {
                match.Dispose();
            }
            throw new InvalidOperationException("identity.certificate_missing");
        }
        X509Certificate2 certificate = new(matches[0]);
        matches[0].Dispose();
        return certificate;
    }

    internal static bool CanSign(X509Certificate2 certificate)
    {
        using RSA? privateKey = certificate.GetRSAPrivateKey();
        using RSA? publicKey = certificate.GetRSAPublicKey();
        if (privateKey is null || publicKey is null)
        {
            return false;
        }
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] signature = privateKey.SignData(
            challenge,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return publicKey.VerifyData(
            challenge,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
    }

    private void CleanupInvalidPending()
    {
        DeviceIdentityRecord? pending;
        try
        {
            pending = TryReadRecord(PendingPath);
        }
        catch (Exception error) when (error is IOException
            or AgentContractException
            or JsonException)
        {
            pending = null;
        }
        Cleanup(pending);
        deleteFile(PendingPath);
    }

    internal bool TryFinalizeRetired()
    {
        try
        {
            DeviceIdentityRecord? retired = TryReadRecord(RetiredPath);
            if (retired is null)
            {
                return true;
            }
            DeviceIdentityRecord? active = TryReadRecord(ActivePath);
            if (active is null)
            {
                return false;
            }
            ValidateRecord(retired);
            ValidateRecord(active);
            if (active.KeyName == retired.KeyName
                && active.CertificateStoreThumbprint == retired.CertificateStoreThumbprint)
            {
                deleteFile(RetiredPath);
                return true;
            }
            Cleanup(retired);
            deleteFile(RetiredPath);
            return true;
        }
        catch (Exception error) when (error is CryptographicException
            or IOException
            or UnauthorizedAccessException
            or InvalidOperationException
            or AgentContractException
            or JsonException)
        {
            return false;
        }
    }

    private void Cleanup(DeviceIdentityRecord? record)
    {
        if (record is null)
        {
            return;
        }
        removeCertificate(record.CertificateStoreThumbprint);
        deleteKey(record.KeyName);
    }

    internal static void RemoveCertificate(string thumbprint)
    {
        using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        X509Certificate2Collection matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint,
            validOnly: false);
        foreach (X509Certificate2 certificate in matches)
        {
            store.Remove(certificate);
            certificate.Dispose();
        }
    }

    internal static void DeleteKey(string keyName)
    {
        if (!keyName.StartsWith(KeyPrefix, StringComparison.Ordinal)
            || !CngKey.Exists(keyName, Provider, CngKeyOpenOptions.MachineKey))
        {
            return;
        }
        using CngKey key = CngKey.Open(keyName, Provider, CngKeyOpenOptions.MachineKey);
        key.Delete();
    }

    private static void ValidateCode(char[] code)
    {
        if (code.Length is < 16 or > 256
            || code.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '_' and not '-'))
        {
            throw new InvalidOperationException("enrollment.code_invalid");
        }
    }

    private static void ValidateRecord(DeviceIdentityRecord record)
    {
        if (record.SchemaVersion != 1
            || !record.KeyName.StartsWith(KeyPrefix, StringComparison.Ordinal)
            || record.KeyName.Length != KeyPrefix.Length + 32
            || record.CertificateStoreThumbprint.Length != 40
            || record.CertificateStoreThumbprint.Any(character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
            || string.IsNullOrWhiteSpace(record.EnrollmentResponseBase64))
        {
            throw new InvalidOperationException("identity.record_invalid");
        }
    }
}
