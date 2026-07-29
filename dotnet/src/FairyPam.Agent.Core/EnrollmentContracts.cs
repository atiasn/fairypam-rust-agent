using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FairyPam.Agent.Core;

public sealed record EnrollmentCandidate(
    Guid AgentId,
    Uri ControlEndpoint,
    Uri FrameEndpoint,
    string HubServerName,
    string ProfileRootPublicKeyHex,
    string CaPem,
    string ClientCertificatePem,
    DateTimeOffset ExpiresAt,
    string CertificateFingerprint);

public static class EnrollmentContract
{
    private const int MaximumResponseBytes = 64 * 1024;
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    public static EnrollmentCandidate ParseResponse(
        ReadOnlySpan<byte> utf8Json,
        DateTimeOffset now,
        ReadOnlySpan<byte> expectedSubjectPublicKeyInfo)
    {
        if (utf8Json.IsEmpty
            || utf8Json.Length > MaximumResponseBytes
            || expectedSubjectPublicKeyInfo.IsEmpty)
        {
            throw Invalid();
        }

        EnrollmentResponseDocument document;
        try
        {
            document = JsonSerializer.Deserialize<EnrollmentResponseDocument>(utf8Json, StrictJson.Options)
                ?? throw Invalid();
        }
        catch (JsonException error)
        {
            throw new AgentContractException("enrollment.response_invalid", error.Message);
        }

        if (!Guid.TryParseExact(document.AgentId, "D", out Guid agentId)
            || agentId.ToString("D") != document.AgentId
            || !TryHttpsEndpoint(document.ControlEndpoint, out Uri? controlEndpoint)
            || !TryHttpsEndpoint(document.FrameEndpoint, out Uri? frameEndpoint)
            || Uri.CheckHostName(document.HubServerName) == UriHostNameType.Unknown
            || !IsLowerHex(document.ProfileRootPublicKeyHex)
            || document.ProfileRootPublicKeyHex.All(character => character == '0')
            || document.ExpiresAt <= now)
        {
            throw Invalid();
        }

        try
        {
            using X509Certificate2 ca = X509Certificate2.CreateFromPem(document.CaPem);
            using X509Certificate2 client = X509Certificate2.CreateFromPem(document.ClientCertificatePem);
            if (ca.ExportCertificatePem() != document.CaPem
                || client.ExportCertificatePem() != document.ClientCertificatePem
                || !IsCertificateAuthority(ca)
                || IsCertificateAuthority(client)
                || !HasClientAuthentication(client)
                || !HasSupportedClientKey(client)
                || !CryptographicOperations.FixedTimeEquals(
                    client.PublicKey.ExportSubjectPublicKeyInfo(),
                    expectedSubjectPublicKeyInfo)
                || !client.SubjectName.RawData.AsSpan().SequenceEqual(
                    new X500DistinguishedName($"CN={document.AgentId}").RawData)
                || !HasUriSubjectAlternativeName(client, $"spiffe://fairypam/agent/{document.AgentId}")
                || document.ExpiresAt != new DateTimeOffset(client.NotAfter.ToUniversalTime())
                || now < new DateTimeOffset(client.NotBefore.ToUniversalTime())
                || !BuildChain(client, ca, now))
            {
                throw Invalid();
            }

            return new(
                agentId,
                controlEndpoint!,
                frameEndpoint!,
                document.HubServerName,
                document.ProfileRootPublicKeyHex,
                document.CaPem,
                document.ClientCertificatePem,
                document.ExpiresAt,
                Convert.ToHexString(client.GetCertHash(HashAlgorithmName.SHA256)).ToLowerInvariant());
        }
        catch (CryptographicException error)
        {
            throw new AgentContractException("enrollment.response_invalid", error.Message);
        }
        catch (InvalidOperationException error)
        {
            throw new AgentContractException("enrollment.response_invalid", error.Message);
        }
    }

    private static bool TryHttpsEndpoint(string value, out Uri? endpoint)
    {
        bool valid = Uri.TryCreate(value, UriKind.Absolute, out endpoint)
            && endpoint.Scheme == Uri.UriSchemeHttps
            && !string.IsNullOrEmpty(endpoint.Host)
            && string.IsNullOrEmpty(endpoint.UserInfo)
            && string.IsNullOrEmpty(endpoint.Query)
            && string.IsNullOrEmpty(endpoint.Fragment);
        if (!valid)
        {
            endpoint = null;
        }
        return valid;
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault()
            ?.CertificateAuthority == true;

    private static bool HasClientAuthentication(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault()
            ?.EnhancedKeyUsages
            .Cast<Oid>()
            .Select(oid => oid.Value)
            .SequenceEqual([ClientAuthenticationOid]) == true;

    private static bool HasSupportedClientKey(X509Certificate2 certificate)
    {
        using RSA? key = certificate.GetRSAPublicKey();
        if (key is null || key.KeySize < 2048)
        {
            return false;
        }
        RSAParameters parameters = key.ExportParameters(includePrivateParameters: false);
        return parameters.Exponent is [0x01, 0x00, 0x01];
    }

    private static bool HasUriSubjectAlternativeName(X509Certificate2 certificate, string expected)
    {
        X509Extension? extension = certificate.Extensions
            .Cast<X509Extension>()
            .SingleOrDefault(item => item.Oid?.Value == SubjectAlternativeNameOid);
        if (extension is null)
        {
            return false;
        }

        try
        {
            AsnReader reader = new(extension.RawData, AsnEncodingRules.DER);
            AsnReader names = reader.ReadSequence();
            Asn1Tag uriTag = new(TagClass.ContextSpecific, 6);
            int uriCount = 0;
            bool matches = true;
            while (names.HasData)
            {
                if (names.PeekTag().HasSameClassAndValue(uriTag))
                {
                    uriCount++;
                    matches &= names.ReadCharacterString(UniversalTagNumber.IA5String, uriTag) == expected;
                }
                else
                {
                    names.ReadEncodedValue();
                }
            }
            reader.ThrowIfNotEmpty();
            return uriCount == 1 && matches;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool BuildChain(X509Certificate2 client, X509Certificate2 ca, DateTimeOffset now)
    {
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationTime = now.UtcDateTime;
        return chain.Build(client);
    }

    private static bool IsLowerHex(string value) =>
        value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static AgentContractException Invalid() =>
        new("enrollment.response_invalid", "Enrollment response is invalid.");

    private sealed record EnrollmentResponseDocument(
        [property: JsonPropertyName("agent_id")] string AgentId,
        [property: JsonPropertyName("control_endpoint")] string ControlEndpoint,
        [property: JsonPropertyName("frame_endpoint")] string FrameEndpoint,
        [property: JsonPropertyName("hub_server_name")] string HubServerName,
        [property: JsonPropertyName("profile_root_public_key_hex")] string ProfileRootPublicKeyHex,
        [property: JsonPropertyName("ca_pem")] string CaPem,
        [property: JsonPropertyName("client_cert_pem")] string ClientCertificatePem,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);
}
