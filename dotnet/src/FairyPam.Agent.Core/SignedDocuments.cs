using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace FairyPam.Agent.Core;

public sealed class AgentContractException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class StrictJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        AllowDuplicateProperties = false,
        AllowTrailingCommas = false,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static T ReadCanonical<T>(string path, int maximumBytes)
    {
        byte[] raw = File.ReadAllBytes(path);
        if (raw.Length is 0 || raw.Length > maximumBytes || raw[^1] != (byte)'\n')
        {
            throw Invalid("signed_document.size_or_terminator_invalid");
        }

        ReadOnlySpan<byte> json = raw.AsSpan(0, raw.Length - 1);
        if (json.Contains((byte)'\n') || json.Contains((byte)'\r'))
        {
            throw Invalid("signed_document.not_single_line");
        }

        T value;
        try
        {
            value = JsonSerializer.Deserialize<T>(json, Options)
                ?? throw Invalid("signed_document.empty");
        }
        catch (JsonException error)
        {
            throw new AgentContractException("signed_document.schema_invalid", error.Message);
        }

        if (!json.SequenceEqual(Canonicalize(value)))
        {
            throw Invalid("signed_document.not_canonical");
        }
        return value;
    }

    public static byte[] Canonicalize<T>(T value)
    {
        JsonElement element = JsonSerializer.SerializeToElement(value, Options);
        ArrayBufferWriter<byte> buffer = new();
        using Utf8JsonWriter writer = new(buffer, new JsonWriterOptions { Indented = false });
        WriteCanonical(element, writer);
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteCanonical(JsonElement element, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (JsonProperty property in element.EnumerateObject().OrderBy(
                             property => property.Name,
                             StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(property.Value, writer);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (JsonElement item in element.EnumerateArray())
                {
                    WriteCanonical(item, writer);
                }
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static AgentContractException Invalid(string code) =>
        new(code, "Signed JSON document is invalid.");
}

public static class SignedDocumentVerifier
{
    public static string DigestHex<T>(T content) =>
        Convert.ToHexStringLower(SHA256.HashData(StrictJson.Canonicalize(content)));

    public static void Verify<T>(T content, string signatureHex, string publicKeyHex)
    {
        byte[] signature = DecodeLowerHex(signatureHex, 64, "signature.invalid");
        byte[] publicKey = DecodeLowerHex(publicKeyHex, 32, "public_key.invalid");
        byte[] digest = SHA256.HashData(StrictJson.Canonicalize(content));
        Ed25519Signer verifier = new();
        verifier.Init(false, new Ed25519PublicKeyParameters(publicKey));
        verifier.BlockUpdate(digest, 0, digest.Length);
        if (!verifier.VerifySignature(signature))
        {
            throw new AgentContractException("signature.invalid", "Document signature is invalid.");
        }
    }

    public static string ReadDetachedSignature(string path)
    {
        byte[] raw = File.ReadAllBytes(path);
        if (raw.Length != 129 || raw[^1] != (byte)'\n')
        {
            throw new AgentContractException("signature.invalid", "Detached signature is invalid.");
        }
        return Encoding.ASCII.GetString(raw, 0, 128);
    }

    private static byte[] DecodeLowerHex(string value, int byteCount, string code)
    {
        if (value.Length != byteCount * 2 || value.Any(character =>
                !char.IsAsciiDigit(character) && character is not (>= 'a' and <= 'f')))
        {
            throw new AgentContractException(code, "Hex value is invalid.");
        }
        return Convert.FromHexString(value);
    }
}

public sealed record BootstrapDocument(
    [property: JsonPropertyName("enrollment_base_url")] string EnrollmentBaseUrl,
    [property: JsonPropertyName("schema_version")] int SchemaVersion);

public sealed record VerifiedBootstrap(Uri EnrollmentBaseUri);

public static class BootstrapLoader
{
    public const int MaximumDocumentBytes = 16 * 1024;

    public static VerifiedBootstrap Load(string documentPath, string signaturePath, string publicKeyHex)
    {
        BootstrapDocument document = StrictJson.ReadCanonical<BootstrapDocument>(
            documentPath,
            MaximumDocumentBytes);
        SignedDocumentVerifier.Verify(
            document,
            SignedDocumentVerifier.ReadDetachedSignature(signaturePath),
            publicKeyHex);

        if (document.SchemaVersion != 1
            || !Uri.TryCreate(document.EnrollmentBaseUrl, UriKind.Absolute, out Uri? uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new AgentContractException("bootstrap.invalid", "Bootstrap endpoint is invalid.");
        }
        return new VerifiedBootstrap(uri);
    }
}

public sealed record ProfileEnvelope(
    [property: JsonPropertyName("content")] ProfileContent Content,
    [property: JsonPropertyName("content_sha256")] string ContentSha256,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record ProfileContent(
    [property: JsonPropertyName("allowed_install_roots")] string[] AllowedInstallRoots,
    [property: JsonPropertyName("capabilities")] int[] Capabilities,
    [property: JsonPropertyName("input_policy")] InputPolicy InputPolicy,
    [property: JsonPropertyName("process_names")] string[] ProcessNames,
    [property: JsonPropertyName("profile_id")] string ProfileId,
    [property: JsonPropertyName("profile_version")] string ProfileVersion,
    [property: JsonPropertyName("publisher_subject")] string? PublisherSubject,
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("unsigned_executable_sha256")] string? UnsignedExecutableSha256,
    [property: JsonPropertyName("window_rules")] WindowRules WindowRules);

public sealed record WindowRules(
    [property: JsonPropertyName("classes")] string[] Classes,
    [property: JsonPropertyName("minimum_client_height")] int MinimumClientHeight,
    [property: JsonPropertyName("minimum_client_width")] int MinimumClientWidth,
    [property: JsonPropertyName("minimum_dpi")] int MinimumDpi,
    [property: JsonPropertyName("title_patterns")] string[] TitlePatterns);

public sealed record InputPolicy(
    [property: JsonPropertyName("keys")] PhysicalKeyPolicy[] Keys,
    [property: JsonPropertyName("maximum_wheel_delta")] int MaximumWheelDelta,
    [property: JsonPropertyName("minimum_wheel_delta")] int MinimumWheelDelta,
    [property: JsonPropertyName("mouse_buttons")] int[] MouseButtons);

public sealed record PhysicalKeyPolicy(
    [property: JsonPropertyName("extended")] bool Extended,
    [property: JsonPropertyName("scan_code")] int ScanCode);

public sealed record VerifiedProfile(ProfileContent Content, string ContentSha256);

public static partial class ProfileLoader
{
    public const int MaximumDocumentBytes = 256 * 1024;

    [GeneratedRegex("^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex ProfileIdPattern();

    [GeneratedRegex("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();

    [GeneratedRegex("^[A-Za-z]:\\\\(?:[^<>:\"/\\\\|?*]+\\\\?)*$", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsRootPattern();

    public static VerifiedProfile Load(string path, string publicKeyHex)
    {
        ProfileEnvelope envelope = StrictJson.ReadCanonical<ProfileEnvelope>(
            path,
            MaximumDocumentBytes);
        string digest = SignedDocumentVerifier.DigestHex(envelope.Content);
        if (envelope.ContentSha256 != digest)
        {
            throw new AgentContractException("profile.digest_mismatch", "Profile digest is invalid.");
        }
        SignedDocumentVerifier.Verify(envelope.Content, envelope.Signature, publicKeyHex);
        Validate(envelope.Content);
        return new VerifiedProfile(envelope.Content, digest);
    }

    public static void Validate(ProfileContent profile)
    {
        bool signerIsValid = !string.IsNullOrWhiteSpace(profile.PublisherSubject)
            ^ IsLowerSha256(profile.UnsignedExecutableSha256);
        if (profile.SchemaVersion != 1
            || !ProfileIdPattern().IsMatch(profile.ProfileId)
            || !VersionPattern().IsMatch(profile.ProfileVersion)
            || !signerIsValid
            || !IsSortedUnique(profile.ProcessNames, StringComparer.OrdinalIgnoreCase)
            || profile.ProcessNames.Any(name => !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            || !IsSortedUnique(profile.AllowedInstallRoots, StringComparer.OrdinalIgnoreCase)
            || profile.AllowedInstallRoots.Any(root => !WindowsRootPattern().IsMatch(root) || root.Contains("..", StringComparison.Ordinal))
            || !IsSortedUnique(profile.Capabilities)
            || profile.Capabilities.Any(value => value is < 1 or > 6))
        {
            throw new AgentContractException("profile.invalid", "Profile identity or target policy is invalid.");
        }

        ValidateWindowRules(profile.WindowRules);
        ValidateInputPolicy(profile.InputPolicy);
    }

    private static void ValidateWindowRules(WindowRules rules)
    {
        if (!IsSortedUnique(rules.Classes, StringComparer.Ordinal)
            || !IsSortedUnique(rules.TitlePatterns, StringComparer.Ordinal)
            || rules.MinimumClientWidth <= 0
            || rules.MinimumClientHeight <= 0
            || rules.MinimumDpi < 72)
        {
            throw new AgentContractException("profile.window_rules_invalid", "Window rules are invalid.");
        }
    }

    private static void ValidateInputPolicy(InputPolicy policy)
    {
        (int ScanCode, bool Extended)[] keys = policy.Keys
            .Select(key => (key.ScanCode, key.Extended))
            .ToArray();
        if (keys.Length == 0
            || keys.Any(key => key.ScanCode is < 1 or > 255)
            || !keys.SequenceEqual(keys.OrderBy(key => key.ScanCode).ThenBy(key => key.Extended))
            || keys.Distinct().Count() != keys.Length
            || !IsSortedUnique(policy.MouseButtons)
            || policy.MouseButtons.Any(button => button is < 1 or > 5)
            || policy.MinimumWheelDelta is < -1200 or > 0
            || policy.MaximumWheelDelta is < 0 or > 1200
            || policy.MinimumWheelDelta % 120 != 0
            || policy.MaximumWheelDelta % 120 != 0)
        {
            throw new AgentContractException("profile.input_policy_invalid", "Input policy is invalid.");
        }
    }

    private static bool IsLowerSha256(string? value) => value is not null
        && value.Length == 64
        && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');

    private static bool IsSortedUnique<T>(IReadOnlyCollection<T> values, IComparer<T>? comparer = null)
        where T : notnull
    {
        if (values.Count == 0)
        {
            return false;
        }
        comparer ??= Comparer<T>.Default;
        T[] items = values.ToArray();
        return items.SequenceEqual(items.Order(comparer))
            && items.Distinct(new ComparerEqualityAdapter<T>(comparer)).Count() == items.Length;
    }

    private sealed class ComparerEqualityAdapter<T>(IComparer<T> comparer) : IEqualityComparer<T>
        where T : notnull
    {
        public bool Equals(T? left, T? right) => comparer.Compare(left!, right!) == 0;

        public int GetHashCode(T value) => 0;
    }
}
