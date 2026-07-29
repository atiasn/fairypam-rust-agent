using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FairyPam.Agent.Core;
using FairyPam.Agent.Protocol.V2;
using Grpc.Core;
using Grpc.Net.Client;

namespace FairyPam.Agent;

internal sealed record HubConnectionState(bool ControlConnected, bool FrameConnected, string? ErrorCode);

internal sealed class HubSupervisor(Action<HubConnectionState> reportState)
{
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(10),
        TimeSpan.FromSeconds(30),
    ];

    public async Task RunAsync(
        DeviceIdentity identity,
        IReadOnlyList<VerifiedProfile> profiles,
        CancellationToken cancellationToken)
    {
        int failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(identity, profiles, cancellationToken);
                failures = 0;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error) when (error is RpcException
                or HttpRequestException
                or IOException
                or AuthenticationException
                or CryptographicException
                or AgentContractException
                or InvalidOperationException)
            {
                reportState(new(false, false, RedactedError(error)));
            }
            TimeSpan delay = RetryDelays[Math.Min(failures++, RetryDelays.Length - 1)];
            await Task.Delay(delay, cancellationToken);
        }
    }

    private async Task RunOnceAsync(
        DeviceIdentity identity,
        IReadOnlyList<VerifiedProfile> profiles,
        CancellationToken cancellationToken)
    {
        using GrpcChannel controlChannel = CreateChannel(
            identity.Enrollment.ControlEndpoint,
            identity);
        AgentControlService.AgentControlServiceClient client = new(controlChannel);
        using AsyncDuplexStreamingCall<AgentControlEvent, HubControlCommand> call =
            client.ControlTunnel(cancellationToken: cancellationToken);
        AgentHello agentHello = BuildHello(identity, profiles);
        await call.RequestStream.WriteAsync(new AgentControlEvent
        {
            Hello = agentHello,
        }, cancellationToken);
        if (!await call.ResponseStream.MoveNext(cancellationToken)
            || call.ResponseStream.Current.PayloadCase != HubControlCommand.PayloadOneofCase.Hello)
        {
            throw new InvalidOperationException("hub.hello_missing");
        }

        HubSessionContract contract = new(
            identity.Enrollment.AgentId.ToString("D"),
            agentHello.SuiteBuildId,
            agentHello.InstalledProfiles.ToDictionary(
                profile => profile.ProfileId,
                profile => profile.ContentDigest,
                StringComparer.Ordinal));
        HubHello hello = call.ResponseStream.Current.Hello;
        SessionRef session = contract.AcceptHello(hello);
        SafeCommandResponder responder = new();
        using CancellationTokenSource connection = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        Task frame = RunFrameAsync(identity, session, connection.Token);
        reportState(new(true, false, null));

        await call.RequestStream.WriteAsync(new AgentControlEvent
        {
            Status = new AgentStatus
            {
                Session = session.Clone(),
                State = AgentRuntimeState.ConnectedIdle,
            },
        }, cancellationToken);
        await call.RequestStream.WriteAsync(new AgentControlEvent
        {
            DiscoverySnapshot = WindowsGameDiscovery.Scan(session, profiles),
        }, cancellationToken);

        TimeSpan heartbeatInterval = TimeSpan.FromMilliseconds(hello.HeartbeatIntervalMs);
        Task<bool> read = call.ResponseStream.MoveNext(connection.Token);
        Task heartbeat = Task.Delay(heartbeatInterval, connection.Token);
        try
        {
            while (true)
            {
                Task completed = await Task.WhenAny(read, heartbeat, frame);
                if (completed == frame)
                {
                    await frame;
                    throw new InvalidOperationException("hub.frame_disconnected");
                }
                if (completed == heartbeat)
                {
                    await call.RequestStream.WriteAsync(new AgentControlEvent
                    {
                        Heartbeat = new Heartbeat
                        {
                            Session = session.Clone(),
                            SentAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        },
                    }, connection.Token);
                    heartbeat = Task.Delay(heartbeatInterval, connection.Token);
                    continue;
                }
                if (!await read)
                {
                    throw new InvalidOperationException("hub.control_disconnected");
                }

                HubControlCommand command = call.ResponseStream.Current;
                CommandAdmission admission = contract.Validate(
                    command,
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                CommandResult result = responder.Respond(command, admission);
                await call.RequestStream.WriteAsync(new AgentControlEvent
                {
                    CommandResult = result,
                }, connection.Token);
                if (command.PayloadCase == HubControlCommand.PayloadOneofCase.StopSession
                    && admission is CommandAdmission.New or CommandAdmission.Replay)
                {
                    await call.RequestStream.CompleteAsync();
                    return;
                }
                read = call.ResponseStream.MoveNext(connection.Token);
            }
        }
        finally
        {
            connection.Cancel();
            contract.Disconnect();
            try
            {
                await frame;
            }
            catch (Exception error) when (error is OperationCanceledException or RpcException)
            {
            }
            reportState(new(false, false, null));
        }
    }

    private async Task RunFrameAsync(
        DeviceIdentity identity,
        SessionRef session,
        CancellationToken cancellationToken)
    {
        using GrpcChannel frameChannel = CreateChannel(identity.Enrollment.FrameEndpoint, identity);
        AgentFrameService.AgentFrameServiceClient client = new(frameChannel);
        using AsyncDuplexStreamingCall<FramePacket, FrameDirective> call =
            client.FrameTunnel(cancellationToken: cancellationToken);
        await call.RequestStream.WriteAsync(new FramePacket
        {
            Session = session.Clone(),
        }, cancellationToken);
        if (!await call.ResponseStream.MoveNext(cancellationToken))
        {
            throw new InvalidOperationException("hub.frame_attach_missing");
        }
        ValidateFrameDirective(call.ResponseStream.Current, session, initial: true);
        reportState(new(true, true, null));
        while (await call.ResponseStream.MoveNext(cancellationToken))
        {
            ValidateFrameDirective(call.ResponseStream.Current, session, initial: false);
        }
        throw new InvalidOperationException("hub.frame_disconnected");
    }

    private static void ValidateFrameDirective(
        FrameDirective directive,
        SessionRef session,
        bool initial)
    {
        if (directive?.Session is null
            || directive.Session.AgentId != session.AgentId
            || directive.Session.SessionId != session.SessionId
            || directive.Session.Generation != session.Generation
            || (initial && (!string.IsNullOrEmpty(directive.CaptureSourceId)
                || directive.HasAcceptedFrameSequence)))
        {
            throw new InvalidOperationException("hub.frame_directive_invalid");
        }
    }

    private static AgentHello BuildHello(
        DeviceIdentity identity,
        IEnumerable<VerifiedProfile> profiles)
    {
        Assembly assembly = Assembly.GetExecutingAssembly();
        Dictionary<string, string> metadata = assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToDictionary(item => item.Key, item => item.Value ?? string.Empty, StringComparer.Ordinal);
        AgentHello hello = new()
        {
            AgentId = identity.Enrollment.AgentId.ToString("D"),
            AgentVersion = assembly.GetName().Version?.ToString() ?? "0.0.0.0",
            ProtocolMajor = 2,
            ProtocolMinor = 0,
            BuildCommit = Metadata(metadata, "FairyPamSourceCommit"),
            SuiteBuildId = Metadata(metadata, "FairyPamSuiteBuildId"),
        };
        hello.InstalledProfiles.Add(profiles
            .OrderBy(profile => profile.Content.ProfileId, StringComparer.Ordinal)
            .Select(profile => new InstalledProfile
            {
                ProfileId = profile.Content.ProfileId,
                SchemaVersion = (uint)profile.Content.SchemaVersion,
                ContentDigest = profile.ContentSha256,
            }));
        return hello;
    }

    private static string Metadata(IReadOnlyDictionary<string, string> metadata, string name) =>
        metadata.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException("build.metadata_missing");

    private static GrpcChannel CreateChannel(Uri endpoint, DeviceIdentity identity)
    {
        SocketsHttpHandler handler = new()
        {
            EnableMultipleHttp2Connections = true,
            SslOptions = new()
            {
                ClientCertificates = new X509CertificateCollection { identity.Certificate },
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                TargetHost = identity.Enrollment.HubServerName,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    ValidateHubCertificate(
                        certificate,
                        errors,
                        identity.CertificateAuthority),
            },
        };
        return GrpcChannel.ForAddress(endpoint, new GrpcChannelOptions
        {
            HttpHandler = handler,
            DisposeHttpClient = true,
        });
    }

    private static bool ValidateHubCertificate(
        X509Certificate? certificate,
        SslPolicyErrors errors,
        X509Certificate2 certificateAuthority)
    {
        if (certificate is null
            || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch
                | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0)
        {
            return false;
        }
        using X509Certificate2 server = new(certificate);
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(certificateAuthority);
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        return chain.Build(server);
    }

    private static string RedactedError(Exception error) => error switch
    {
        AgentContractException contract => contract.Code,
        RpcException rpc => $"grpc.{rpc.StatusCode.ToString().ToLowerInvariant()}",
        AuthenticationException => "tls.authentication_failed",
        CryptographicException => "tls.certificate_failed",
        HttpRequestException => "hub.network_failed",
        IOException => "hub.io_failed",
        InvalidOperationException invalid when invalid.Message.StartsWith("hub.", StringComparison.Ordinal)
            || invalid.Message.StartsWith("build.", StringComparison.Ordinal) => invalid.Message,
        _ => "hub.connection_failed",
    };
}

internal static class WindowsGameDiscovery
{
    public static DiscoverySnapshot Scan(SessionRef session, IReadOnlyList<VerifiedProfile> profiles)
    {
        List<DiscoveredGame> games = [];
        foreach (VerifiedProfile profile in profiles)
        {
            foreach (string root in profile.Content.AllowedInstallRoots)
            {
                string normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
                if (!Directory.Exists(normalizedRoot)
                    || (File.GetAttributes(normalizedRoot) & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }
                EnumerationOptions options = new()
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint,
                    MatchCasing = MatchCasing.CaseInsensitive,
                };
                foreach (string processName in profile.Content.ProcessNames)
                {
                    foreach (string executable in Directory.EnumerateFiles(
                                 normalizedRoot,
                                 processName,
                                 options))
                    {
                        string fullPath = Path.GetFullPath(executable);
                        if (!fullPath.StartsWith(
                                normalizedRoot + Path.DirectorySeparatorChar,
                                StringComparison.OrdinalIgnoreCase)
                            || !VerifyExecutable(fullPath, profile.Content))
                        {
                            continue;
                        }
                        string installRoot = Path.TrimEndingDirectorySeparator(
                            Path.GetDirectoryName(fullPath)!);
                        DiscoveredGame game = new()
                        {
                            ProfileId = profile.Content.ProfileId,
                            NormalizedInstallRoot = installRoot,
                            ExecutableName = Path.GetFileName(fullPath),
                            ProcessName = Path.GetFileNameWithoutExtension(fullPath),
                            Available = true,
                        };
                        if (profile.Content.PublisherSubject is not null)
                        {
                            game.PublisherSubject = profile.Content.PublisherSubject;
                        }
                        else
                        {
                            game.ExecutableSha256 = profile.Content.UnsignedExecutableSha256;
                        }
                        games.Add(game);
                    }
                }
            }
        }
        return DiscoveryContract.Create(
            session,
            Guid.NewGuid().ToString("D"),
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            games);
    }

    public static IReadOnlyList<VerifiedProfile> LoadProfiles(string profileRootPublicKeyHex)
    {
        string root = Path.Combine(AppContext.BaseDirectory, "profiles");
        if (!Directory.Exists(root))
        {
            return [];
        }
        EnumerationOptions options = new()
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            AttributesToSkip = FileAttributes.ReparsePoint,
        };
        return Directory.EnumerateFiles(root, "profile.json", options)
            .Order(StringComparer.OrdinalIgnoreCase)
            .Select(path =>
            {
                WindowsProtectedPath.VerifyProtectedFile(path, AppContext.BaseDirectory);
                return ProfileLoader.Load(path, profileRootPublicKeyHex);
            })
            .ToArray();
    }

    private static bool VerifyExecutable(string path, ProfileContent profile)
    {
        if (profile.PublisherSubject is not null)
        {
            return AuthenticodeVerifier.Verify(path, profile.PublisherSubject);
        }
        using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexStringLower(SHA256.HashData(stream))
            == profile.UnsignedExecutableSha256;
    }
}

internal static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static bool Verify(string path, string expectedPublisher)
    {
        WinTrustFileInfo file = new(path);
        IntPtr filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(file, filePointer, fDeleteOld: false);
            WinTrustData data = new(filePointer, stateAction: 1);
            Guid action = GenericVerifyV2;
            uint result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.StateAction = 2;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            if (result != 0)
            {
                return false;
            }
#pragma warning disable SYSLIB0057 // WinVerifyTrust has already validated this signed PE file.
            using X509Certificate2 signer = new(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return signer.GetNameInfo(X509NameType.SimpleName, forIssuer: false)
                == expectedPublisher;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(filePointer);
            Marshal.FreeHGlobal(filePointer);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern uint WinVerifyTrust(
        IntPtr window,
        ref Guid action,
        ref WinTrustData data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo
    {
        public uint Size = (uint)Marshal.SizeOf<WinTrustFileInfo>();
        public string FilePath;
        public IntPtr File = IntPtr.Zero;
        public IntPtr KnownSubject = IntPtr.Zero;

        public WinTrustFileInfo(string filePath) => FilePath = filePath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData(IntPtr file, uint stateAction)
    {
        public uint Size = (uint)Marshal.SizeOf<WinTrustData>();
        public IntPtr PolicyCallbackData = IntPtr.Zero;
        public IntPtr SipClientData = IntPtr.Zero;
        public uint UiChoice = 2;
        public uint RevocationChecks = 0;
        public uint UnionChoice = 1;
        public IntPtr File = file;
        public uint StateAction = stateAction;
        public IntPtr StateData = IntPtr.Zero;
        public IntPtr UrlReference = IntPtr.Zero;
        public uint ProviderFlags = 0x00001010;
        public uint UiContext = 0;
        public IntPtr SignatureSettings = IntPtr.Zero;
    }
}
