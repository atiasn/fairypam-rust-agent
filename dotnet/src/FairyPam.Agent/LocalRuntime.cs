using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using FairyPam.Agent.Core;

namespace FairyPam.Agent;

internal sealed record LocalRuntimeStatus(
    string DeviceStatus,
    string ControlStatus,
    string FrameStatus,
    string SafetyStatus,
    bool RecoveryBlocked);

internal sealed class LocalRuntime
{
    private const string PublicKeyMetadataName = "FairyPamBootstrapPublicKeyHex";
    private readonly object statusLock = new();
    private readonly SemaphoreSlim operation = new(1, 1);
    private readonly HttpClient enrollmentClient;
    private readonly Func<DeviceIdentity, IReadOnlyList<VerifiedProfile>, CancellationToken, Task>?
        connectionRunner;
    private readonly TimeSpan connectionStopTimeout;
    private readonly VerifiedBootstrap? bootstrap;
    private readonly DeviceIdentityStore? identityStore;
    private DeviceIdentity? identity;
    private CancellationTokenSource? connectionCancellation;
    private Task? connectionTask;
    private LocalRuntimeStatus status;

    internal LocalRuntime(
        LocalRuntimeStatus status,
        VerifiedBootstrap? bootstrap = null,
        DeviceIdentityStore? identityStore = null,
        DeviceIdentity? identity = null,
        HttpClient? enrollmentClient = null,
        Func<DeviceIdentity, IReadOnlyList<VerifiedProfile>, CancellationToken, Task>?
            connectionRunner = null,
        TimeSpan? connectionStopTimeout = null)
    {
        this.status = status;
        this.bootstrap = bootstrap;
        this.identityStore = identityStore;
        this.identity = identity;
        this.enrollmentClient = enrollmentClient ?? new() { Timeout = TimeSpan.FromSeconds(30) };
        this.connectionRunner = connectionRunner;
        this.connectionStopTimeout = connectionStopTimeout ?? TimeSpan.FromSeconds(10);
    }

    public event Action<LocalRuntimeStatus>? StatusChanged;

    public LocalRuntimeStatus Status
    {
        get
        {
            lock (statusLock)
            {
                return status;
            }
        }
    }

    public static LocalRuntime Initialize()
    {
        try
        {
            WindowsProtectedPath.VerifyInstallRoot(AppContext.BaseDirectory);
            string attemptRoot = Path.Combine(WindowsProtectedPath.AgentStateRoot, "attempts");
            LedgerRecovery recovery;
            try
            {
                WindowsProtectedPath.EnsurePrivateDirectory(attemptRoot);
                recovery = new AttemptLedger(attemptRoot).Recover();
            }
            catch (Exception error) when (error is IOException
                or UnauthorizedAccessException
                or InvalidOperationException
                or AgentContractException)
            {
                return new(new(
                    "未注册",
                    "未连接",
                    "未连接",
                    "需要本机恢复",
                    RecoveryBlocked: true));
            }
            if (recovery.IsBlocked)
            {
                return new(new(
                    "未注册",
                    "未连接",
                    "未连接",
                    "需要本机恢复",
                    RecoveryBlocked: true));
            }

            string key = Assembly.GetExecutingAssembly()
                .GetCustomAttributes<AssemblyMetadataAttribute>()
                .Single(attribute => attribute.Key == PublicKeyMetadataName)
                .Value
                ?? throw new InvalidOperationException("bootstrap.key_missing");
            string bootstrapPath = Path.Combine(AppContext.BaseDirectory, "agent-bootstrap.json");
            string signaturePath = Path.Combine(AppContext.BaseDirectory, "agent-bootstrap.json.sig");
            WindowsProtectedPath.VerifyProtectedFile(bootstrapPath, AppContext.BaseDirectory);
            WindowsProtectedPath.VerifyProtectedFile(signaturePath, AppContext.BaseDirectory);
            VerifiedBootstrap bootstrap = BootstrapLoader.Load(bootstrapPath, signaturePath, key);
            HttpClient client = new() { Timeout = TimeSpan.FromSeconds(30) };
            DeviceIdentityStore identityStore = new(client);
            DeviceIdentity? identity = identityStore.Load();
            LocalRuntime runtime = new(
                new(
                    identity is null ? "未注册" : "已注册",
                    "未连接",
                    "未连接",
                    "输入已禁用",
                    RecoveryBlocked: false),
                bootstrap,
                identityStore,
                identity,
                client);
            return runtime;
        }
        catch (Exception error) when (error is IOException
            or UnauthorizedAccessException
            or InvalidOperationException
            or AgentContractException
            or CryptographicException)
        {
            return new(new("配置不可用", "未连接", "未连接", "输入已禁用", RecoveryBlocked: false));
        }
    }

    public async Task StartAsync()
    {
        await operation.WaitAsync();
        try
        {
            StartConnection();
        }
        finally
        {
            operation.Release();
        }
    }

    public async Task RegisterAsync(char[] enrollmentCode, CancellationToken cancellationToken)
    {
        bool entered = false;
        try
        {
            await operation.WaitAsync(cancellationToken);
            entered = true;
            if (bootstrap is null || identityStore is null)
            {
                throw new InvalidOperationException("enrollment.unavailable");
            }
            if (!await StopConnectionAsync())
            {
                throw new InvalidOperationException("hub.shutdown_failed");
            }
            (DeviceIdentity replacement, bool cleanupComplete) = await identityStore.EnrollAsync(
                bootstrap,
                enrollmentCode,
                cancellationToken);
            identity?.Dispose();
            identity = replacement;
            if (!cleanupComplete)
            {
                Update(new("注册待恢复", "未连接", "未连接", "需要本机恢复", true));
                return;
            }
            Update(new("已注册", "未连接", "未连接", "输入已禁用", false));
            StartConnection();
        }
        finally
        {
            Array.Clear(enrollmentCode);
            if (entered)
            {
                operation.Release();
            }
        }
    }

    public async Task RescanAsync(CancellationToken cancellationToken)
    {
        await operation.WaitAsync(cancellationToken);
        try
        {
            if (identity is null)
            {
                throw new InvalidOperationException("discovery.registration_required");
            }
            if (!await StopConnectionAsync())
            {
                throw new InvalidOperationException("hub.shutdown_failed");
            }
            StartConnection();
        }
        finally
        {
            operation.Release();
        }
    }

    public async Task<bool> TryShutdownAsync()
    {
        await operation.WaitAsync();
        try
        {
            bool stopped = await StopConnectionAsync();
            if (!stopped || Status.RecoveryBlocked)
            {
                return false;
            }
            identity?.Dispose();
            identity = null;
            enrollmentClient.Dispose();
            return true;
        }
        finally
        {
            operation.Release();
        }
    }

    private void StartConnection()
    {
        if (identity is null || connectionTask is not null)
        {
            return;
        }
        IReadOnlyList<VerifiedProfile> profiles = WindowsGameDiscovery.LoadProfiles(
            identity.Enrollment.ProfileRootPublicKeyHex);
        connectionCancellation = new();
        connectionTask = connectionRunner is null
            ? new HubSupervisor(ReportConnectionState).RunAsync(
                identity,
                profiles,
                connectionCancellation.Token)
            : connectionRunner(identity, profiles, connectionCancellation.Token);
    }

    private async Task<bool> StopConnectionAsync()
    {
        CancellationTokenSource? cancellation = connectionCancellation;
        Task? task = connectionTask;
        if (task is null)
        {
            return true;
        }
        cancellation!.Cancel();
        try
        {
            await task.WaitAsync(connectionStopTimeout);
            return true;
        }
        catch (TimeoutException)
        {
            Update(Status with
            {
                SafetyStatus = "需要本机恢复",
                RecoveryBlocked = true,
            });
            return false;
        }
        catch (OperationCanceledException)
        {
            return true;
        }
        finally
        {
            if (task.IsCompleted)
            {
                cancellation.Dispose();
                connectionCancellation = null;
                connectionTask = null;
                Update(Status with
                {
                    ControlStatus = "未连接",
                    FrameStatus = "未连接",
                    SafetyStatus = "输入已禁用",
                    RecoveryBlocked = false,
                });
            }
        }
    }

    private void ReportConnectionState(HubConnectionState connection)
    {
        Update(Status with
        {
            ControlStatus = connection.ControlConnected ? "已连接" : "未连接",
            FrameStatus = connection.FrameConnected ? "已连接" : "未连接",
        });
    }

    private void Update(LocalRuntimeStatus next)
    {
        lock (statusLock)
        {
            status = next;
        }
        StatusChanged?.Invoke(next);
    }
}
