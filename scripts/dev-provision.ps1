[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('provision', 'start', 'unprovision')]
    [string]$Operation
)

$ErrorActionPreference = 'Stop'
$taskName = 'FairyPam Agent Dev'
$devRoot = Join-Path $env:LOCALAPPDATA 'FairyPam\dev'
$current = Join-Path $devRoot 'current'
$agent = Join-Path $current 'fairypam-agent.exe'
$state = Join-Path $devRoot 'state'
$enrollment = Join-Path $state 'enrollment'
$certificates = Join-Path $devRoot 'certificates'
$receipt = Join-Path $devRoot 'provision.json'
$verifiedArtifactReceipt = Join-Path $current '.verified-dev-artifact.json'
$provisionResult = Join-Path $current '.dev-provision-result.json'

function Write-ProvisionResult([string]$Status, [string]$Message) {
    $result = [ordered]@{
        schema_version = 1
        operation = 'provision'
        status = $Status
        message = $Message
    }
    [IO.File]::WriteAllText($provisionResult, ($result | ConvertTo-Json -Depth 2), [Text.UTF8Encoding]::new($false))
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'dev.task.elevation_required: provision and unprovision require explicit UAC elevation'
    }
}

function Protect-PrivateDirectory([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    & icacls.exe $Path /setowner '*S-1-5-32-544' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'dev.state.acl_failed: failed to set the private directory owner' }
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'dev.state.acl_failed: failed to protect the private directory' }
}

function Get-InteractiveShellLogonSid([int]$SessionId) {
    if (-not ('FairyPamTokenIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;

public static class FairyPamTokenIdentity
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenStatistics
    {
        public Luid TokenId;
        public Luid AuthenticationId;
        public long ExpirationTime;
        public int TokenType;
        public int ImpersonationLevel;
        public uint DynamicCharged;
        public uint DynamicAvailable;
        public uint GroupCount;
        public uint PrivilegeCount;
        public Luid ModifiedId;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int informationClass, IntPtr information, int informationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static string LogonSidForProcess(IntPtr processHandle)
    {
        IntPtr token = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(processHandle, 0x0008, out token))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            int length;
            if (GetTokenInformation(token, 10, IntPtr.Zero, 0, out length) || Marshal.GetLastWin32Error() != 122 || length <= 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            buffer = Marshal.AllocHGlobal(length);
            if (!GetTokenInformation(token, 10, buffer, length, out length))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var statistics = (TokenStatistics)Marshal.PtrToStructure(buffer, typeof(TokenStatistics));
            return string.Format(CultureInfo.InvariantCulture, "S-1-5-5-{0}-{1}", unchecked((uint)statistics.AuthenticationId.HighPart), statistics.AuthenticationId.LowPart);
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }
}
'@
    }
    # ponytail: the desktop shell owns the standard token used by local CLI and GUI clients.
    $shell = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $SessionId })
    if ($shell.Count -eq 0) {
        throw 'dev.task.interactive_session_required: provision requires the desktop Explorer shell in the current session'
    }
    try {
        return [FairyPamTokenIdentity]::LogonSidForProcess($shell[0].Handle)
    }
    catch {
        throw "dev.task.logon_session_query_failed: $($_.Exception.Message)"
    }
}

function Get-InteractiveProvisionIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($sessionId -le 0) {
        throw 'dev.task.interactive_session_required: provision must run from the developer desktop session'
    }
    $logonSid = Get-InteractiveShellLogonSid $sessionId
    return [pscustomobject]@{
        Identity = $identity
        LogonSid = $logonSid
        SessionId = $sessionId
    }
}

function Assert-VerifiedDevSlot {
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
        throw "dev.task.slot_missing: install a verified Dev artifact first: $agent"
    }
    if (-not (Test-Path -LiteralPath $verifiedArtifactReceipt -PathType Leaf)) {
        throw 'dev.task.artifact_proof_missing: reinstall the Dev artifact through dev install before provision'
    }
    try {
        $artifact = Get-Content -LiteralPath $verifiedArtifactReceipt -Raw | ConvertFrom-Json
    }
    catch {
        throw 'dev.task.artifact_proof_invalid: Dev artifact receipt is invalid'
    }
    if ($artifact.schema_version -ne 1 -or $artifact.artifact_class -cne 'dev-automation' -or $artifact.promotable -ne $false -or -not [regex]::IsMatch([string]$artifact.run_id, '^[1-9][0-9]{0,19}$') -or -not [regex]::IsMatch([string]$artifact.run_attempt, '^[1-9][0-9]*$') -or -not [regex]::IsMatch([string]$artifact.source_commit, '^[0-9a-f]{40}$') -or -not [regex]::IsMatch([string]$artifact.public_commit, '^[0-9a-f]{40}$') -or @($artifact.features).Count -ne 2 -or @($artifact.features) -notcontains 'dev-automation' -or @($artifact.features) -notcontains 'testbed') {
        throw 'dev.task.artifact_proof_invalid: Dev artifact receipt is not a complete non-promotable Dev record'
    }
    $agentMember = @($artifact.files | Where-Object { $_.path -ceq 'fairypam-agent.exe' })
    if ($agentMember.Count -ne 1 -or -not [regex]::IsMatch([string]$agentMember[0].sha256, '^[0-9a-f]{64}$') -or [uint64]$agentMember[0].size -eq 0 -or [uint64]$agentMember[0].size -ne (Get-Item -LiteralPath $agent).Length -or (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$agentMember[0].sha256) {
        throw 'dev.task.artifact_proof_invalid: Dev Agent does not match its verified artifact receipt'
    }
}

function Assert-FixedTask {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $action = @($task.Actions)[0]
    if ($action.Execute -ine $agent -or $action.Arguments -or $action.WorkingDirectory -ine $current) {
        throw 'dev.task.fixed_action_required: refusing a task whose action differs from the provisioned Dev slot'
    }
}

function Stop-RunningDevAgent {
    $expectedAgent = [IO.Path]::GetFullPath($agent)
    foreach ($process in @(Get-Process -Name 'fairypam-agent' -ErrorAction SilentlyContinue)) {
        try {
            $processPath = [IO.Path]::GetFullPath($process.Path)
        }
        catch {
            continue
        }
        if ($processPath -ieq $expectedAgent) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Wait-Process -Id $process.Id -Timeout 10 -ErrorAction Stop
        }
    }
}

switch ($Operation) {
    'provision' {
        $registered = $false
        try {
            if (Test-Path -LiteralPath $provisionResult -PathType Leaf) {
                Remove-Item -LiteralPath $provisionResult -Force -ErrorAction Stop
            }
            Assert-Elevated
            Assert-VerifiedDevSlot
            $boundIdentity = Get-InteractiveProvisionIdentity
            New-Item -ItemType Directory -Force -Path $certificates | Out-Null
            Protect-PrivateDirectory $state
            Protect-PrivateDirectory $enrollment
            $identity = $boundIdentity.Identity
            $action = New-ScheduledTaskAction -Execute $agent -WorkingDirectory $current
            $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Description 'FairyPam Dev-only elevated Agent' -Force | Out-Null
            $registered = $true
            $record = [ordered]@{ schema_version = 1; task_name = $taskName; owner_sid = $identity.User.Value; logon_sid = $boundIdentity.LogonSid; session_id = $boundIdentity.SessionId; task_action = $agent; working_directory = $current; state_dir = $state; enrollment_dir = $enrollment; certificate_dir = $certificates; pipe_name = '\\.\pipe\FairyPam.Agent.Dev.v1' }
            [IO.File]::WriteAllText($receipt, ($record | ConvertTo-Json -Depth 3), [Text.UTF8Encoding]::new($false))
            Assert-FixedTask
            Write-ProvisionResult 'completed' ''
        }
        catch {
            if ($registered) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            }
            try { Write-ProvisionResult 'failed' $_.Exception.Message } catch {}
            throw
        }
    }
    'start' {
        Assert-FixedTask
        Start-ScheduledTask -TaskName $taskName
    }
    'unprovision' {
        Assert-Elevated
        if (Test-Path -LiteralPath $receipt -PathType Leaf) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop }
        Stop-RunningDevAgent
        if (Test-Path -LiteralPath $devRoot -PathType Container) { Remove-Item -LiteralPath $devRoot -Recurse -Force -ErrorAction Stop }
    }
}
