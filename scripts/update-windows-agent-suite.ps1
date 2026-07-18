param(
    [Parameter(Mandatory=$true)][string]$CandidateRoot,
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot,
    [Parameter(Mandatory=$true)][string]$BuildId,
    [Parameter(Mandatory=$true)][string]$SuiteVersion,
    [Parameter(Mandatory=$true)][string]$ManifestSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$AgentTask = 'FairyPam Agent'
$UiTask = 'FairyPam Agent UI'
$Active = Join-Path $InstallRoot 'active'
$Stage = Join-Path $InstallRoot ('.update-' + $BuildId)
$Rollback = Join-Path $InstallRoot ('.rollback-' + $BuildId)
$switched = $false
$released = $false

function Invoke-Native([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Assert-StagedSuite([string]$Root) {
    $manifestPath = Join-Path $Root 'BUILD-MANIFEST.json'
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) { throw 'update staging manifest identity mismatch' }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $declared = @($manifest.members.PSObject.Properties.Name | Sort-Object)
    $actual = @(Get-ChildItem -File -Recurse -LiteralPath $Root | ForEach-Object { $_.FullName.Substring($Root.Length + 1).Replace('\','/') } | Where-Object { $_ -cne 'BUILD-MANIFEST.json' } | Sort-Object)
    if (Compare-Object $declared $actual) { throw 'update staging member set mismatch' }
    foreach ($name in $declared) {
        $file = Get-Item -LiteralPath (Join-Path $Root $name)
        $expected = $manifest.members.$name
        if ($file.Length -ne [long]$expected.size_bytes -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$expected.sha256) { throw "update staging member identity mismatch: $name" }
    }
}

function Start-And-Check([string]$ExpectedVersion) {
    Invoke-Native 'schtasks.exe' @('/Run','/TN',$AgentTask)
    Start-Sleep -Seconds 2
    Invoke-Native (Join-Path $Active 'fairypam-agentctl.exe') @('doctor')
    $guardian = Join-Path $Active 'fairypam-agent-guardian.exe'
    $requests = @((@{type='register_agent';agent_pid=$PID;heartbeat_timeout_ms=5000}|ConvertTo-Json -Compress),(@{type='heartbeat';sequence=1}|ConvertTo-Json -Compress),(@{type='status'}|ConvertTo-Json -Compress))
    $responses = @($requests | & $guardian | ForEach-Object { $_ | ConvertFrom-Json })
    if ($LASTEXITCODE -ne 0 -or $responses.Count -ne 3 -or [string]$responses[2].type -cne 'status' -or [int]$responses[2].agent_pid -ne $PID -or [long]$responses[2].last_sequence -ne 1) { throw 'Guardian heartbeat health check failed' }
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $Active 'BUILD-MANIFEST.json') | ConvertFrom-Json
    if ([string]$manifest.suite_version -cne $ExpectedVersion) { throw 'running suite version does not match active manifest' }
}

function Wait-Stopped {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (@(Get-Process -Name 'fairypam-agent','fairypam-agent-guardian' -ErrorAction SilentlyContinue).Count -gt 0) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'suite did not stop after Guardian ReleaseAll' }
        Start-Sleep -Milliseconds 100
    }
}

function Write-Receipt([string]$Result, [string]$FailureStage, [string]$RollbackResult) {
    $audit = Join-Path $DataRoot 'audit'
    New-Item -ItemType Directory -Force -Path $audit | Out-Null
    $receipt = [ordered]@{schema_version=1;operation='update';result=$Result;failure_stage=$FailureStage;rollback_result=$RollbackResult;build_id=$BuildId;suite_version=$SuiteVersion;manifest_sha256=$ManifestSha256;created_at=[DateTimeOffset]::UtcNow.ToString('O')}
    [IO.File]::WriteAllText((Join-Path $audit (([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()) + '-update.json')), (ConvertTo-Json $receipt -Compress), [Text.UTF8Encoding]::new($false))
}

foreach ($path in @($CandidateRoot,$InstallRoot,$DataRoot,$Active,$Stage,$Rollback)) {
    if (-not [IO.Path]::IsPathRooted($path)) { throw "update path is not absolute: $path" }
}
if (-not (Test-Path -LiteralPath $Active -PathType Container)) { throw 'installed active suite is missing' }
$oldVersion = [string]((Get-Content -Raw -LiteralPath (Join-Path $Active 'BUILD-MANIFEST.json') | ConvertFrom-Json).suite_version)

try {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $Stage,$Rollback
    Copy-Item -Recurse -Force -LiteralPath $CandidateRoot -Destination $Stage
    Assert-StagedSuite $Stage
    Invoke-Native 'icacls.exe' @($Stage,'/inheritance:r')
    Invoke-Native 'icacls.exe' @($Stage,'/grant:r','SYSTEM:(OI)(CI)F','BUILTIN\Administrators:(OI)(CI)F','BUILTIN\Users:(OI)(CI)RX')

    Invoke-Native (Join-Path $Active 'fairypam-agentctl.exe') @('maintenance-prepare-update','--timeout-ms','15000')
    $released = $true
    & schtasks.exe /End /TN $AgentTask 2>$null | Out-Null
    Wait-Stopped
    Move-Item -LiteralPath $Active -Destination $Rollback
    Move-Item -LiteralPath $Stage -Destination $Active
    $switched = $true
    Start-And-Check $SuiteVersion
    Remove-Item -Recurse -Force -LiteralPath $Rollback
    Write-Receipt 'committed' '' 'not_required'
    Invoke-Native 'schtasks.exe' @('/Run','/TN',$UiTask)
}
catch {
    $message = $_.Exception.Message
    if ($switched) {
        & schtasks.exe /End /TN $AgentTask 2>$null | Out-Null
        Wait-Stopped
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $Active
        Move-Item -LiteralPath $Rollback -Destination $Active
        try {
            Start-And-Check $oldVersion
            Write-Receipt 'rolled_back' $message 'passed'
            Invoke-Native 'schtasks.exe' @('/Run','/TN',$UiTask)
        }
        catch {
            Write-Receipt 'repair_required' $message ('failed: ' + $_.Exception.Message)
            throw 'new and rollback suite health checks failed; Guardian files were preserved and Repair is required'
        }
    } elseif ($released) {
        try { Invoke-Native (Join-Path $Active 'fairypam-agentctl.exe') @('maintenance-resume-update') } catch { Write-Receipt 'repair_required' $message ('resume_failed: ' + $_.Exception.Message); throw }
    }
    throw
}
finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $Stage
}
