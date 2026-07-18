param(
    [Parameter(Mandatory=$true)][string]$CandidateArchive,
    [Parameter(Mandatory=$true)][string]$CandidateManifest,
    [Parameter(Mandatory=$true)][string]$SecurityPolicyPath,
    [Parameter(Mandatory=$true)][string]$ExpectedBuildId,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][long]$ExpectedSizeBytes,
    [Parameter(Mandatory=$true)][string]$ExpectedManifestSha256,
    [Parameter(Mandatory=$true)][ValidateSet('success','rollback')][string]$ExpectedUpdateOutcome,
    [Parameter(Mandatory=$true)][string]$ExpectedFinalVersion,
    [Parameter(Mandatory=$true)][string]$ReceiptPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'suite lifecycle smoke requires the fixed elevated gate' }
$manifest = Get-Content -Raw -LiteralPath $CandidateManifest | ConvertFrom-Json
if ([string]$manifest.build_id -cne $ExpectedBuildId -or [string]$manifest.sha256 -cne $ExpectedSha256 -or [long]$manifest.size_bytes -ne $ExpectedSizeBytes -or [string]$manifest.suite_manifest_sha256 -cne $ExpectedManifestSha256) { throw 'candidate metadata does not match the local import identity' }
if ((Get-Item -LiteralPath $CandidateArchive).Length -ne $ExpectedSizeBytes -or (Get-FileHash -LiteralPath $CandidateArchive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) { throw 'candidate archive identity mismatch' }
if ($manifest.signed -ne $true -or $manifest.promotable -ne $true -or $manifest.gates.TUF -cne 'passed' -or $manifest.gates.AUTHENTICODE -cne 'passed') { throw 'suite lifecycle gate requires a signed TUF-bound candidate' }

$root = Join-Path ([IO.Path]::GetTempPath()) ('fairypam-suite-gate-' + [Guid]::NewGuid().ToString('N'))
$suite = Join-Path $root 'suite'
$programFilesRoot = Join-Path $env:ProgramFiles 'FairyPam\Agent'
$dataRoot = Join-Path $env:ProgramData 'FairyPam\Agent'
$userRoot = Join-Path $env:LOCALAPPDATA 'FairyPam\Agent'
$setup = $null
$installed = $false

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Assert-NoBroadWrite([string]$Path) {
    $bad = @(Get-Acl -LiteralPath $Path | Select-Object -ExpandProperty Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' -and $_.IdentityReference.Value -match 'Everyone|Authenticated Users|\\Users$'
    })
    if ($bad.Count -ne 0) { throw "broad principal can modify protected path: $Path" }
}

function Wait-Task([string]$Name, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $task = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
        if ($task.State -ne 'Running') { return (Get-ScheduledTaskInfo -TaskName $Name).LastTaskResult }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "scheduled task timed out: $Name"
}

try {
    New-Item -ItemType Directory -Force -Path $suite | Out-Null
    Expand-Archive -LiteralPath $CandidateArchive -DestinationPath $suite
    if ((Get-FileHash -LiteralPath (Join-Path $suite 'BUILD-MANIFEST.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedManifestSha256) { throw 'extracted suite manifest hash mismatch' }
    $setup = Join-Path $suite 'FairyPamAgentSetup.exe'
    Invoke-Checked $setup @()
    $installed = $true

    $active = Join-Path $programFilesRoot 'active'
    $installedPolicy = Join-Path $dataRoot 'security-policy.json'
    if ((Get-FileHash -LiteralPath $installedPolicy -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $SecurityPolicyPath -Algorithm SHA256).Hash) { throw 'no-argument install did not persist the packaged production security policy' }
    $agentTask = Get-ScheduledTask -TaskName 'FairyPam Agent'
    $uiTask = Get-ScheduledTask -TaskName 'FairyPam Agent UI'
    $updateTask = Get-ScheduledTask -TaskName 'FairyPam Agent Update'
    if ($agentTask.Principal.RunLevel -ne 'Highest' -or $uiTask.Principal.RunLevel -ne 'Limited' -or $updateTask.Principal.RunLevel -ne 'Highest') { throw 'scheduled task run-level matrix is invalid' }
    if ([IO.Path]::GetFullPath($agentTask.Actions.Execute) -cne [IO.Path]::GetFullPath((Join-Path $active 'fairypam-agent.exe')) -or [IO.Path]::GetFullPath($uiTask.Actions.Execute) -cne [IO.Path]::GetFullPath((Join-Path $active 'fairypam-agent-ui.exe')) -or [IO.Path]::GetFullPath($updateTask.Actions.Execute) -cne [IO.Path]::GetFullPath((Join-Path $active 'fairypam-agent-updater.exe'))) { throw 'scheduled task action is not the protected fixed absolute path' }
    foreach ($path in @($active,$dataRoot,(Join-Path $dataRoot 'security-policy.json'),(Join-Path $dataRoot 'tasks'))) { Assert-NoBroadWrite $path }

    Invoke-Checked (Join-Path $active 'FairyPamAgentSetup.exe') @('repair')
    Start-ScheduledTask -TaskName 'FairyPam Agent Update'
    $updateResult = Wait-Task 'FairyPam Agent Update' 300
    $final = Get-Content -Raw -LiteralPath (Join-Path $active 'BUILD-MANIFEST.json') | ConvertFrom-Json
    if ([string]$final.suite_version -cne $ExpectedFinalVersion) { throw 'post-update active suite version is unexpected' }
    if ($ExpectedUpdateOutcome -eq 'success' -and $updateResult -ne 0) { throw "update task failed: $updateResult" }
    if ($ExpectedUpdateOutcome -eq 'rollback' -and ($updateResult -eq 0 -or -not (Test-Path -LiteralPath (Join-Path $active 'fairypam-agent-guardian.exe')))) { throw 'rollback fault did not fail closed with Guardian preserved' }

    Invoke-Checked (Join-Path $active 'FairyPamAgentSetup.exe') @('uninstall')
    $installed = $false
    foreach ($name in @('FairyPam Agent','FairyPam Agent UI','FairyPam Agent Update')) { if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw "uninstall left task: $name" } }
    if (-not (Test-Path -LiteralPath $userRoot -PathType Container)) { throw 'default uninstall did not preserve user data' }

    $receipt = [ordered]@{schema_version=1;gate='WINDOWS-SUITE-CLI';result='passed';build_id=$ExpectedBuildId;sha256=$ExpectedSha256;size_bytes=$ExpectedSizeBytes;suite_manifest_sha256=$ExpectedManifestSha256;update_outcome=$ExpectedUpdateOutcome;final_version=$ExpectedFinalVersion;completed_at=[DateTimeOffset]::UtcNow.ToString('O')}
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReceiptPath) | Out-Null
    [IO.File]::WriteAllText($ReceiptPath, (ConvertTo-Json $receipt -Compress), [Text.UTF8Encoding]::new($false))
}
finally {
    if ($installed -and $setup) {
        try { & (Join-Path $programFilesRoot 'active\FairyPamAgentSetup.exe') uninstall | Out-Null } catch { Write-Warning $_ }
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $root
}
