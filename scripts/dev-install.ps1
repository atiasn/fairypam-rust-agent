[CmdletBinding(DefaultParameterSetName = 'GitHub')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'GitHub')]
    [ValidatePattern('^[1-9][0-9]{0,19}$')]
    [string]$RunId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Relay')]
    [ValidatePattern('^[1-9][0-9]{0,19}$')]
    [string]$ExpectedRunId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Relay')]
    [string]$ZipPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Relay')]
    [string]$ReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = 'atiasn/fairypam-rust-agent'
$workflowId = '312470124'
$workflowPath = 'atiasn/fairypam-rust-agent/.github/workflows/windows-candidate.yml'
$devRoot = Join-Path $env:LOCALAPPDATA 'FairyPam\dev'
$current = Join-Path $devRoot 'current'
$previous = Join-Path $devRoot 'previous'
$provisionReceipt = Join-Path $devRoot 'provision.json'
$canonicalTestbed = 'C:\FairyPam\Testbed\fairypam-test-window.exe'
$canonicalTestbedDirectory = Split-Path -Parent $canonicalTestbed

function Fail([string]$Code, [string]$Message) {
    throw "${Code}: $Message"
}

function Invoke-Gh([string[]]$Arguments) {
    $result = & gh @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail 'dev.artifact.github_failed' (([string[]]$result) -join [Environment]::NewLine)
    }
    return (([string[]]$result) -join [Environment]::NewLine)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-NotReparsePoint([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'dev.testbed.path_invalid' "refusing a reparse-point Testbed path: $Path"
    }
}

function Sync-CanonicalTestbed([string]$Source, [object]$Member) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf) -or
        (Get-Item -LiteralPath $Source).Length -ne [uint64]$Member.size -or
        (Get-Sha256 $Source) -cne [string]$Member.sha256) {
        Fail 'dev.artifact.members_invalid' 'verified Dev Testbed payload is missing or does not match its receipt'
    }

    $canonicalParent = Split-Path -Parent $canonicalTestbedDirectory
    Assert-NotReparsePoint $canonicalParent
    [IO.Directory]::CreateDirectory($canonicalTestbedDirectory) | Out-Null
    Assert-NotReparsePoint $canonicalParent
    Assert-NotReparsePoint $canonicalTestbedDirectory
    if ((Test-Path -LiteralPath $canonicalTestbed) -and -not (Test-Path -LiteralPath $canonicalTestbed -PathType Leaf)) {
        Fail 'dev.testbed.path_invalid' 'canonical Testbed destination is not a regular file'
    }
    Assert-NotReparsePoint $canonicalTestbed

    $temporary = Join-Path $canonicalTestbedDirectory ('.fairypam-test-window-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::Copy($Source, $temporary, $true)
        if ((Get-Item -LiteralPath $temporary).Length -ne [uint64]$Member.size -or (Get-Sha256 $temporary) -cne [string]$Member.sha256) {
            Fail 'dev.testbed.deploy_invalid' 'canonical Testbed temporary file does not match the verified Dev artifact'
        }
        if (Test-Path -LiteralPath $canonicalTestbed -PathType Leaf) {
            [IO.File]::Replace($temporary, $canonicalTestbed, $null)
        }
        else {
            [IO.File]::Move($temporary, $canonicalTestbed)
        }
        if ((Get-Item -LiteralPath $canonicalTestbed).Length -ne [uint64]$Member.size -or (Get-Sha256 $canonicalTestbed) -cne [string]$Member.sha256) {
            Fail 'dev.testbed.deploy_invalid' 'canonical Testbed does not match the verified Dev artifact'
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Assert-ExistingProvision {
    if (-not (Test-Path -LiteralPath $provisionReceipt -PathType Leaf)) {
        return
    }
    try {
        $record = Get-Content -LiteralPath $provisionReceipt -Raw | ConvertFrom-Json
    }
    catch {
        Fail 'dev.task.provision_invalid' 'existing Dev provision receipt is invalid'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($record.schema_version -ne 1 -or $record.owner_sid -cne $identity.User.Value) {
        Fail 'dev.task.owner_mismatch' 'only the provisioned developer SID may replace the Dev slot'
    }
    $task = Get-ScheduledTask -TaskName $record.task_name -ErrorAction Stop
    $action = @($task.Actions)[0]
    $expectedAgent = Join-Path $current 'fairypam-agent.exe'
    if ($action.Execute -ine $expectedAgent -or -not [string]::IsNullOrEmpty($action.Arguments) -or $action.WorkingDirectory -ine $current) {
        Fail 'dev.task.fixed_action_required' 'refusing to replace a Dev slot with a non-fixed task action'
    }
}

function Test-AllowedPath([string]$Path) {
    $rootFiles = Get-RequiredRootFiles
    return $rootFiles -ccontains $Path -or ($Path.StartsWith('profiles/', [StringComparison]::Ordinal) -and -not $Path.EndsWith('/', [StringComparison]::Ordinal) -and -not $Path.Contains('//'))
}

function Get-RequiredRootFiles {
    return @(
        'fairypam-agent.exe',
        'fairypam-agent-guardian.exe',
        'fairypam-agentctl.exe',
        'fairypam-agent-testbed.exe',
        'test-profile-root-public-key.hex',
        'dev-install.ps1',
        'dev-provision.ps1'
    )
}

function Assert-Receipt([object]$Receipt, [string]$ExpectedRunId, [string]$ExpectedRunAttempt, [string]$ZipPath) {
    if ($Receipt.schema_version -ne 1 -or $Receipt.artifact_class -cne 'dev-automation' -or $Receipt.promotable -ne $false) {
        Fail 'dev.artifact.promotable_invalid' 'receipt must describe a non-promotable Dev artifact'
    }
    if ([string]$Receipt.run_id -cne $ExpectedRunId -or [string]$Receipt.run_attempt -cne $ExpectedRunAttempt) {
        Fail 'dev.artifact.run_mismatch' 'receipt is not bound to the requested GitHub Actions run'
    }
    if (-not [regex]::IsMatch([string]$Receipt.source_commit, '^[0-9a-f]{40}$') -or -not [regex]::IsMatch([string]$Receipt.public_commit, '^[0-9a-f]{40}$')) {
        Fail 'dev.artifact.metadata_invalid' 'receipt must bind a complete source and public commit'
    }
    if (@($Receipt.features).Count -ne 2 -or @($Receipt.features) -notcontains 'dev-automation' -or @($Receipt.features) -notcontains 'testbed') {
        Fail 'dev.artifact.features_invalid' 'receipt must contain only the Dev automation and testbed features'
    }
    $expectedHash = Get-Sha256 $ZipPath
    if ($Receipt.zip_sha256 -cne $expectedHash -or [uint64]$Receipt.zip_size -ne (Get-Item -LiteralPath $ZipPath).Length) {
        Fail 'dev.artifact.hash_mismatch' 'Dev ZIP does not match its receipt'
    }
    $members = @{}
    foreach ($member in @($Receipt.files)) {
        $path = [string]$member.path
        if (-not (Test-AllowedPath $path) -or $path.Contains('..') -or $path.Contains([string][char]92) -or $path.StartsWith('/', [StringComparison]::Ordinal) -or $path -match '^[A-Za-z]:') {
            Fail 'dev.artifact.members_invalid' 'receipt contains an unexpected member path'
        }
        if (-not [regex]::IsMatch([string]$member.sha256, '^[0-9a-f]{64}$') -or [uint64]$member.size -eq 0 -or $members.ContainsKey($path)) {
            Fail 'dev.artifact.members_invalid' 'receipt contains an invalid or duplicate member'
        }
        $members[$path] = $member
    }
    if ($members.Count -eq 0) {
        Fail 'dev.artifact.members_invalid' 'receipt contains no Dev artifact members'
    }
    foreach ($required in Get-RequiredRootFiles) {
        if (-not $members.ContainsKey($required)) {
            Fail 'dev.artifact.members_invalid' 'receipt is missing a required Dev artifact member'
        }
    }
    return $members
}

function Expand-VerifiedArchive([string]$ZipPath, [hashtable]$Members, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entries = @{}
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.EndsWith('/', [StringComparison]::Ordinal)) {
                continue
            }
            $path = $entry.FullName.Replace([char]92, [char]47)
            if (-not (Test-AllowedPath $path) -or $path.Contains('..') -or $path.Contains('//') -or $path.StartsWith('/', [StringComparison]::Ordinal) -or $entries.ContainsKey($path)) {
                Fail 'dev.artifact.members_invalid' 'ZIP contains an unexpected or duplicate member'
            }
            $entries[$path] = $entry
        }
        if ($entries.Count -ne $Members.Count) {
            Fail 'dev.artifact.members_invalid' 'ZIP member count does not match its receipt'
        }
        $destinationRoot = ([IO.Path]::GetFullPath($Destination)).TrimEnd([char]92) + [IO.Path]::DirectorySeparatorChar
        foreach ($path in $Members.Keys) {
            if (-not $entries.ContainsKey($path)) {
                Fail 'dev.artifact.members_invalid' 'ZIP is missing a receipt member'
            }
            $member = $Members[$path]
            $entry = $entries[$path]
            if ([uint64]$entry.Length -ne [uint64]$member.size) {
                Fail 'dev.artifact.members_invalid' 'ZIP member size does not match its receipt'
            }
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $path.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            if (-not $target.StartsWith($destinationRoot, [StringComparison]::OrdinalIgnoreCase)) {
                Fail 'dev.artifact.members_invalid' 'ZIP member escapes the Dev staging directory'
            }
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
            if ((Get-Item -LiteralPath $target).Length -ne [uint64]$member.size -or (Get-Sha256 $target) -cne [string]$member.sha256) {
                Fail 'dev.artifact.members_invalid' 'extracted member hash does not match its receipt'
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Replace-DevSlot([string]$Staging) {
    if (Test-Path -LiteralPath $previous -PathType Container) {
        Remove-Item -LiteralPath $previous -Recurse -Force -ErrorAction Stop
    }
    $movedCurrent = $false
    try {
        if (Test-Path -LiteralPath $current -PathType Container) {
            Move-Item -LiteralPath $current -Destination $previous -ErrorAction Stop
            $movedCurrent = $true
        }
        Move-Item -LiteralPath $Staging -Destination $current -ErrorAction Stop
    }
    catch {
        if ($movedCurrent -and -not (Test-Path -LiteralPath $current) -and (Test-Path -LiteralPath $previous)) {
            Move-Item -LiteralPath $previous -Destination $current -ErrorAction SilentlyContinue
        }
        Fail 'dev.task.busy' 'Dev slot is in use or cannot be atomically replaced; the previous current slot was preserved'
    }
}

if ($PSCmdlet.ParameterSetName -eq 'GitHub' -and -not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Fail 'dev.artifact.gh_missing' 'GitHub CLI (gh) is required to install a Dev artifact'
}

Assert-ExistingProvision
[IO.Directory]::CreateDirectory($devRoot) | Out-Null
$work = Join-Path $devRoot ('.download-' + [guid]::NewGuid().ToString('N'))
$staging = Join-Path $devRoot ('.staging-' + [guid]::NewGuid().ToString('N'))
$installed = $false
try {
    [IO.Directory]::CreateDirectory($work) | Out-Null
    if ($PSCmdlet.ParameterSetName -eq 'GitHub') {
        $run = (Invoke-Gh @('api', "repos/$repository/actions/runs/$RunId")) | ConvertFrom-Json
        if ([string]$run.repository.full_name -cne $repository -or [string]$run.workflow_id -cne $workflowId -or $run.status -cne 'completed' -or $run.conclusion -cne 'success' -or [int]$run.run_attempt -lt 1) {
            Fail 'dev.artifact.run_invalid' 'requested run is not a successful Dev workflow run from the fixed repository'
        }
        $artifactName = "fairypam-agent-dev-$RunId-$($run.run_attempt)"
        Invoke-Gh @('run', 'download', $RunId, '--repo', $repository, '--name', $artifactName, '--dir', $work) | Out-Null
        $zip = @(Get-ChildItem -LiteralPath $work -File -Recurse | Where-Object { $_.Name -ceq 'fairypam-agent-dev-windows.zip' })
        $receipt = @(Get-ChildItem -LiteralPath $work -File -Recurse | Where-Object { $_.Name -ceq 'dev-build-receipt.json' })
        if ($zip.Count -ne 1 -or $receipt.Count -ne 1) {
            Fail 'dev.artifact.download_invalid' 'GitHub artifact must contain exactly one Dev ZIP and one receipt'
        }
        Invoke-Gh @('attestation', 'verify', $zip[0].FullName, '--repo', $repository, '--signer-workflow', $workflowPath, '--deny-self-hosted-runners') | Out-Null
        Invoke-Gh @('attestation', 'verify', $receipt[0].FullName, '--repo', $repository, '--signer-workflow', $workflowPath, '--deny-self-hosted-runners') | Out-Null
        $expectedRunId = $RunId
        $expectedRunAttempt = [string]$run.run_attempt
        $zipFile = $zip[0].FullName
        $receiptFile = $receipt[0].FullName
    }
    else {
        if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf) -or -not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) {
            Fail 'dev.artifact.relay_invalid' 'relay must provide one readable Dev ZIP and receipt'
        }
        $zipFile = (Resolve-Path -LiteralPath $ZipPath).Path
        $receiptFile = (Resolve-Path -LiteralPath $ReceiptPath).Path
        $relayReceipt = Get-Content -LiteralPath $receiptFile -Raw | ConvertFrom-Json
        if (-not [regex]::IsMatch([string]$relayReceipt.run_attempt, '^[1-9][0-9]*$')) {
            Fail 'dev.artifact.relay_invalid' 'relay receipt has an invalid run attempt'
        }
        $expectedRunId = $ExpectedRunId
        $expectedRunAttempt = [string]$relayReceipt.run_attempt
    }
    $receiptObject = Get-Content -LiteralPath $receiptFile -Raw | ConvertFrom-Json
    $members = Assert-Receipt $receiptObject $expectedRunId $expectedRunAttempt $zipFile
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    Expand-VerifiedArchive $zipFile $members $staging
    [IO.File]::WriteAllText((Join-Path $staging '.verified-dev-artifact.json'), (Get-Content -LiteralPath $receiptFile -Raw), [Text.UTF8Encoding]::new($false))
    Sync-CanonicalTestbed (Join-Path $staging 'fairypam-agent-testbed.exe') $members['fairypam-agent-testbed.exe']
    Replace-DevSlot $staging
    $installed = $true
    [ordered]@{
        status = 'installed'
        run_id = $expectedRunId
        run_attempt = $expectedRunAttempt
        build_id = [string]$receiptObject.build_id
        slot = $current
    } | ConvertTo-Json -Compress
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not $installed -and (Test-Path -LiteralPath $staging)) {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}
