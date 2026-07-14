param(
    [ValidateSet('Register', 'Run', 'Execute', 'Unregister')]
    [string]$Mode = 'Run',
    [string]$CandidateMetadataUrl = '',
    [string]$ExpectedSha256 = '',
    [string]$ExpectedBuildId = '',
    # 60s metadata + 60s ZIP + 15s CLI + 75s cleanup/receipt.
    [int]$TimeoutSeconds = 210
)

$ErrorActionPreference = 'Stop'
$TaskName = 'FairyPamAgentCandidateSafeSmoke'
$RunMutexName = 'Local\FairyPamAgentCandidateSafeSmokeRun'
$TargetDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target'))
$RequestPath = Join-Path $TargetDirectory 'candidate-smoke-request.json'
$ResultPath = Join-Path $TargetDirectory 'candidate-smoke-result.json'
$LeasePath = Join-Path $TargetDirectory 'candidate-smoke-lease.json'
$DeadlinePath = Join-Path $TargetDirectory 'candidate-smoke-deadline.json'
$HarnessPath = Join-Path $PSScriptRoot 'package-smoke-test.js'
$NetworkTimeoutSeconds = 60

function Write-AtomicJsonFile([string]$Path, $Payload) {
    $targetPath = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($targetPath)
    if ([string]::IsNullOrWhiteSpace($parent)) { throw 'candidate JSON target directory is invalid' }
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $temporary = Join-Path $parent ".$([IO.Path]::GetFileName($targetPath)).$([guid]::NewGuid().ToString('N')).tmp"
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($temporary, (($Payload | ConvertTo-Json -Depth 12) + [Environment]::NewLine), $encoding)
    try {
        if ([IO.File]::Exists($targetPath)) {
            [IO.File]::Replace($temporary, $targetPath, [System.Management.Automation.Language.NullString]::Value)
        } else {
            [IO.File]::Move($temporary, $targetPath)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -Force -LiteralPath $temporary
        }
    }
}

function Enter-CandidateSmokeRunMutex {
    $mutex = [System.Threading.Mutex]::new($false, $RunMutexName)
    try {
        $acquired = $mutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        # The prior owner cannot still be using the files; fail closed only for live owners.
        $acquired = $true
    }
    if (-not $acquired) {
        $mutex.Dispose()
        throw 'candidate smoke run already active for this user'
    }
    return $mutex
}

function Assert-RequestId([string]$RequestId) {
    if ($RequestId -notmatch '^[0-9a-f]{32}$') {
        throw 'candidate smoke request_id is invalid'
    }
}

function Assert-CandidateSmokeSchemaVersion($SchemaVersion) {
    if ($SchemaVersion -isnot [int] -and $SchemaVersion -isnot [long]) {
        throw 'candidate smoke lease schema is invalid'
    }
    if ([long]$SchemaVersion -ne [long]1) {
        throw 'candidate smoke lease schema is invalid'
    }
}

function Assert-ResultMatchesRequest($Result, [string]$RequestId, [string]$LeaseId, [string]$ExpectedSha256, [string]$ExpectedBuildId) {
    if ($Result.completion_receipt -ne $true -or
        [string]$Result.request_id -cne $RequestId -or
        [string]$Result.lease_id -cne $LeaseId -or
        [string]$Result.expected_sha256 -cne $ExpectedSha256 -or
        [string]$Result.sha256 -cne $ExpectedSha256) {
        throw 'candidate smoke result does not match request'
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedBuildId) -and
        ([string]$Result.expected_build_id -cne $ExpectedBuildId -or
         [string]$Result.build_id -cne $ExpectedBuildId)) {
        throw 'candidate smoke result does not match request'
    }
}

function Get-CandidateSmokeLease($Request) {
    if (-not (Test-Path -LiteralPath $LeasePath)) {
        throw 'candidate smoke lease is missing for request'
    }
    try {
        $lease = Get-Content -Encoding UTF8 -Raw -LiteralPath $LeasePath | ConvertFrom-Json
    } catch {
        throw 'candidate smoke lease is unreadable; manual diagnosis required'
    }
    Assert-CandidateSmokeSchemaVersion $lease.schema_version
    if ([string]$lease.request_id -cne [string]$Request.request_id -or
        [string]$lease.lease_id -cne [string]$Request.lease_id -or
        [string]$lease.candidate_metadata_url -cne [string]$Request.candidate_metadata_url -or
        [string]$lease.expected_sha256 -cne [string]$Request.expected_sha256 -or
        [string]$lease.expected_build_id -cne [string]$Request.expected_build_id) {
        throw 'candidate smoke lease does not match request'
    }
    return $lease
}

function New-CandidateSmokeLease($Request) {
    $parent = Split-Path -Parent $LeasePath
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $payload = [ordered]@{
        schema_version = 1
        request_id = [string]$Request.request_id
        lease_id = [string]$Request.lease_id
        candidate_metadata_url = [string]$Request.candidate_metadata_url
        expected_sha256 = [string]$Request.expected_sha256
        expected_build_id = [string]$Request.expected_build_id
    } | ConvertTo-Json -Depth 4
    try {
        $stream = [IO.File]::Open($LeasePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    } catch [IO.IOException] {
        throw 'candidate smoke lease already exists; manual diagnosis required'
    }
    try {
        $writer = New-Object IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $writer.WriteLine($payload)
            $writer.Flush()
            $stream.Flush($true)
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Clear-CandidateSmokeLease($Request) {
    Get-CandidateSmokeLease $Request | Out-Null
    Remove-Item -Force -ErrorAction Stop -LiteralPath $LeasePath
    if (Test-Path -LiteralPath $LeasePath) {
        throw 'candidate smoke lease remains after result'
    }
}

function Test-CandidateSmokeDeadline($Request) {
    if (-not (Test-Path -LiteralPath $DeadlinePath)) {
        return $false
    }
    try {
        $deadline = Get-Content -Encoding UTF8 -Raw -LiteralPath $DeadlinePath | ConvertFrom-Json
    } catch {
        throw 'candidate smoke deadline marker is unreadable; manual diagnosis required'
    }
    if ([string]$deadline.request_id -cne [string]$Request.request_id -or
        [string]$deadline.lease_id -cne [string]$Request.lease_id -or
        [string]$deadline.expected_sha256 -cne [string]$Request.expected_sha256 -or
        [string]$deadline.expected_build_id -cne [string]$Request.expected_build_id) {
        throw 'candidate smoke deadline marker does not match request'
    }
    return $true
}

function Assert-CandidateTransportUri([Uri]$Uri) {
    if ($Uri.Scheme -eq 'https') {
        return
    }
    if ($Uri.Scheme -eq 'http' -and $Uri.IsLoopback) {
        return
    }
    throw 'candidate transport must use HTTPS or SSH-tunneled loopback HTTP'
}

function Assert-ExactCandidateZip([string]$ZipPath) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $expected = @('BUILD-MANIFEST.json', 'README.txt', 'fairypam-agent-tauri-ui.exe', 'fairypam-agent.exe')
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $actual = @($archive.Entries | Select-Object -ExpandProperty FullName)
        foreach ($member in $actual) {
            if ($member -match '[\\/]' -or [IO.Path]::IsPathRooted($member) -or $member -match '(^|[\\/])\.\.([\\/]|$)') {
                throw 'candidate ZIP contains a non-flat member before extraction'
            }
        }
        if ($actual.Count -ne $expected.Count -or (Compare-Object $expected $actual)) {
            throw 'candidate ZIP members are not exact before extraction'
        }
    } finally {
        $archive.Dispose()
    }
}

if ($Mode -eq 'Register') {
    $script = $PSCommandPath
    $arguments = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$script`"",
        '-Mode', 'Execute'
    ) -join ' '
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    Write-Host "registered fixed least-privilege candidate smoke task: $TaskName"
    exit 0
}

if ($Mode -eq 'Unregister') {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "unregistered candidate smoke task: $TaskName"
    exit 0
}

if ($Mode -eq 'Run') {
    $runMutex = Enter-CandidateSmokeRunMutex
    try {
        $metadataUri = [Uri]$CandidateMetadataUrl
        Assert-CandidateTransportUri $metadataUri
        $ExpectedSha256 = $ExpectedSha256.ToLowerInvariant()
        if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') { throw 'ExpectedSha256 must be a SHA256 pin' }
        $ExpectedBuildId = $ExpectedBuildId.Trim()
        $scheduledTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $scheduledTask) {
            throw "scheduled task is not registered; run -Mode Register once: $TaskName"
        }
        if ($scheduledTask.State -eq 'Running') {
            throw 'candidate smoke task is still running; refusing to overwrite its request'
        }
        if (Test-Path -LiteralPath $LeasePath) {
            throw 'candidate smoke lease already exists; manual diagnosis required'
        }
        if (Test-Path -LiteralPath $DeadlinePath) {
            throw 'candidate smoke deadline marker exists; manual diagnosis required'
        }
        $requestId = [guid]::NewGuid().ToString('N')
        $leaseId = [guid]::NewGuid().ToString('N')
        $request = [ordered]@{
            request_id = $requestId
            lease_id = $leaseId
            candidate_metadata_url = $metadataUri.AbsoluteUri
            expected_sha256 = $ExpectedSha256
            expected_build_id = $ExpectedBuildId
        }
        if (Test-Path -LiteralPath $ResultPath) {
            Remove-Item -Force -ErrorAction Stop -LiteralPath $ResultPath
        }
        New-CandidateSmokeLease $request
        Write-AtomicJsonFile $RequestPath $request
        Start-ScheduledTask -TaskName $TaskName
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $result = $null
        while ((Get-Date) -lt $deadline) {
            if (Test-Path $ResultPath) {
                $raw = Get-Content -Encoding UTF8 -Raw -Path $ResultPath
                $result = $raw | ConvertFrom-Json
                Assert-ResultMatchesRequest $result $requestId $leaseId $ExpectedSha256 $ExpectedBuildId
                if (Test-Path -LiteralPath $LeasePath) {
                    $result = $null
                    Start-Sleep -Milliseconds 500
                    continue
                }
                $raw
                break
            }
            $scheduledTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if (-not $scheduledTask -or $scheduledTask.State -ne 'Running') {
                throw 'candidate smoke task stopped without matching result'
            }
            Start-Sleep -Milliseconds 500
        }
        if ($null -eq $result) {
            $scheduledTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($scheduledTask -and $scheduledTask.State -eq 'Running') {
                Write-AtomicJsonFile $DeadlinePath $request
                throw 'candidate smoke deadline expired while task remains running; lease preserved for manual diagnosis'
            }
            throw 'candidate smoke deadline expired without matching result'
        }
        if ($result.ok -ne $true) {
            throw 'candidate smoke result reported failure'
        }
    } finally {
        $runMutex.ReleaseMutex()
        $runMutex.Dispose()
    }
}

if ($Mode -eq 'Execute') {
    $temp = $null
    $requestId = ''
    $leaseId = ''
    $expectedSha256 = ''
    $expectedBuildId = ''
    $buildId = ''
    $resultPayload = $null
    $failureMessage = $null
    $networkPhase = $null
    $executionPhase = $null
    $leaseVerified = $false
    $cleanupComplete = $true
    $cliEvidence = $null
    $requiresGuiSmoke = $null
    try {
        $request = Get-Content -Encoding UTF8 -Raw -Path $RequestPath | ConvertFrom-Json
        $requestId = [string]$request.request_id
        Assert-RequestId $requestId
        $leaseId = [string]$request.lease_id
        Assert-RequestId $leaseId
        $metadataUrl = [string]$request.candidate_metadata_url
        $metadataUri = [Uri]$metadataUrl
        Assert-CandidateTransportUri $metadataUri
        $expectedSha256 = ([string]$request.expected_sha256).ToLowerInvariant()
        if ($expectedSha256 -notmatch '^[0-9a-f]{64}$') { throw 'candidate request SHA256 pin is invalid' }
        $expectedBuildId = [string]$request.expected_build_id
        Get-CandidateSmokeLease $request | Out-Null
        $leaseVerified = $true
        $networkPhase = 'metadata_get'
        $metadata = Invoke-RestMethod -Uri $metadataUrl -Method Get -MaximumRedirection 0 -TimeoutSec $NetworkTimeoutSeconds
        $networkPhase = $null
        foreach ($field in @('build_id', 'source_commit', 'sha256', 'size_bytes', 'download_url', 'requires_gui_smoke')) {
            if ($null -eq $metadata.$field -or [string]::IsNullOrWhiteSpace([string]$metadata.$field)) {
                throw "candidate metadata field is missing: $field"
            }
        }
        if ($metadata.requires_gui_smoke -isnot [bool]) {
            throw 'candidate metadata requires_gui_smoke must be boolean'
        }
        if ($metadata.signed -ne $false -or $metadata.candidate_status -notin @('unsigned-candidate', 'unsigned-validated-candidate')) {
            throw 'candidate metadata does not describe an unsigned candidate'
        }
        $metadataSha256 = ([string]$metadata.sha256).ToLowerInvariant()
        if ($metadataSha256 -notmatch '^[0-9a-f]{64}$' -or $metadataSha256 -cne $expectedSha256) {
            throw 'metadata SHA256 does not match expected pin'
        }
        $buildId = [string]$metadata.build_id
        if (-not [string]::IsNullOrWhiteSpace($expectedBuildId) -and $buildId -cne $expectedBuildId) {
            throw 'metadata build_id does not match expected build identity'
        }
        $requiresGuiSmoke = [bool]$metadata.requires_gui_smoke

        $temp = Join-Path ([IO.Path]::GetTempPath()) "fairypam-candidate-smoke-$([guid]::NewGuid())"
        $extract = Join-Path $temp 'package'
        $zip = Join-Path $temp 'candidate.zip'
        New-Item -ItemType Directory -Force -Path $extract | Out-Null
        $downloadUri = [Uri]::new($metadataUri, [string]$metadata.download_url)
        Assert-CandidateTransportUri $downloadUri
        $networkPhase = 'zip_get'
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUri -OutFile $zip -MaximumRedirection 0 -TimeoutSec $NetworkTimeoutSeconds
        $networkPhase = $null
        if ((Get-Item -LiteralPath $zip).Length -ne [long]$metadata.size_bytes) {
            throw 'downloaded candidate size does not match metadata'
        }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
        if ($hash -ne $expectedSha256) {
            throw 'downloaded candidate SHA256 does not match expected pin'
        }

        $executionPhase = 'extract_manifest'
        Assert-ExactCandidateZip $zip
        Expand-Archive -LiteralPath $zip -DestinationPath $extract
        $expected = @('BUILD-MANIFEST.json', 'README.txt', 'fairypam-agent-tauri-ui.exe', 'fairypam-agent.exe')
        $actual = @(Get-ChildItem -File -LiteralPath $extract | Sort-Object Name | Select-Object -ExpandProperty Name)
        if ((Get-ChildItem -Directory -LiteralPath $extract) -or (Compare-Object $expected $actual)) {
            throw "candidate ZIP members are not exact: $($actual -join ', ')"
        }
        $inner = Get-Content -Encoding UTF8 -Raw -Path (Join-Path $extract 'BUILD-MANIFEST.json') | ConvertFrom-Json
        if ($inner.build_id -ne $metadata.build_id -or $inner.source_commit -ne $metadata.source_commit -or $inner.signed -ne $false -or $inner.requires_gui_smoke -ne $metadata.requires_gui_smoke) {
            throw 'inner build manifest does not match candidate metadata'
        }
        $executionPhase = $null

        $env:FAIRYPAM_CANDIDATE_EXE = Join-Path $extract 'fairypam-agent.exe'
        $env:FAIRYPAM_CANDIDATE_BUILD_ID = [string]$metadata.build_id
        $env:FAIRYPAM_CANDIDATE_SOURCE_COMMIT = [string]$metadata.source_commit
        $env:FAIRYPAM_CANDIDATE_SHA256 = $hash
        $cliEvidencePath = Join-Path $temp 'cli-smoke-result.json'
        $env:FAIRYPAM_CANDIDATE_EVIDENCE_PATH = $cliEvidencePath
        $executionPhase = 'cli_harness'
        & node $HarnessPath
        if ($LASTEXITCODE -ne 0) {
            throw "packaged candidate smoke failed with exit code $LASTEXITCODE"
        }
        $cliEvidence = Get-Content -Encoding UTF8 -Raw -Path $cliEvidencePath | ConvertFrom-Json
        if ($cliEvidence.ok -ne $true) {
            throw 'CLI safe smoke evidence is not successful'
        }
        $executionPhase = $null
        $resultPayload = [ordered]@{
            schema_version = 1
            gate = 'RUST-CLI-SAFE'
            ok = $cliEvidence.ok -eq $true
            completion_receipt = $true
            request_id = $requestId
            lease_id = $leaseId
            expected_sha256 = $expectedSha256
            expected_build_id = $expectedBuildId
            build_id = $buildId
            source_commit = [string]$metadata.source_commit
            sha256 = $hash
            saw_hello = $cliEvidence.saw_hello -eq $true
            saw_heartbeat = $cliEvidence.saw_heartbeat -eq $true
            log_initialized = $cliEvidence.log_initialized -eq $true
            process_cleaned = $cliEvidence.process_cleaned -eq $true
            gui_smoke_required = $requiresGuiSmoke
            gui_smoke_executed = $false
            gui_smoke_passed = $null
            gui_window_visible = $null
            gui_process_cleaned = $null
            gui_gate = if ($requiresGuiSmoke) { 'TAURI-GUI-HUMAN:pending' } else { 'not-required' }
            network_phase = $networkPhase
            execution_phase = $executionPhase
            completed_at = (Get-Date).ToUniversalTime().ToString('o')
            message = [string]$cliEvidence.message
        }
    } catch {
        $failureMessage = $_.Exception.Message
    } finally {
        if ($temp) {
            try {
                Remove-Item -Recurse -Force -ErrorAction Stop -LiteralPath $temp
                if (Test-Path -LiteralPath $temp) {
                    throw 'candidate smoke temp directory remains'
                }
            } catch {
                $failureMessage = "candidate smoke cleanup failed: $($_.Exception.Message)"
                $resultPayload = $null
                $cleanupComplete = $false
            }
        }
    }
    if ($null -eq $resultPayload -or -not [string]::IsNullOrWhiteSpace($failureMessage)) {
        $resultPayload = [ordered]@{
            schema_version = 1
            gate = 'RUST-CLI-SAFE'
            ok = $false
            completion_receipt = $true
            request_id = $requestId
            lease_id = $leaseId
            expected_sha256 = $expectedSha256
            expected_build_id = $expectedBuildId
            build_id = $buildId
            sha256 = $expectedSha256
            network_phase = $networkPhase
            execution_phase = $executionPhase
            error = if ($failureMessage) { $failureMessage } else { 'candidate smoke execution failed' }
            completed_at = (Get-Date).ToUniversalTime().ToString('o')
        }
        if ($null -ne $cliEvidence -and $cliEvidence.ok -eq $true) {
            $resultPayload.saw_hello = $cliEvidence.saw_hello -eq $true
            $resultPayload.saw_heartbeat = $cliEvidence.saw_heartbeat -eq $true
            $resultPayload.log_initialized = $cliEvidence.log_initialized -eq $true
            $resultPayload.process_cleaned = $cliEvidence.process_cleaned -eq $true
        }
    }
    if (-not $leaseVerified) {
        exit 1
    }
    if (-not $cleanupComplete) { exit 1 }
    if (Test-CandidateSmokeDeadline $request) { exit 1 }
    Clear-CandidateSmokeLease $request
    Write-AtomicJsonFile $ResultPath $resultPayload
    if ($resultPayload.ok -eq $true) { exit 0 }
    exit 1
}
