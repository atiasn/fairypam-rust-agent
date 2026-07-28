param(
    [ValidateSet('Register', 'Run', 'Execute', 'Unregister')]
    [string]$Mode = 'Run',
    [string]$CandidateMetadataUrl = '',
    [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
$TaskName = 'FairyPamAgentCandidateSafeSmoke'
$RequestPath = Join-Path $PSScriptRoot '..\target\candidate-smoke-request.json'
$ResultPath = Join-Path $PSScriptRoot '..\target\candidate-smoke-result.json'
$HarnessPath = Join-Path $PSScriptRoot 'package-smoke-test.js'

function Write-JsonFile([string]$Path, $Payload) {
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Payload | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 -Path $Path
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
    if ($CandidateMetadataUrl -notmatch '^https?://') {
        throw 'CandidateMetadataUrl must use http or https'
    }
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        throw "scheduled task is not registered; run -Mode Register once: $TaskName"
    }
    Write-JsonFile $RequestPath ([ordered]@{ candidate_metadata_url = $CandidateMetadataUrl })
    Remove-Item -ErrorAction SilentlyContinue -Path $ResultPath
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $ResultPath) {
            $raw = Get-Content -Raw -Path $ResultPath
            $raw
            if (($raw | ConvertFrom-Json).ok -ne $true) {
                exit 1
            }
            exit 0
        }
        Start-Sleep -Milliseconds 500
    }
    throw "timed out waiting for candidate smoke result: $ResultPath"
}

if ($Mode -eq 'Execute') {
    $temp = $null
    try {
        $request = Get-Content -Raw -Path $RequestPath | ConvertFrom-Json
        $metadataUrl = [string]$request.candidate_metadata_url
        if ($metadataUrl -notmatch '^https?://') {
            throw 'invalid candidate metadata URL'
        }
        $metadata = Invoke-RestMethod -Uri $metadataUrl -Method Get
        foreach ($field in @('build_id', 'source_commit', 'sha256', 'size_bytes', 'download_url')) {
            if ($null -eq $metadata.$field -or [string]::IsNullOrWhiteSpace([string]$metadata.$field)) {
                throw "candidate metadata field is missing: $field"
            }
        }
        if ($metadata.signed -ne $false -or $metadata.candidate_status -notin @('unsigned-candidate', 'unsigned-validated-candidate')) {
            throw 'candidate metadata does not describe an unsigned candidate'
        }

        $temp = Join-Path ([IO.Path]::GetTempPath()) "fairypam-candidate-smoke-$([guid]::NewGuid())"
        $extract = Join-Path $temp 'package'
        $zip = Join-Path $temp 'candidate.zip'
        New-Item -ItemType Directory -Force -Path $extract | Out-Null
        $downloadUri = [Uri]::new([Uri]$metadataUrl, [string]$metadata.download_url)
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUri -OutFile $zip
        if ((Get-Item -LiteralPath $zip).Length -ne [long]$metadata.size_bytes) {
            throw 'downloaded candidate size does not match metadata'
        }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
        if ($hash -ne ([string]$metadata.sha256).ToLowerInvariant()) {
            throw 'downloaded candidate SHA256 does not match metadata'
        }

        Expand-Archive -LiteralPath $zip -DestinationPath $extract
        $expected = @('BUILD-MANIFEST.json', 'README.txt', 'fairypam-agent-tauri-ui.exe', 'fairypam-agent.exe')
        $actual = @(Get-ChildItem -File -LiteralPath $extract | Sort-Object Name | Select-Object -ExpandProperty Name)
        if ((Get-ChildItem -Directory -LiteralPath $extract) -or (Compare-Object $expected $actual)) {
            throw "candidate ZIP members are not exact: $($actual -join ', ')"
        }
        $inner = Get-Content -Raw -Path (Join-Path $extract 'BUILD-MANIFEST.json') | ConvertFrom-Json
        if ($inner.build_id -ne $metadata.build_id -or $inner.source_commit -ne $metadata.source_commit -or $inner.signed -ne $false) {
            throw 'inner build manifest does not match candidate metadata'
        }

        $env:FAIRYPAM_CANDIDATE_EXE = Join-Path $extract 'fairypam-agent.exe'
        $env:FAIRYPAM_CANDIDATE_BUILD_ID = [string]$metadata.build_id
        $env:FAIRYPAM_CANDIDATE_SOURCE_COMMIT = [string]$metadata.source_commit
        $env:FAIRYPAM_CANDIDATE_SHA256 = $hash
        $env:FAIRYPAM_CANDIDATE_EVIDENCE_PATH = $ResultPath
        & node $HarnessPath
        if ($LASTEXITCODE -ne 0) {
            throw "packaged candidate smoke failed with exit code $LASTEXITCODE"
        }
        exit 0
    } catch {
        if (-not (Test-Path $ResultPath)) {
            Write-JsonFile $ResultPath ([ordered]@{
                schema_version = 1
                gate = 'RUST-CLI-SAFE'
                ok = $false
                error = $_.Exception.Message
                completed_at = (Get-Date).ToUniversalTime().ToString('o')
            })
        }
        exit 1
    } finally {
        if ($temp) {
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $temp
        }
    }
}
