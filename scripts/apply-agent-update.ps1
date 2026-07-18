param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ParamsPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string]$Code) {
    [Console]::Error.WriteLine($Code)
    exit 1
}

function Read-StrictParams([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { Fail 'agent_update_helper_params_invalid' }
    $acl = Get-Acl -LiteralPath $Path
    $unsafeWriter = @($acl.Access | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' -and
        $_.IdentityReference.Value -match 'Everyone|Authenticated Users|\\Users$'
    })
    if ($unsafeWriter.Count -ne 0) { Fail 'agent_update_helper_params_acl_invalid' }
    $raw = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $params = $raw | ConvertFrom-Json
    $required = @(
        'schema_version', 'attempt_nonce', 'old_executable', 'old_executable_sha256',
        'old_pid', 'target_executable', 'target_executable_sha256', 'mode',
        'handoff_path', 'marker_directory', 'timeout_seconds', 'update_id',
        'source_build_id', 'target_build_id', 'prior_connection_id', 'agent_id',
        'promotion_id', 'rollback_handoff_path'
    )
    foreach ($name in $required) {
        if ($null -eq $params.PSObject.Properties[$name] -or [string]::IsNullOrWhiteSpace([string]$params.$name)) {
            Fail 'agent_update_helper_params_invalid'
        }
    }
    if ($params.schema_version -ne 1 -or $params.mode -notin @('cli', 'gui')) {
        Fail 'agent_update_helper_params_invalid'
    }
    if ($params.attempt_nonce -notmatch '^[A-Za-z0-9_-]{16,128}$') { Fail 'agent_update_helper_params_invalid' }
    foreach ($pathName in @('old_executable', 'target_executable', 'handoff_path', 'rollback_handoff_path', 'marker_directory')) {
        if (-not [IO.Path]::IsPathRooted([string]$params.$pathName)) { Fail 'agent_update_helper_params_invalid' }
    }
    return $params
}

function Get-PackageBuildId([string]$Executable) {
    $manifestPath = Join-Path (Split-Path -Parent $Executable) 'BUILD-MANIFEST.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { Fail 'agent_update_helper_manifest_invalid' }
    $manifest = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$manifest.build_id)) { Fail 'agent_update_helper_manifest_invalid' }
    return [string]$manifest.build_id
}

function Write-RollbackHandoff($Params, [string]$RunningBuildId) {
    if ($RunningBuildId -ne $Params.source_build_id) { Fail 'agent_update_helper_old_build_mismatch' }
    $handoff = [ordered]@{
        schema_version = 1
        mode = 'rollback'
        agent_id = $Params.agent_id
        promotion_id = $Params.promotion_id
        update_id = $Params.update_id
        attempt_nonce = $Params.attempt_nonce
        source_build_id = $Params.source_build_id
        target_build_id = $Params.target_build_id
        prior_connection_id = $Params.prior_connection_id
        running_build_id = $RunningBuildId
    }
    $json = ConvertTo-Json -InputObject $handoff -Depth 3 -Compress
    $stream = [IO.File]::Open($Params.rollback_handoff_path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
        try { $writer.Write($json) } finally { $writer.Dispose() }
    } finally {
        $stream.Dispose()
    }
}

function Get-Sha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail 'agent_update_helper_file_missing' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$params = Read-StrictParams $ParamsPath
$marker = Join-Path $params.marker_directory ($params.attempt_nonce + '.pending')
$ready = Join-Path $params.marker_directory ($params.attempt_nonce + '.ready')
$createdMarker = $false
$newProcess = $null

try {
    [IO.Directory]::CreateDirectory($params.marker_directory) | Out-Null
    $markerStream = [IO.File]::Open($marker, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $markerStream.Dispose()
    $createdMarker = $true

    if ((Get-Sha256 $params.old_executable) -ne $params.old_executable_sha256.ToLowerInvariant()) {
        Fail 'agent_update_helper_old_exe_hash_mismatch'
    }
    if ((Get-Sha256 $params.target_executable) -ne $params.target_executable_sha256.ToLowerInvariant()) {
        Fail 'agent_update_helper_target_exe_hash_mismatch'
    }
    $oldBuildId = Get-PackageBuildId $params.old_executable
    if ($oldBuildId -ne $params.source_build_id) { Fail 'agent_update_helper_old_build_mismatch' }

    $old = Get-Process -Id ([int]$params.old_pid) -ErrorAction SilentlyContinue
    if ($null -ne $old) { $old.WaitForExit() }

    $workingDirectory = Split-Path -Parent $params.target_executable
    $arguments = if ($params.mode -eq 'gui') { '--gui' } else { '--run' }
    $env:FAIRYPAM_AGENT_UPDATE_HANDOFF = $params.handoff_path
    $env:FAIRYPAM_AGENT_UPDATE_MARKER = $marker
    $newProcess = Start-Process -FilePath $params.target_executable -ArgumentList $arguments -WorkingDirectory $workingDirectory -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds([int]$params.timeout_seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $ready -PathType Leaf) {
            $receipt = [IO.File]::ReadAllText($ready, [Text.Encoding]::UTF8) | ConvertFrom-Json
            if ($receipt.update_id -eq $params.update_id -and
                $receipt.attempt_nonce -eq $params.attempt_nonce -and
                $receipt.source_build_id -eq $params.source_build_id -and
                $receipt.target_build_id -eq $params.target_build_id -and
                $receipt.prior_connection_id -eq $params.prior_connection_id -and
                $receipt.running_build_id -eq $params.target_build_id) {
                exit 0
            }
            break
        }
        if ($newProcess.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }

    if ($null -ne $newProcess -and -not $newProcess.HasExited) { Stop-Process -Id $newProcess.Id -Force }
    Write-RollbackHandoff $params $oldBuildId
    $env:FAIRYPAM_AGENT_UPDATE_HANDOFF = $params.rollback_handoff_path
    Remove-Item Env:FAIRYPAM_AGENT_UPDATE_MARKER -ErrorAction SilentlyContinue
    Start-Process -FilePath $params.old_executable -ArgumentList $arguments -WorkingDirectory (Split-Path -Parent $params.old_executable) | Out-Null
    Fail 'agent_update_helper_handoff_timeout'
}
finally {
    if ($createdMarker) { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ParamsPath -Force -ErrorAction SilentlyContinue
}
