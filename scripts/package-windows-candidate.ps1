param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$BuildId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40,64}$')]
    [string]$SourceCommit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40,64}$')]
    [string]$PublicCommit,
    [Parameter(Mandatory = $true)]
    [string]$RunId,
    [Parameter(Mandatory = $true)]
    [string]$RunAttempt,
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$CoreExe = Join-Path $Root 'target/release/fairypam-agent.exe'
$TauriExe = Join-Path $Root 'tauri-ui/src-tauri/target/release/fairypam-agent-tauri-ui.exe'

foreach ($path in @($CoreExe, $TauriExe)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required candidate executable is missing: $path"
    }
}

$Output = Join-Path $Root $OutputDirectory
if (Test-Path -LiteralPath $Output) {
    Remove-Item -Recurse -Force -LiteralPath $Output
}
New-Item -ItemType Directory -Force -Path $Output | Out-Null

$Stage = Join-Path ([IO.Path]::GetTempPath()) "fairypam-agent-candidate-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
try {
    Copy-Item -LiteralPath $CoreExe -Destination (Join-Path $Stage 'fairypam-agent.exe')
    Copy-Item -LiteralPath $TauriExe -Destination (Join-Path $Stage 'fairypam-agent-tauri-ui.exe')

    $BuiltAt = (Get-Date).ToUniversalTime().ToString('o')
    $BuildManifest = [ordered]@{
        schema_version = 1
        kind = 'fairypam-windows-agent-candidate'
        build_id = $BuildId
        source_commit = $SourceCommit.ToLowerInvariant()
        public_commit = $PublicCommit.ToLowerInvariant()
        workflow_run_id = $RunId
        workflow_run_attempt = $RunAttempt
        built_at = $BuiltAt
        signed = $false
        gates = [ordered]@{
            'WINDOWS-BUILD' = 'passed'
            'RUST-CLI-SAFE' = 'pending'
        }
    }
    $BuildManifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path (Join-Path $Stage 'BUILD-MANIFEST.json')

    @"
FairyPam Rust Agent unsigned candidate

Build ID: $BuildId
Source commit: $SourceCommit

This is not a stable release and is not Authenticode signed.
The package intentionally does not include config.yaml or credentials.
Only promote it in FairyPam Hub after RUST-CLI-SAFE smoke passes.
"@ | Set-Content -Encoding utf8 -Path (Join-Path $Stage 'README.txt')

    $ExpectedMembers = @(
        'BUILD-MANIFEST.json',
        'README.txt',
        'fairypam-agent-tauri-ui.exe',
        'fairypam-agent.exe'
    )
    $ActualMembers = @(Get-ChildItem -File -LiteralPath $Stage | Sort-Object Name | Select-Object -ExpandProperty Name)
    if (Compare-Object $ExpectedMembers $ActualMembers) {
        throw "candidate staging members are not exact: $($ActualMembers -join ', ')"
    }

    $PackageName = "fairypam-agent-$BuildId-windows-x64-portable.zip"
    $PackagePath = Join-Path $Output $PackageName
    Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $PackagePath -CompressionLevel Optimal

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Archive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        $ZipMembers = @($Archive.Entries | Sort-Object FullName | Select-Object -ExpandProperty FullName)
    } finally {
        $Archive.Dispose()
    }
    if (Compare-Object $ExpectedMembers $ZipMembers) {
        throw "candidate ZIP members are not exact: $($ZipMembers -join ', ')"
    }

    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $PackagePath).Hash.ToLowerInvariant()
    $Size = (Get-Item -LiteralPath $PackagePath).Length
    $CandidateManifest = [ordered]@{
        schema_version = 1
        kind = 'fairypam-windows-agent-candidate'
        build_id = $BuildId
        version = $BuildId
        platform = 'windows-x64'
        source_commit = $SourceCommit.ToLowerInvariant()
        public_commit = $PublicCommit.ToLowerInvariant()
        workflow_run_id = $RunId
        workflow_run_attempt = $RunAttempt
        built_at = $BuiltAt
        signed = $false
        file_name = $PackageName
        sha256 = $Hash
        size_bytes = $Size
        gates = [ordered]@{
            'WINDOWS-BUILD' = 'passed'
            'RUST-CLI-SAFE' = 'pending'
        }
    }
    $CandidateManifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path (Join-Path $Output 'candidate-manifest.json')
    "$Hash  $PackageName" | Set-Content -Encoding ascii -Path (Join-Path $Output 'SHA256SUMS')
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $Stage
}
