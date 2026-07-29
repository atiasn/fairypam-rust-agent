param(
    [Parameter(Mandatory = $true)][string]$EvidenceKind,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$RunAttempt,
    [Parameter(Mandatory = $true)][string]$BuildId,
    [Parameter(Mandatory = $true)][string]$AgentDirectory,
    [Parameter(Mandatory = $true)][string]$GuardianDirectory,
    [Parameter(Mandatory = $true)][string]$AgentZip,
    [Parameter(Mandatory = $true)][string]$GuardianZip,
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'

if ($EvidenceKind -cnotmatch '^csharp-windows-(?:slice[1-5]-preliminary|slice2-live-test)$') { throw 'evidence kind is invalid' }
if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'source commit is invalid' }
if ($RunId -notmatch '^[1-9][0-9]*$') { throw 'run id is invalid' }
if ($RunAttempt -notmatch '^[1-9][0-9]*$') { throw 'run attempt is invalid' }
if ($BuildId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw 'build id is invalid' }

$artifacts = @($AgentZip, $GuardianZip) | ForEach-Object {
    $file = Get-Item -LiteralPath $_
    [ordered]@{
        name = $file.Name
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = [int64]$file.Length
    }
}

$files = @(
    @{ name = 'agent'; path = $AgentDirectory },
    @{ name = 'guardian'; path = $GuardianDirectory }
) | ForEach-Object {
    $component = $_.name
    $root = (Get-Item -LiteralPath $_.path).FullName
    Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
        [ordered]@{
            component = $component
            path = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = [int64]$_.Length
        }
    }
} | Sort-Object component, path

$manifest = [ordered]@{
    schema_version = 1
    evidence_kind = $EvidenceKind
    formal_gate = 'CSHARP-WINDOWS-BUILD'
    formal_gate_status = 'blocked'
    promotable = $false
    source_commit = $SourceCommit
    build_id = $BuildId
    runtime_identifier = 'win-x64'
    files = @($files)
}
$manifestParent = Split-Path -Parent $ManifestPath
New-Item -ItemType Directory -Path $manifestParent -Force | Out-Null
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ManifestPath -Encoding utf8NoBOM
$manifestFile = Get-Item -LiteralPath $ManifestPath
$dotnetSdk = & dotnet --version
if ($LASTEXITCODE -ne 0) { throw 'dotnet --version failed' }

$receipt = [ordered]@{
    schema_version = 1
    evidence_kind = $EvidenceKind
    formal_gate = 'CSHARP-WINDOWS-BUILD'
    formal_gate_status = 'blocked'
    result = 'passed'
    promotable = $false
    source_commit = $SourceCommit
    run_id = [int64]$RunId
    run_attempt = [int]$RunAttempt
    build_id = $BuildId
    dotnet_sdk = $dotnetSdk.Trim()
    runtime_identifier = 'win-x64'
    test_result = 'passed'
    publish_result = 'passed'
    manifest_sha256 = (Get-FileHash -LiteralPath $manifestFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    manifest_size = [int64]$manifestFile.Length
    artifacts = $artifacts
}

$parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
