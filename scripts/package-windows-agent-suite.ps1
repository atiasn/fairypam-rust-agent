param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$BuildId,
    [Parameter(Mandatory=$true)][string]$SourceCommit,
    [Parameter(Mandatory=$true)][string]$PublicCommit,
    [Parameter(Mandatory=$true)][string]$Workflow,
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$RunAttempt,
    [Parameter(Mandatory=$true)][string]$SuiteVersion,
    [Parameter(Mandatory=$true)][string]$TargetDirectory,
    [Parameter(Mandatory=$true)][string]$GuiExecutable,
    [string]$SecurityPolicyPath = $env:FAIRYPAM_PRODUCTION_SECURITY_POLICY,
    [string]$SetupSigner,
    [string[]]$SetupSignerArguments = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
$target = [IO.Path]::GetFullPath($TargetDirectory)
$stage = Join-Path $output '.suite-stage'
$payloadStage = Join-Path $output '.suite-payload-stage'
$payloadSuite = Join-Path $payloadStage 'suite'
$payloadArchive = Join-Path $output '.suite-payload.zip'
$fileName = 'fairypam-agent-suite-windows-x64-' + $BuildId + '.zip'
$packagePath = Join-Path $output $fileName
$required = [ordered]@{
    'FairyPamAgentSetup.exe' = (Join-Path $target 'FairyPamAgentSetup.exe')
    'fairypam-agent.exe' = (Join-Path $target 'fairypam-agent.exe')
    'fairypam-agent-guardian.exe' = (Join-Path $target 'fairypam-agent-guardian.exe')
    'fairypam-agent-updater.exe' = (Join-Path $target 'fairypam-agent-updater.exe')
    'fairypam-agent-ui.exe' = [IO.Path]::GetFullPath($GuiExecutable)
    'fairypam-agentctl.exe' = (Join-Path $target 'fairypam-agentctl.exe')
    'protocol/fairypam-agent-v1.proto' = (Join-Path $root 'proto/fairypam/agent/v1/agent.proto')
    'resources/install-windows-agent-suite.ps1' = (Join-Path $root 'scripts/install-windows-agent-suite.ps1')
    'resources/update-windows-agent-suite.ps1' = (Join-Path $root 'scripts/update-windows-agent-suite.ps1')
    'resources/profiles/fairypam-test-window/profile.json' = (Join-Path $root 'profiles/fairypam-test-window/profile.json')
    'resources/profiles/genshin-impact/profile.json' = (Join-Path $root 'profiles/genshin-impact/profile.json')
    'resources/test-profile-root-public-key.hex' = (Join-Path $root 'test-profile-root-public-key.hex')
}

if ($BuildId -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') { throw 'invalid build id' }
if ($SourceCommit -notmatch '^[a-fA-F0-9]{40,64}$' -or $PublicCommit -notmatch '^[a-fA-F0-9]{40,64}$') { throw 'source/public commits must be full hashes' }
foreach ($source in $required.Values) { if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "suite member is missing: $source" } }
if ([string]::IsNullOrWhiteSpace($SecurityPolicyPath)) { throw 'production security policy is required' }
if (-not [IO.Path]::IsPathRooted($SecurityPolicyPath)) { throw 'production security policy must be an absolute file' }
$SecurityPolicyPath = [IO.Path]::GetFullPath($SecurityPolicyPath)
$policyItem = Get-Item -Force -LiteralPath $SecurityPolicyPath -ErrorAction Stop
if (-not $policyItem.PSIsContainer -and ($policyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $policyItem.Length -le 65536) {
    $policyRaw = [IO.File]::ReadAllText($SecurityPolicyPath, [Text.Encoding]::UTF8)
} else {
    throw 'production security policy must be a small regular non-reparse file'
}
if ($policyRaw -match '(?i)TODO|CHANGEME|example\.(com|org|net)') { throw 'production security policy contains placeholder values' }
try { $policy = $policyRaw | ConvertFrom-Json } catch { throw 'production security policy is invalid JSON' }
$rootFields = @($policy.PSObject.Properties.Name | Sort-Object)
if (Compare-Object $rootFields @('suite_authenticode_publisher','tuf')) { throw 'production security policy fields are not exact' }
$tufFields = @($policy.tuf.PSObject.Properties.Name | Sort-Object)
$expectedTufFields = @('datastore_dir','metadata_url','target_name','targets_url','trusted_root','verifier_authenticode_publisher','verifier_executable') | Sort-Object
if (Compare-Object $tufFields $expectedTufFields) { throw 'production TUF policy fields are not exact' }
foreach ($publisher in @([string]$policy.suite_authenticode_publisher,[string]$policy.tuf.verifier_authenticode_publisher)) {
    if ([string]::IsNullOrWhiteSpace($publisher) -or $publisher -notmatch '=') { throw 'production publisher subject is invalid' }
}
foreach ($path in @([string]$policy.tuf.verifier_executable,[string]$policy.tuf.trusted_root,[string]$policy.tuf.datastore_dir)) {
    if (-not [IO.Path]::IsPathRooted($path)) { throw 'production TUF paths must be absolute' }
}
foreach ($url in @([string]$policy.tuf.metadata_url,[string]$policy.tuf.targets_url)) {
    $uri = $null
    if (-not [Uri]::TryCreate($url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https') { throw 'production TUF URLs must use HTTPS' }
}
if ([IO.Path]::GetFileName([string]$policy.tuf.target_name) -cne [string]$policy.tuf.target_name) { throw 'production TUF target_name must be a basename' }

function New-SuiteManifest([string]$Root) {
    $members = [ordered]@{}
    foreach ($entry in $required.GetEnumerator()) {
        $path = Join-Path $Root $entry.Key
        $item = Get-Item -LiteralPath $path
        $members[$entry.Key] = [ordered]@{sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();size_bytes=[int64]$item.Length}
    }
    return [ordered]@{
        schema_version=2
        kind='fairypam-windows-agent-suite'
        build_id=$BuildId
        source_commit=$SourceCommit.ToLowerInvariant()
        public_commit=$PublicCommit.ToLowerInvariant()
        suite_version=$SuiteVersion
        platform='windows-x64'
        build_source=[ordered]@{workflow=$Workflow;run_id=$RunId;run_attempt=$RunAttempt}
        compatibility=[ordered]@{agent_protocol_major=1;guardian_protocol_major=1;local_protocol_major=1}
        members=$members
    }
}

New-Item -ItemType Directory -Force -Path $output | Out-Null
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $stage,$payloadStage
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $payloadArchive
New-Item -ItemType Directory -Path $payloadStage | Out-Null
foreach ($entry in $required.GetEnumerator()) {
    $destination = Join-Path $payloadSuite $entry.Key
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -Force -LiteralPath $entry.Value -Destination $destination
}
$payloadManifest = New-SuiteManifest $payloadSuite
[IO.File]::WriteAllText((Join-Path $payloadSuite 'BUILD-MANIFEST.json'), (ConvertTo-Json $payloadManifest -Depth 6), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $payloadStage 'production-security-policy.json'), $policyRaw, [Text.UTF8Encoding]::new($false))
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($payloadStage, $payloadArchive, [IO.Compression.CompressionLevel]::Optimal, $false)
$payloadDigest = (Get-FileHash -LiteralPath $payloadArchive -Algorithm SHA256).Hash.ToLowerInvariant()

Copy-Item -Recurse -LiteralPath $payloadSuite -Destination $stage
$setupPath = Join-Path $stage 'FairyPamAgentSetup.exe'
$setupBytes = [IO.File]::ReadAllBytes($setupPath)
$placeholder = [Text.Encoding]::ASCII.GetBytes('FAIRYPAM-SUITE-PAYLOAD-SHA256:' + ('0' * 64))
$matches = [Collections.Generic.List[int]]::new()
# ponytail: one bounded binary scan; replace with a PE section parser only if the layout changes.
for ($offset = 0; $offset -le $setupBytes.Length - $placeholder.Length; $offset++) {
    $matchesAtOffset = $true
    for ($index = 0; $index -lt $placeholder.Length; $index++) {
        if ($setupBytes[$offset + $index] -ne $placeholder[$index]) { $matchesAtOffset = $false; break }
    }
    if ($matchesAtOffset) { $matches.Add($offset) }
}
if ($matches.Count -ne 1) { throw 'setup payload digest placeholder must occur exactly once' }
$digestBytes = [Text.Encoding]::ASCII.GetBytes($payloadDigest)
[Array]::Copy($digestBytes, 0, $setupBytes, $matches[0] + 30, $digestBytes.Length)
[IO.File]::WriteAllBytes($setupPath, $setupBytes)

if (-not [string]::IsNullOrWhiteSpace($SetupSigner)) {
    if (-not [IO.Path]::IsPathRooted($SetupSigner)) { throw 'setup signer must be an existing absolute executable' }
    $SetupSigner = [IO.Path]::GetFullPath($SetupSigner)
    if (-not (Test-Path -LiteralPath $SetupSigner -PathType Leaf)) { throw 'setup signer must be an existing absolute executable' }
    & $SetupSigner @SetupSignerArguments $setupPath
    if ($LASTEXITCODE -ne 0) { throw "setup signer failed with exit code $LASTEXITCODE" }
}

$setup = [IO.File]::Open($setupPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::None)
$payload = [IO.File]::OpenRead($payloadArchive)
try {
    $payload.CopyTo($setup)
    $setup.Write([BitConverter]::GetBytes([int64]$payload.Length), 0, 8)
    $marker = [Text.Encoding]::ASCII.GetBytes('FAIRYPAM-SUITE-PAYLOAD1')
    $setup.Write($marker, 0, $marker.Length)
}
finally {
    $payload.Dispose()
    $setup.Dispose()
}
$manifest = New-SuiteManifest $stage
$manifestPath = Join-Path $stage 'BUILD-MANIFEST.json'
[IO.File]::WriteAllText($manifestPath, (ConvertTo-Json $manifest -Depth 6), [Text.UTF8Encoding]::new($false))
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $packagePath
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $packagePath, [IO.Compression.CompressionLevel]::Optimal, $false)
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$asset = Get-Item -LiteralPath $packagePath
$candidate = [ordered]@{
    schema_version=2
    kind='fairypam-windows-agent-suite-candidate'
    build_id=$BuildId
    platform='windows-x64'
    source_commit=$SourceCommit.ToLowerInvariant()
    public_commit=$PublicCommit.ToLowerInvariant()
    validated_base_public_commit=$null
    suite_version=$SuiteVersion
    signed=$false
    promotable=$false
    requires_gui_smoke=$true
    gates=[ordered]@{'WINDOWS-BUILD'='passed';'TUF'='pending';'AUTHENTICODE'='pending';'RUST-CLI-SAFE'='pending';'WINDOWS-SUITE-CLI'='pending';'TAURI-GUI-HUMAN'='pending'}
    file_name=$fileName
    sha256=(Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    size_bytes=[int64]$asset.Length
    suite_manifest_sha256=$manifestHash
    built_at=[DateTimeOffset]::UtcNow.ToString('O')
    build_source=$manifest.build_source
}
[IO.File]::WriteAllText((Join-Path $output 'candidate-manifest.json'), (ConvertTo-Json $candidate -Depth 5), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS'), ($candidate.sha256 + '  ' + $fileName + [Environment]::NewLine), [Text.Encoding]::ASCII)
Remove-Item -Recurse -Force -LiteralPath $stage,$payloadStage
Remove-Item -Force -LiteralPath $payloadArchive
Write-Output $packagePath
