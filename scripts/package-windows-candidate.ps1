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
    [AllowNull()]
    [string]$ValidatedBasePublicCommit = $null,
    [bool]$RequiresGuiSmoke = $true,
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'
$NormalizedValidatedBasePublicCommit = if ([string]::IsNullOrWhiteSpace($ValidatedBasePublicCommit)) { $null } else { $ValidatedBasePublicCommit.ToLowerInvariant() }
if ($null -ne $NormalizedValidatedBasePublicCommit -and $NormalizedValidatedBasePublicCommit -notmatch '^[0-9a-f]{40,64}$') {
    throw 'ValidatedBasePublicCommit must be null or a full hexadecimal commit'
}
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

    @"
FairyPam Rust Agent unsigned candidate

Build ID: $BuildId
Source commit: $SourceCommit

This is not a stable release and is not Authenticode signed.
The package intentionally does not include config.yaml or credentials.
Only promote it in FairyPam Hub after required candidate smoke gates pass.
"@ | Set-Content -Encoding utf8 -Path (Join-Path $Stage 'README.txt')

    $PayloadMembers = @('README.txt', 'fairypam-agent.exe', 'fairypam-agent-tauri-ui.exe')
    $MemberIdentities = [ordered]@{}
    foreach ($member in $PayloadMembers) {
        $item = Get-Item -LiteralPath (Join-Path $Stage $member)
        $MemberIdentities[$member] = [ordered]@{
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size_bytes = [int64]$item.Length
        }
    }
    $BuiltAt = (Get-Date).ToUniversalTime().ToString('o')
    $BuildManifest = [ordered]@{
        schema_version = 1
        kind = 'fairypam-windows-agent-candidate'
        build_id = $BuildId
        source_commit = $SourceCommit.ToLowerInvariant()
        public_commit = $PublicCommit.ToLowerInvariant()
        validated_base_public_commit = $NormalizedValidatedBasePublicCommit
        workflow_run_id = $RunId
        workflow_run_attempt = $RunAttempt
        built_at = $BuiltAt
        signed = $false
        attestation_identity = "actions:$RunId.$RunAttempt"
        tauri_gui_changed = $RequiresGuiSmoke
        requires_gui_smoke = $RequiresGuiSmoke
        members = $MemberIdentities
        gates = [ordered]@{
            'WINDOWS-BUILD' = 'passed'
            'RUST-CLI-SAFE' = 'pending'
            'TAURI-GUI-SMOKE' = $(if ($RequiresGuiSmoke) { 'pending' } else { 'not_required' })
        }
    }
    $BuildManifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path (Join-Path $Stage 'BUILD-MANIFEST.json')

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
        $ManifestEntry = $Archive.GetEntry('BUILD-MANIFEST.json')
        if ($null -eq $ManifestEntry) { throw 'candidate BUILD-MANIFEST.json is missing' }
        $ManifestReader = [IO.StreamReader]::new($ManifestEntry.Open(), [Text.Encoding]::UTF8)
        try {
            $ArchivedManifest = $ManifestReader.ReadToEnd() | ConvertFrom-Json
        } finally {
            $ManifestReader.Dispose()
        }
    } finally {
        $Archive.Dispose()
    }
    if (Compare-Object $ExpectedMembers $ZipMembers) {
        throw "candidate ZIP members are not exact: $($ZipMembers -join ', ')"
    }
    $ManifestMembers = @($ArchivedManifest.members.PSObject.Properties.Name | Sort-Object)
    $ExpectedPayloadMembers = @($PayloadMembers | Sort-Object)
    if ($ArchivedManifest.build_id -cne $BuildId -or
        $ArchivedManifest.source_commit -cne $SourceCommit.ToLowerInvariant() -or
        $ArchivedManifest.attestation_identity -cne "actions:$RunId.$RunAttempt" -or
        $null -eq $ArchivedManifest.members -or
        (Compare-Object $ExpectedPayloadMembers $ManifestMembers)) {
        throw 'candidate BUILD-MANIFEST identity is invalid'
    }
    foreach ($member in $PayloadMembers) {
        $identity = $ArchivedManifest.members.$member
        $item = Get-Item -LiteralPath (Join-Path $Stage $member)
        if ($null -eq $identity -or
            $identity.sha256 -cne (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -or
            [int64]$identity.size_bytes -ne [int64]$item.Length) {
            throw "candidate BUILD-MANIFEST payload identity is invalid: $member"
        }
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
        validated_base_public_commit = $NormalizedValidatedBasePublicCommit
        workflow_run_id = $RunId
        workflow_run_attempt = $RunAttempt
        built_at = $BuiltAt
        signed = $false
        requires_gui_smoke = $RequiresGuiSmoke
        file_name = $PackageName
        sha256 = $Hash
        size_bytes = $Size
        gates = [ordered]@{
            'WINDOWS-BUILD' = 'passed'
            'RUST-CLI-SAFE' = 'pending'
            'TAURI-GUI-SMOKE' = $(if ($RequiresGuiSmoke) { 'pending' } else { 'not_required' })
        }
    }
    $CandidateManifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path (Join-Path $Output 'candidate-manifest.json')
    "$Hash  $PackageName" | Set-Content -Encoding ascii -Path (Join-Path $Output 'SHA256SUMS')
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $Stage
}
