param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Lock,
    [Parameter(Mandatory = $true)][string]$SignedManifest,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$runtimeLock = Get-Content -LiteralPath $Lock -Raw | ConvertFrom-Json
if ($runtimeLock.schema_version -ne 1 -or
    $runtimeLock.sdk_version -cne '5.12.3' -or
    $runtimeLock.release_asset -cne 'MAA-win-x86_64-v5.12.3.zip') {
    throw 'MAA runtime lock is not the frozen FairyPam compatibility profile'
}
$archiveHash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($archiveHash -cne $runtimeLock.release_sha256) {
    throw 'MAA release archive SHA-256 does not match the runtime lock'
}
$signed = Get-Content -LiteralPath $SignedManifest -Raw | ConvertFrom-Json
if ($signed.content.sdk_version -cne $runtimeLock.sdk_version -or
    [string]::IsNullOrWhiteSpace($signed.content_sha256) -or
    [string]::IsNullOrWhiteSpace($signed.signature)) {
    throw 'signed MAA runtime manifest does not match the runtime lock'
}

$staging = "$Output.staging-$PID"
if ((Test-Path -LiteralPath $Output) -or (Test-Path -LiteralPath $staging)) {
    throw 'MAA runtime output or staging directory already exists'
}
$expanded = Join-Path $staging 'expanded'
$runtime = Join-Path $staging 'runtime'
New-Item -ItemType Directory -Path $expanded, $runtime | Out-Null
Expand-Archive -LiteralPath $Archive -DestinationPath $expanded

$versionRoot = Join-Path $runtime "versions\$($runtimeLock.sdk_version)"
foreach ($file in $runtimeLock.files) {
    $relative = $file.path -replace '/', '\'
    $source = Join-Path $expanded $relative
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "MAA runtime file is missing from the official archive: $($file.path)"
    }
    $actual = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $file.sha256) {
        throw "MAA runtime file SHA-256 mismatch: $($file.path)"
    }
    $destination = Join-Path $versionRoot $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination
}

Copy-Item -LiteralPath $Lock -Destination (Join-Path $runtime 'maa-runtime.lock.json')
Copy-Item -LiteralPath $SignedManifest -Destination (Join-Path $runtime 'maa-runtime.manifest.json')
New-Item -ItemType Directory -Path (Join-Path $runtime 'licenses') | Out-Null
Copy-Item -LiteralPath (Join-Path $expanded 'LICENSE.md') -Destination (Join-Path $runtime 'licenses\MAA-LICENSE.md')
[ordered]@{
    schema_version = 1
    active_version = '5.12.3'
    previous_stable_version = $null
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtime 'active.json') -Encoding utf8

Move-Item -LiteralPath $runtime -Destination $Output
Remove-Item -LiteralPath $staging -Recurse -Force
