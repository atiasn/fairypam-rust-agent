param(
    [ValidateSet('Register', 'Run', 'Execute', 'Unregister')]
    [string]$Mode = 'Run',
    [ValidateSet('Safe', 'Device')]
    [string]$Suite = 'Safe',
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$TaskName = "FairyPamAgentElevated${Suite}Smoke"
$SmokeScript = Join-Path $PSScriptRoot 'smoke-test.js'
$ResultPath = Join-Path $PSScriptRoot "..\target\elevated-$($Suite.ToLower())-smoke-result.json"

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-JsonResult($Payload) {
    $parent = Split-Path -Parent $ResultPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Payload | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 -Path $ResultPath
}

if ($Mode -eq 'Register') {
    $script = $PSCommandPath
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$script`"",
        '-Mode', 'Execute',
        '-Suite', $Suite
    ) -join ' '
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    Write-Host "registered fixed elevated smoke task: $TaskName"
    exit 0
}

if ($Mode -eq 'Unregister') {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "unregistered fixed elevated smoke task: $TaskName"
    exit 0
}

if ($Mode -eq 'Run') {
    Remove-Item -ErrorAction SilentlyContinue -Path $ResultPath
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $ResultPath) {
            $raw = Get-Content -Raw -Path $ResultPath
            $raw
            if (($raw | ConvertFrom-Json).error) {
                exit 1
            }
            exit 0
        }
        Start-Sleep -Milliseconds 500
    }
    throw "timed out waiting for elevated smoke result: $ResultPath"
}

if ($Mode -eq 'Execute') {
    try {
        $elevated = Test-IsElevated
        $env:FAIRYPAM_SMOKE_SUITE = $Suite.ToLower()
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $OutputEncoding = [Console]::OutputEncoding
        $smokeRaw = & node $SmokeScript 2>&1
        if ($LASTEXITCODE -ne 0) {
            $detail = ($smokeRaw | Select-Object -Last 1)
            throw "CLI smoke failed with exit code $LASTEXITCODE`: $detail"
        }
        $payload = [ordered]@{
            task = $TaskName
            suite = $Suite
            elevated = $elevated
            completed_at = (Get-Date).ToString('o')
            smoke = ($smokeRaw | ConvertFrom-Json)
        }
        Write-JsonResult $payload
        if (-not $elevated) {
            exit 2
        }
        exit 0
    } catch {
        Write-JsonResult ([ordered]@{
            task = $TaskName
            suite = $Suite
            elevated = $elevated
            completed_at = (Get-Date).ToString('o')
            error = $_.Exception.Message
        })
        exit 1
    }
}
