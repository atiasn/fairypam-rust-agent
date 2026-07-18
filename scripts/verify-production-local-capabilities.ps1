[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AgentPath,
    [Parameter(Mandatory = $true)][string]$AgentctlPath
)

$ErrorActionPreference = 'Stop'
$forbidden = [string[]]@(
    'DevStartAutomation',
    'DevEmergencyStop',
    'dev_start_automation',
    'dev_hold_testbed',
    'LiveGameArmChallenge',
    'provision_current_build',
    'fairypam-agent-testbed',
    'fairypam-agent-dev-provision',
    'fault_injection',
    'FAIRYPAM_DEV_AUTOMATION_BUILD_V1'
)

function Read-BinaryText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "production binary is missing: $Path"
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    return [Text.Encoding]::ASCII.GetString($bytes) + "`n" + [Text.Encoding]::Unicode.GetString($bytes)
}

$agent = Read-BinaryText $AgentPath
$agentctl = Read-BinaryText $AgentctlPath
foreach ($token in $forbidden) {
    if ($agent.Contains($token) -or $agentctl.Contains($token)) {
        throw "production capability scan found forbidden token: $token"
    }
}
if (-not $agent.Contains('UNSUPPORTED_CAPABILITY')) {
    throw 'production Agent does not contain the fail-closed UNSUPPORTED_CAPABILITY response code'
}

Write-Output 'production-local-capability-scan-ok'
