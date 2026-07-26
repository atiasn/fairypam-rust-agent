#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
script="$root/scripts/dev-install.ps1"
provision="$root/scripts/dev-provision.ps1"
agentctl="$root/bins/fairypam-agentctl/src/main.rs"

test -f "$script"
test -f "$provision"
test -f "$agentctl"
for required in 'atiasn/fairypam-rust-agent' '312470124' 'fairypam-agent-dev-$RunId' "attestation', 'verify" '--signer-workflow' '--deny-self-hosted-runners' 'ExpectedRunId' 'dev.artifact.relay_invalid' 'dev.artifact.run_invalid' 'dev.artifact.hash_mismatch' 'dev.artifact.members_invalid' '.verified-dev-artifact.json' 'dev.task.busy' 'Replace-DevSlot' 'Sync-CanonicalTestbed' 'C:\FairyPam\Testbed\fairypam-test-window.exe' 'fairypam-agent-testbed.exe'; do
  grep -Fq -- "$required" "$script" || {
    printf '[ERROR] Dev installer contract missing: %s\n' "$required" >&2
    exit 1
  }
done
if grep -Fq -- '[IO.File]::Replace($temporary, $canonicalTestbed, $null)' "$script" ||
  ! grep -Fq -- '[IO.File]::Replace($temporary, $canonicalTestbed, $backup)' "$script" ||
  ! grep -Fq -- 'Remove-Item -LiteralPath $temporary, $backup' "$script"; then
  printf '[ERROR] Dev Testbed replacement must use and clean a real backup path for Windows PowerShell 5.1\n' >&2
  exit 1
fi
for required in 'Assert-VerifiedDevSlot' 'Get-InteractiveProvisionIdentity' 'Get-InteractiveShellLogonSid' 'Get-Process -Name explorer' 'LogonSidForProcess' 'TokenStatistics' 'AuthenticationId' 'dev.task.artifact_proof_missing' 'dev.task.artifact_proof_invalid' 'dev.task.logon_session_query_failed' 'dev.task.interactive_session_required' 'dev.task.fixed_action_required' 'Stop-RunningDevAgent' "Get-Process -Name 'fairypam-agent'" 'Stop-Process -Id $process.Id' 'Wait-Process -Id $process.Id' 'Unregister-ScheduledTask -TaskName $taskName' '.dev-provision-result.json' 'Write-ProvisionResult'; do
  grep -Fq -- "$required" "$provision" || {
    printf '[ERROR] Dev provision contract missing: %s\n' "$required" >&2
    exit 1
  }
done
if grep -Fq -- 'CurrentLogonSid' "$provision"; then
  printf '[ERROR] Dev provision must bind the desktop shell Logon SID, not the UAC token\n' >&2
  exit 1
fi
for required in 'Start-Process -FilePath' '-PassThru' '-ErrorAction Stop' '$process.ExitCode' '.dev-provision-result.json'; do
  grep -Fq -- "$required" "$agentctl" || {
    printf '[ERROR] Dev launcher contract missing: %s\n' "$required" >&2
    exit 1
  }
done

printf '[PASS] Dev installer fixed-trust contract\n'
