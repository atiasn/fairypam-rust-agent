#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
helper="$root/scripts/apply-agent-update.ps1"

grep -Fq '[IO.FileMode]::CreateNew' "$helper"
grep -Fq 'Get-Acl -LiteralPath $Path' "$helper"
grep -Fq 'Get-Sha256 $params.old_executable' "$helper"
grep -Fq 'Get-Sha256 $params.target_executable' "$helper"
grep -Fq "@('cli', 'gui')" "$helper"
grep -Fq 'FAIRYPAM_AGENT_UPDATE_HANDOFF' "$helper"
grep -Fq 'FAIRYPAM_AGENT_UPDATE_MARKER' "$helper"
grep -Fq 'rollback_handoff_path' "$helper"
grep -Fq 'BUILD-MANIFEST.json' "$helper"
grep -Fq "mode = 'rollback'" "$helper"
grep -Fq 'FAIRYPAM_AGENT_UPDATE_HANDOFF = $params.rollback_handoff_path' "$helper"
grep -Fq 'Remove-Item Env:FAIRYPAM_AGENT_UPDATE_MARKER' "$helper"
grep -Fq 'agent_update_helper_handoff_timeout' "$helper"
grep -Fq 'Start-Process -FilePath $params.old_executable' "$helper"
! grep -Fq -- "-ArgumentList '--run' -WorkingDirectory (Split-Path -Parent \$params.old_executable)" "$helper"
grep -Fq 'Remove-Item -LiteralPath $ParamsPath -Force' "$helper"
! grep -Fq 'Invoke-Expression' "$helper"
