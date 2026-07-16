#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
candidate_packager="$root/../ops/rust-agent-public/scripts/package-windows-candidate.ps1"
local_packager="$root/scripts/build-and-test.bat"

for packager in "$candidate_packager" "$local_packager"; do
  grep -Fq 'BUILD-MANIFEST.json' "$packager"
  grep -Fq 'README.txt' "$packager"
  grep -Fq 'fairypam-agent.exe' "$packager"
  grep -Fq 'fairypam-agent-tauri-ui.exe' "$packager"
done

grep -Fq '$PayloadMembers' "$candidate_packager"
grep -Fq '$MemberIdentities' "$candidate_packager"
grep -Fq 'attestation_identity' "$candidate_packager"
grep -Fq 'Get-FileHash' "$candidate_packager"
grep -Fq 'Compare-Object $ExpectedPayloadMembers $ManifestMembers' "$candidate_packager"
! grep -Fq '@($ArchivedManifest.members.PSObject.Properties.Name | Sort-Object) -ne @($PayloadMembers | Sort-Object)' "$candidate_packager"
! grep -Eiq 'self[_-]?digest' "$candidate_packager"
! grep -Eiq 'self[_-]?digest' "$local_packager"
