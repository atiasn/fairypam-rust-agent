#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
RUNNER="$ROOT_DIR/agent/scripts/candidate-smoke-runner.ps1"
PACKAGER="$ROOT_DIR/ops/rust-agent-public/scripts/package-windows-candidate.ps1"
WORKFLOW="$ROOT_DIR/ops/rust-agent-public/.github/workflows/windows-candidate.yml"
CLEIAGENT="$ROOT_DIR/scripts/run-cleiagent.sh"

grep -Fq 'git diff --name-only' "$WORKFLOW"
grep -Fq '$requiresGuiSmoke = $true' "$WORKFLOW"
grep -Fq 'tauri-ui/' "$WORKFLOW"
grep -Fq 'src/' "$WORKFLOW"
grep -Fq 'Cargo\.toml' "$WORKFLOW"
grep -Fq 'Cargo\.lock' "$WORKFLOW"
grep -Fq 'rust-toolchain\.toml' "$WORKFLOW"
grep -Fq 'build\.rs' "$WORKFLOW"
grep -Fq 'scripts/package-windows-candidate.ps1' "$WORKFLOW"
grep -Fq 'scripts/candidate-smoke-runner\.ps1' "$WORKFLOW"
grep -Fq 'requires_gui_smoke' "$PACKAGER"
test "$(grep -Fc 'requires_gui_smoke' "$PACKAGER")" -ge 2
grep -Fq 'gui_smoke_required' "$RUNNER"
grep -Fq '$requiresGuiSmoke = [bool]$metadata.requires_gui_smoke' "$RUNNER"
grep -Fq 'gui_smoke_executed = $false' "$RUNNER"
grep -Fq 'gui_smoke_passed = $null' "$RUNNER"
grep -Fq "gui_gate = if (\$requiresGuiSmoke) { 'TAURI-GUI-HUMAN:pending' } else { 'not-required' }" "$RUNNER"
grep -Fq 'ok = $cliEvidence.ok -eq $true' "$RUNNER"
! grep -Fq 'Invoke-CandidateGuiSmoke' "$RUNNER"
! grep -Fq 'Test-CandidateGuiWindowVisible' "$RUNNER"
! grep -Fq 'Start-Process -FilePath $GuiExecutable' "$RUNNER"
! grep -Fq 'Stop-Process -Id $process.Id' "$RUNNER"
! grep -Fq 'Wait-Process -Id $process.Id' "$RUNNER"
! grep -Fq 'IsWindowVisible' "$RUNNER"
! grep -Fq 'Add-Type -TypeDefinition' "$RUNNER"
! grep -Fq 'guiEvidence' "$RUNNER"
grep -Fq 'gui_smoke_passed' "$RUNNER"
grep -Fq 'ExpectedSha256' "$RUNNER"
grep -Fq 'metadata SHA256 does not match expected pin' "$RUNNER"
grep -Fq 'IsLoopback' "$RUNNER"
test "$(grep -Fc -- '-MaximumRedirection 0' "$RUNNER")" -eq 2
grep -Fq 'ZipFile]::OpenRead' "$RUNNER"
grep -Fq 'candidate ZIP members are not exact before extraction' "$RUNNER"
grep -Fq 'FairyPamAgentCandidateSafeSmokeRun' "$RUNNER"
grep -Fq 'WaitOne(0)' "$RUNNER"
grep -Fq 'request_id' "$RUNNER"
grep -Fq 'ExpectedBuildId' "$RUNNER"
grep -Fq 'expected_build_id' "$RUNNER"
grep -Fq 'Assert-ResultMatchesRequest' "$RUNNER"
grep -Fq 'candidate smoke run already active for this user' "$RUNNER"
grep -Fq "State -eq 'Running'" "$RUNNER"
grep -Fq 'candidate smoke result does not match request' "$RUNNER"
grep -Fq 'candidate-smoke-lease.json' "$RUNNER"
grep -Fq 'New-CandidateSmokeLease' "$RUNNER"
grep -Fq 'Get-CandidateSmokeLease' "$RUNNER"
grep -Fq 'Clear-CandidateSmokeLease' "$RUNNER"
grep -Fq 'FileMode]::CreateNew' "$RUNNER"
grep -Fq 'candidate smoke lease already exists; manual diagnosis required' "$RUNNER"
grep -Fq 'candidate smoke lease does not match request' "$RUNNER"
grep -Fq 'candidate smoke lease remains after result' "$RUNNER"
grep -Fq 'candidate smoke lease schema is invalid' "$RUNNER"
grep -Fq 'function Assert-CandidateSmokeSchemaVersion($SchemaVersion)' "$RUNNER"
grep -Fq '$SchemaVersion -isnot [int] -and $SchemaVersion -isnot [long]' "$RUNNER"
grep -Fq '[long]$SchemaVersion -ne [long]1' "$RUNNER"
grep -Fq 'Assert-CandidateSmokeSchemaVersion $lease.schema_version' "$RUNNER"
! grep -Fq '$lease.schema_version -isnot [long]' "$RUNNER"
grep -Fq 'completion_receipt' "$RUNNER"
grep -Fq 'lease_id' "$RUNNER"
grep -Fq 'if (-not $leaseVerified)' "$RUNNER"
grep -Fq 'Write-AtomicJsonFile $ResultPath' "$RUNNER"
grep -Fq '[int]$TimeoutSeconds = 210' "$RUNNER"
grep -Fq '$NetworkTimeoutSeconds = 60' "$RUNNER"
test "$(grep -Fc -- '-TimeoutSec $NetworkTimeoutSeconds' "$RUNNER")" -eq 2
grep -Fq '$networkPhase = $null' "$RUNNER"
grep -Fq "\$networkPhase = 'metadata_get'" "$RUNNER"
grep -Fq "\$networkPhase = 'zip_get'" "$RUNNER"
test "$(grep -Fc 'network_phase = $networkPhase' "$RUNNER")" -eq 2
grep -Fq "\$executionPhase = 'extract_manifest'" "$RUNNER"
grep -Fq "\$executionPhase = 'cli_harness'" "$RUNNER"
! grep -Fq "\$executionPhase = 'gui_harness'" "$RUNNER"
! grep -Fq "\$ExecutionPhase.Value = 'gui_process_start'" "$RUNNER"
grep -Fq '$cliEvidence = $null' "$RUNNER"
grep -Fq 'if ($null -ne $cliEvidence -and $cliEvidence.ok -eq $true)' "$RUNNER"
grep -Fq '$resultPayload.saw_hello = $cliEvidence.saw_hello -eq $true' "$RUNNER"
grep -Fq '$resultPayload.saw_heartbeat = $cliEvidence.saw_heartbeat -eq $true' "$RUNNER"
grep -Fq '$resultPayload.log_initialized = $cliEvidence.log_initialized -eq $true' "$RUNNER"
grep -Fq '$resultPayload.process_cleaned = $cliEvidence.process_cleaned -eq $true' "$RUNNER"
test "$(grep -Fc 'execution_phase = $executionPhase' "$RUNNER")" -eq 2
grep -Fq 'candidate-smoke-deadline.json' "$RUNNER"
grep -Fq 'function Test-CandidateSmokeDeadline($Request)' "$RUNNER"
grep -Fq 'Write-AtomicJsonFile $DeadlinePath $request' "$RUNNER"
grep -Fq 'candidate smoke deadline expired while task remains running; lease preserved for manual diagnosis' "$RUNNER"
grep -Fq 'if (Test-CandidateSmokeDeadline $request) { exit 1 }' "$RUNNER"
test "$(grep -Fc 'Get-Content -Encoding UTF8 -Raw' "$RUNNER")" -eq 6
! grep -Fq 'Get-Content -Raw' "$RUNNER"
grep -Fq 'System.Text.UTF8Encoding($false)' "$RUNNER"
grep -Fq "\$TargetDirectory = [IO.Path]::GetFullPath((Join-Path \$PSScriptRoot '..\\target'))" "$RUNNER"
grep -Fq "\$RequestPath = Join-Path \$TargetDirectory 'candidate-smoke-request.json'" "$RUNNER"
grep -Fq "\$ResultPath = Join-Path \$TargetDirectory 'candidate-smoke-result.json'" "$RUNNER"
grep -Fq "\$LeasePath = Join-Path \$TargetDirectory 'candidate-smoke-lease.json'" "$RUNNER"
grep -Fq '$targetPath = [IO.Path]::GetFullPath($Path)' "$RUNNER"
grep -Fq '$temporary = Join-Path $parent' "$RUNNER"
grep -Fq '[IO.File]::Replace($temporary, $targetPath, $null)' "$RUNNER"
grep -Fq '[IO.File]::Move($temporary, $targetPath)' "$RUNNER"
! grep -Fq 'Stop-ScheduledTask' "$RUNNER"
! grep -Fq 'candidate-smoke-active.json' "$RUNNER"
! grep -Fq 'FAIRYPAM_CANDIDATE_CLEANUP_STATE_PATH' "$RUNNER"
! grep -Fq 'FAIRYPAM_CANDIDATE_CLEANUP_STATE_PATH' "$ROOT_DIR/agent/scripts/package-smoke-test.js"
! grep -Fq 'FAIRYPAM_CANDIDATE_REQUEST_ID' "$ROOT_DIR/agent/scripts/package-smoke-test.js"
! grep -Fq 'Get-CimInstance' "$RUNNER"

lease_line="$(grep -n 'New-CandidateSmokeLease \$request' "$RUNNER" | cut -d: -f1)"
start_line="$(grep -n 'Start-ScheduledTask -TaskName \$TaskName' "$RUNNER" | cut -d: -f1)"
result_line="$(grep -n 'Write-AtomicJsonFile \$ResultPath \$resultPayload' "$RUNNER" | cut -d: -f1)"
clear_line="$(grep -n 'Clear-CandidateSmokeLease \$request' "$RUNNER" | cut -d: -f1)"
stale_result_clear_line="$(grep -n 'Remove-Item -Force -ErrorAction Stop -LiteralPath \$ResultPath' "$RUNNER" | cut -d: -f1)"
request_write_line="$(grep -n 'Write-AtomicJsonFile \$RequestPath \$request' "$RUNNER" | cut -d: -f1)"
poll_task_line="$(grep -n '\$scheduledTask = Get-ScheduledTask -TaskName \$TaskName' "$RUNNER" | tail -n 1 | cut -d: -f1)"
deadline_guard_line="$(grep -n 'if (Test-CandidateSmokeDeadline \$request) { exit 1 }' "$RUNNER" | cut -d: -f1)"
metadata_phase_line="$(grep -n "\$networkPhase = 'metadata_get'" "$RUNNER" | cut -d: -f1)"
metadata_get_line="$(grep -n 'Invoke-RestMethod -Uri \$metadataUrl' "$RUNNER" | cut -d: -f1)"
zip_phase_line="$(grep -n "\$networkPhase = 'zip_get'" "$RUNNER" | cut -d: -f1)"
zip_get_line="$(grep -n 'Invoke-WebRequest -UseBasicParsing -Uri \$downloadUri' "$RUNNER" | cut -d: -f1)"
extract_phase_line="$(grep -n "\$executionPhase = 'extract_manifest'" "$RUNNER" | cut -d: -f1)"
extract_line="$(grep -n 'Assert-ExactCandidateZip \$zip' "$RUNNER" | cut -d: -f1)"
cli_phase_line="$(grep -n "\$executionPhase = 'cli_harness'" "$RUNNER" | cut -d: -f1)"
cli_line="$(grep -n '& node \$HarnessPath' "$RUNNER" | cut -d: -f1)"
test "$stale_result_clear_line" -lt "$lease_line"
test "$lease_line" -lt "$start_line"
test "$request_write_line" -lt "$start_line"
test "$start_line" -lt "$poll_task_line"
test "$deadline_guard_line" -lt "$clear_line"
test "$metadata_phase_line" -lt "$metadata_get_line"
test "$zip_phase_line" -lt "$zip_get_line"
test "$extract_phase_line" -lt "$extract_line"
test "$cli_phase_line" -lt "$cli_line"
test "$clear_line" -lt "$result_line"
grep -Fq 'sync_candidate_smoke_sources' "$CLEIAGENT"
grep -Fq 'candidate-smoke-register' "$CLEIAGENT"
grep -Fq 'FAIRYPAM_AGENT_CANDIDATE_STORE' "$CLEIAGENT"
grep -Fq '$REPO_DIR/backend/dist/windows-agent' "$CLEIAGENT"
grep -Fq -- '--store "$CANDIDATE_STORE" inspect "$build_id"' "$CLEIAGENT"
grep -Fq 'candidate-smoke requires <build-id> <metadata-url>' "$CLEIAGENT"
grep -Fq -- '-ExpectedBuildId' "$CLEIAGENT"
grep -Fq '127.0.0.1:${remote_port}' "$CLEIAGENT"
grep -Fq 'status) status_agent' "$CLEIAGENT"
grep -Fq 'logs) tail_log' "$CLEIAGENT"
grep -Fq 'cleanup_tunnel' "$CLEIAGENT"
grep -Fq "trap 'cleanup_tunnel' EXIT" "$CLEIAGENT"
grep -Fq "trap 'cleanup_tunnel; exit 130' INT" "$CLEIAGENT"
grep -Fq "trap 'cleanup_tunnel; exit 143' TERM" "$CLEIAGENT"
grep -Fq 'trap - EXIT INT TERM' "$CLEIAGENT"
remote_run_line="$(grep -n "candidate-smoke-runner.ps1' -Mode Run" "$CLEIAGENT" | cut -d: -f1)"
tunnel_cleanup_line="$(grep -n '^  cleanup_tunnel$' "$CLEIAGENT" | tail -n 1 | cut -d: -f1)"
test "$remote_run_line" -lt "$tunnel_cleanup_line"
! grep -Fq 'manage-windows-agent-candidate.py" show' "$CLEIAGENT"
! grep -Fq 'sync) sync_agent' "$CLEIAGENT"
! grep -Fq 'build) build_agent' "$CLEIAGENT"
! grep -Fq 'verify) verify_agent' "$CLEIAGENT"
! grep -Fq 'cargo build' "$CLEIAGENT"

grep -Fq 'previous_validated_candidate_public_commit' "$WORKFLOW"
grep -Fq 'fetch-depth: 0' "$WORKFLOW"
grep -Fq 'git merge-base --is-ancestor' "$WORKFLOW"
grep -Fq '$base..HEAD' "$WORKFLOW"
grep -Fq "else { 'null' }" "$WORKFLOW"
! grep -Fq "else { 'none' }" "$WORKFLOW"
grep -Fq -- '-ValidatedBasePublicCommit $base' "$WORKFLOW"
grep -Fq '$NormalizedValidatedBasePublicCommit = if' "$PACKAGER"
grep -Fq 'IsNullOrWhiteSpace($ValidatedBasePublicCommit)) { $null } else { $ValidatedBasePublicCommit.ToLowerInvariant() }' "$PACKAGER"
grep -Fq '$null -ne $NormalizedValidatedBasePublicCommit -and $NormalizedValidatedBasePublicCommit -notmatch' "$PACKAGER"
grep -Fq 'ValidatedBasePublicCommit must be null or a full hexadecimal commit' "$PACKAGER"
test "$(grep -Fc 'validated_base_public_commit = $NormalizedValidatedBasePublicCommit' "$PACKAGER")" -eq 2
! grep -Fq '$ValidatedBasePublicCommit = if' "$PACKAGER"
grep -Fq 'must be null or a full hexadecimal commit' "$PACKAGER"
! grep -Fq 'git rev-parse HEAD^' "$WORKFLOW"

repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
git -C "$repo" init -q
git -C "$repo" config user.email smoke@example.invalid
git -C "$repo" config user.name smoke
git -C "$repo" commit --allow-empty -qm base
base="$(git -C "$repo" rev-parse HEAD)"

commit_path() {
  local path="$1"
  local content="$2"
  local message="$3"
  local blob
  blob="$(printf '%s' "$content" | git -C "$repo" hash-object -w --stdin)"
  git -C "$repo" update-index --add --cacheinfo "100644,$blob,$path"
  git -C "$repo" commit -qm "$message"
}

requires_gui_smoke() {
  local previous="${1:-}"
  local resolved
  if [ -z "$previous" ]; then
    return 0
  fi
  if ! resolved="$(git -C "$repo" rev-parse --verify "$previous^{commit}" 2>/dev/null)"; then
    return 0
  fi
  if ! git -C "$repo" merge-base --is-ancestor "$resolved" HEAD; then
    return 0
  fi
  git -C "$repo" diff --name-only "$resolved..HEAD" |
    grep -Eq '^(tauri-ui/|src/|Cargo\.toml$|Cargo\.lock$|rust-toolchain\.toml$|build\.rs$|scripts/package-windows-candidate\.ps1$|scripts/candidate-smoke-runner\.ps1$|\.github/workflows/windows-candidate\.yml$)'
}

validated_base_json() {
  local previous="${1:-}"
  local resolved
  if [ -z "$previous" ] || ! resolved="$(git -C "$repo" rev-parse --verify "$previous^{commit}" 2>/dev/null)" || ! git -C "$repo" merge-base --is-ancestor "$resolved" HEAD; then
    printf 'null\n'
  else
    printf '%s\n' "$resolved"
  fi
}

for shared_path in src/lib.rs Cargo.toml Cargo.lock rust-toolchain.toml build.rs; do
  printf '%s\n' "$shared_path" |
    grep -Eq '^(tauri-ui/|src/|Cargo\.toml$|Cargo\.lock$|rust-toolchain\.toml$|build\.rs$|scripts/package-windows-candidate\.ps1$|scripts/candidate-smoke-runner\.ps1$|\.github/workflows/windows-candidate\.yml$)'
done

commit_path 'tauri-ui/src/App.tsx' gui 'earlier GUI change'
commit_path 'src/lib.rs' cli 'later CLI change'
requires_gui_smoke "$base"
test "$(validated_base_json '')" = null
test "$(validated_base_json "$base")" = "$base"
requires_gui_smoke ''
requires_gui_smoke 'not-a-commit'
git -C "$repo" checkout -qb unrelated "$base"
commit_path 'src/lib.rs' unrelated 'non-ancestor change'
unrelated="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q -
requires_gui_smoke "$unrelated"

printf '[PASS] conditional GUI smoke contract\n'
