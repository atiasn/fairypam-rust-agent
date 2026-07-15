#!/usr/bin/env bash
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
EVIDENCE_PATH="$(mktemp)"
RUST_BIN="$(dirname "$(rustup which --toolchain 1.96.1 rustc)")"
trap 'rm -f "$EVIDENCE_PATH"' EXIT

if grep -Fq 'RunLevel Highest' "$AGENT_DIR/scripts/candidate-smoke-runner.ps1"; then
  printf '[ERROR] candidate safe smoke must not register an elevated task\n' >&2
  exit 1
fi
if ! grep -Fq 'socket.on("error"' "$AGENT_DIR/scripts/package-smoke-test.js"; then
  printf '[ERROR] package smoke must handle socket reset during process cleanup\n' >&2
  exit 1
fi

(
  cd "$AGENT_DIR"
  PATH="$RUST_BIN:$PATH" cargo build --locked
  CANDIDATE_EXE="$AGENT_DIR/target/debug/fairypam-agent"
  if [ -f "${CANDIDATE_EXE}.exe" ]; then
    CANDIDATE_EXE="${CANDIDATE_EXE}.exe"
  fi
  MANIFEST_PATH="$(dirname "$CANDIDATE_EXE")/BUILD-MANIFEST.json"
  if [ -e "$MANIFEST_PATH" ]; then
    printf '[ERROR] package smoke manifest path already exists: %s\n' "$MANIFEST_PATH" >&2
    exit 1
  fi
  trap 'rm -f "$MANIFEST_PATH"' EXIT
  printf '%s\n' '{"build_id":"local-package-smoke","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tauri_gui_changed":false,"attestation_identity":"local-package-smoke","members":{}}' > "$MANIFEST_PATH"
  FAIRYPAM_CANDIDATE_EXE="$CANDIDATE_EXE" \
  FAIRYPAM_CANDIDATE_BUILD_ID="local-package-smoke" \
  FAIRYPAM_CANDIDATE_SOURCE_COMMIT="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  FAIRYPAM_CANDIDATE_SHA256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  FAIRYPAM_CANDIDATE_EVIDENCE_PATH="$EVIDENCE_PATH" \
    node scripts/package-smoke-test.js
)

node -e '
const fs = require("fs");
const evidence = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const key of ["ok", "saw_hello", "saw_heartbeat", "log_initialized", "process_cleaned"]) {
  if (evidence[key] !== true) throw new Error(`${key} was not true`);
}
if (evidence.gate !== "RUST-CLI-SAFE") throw new Error("wrong gate");
' "$EVIDENCE_PATH"

printf '[PASS] packaged RUST-CLI-SAFE smoke\n'
