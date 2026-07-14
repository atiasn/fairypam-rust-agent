#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
RUNTIME="$ROOT_DIR/src/agent_runtime.rs"

grep -Fq 'RunLevel Limited' "$ROOT_DIR/scripts/candidate-smoke-runner.ps1"
grep -Fq 'spawn(executable, ["--safe-smoke", "--config"' "$ROOT_DIR/scripts/package-smoke-test.js"
grep -Fq 'maxRetries: 10' "$ROOT_DIR/scripts/package-smoke-test.js"
grep -Fq 'retryDelay: 100' "$ROOT_DIR/scripts/package-smoke-test.js"
grep -Fq 'child.once("close"' "$ROOT_DIR/scripts/package-smoke-test.js"

safe_connection="$(sed -n '/async fn run_safe_smoke_connection/,/^async fn run_agent_connection/p' "$RUNTIME")"
printf '%s\n' "$safe_connection" | grep -Fq 'WsClient::connect'
printf '%s\n' "$safe_connection" | grep -Fq 'HubMessage::Heartbeat'
if printf '%s\n' "$safe_connection" | grep -Eq 'ScreenCapture|InputController|ProcessManager'; then
  printf '[ERROR] safe smoke must not initialize capture, input, or process operations\n' >&2
  exit 1
fi

printf '[PASS] candidate smoke stays limited and uses safe-smoke mode\n'
