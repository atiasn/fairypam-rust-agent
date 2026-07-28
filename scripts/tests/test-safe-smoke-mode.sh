#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

grep -Fq 'RunLevel Limited' "$ROOT_DIR/scripts/candidate-smoke-runner.ps1"
grep -Fq 'spawn(executable, ["--safe-smoke", "--config"' "$ROOT_DIR/scripts/package-smoke-test.js"
grep -Fq 'maxRetries: 10' "$ROOT_DIR/scripts/package-smoke-test.js"
grep -Fq 'retryDelay: 100' "$ROOT_DIR/scripts/package-smoke-test.js"
grep -Fq 'child.once("close"' "$ROOT_DIR/scripts/package-smoke-test.js"

printf '[PASS] candidate smoke stays limited and uses safe-smoke mode\n'
