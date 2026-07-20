#!/usr/bin/env bash
set -euo pipefail

test "$#" -gt 0 || {
  printf '[ERROR] usage: test-production-dev-isolation.sh <production binary>...\n' >&2
  exit 2
}
for binary in "$@"; do
  test -f "$binary"
  for forbidden in 'FairyPam Agent Dev' 'FairyPam.Agent.Dev.v1' 'fairypam-agent-testbed' 'fairypam-agent-dev-automation' 'dev-automation' 'dev-install.ps1' 'dev-provision.ps1' 'fault-injection'; do
    ! strings "$binary" | grep -Fq "$forbidden" || {
      printf '[ERROR] production binary contains Dev marker %s: %s\n' "$binary" "$forbidden" >&2
      exit 1
    }
  done
done
printf '[PASS] production Dev isolation scan\n'
