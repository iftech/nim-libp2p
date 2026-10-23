#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
work_dir=$(mktemp -d)
nim_pid=
cleanup() {
  if [[ -n "$nim_pid" ]]; then
    kill "$nim_pid" 2>/dev/null || true
    wait "$nim_pid" 2>/dev/null || true
  fi
  cat "$work_dir/nim.log"
  rm -rf "$work_dir"
}
trap cleanup EXIT

./build/topic-streams-nim "$work_dir/address" >"$work_dir/nim.log" 2>&1 &
nim_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  if [[ -s "$work_dir/address" ]]; then
    timeout 50 ./build/topic-streams-go "$work_dir/address"
    exit 0
  fi
  if ! kill -0 "$nim_pid" 2>/dev/null; then
    echo "Nim peer exited before listening" >&2
    exit 1
  fi
  sleep 0.1
done
echo "Timed out waiting for the Nim peer" >&2
exit 1
