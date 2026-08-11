#!/usr/bin/env bash
set -euo pipefail

demo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$demo_dir/../.." && pwd)"
log_file="$(mktemp "${TMPDIR:-/tmp}/auths-incident-demo-test.XXXXXX.log")"

cleanup() {
  trap - EXIT INT TERM
  kill "$launcher_pid" 2>/dev/null || true
  wait "$launcher_pid" 2>/dev/null || true
  rm -f "$log_file"
}
trap cleanup EXIT INT TERM

"$demo_dir/scripts/launch-local.sh" >"$log_file" 2>&1 &
launcher_pid=$!
for _ in {1..120}; do
  if curl --fail --silent http://localhost:7103/healthz >/dev/null; then break; fi
  if ! kill -0 "$launcher_pid" 2>/dev/null; then cat "$log_file"; exit 1; fi
  sleep 1
done

PYTHONPATH="$repo_root/bindings/python/python:$demo_dir/agent-service" \
  uv run pytest -q "$demo_dir/agent-service/tests"
python3 "$demo_dir/tests/integration.py"
node "$demo_dir/tests/browser-smoke.mjs"
cargo test -p auths-cross-company-incident-edgeshield-demo
echo "auths-incident-demo local validation passed"
