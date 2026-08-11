#!/usr/bin/env bash
set -euo pipefail

demo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$demo_dir/../.." && pwd)"
typescript_bin="$repo_root/bindings/typescript/node_modules/.bin/tsc"

if [[ ! -x "$typescript_bin" ]]; then
  echo "TypeScript compiler missing; run npm install in bindings/typescript" >&2
  exit 1
fi

run_dir="$(mktemp -d "${TMPDIR:-/tmp}/auths-incident-demo.XXXXXX")"
cert_dir="$run_dir/certs"
mkdir -p "$cert_dir" "$run_dir/state"
fingerprint="$($demo_dir/scripts/generate-local-certs.sh "$cert_dir")"
service_token="$(openssl rand -hex 24)"

cleanup() {
  trap - EXIT INT TERM
  for pid in ${demo_pids:-}; do kill "$pid" 2>/dev/null || true; done
  wait ${demo_pids:-} 2>/dev/null || true
  rm -rf "$run_dir"
}
trap cleanup EXIT INT TERM

"$typescript_bin" -p "$demo_dir/northstar-service/tsconfig.json"
"$typescript_bin" -p "$demo_dir/control-room/tsconfig.json"
AUTHS_INCIDENT_AGENT_API="http://localhost:7103" node "$demo_dir/control-room/build.mjs"

PORT=7101 \
NORTHSTAR_PUBLIC_URL=http://localhost:7101 \
NORTHSTAR_STATE_PATH="$run_dir/state/northstar.json" \
AUTHS_INCIDENT_ALLOWED_ORIGIN=http://localhost:7100 \
AUTHS_INCIDENT_SERVICE_TOKEN="$service_token" \
node "$demo_dir/northstar-service/dist/server.js" >"$run_dir/northstar.log" 2>&1 &
demo_pids="$!"

PORT=7102 \
EDGESHIELD_STATE_PATH="$run_dir/state/edgeshield.json" \
EDGESHIELD_CLIENT_CERT_FINGERPRINT="$fingerprint" \
cargo run --quiet -p auths-cross-company-incident-edgeshield-demo >"$run_dir/edgeshield.log" 2>&1 &
demo_pids="$demo_pids $!"

PORT=7103 \
AUTHS_REPO_ROOT="$repo_root" \
PYTHONPATH="$repo_root/bindings/python/python:$demo_dir/agent-service" \
AGENT_STATE_PATH="$run_dir/state/agent.sqlite3" \
NORTHSTAR_URL=http://localhost:7101 \
EDGESHIELD_URL=http://localhost:7102 \
AUTHS_INCIDENT_ALLOWED_ORIGIN=http://localhost:7100 \
AUTHS_INCIDENT_SERVICE_TOKEN="$service_token" \
EDGESHIELD_CLIENT_CERT_FINGERPRINT="$fingerprint" \
python3 -m auths_incident_agent.server >"$run_dir/agent.log" 2>&1 &
demo_pids="$demo_pids $!"

python3 -m http.server 7100 --bind 127.0.0.1 --directory "$demo_dir/control-room/public" >"$run_dir/control-room.log" 2>&1 &
demo_pids="$demo_pids $!"

for url in http://localhost:7101/healthz http://localhost:7102/healthz http://localhost:7103/healthz http://localhost:7100/; do
  ready=0
  for _ in {1..90}; do
    if curl --fail --silent "$url" >/dev/null; then ready=1; break; fi
    sleep 1
  done
  if [[ "$ready" != 1 ]]; then
    echo "Service did not become ready: $url" >&2
    echo "Logs: $run_dir" >&2
    exit 1
  fi
done

echo "Auths cross-company incident response is ready:"
echo "  Control room  http://localhost:7100"
echo "  Northstar     http://localhost:7101"
echo "  EdgeShield    http://localhost:7102"
echo "  Agent API     http://localhost:7103"
echo "Press Ctrl-C to stop. Runtime data is isolated in $run_dir"
wait
