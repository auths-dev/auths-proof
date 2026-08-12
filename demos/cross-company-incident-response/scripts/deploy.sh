#!/usr/bin/env bash
set -euo pipefail

demo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$demo_dir/../.." && pwd)"
apps=(auths-incident-demo-northstar auths-incident-demo-edgeshield auths-incident-demo-agent)

for app in "${apps[@]}"; do
  if fly apps list --json | jq -e --arg app "$app" '.[] | select(.Name == $app)' >/dev/null; then
    echo "Refusing to modify existing Fly app: $app" >&2
    exit 1
  fi
done

if vercel project inspect auths-incident-demo-control-room >/dev/null 2>&1; then
  echo "Refusing to modify existing Vercel project: auths-incident-demo-control-room" >&2
  exit 1
fi

service_token="$(openssl rand -hex 32)"
cert_fingerprint="$(openssl rand -hex 32)"

fly apps create auths-incident-demo-northstar
fly apps create auths-incident-demo-edgeshield
fly apps create auths-incident-demo-agent

fly secrets set --app auths-incident-demo-northstar AUTHS_INCIDENT_SERVICE_TOKEN="$service_token"
fly secrets set --app auths-incident-demo-edgeshield EDGESHIELD_CLIENT_CERT_FINGERPRINT="$cert_fingerprint"
fly secrets set --app auths-incident-demo-agent AUTHS_INCIDENT_SERVICE_TOKEN="$service_token" EDGESHIELD_CLIENT_CERT_FINGERPRINT="$cert_fingerprint"

cd "$repo_root"
fly deploy . --ha=false --config demos/cross-company-incident-response/northstar-service/fly.toml --app auths-incident-demo-northstar
fly deploy . --ha=false --config demos/cross-company-incident-response/edgeshield-service/fly.toml --app auths-incident-demo-edgeshield
fly deploy . --ha=false --config demos/cross-company-incident-response/agent-service/fly.toml --app auths-incident-demo-agent

cd "$demo_dir/control-room"
AUTHS_INCIDENT_AGENT_API=https://auths-incident-demo-agent.fly.dev \
  npm run build
cd "$demo_dir/control-room/public"
vercel deploy --prod --yes --name auths-incident-demo-control-room
