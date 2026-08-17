#!/bin/sh
set -eu
compose_file=$(CDPATH= cd -- "$(dirname -- "$0")/../compose" && pwd)/compose.yaml
compose_dir=$(dirname -- "$compose_file")
ca="$compose_dir/postgres/certs/ca.crt"

# Every check below used to fail as a bare curl exit code. `exit 35` on a
# TLS handshake told a reader nothing about which container was wrong, whether
# it was even running, or what it logged. Report the state on the way out.
diagnose() {
  status=$?
  [ "$status" -eq 0 ] && exit 0
  echo "--- compose-smoke failed (exit $status): $1" >&2
  if [ -f "$ca" ]; then
    echo "--- CA validity" >&2
    openssl x509 -in "$ca" -noout -subject -dates >&2 2>&1 || true
    echo "--- ingress certificate validity" >&2
    openssl x509 -in "$compose_dir/ingress/certs/server.crt" -noout -subject -dates >&2 2>&1 || true
    echo "--- does the CA sign the ingress certificate?" >&2
    openssl verify -CAfile "$ca" "$compose_dir/ingress/certs/server.crt" >&2 2>&1 || true
  else
    echo "--- no CA at $ca; run tests/generate-local-certificates.sh first" >&2
  fi
  echo "--- container state" >&2
  docker compose -f "$compose_file" ps >&2 2>&1 || true
  echo "--- ingress log" >&2
  docker compose -f "$compose_file" logs --tail 40 ingress >&2 2>&1 || true
  echo "--- verbose handshake" >&2
  curl --verbose --cacert "$ca" https://localhost:8443/live >&2 2>&1 || true
  exit "$status"
}
trap 'diagnose "$step"' EXIT

step="docker compose config"
docker compose -f "$compose_file" config >/dev/null

step="https://localhost:8443/live through the TLS ingress"
curl --fail --silent --cacert "$ca" https://localhost:8443/live >/dev/null

step="https://localhost:8443/ready through the TLS ingress"
curl --fail --silent --cacert "$ca" https://localhost:8443/ready >/dev/null

for port in 18081 18082 18083; do
  step="http://localhost:$port/ready"
  curl --fail --silent "http://localhost:$port/ready" >/dev/null
  step="http://localhost:$port/metrics exposes auths_operations_total"
  curl --fail --silent "http://localhost:$port/metrics" | grep -q 'auths_operations_total'
done
