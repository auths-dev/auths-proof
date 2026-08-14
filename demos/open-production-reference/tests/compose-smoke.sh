#!/bin/sh
set -eu
compose_file=$(CDPATH= cd -- "$(dirname -- "$0")/../compose" && pwd)/compose.yaml
docker compose -f "$compose_file" config >/dev/null
curl --fail --silent --cacert "$(dirname -- "$compose_file")/postgres/certs/ca.crt" https://localhost:8443/live >/dev/null
curl --fail --silent --cacert "$(dirname -- "$compose_file")/postgres/certs/ca.crt" https://localhost:8443/ready >/dev/null
for port in 18081 18082 18083; do
  curl --fail --silent "http://localhost:$port/ready" >/dev/null
  curl --fail --silent "http://localhost:$port/metrics" | grep -q 'auths_operations_total'
done
