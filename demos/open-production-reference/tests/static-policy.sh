#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
grep -q 'replicas: 3' "$root/deploy/kubernetes/base/deployment.yaml"
grep -q 'readOnlyRootFilesystem: true' "$root/deploy/kubernetes/base/deployment.yaml"
grep -q 'capabilities: {drop: \[ALL\]}' "$root/deploy/kubernetes/base/deployment.yaml"
grep -q 'automountServiceAccountToken: false' "$root/deploy/kubernetes/base/service-account.yaml"
grep -q 'policyTypes: \[Ingress, Egress\]' "$root/deploy/kubernetes/base/network-policy.yaml"
grep -q 'sandbox_providers = false' "$root/deploy/kubernetes/base/config-map.yaml"
if grep -E '^[[:space:]]*image:' "$root/compose/compose.yaml" | grep -v '@sha256:'; then
  exit 1
fi
if grep -R -E '^FROM ' "$root" --include='Dockerfile' | grep -v '@sha256:'; then
  exit 1
fi
if grep -R --exclude-dir=certs -E 'AKIA[0-9A-Z]{16}|BEGIN (RSA |EC )?PRIVATE KEY|AUTHS_LOCAL_SEED[[:space:]]*=' "$root"; then
  exit 1
fi
