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

# The node and both installed SDK tests must agree on the reference-only
# trigger for exercising durable recovery. This exact cross-language drift
# previously made the live stack complete an action the clients expected to be
# recoverable.
recovery_marker='AUTHS-SANDBOX-RECOVER'
grep -Fq "REFERENCE_RECOVERABLE_BODY_MARKER: &str = \"$recovery_marker\";" \
  "$root/../../product/runtime/auths-node/src/local_fixture.rs"
grep -Fq "writeFileSync(recoverPath, \"$recovery_marker issue 104\");" \
  "$root/tests/installed-sdk-e2e.mjs"
grep -Fq "b\"$recovery_marker issue 104\"," \
  "$root/tests/test_installed_sdk.py"
