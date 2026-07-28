#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <immutable-image-a-reference>" >&2
  exit 2
fi

image_a="$1"
case "$image_a" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *)
    echo "image must be an immutable sha256 digest reference" >&2
    exit 2
    ;;
esac

context="${AUTHS_KUBERNETES_CONTEXT:-$(kubectl config current-context)}"
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

kubectl --context "$context" apply -f "$root/cluster/namespace.yaml"
kubectl --context "$context" apply -f "$root/cluster/rbac.yaml"
kubectl --context "$context" apply -f "$root/cluster/admission-policy.yaml"

sed "s#ghcr.io/auths-dev/auths-kubernetes-color-service@sha256:REPLACE_WITH_IMAGE_A#$image_a#" \
  "$root/cluster/workload.yaml" |
  kubectl --context "$context" apply --server-side --force-conflicts \
    --field-manager=auths-demo-bootstrap -f -

sed "s#ghcr.io/auths-dev/auths-kubernetes-color-service@sha256:REPLACE_WITH_IMAGE_A#$image_a#" \
  "$root/cluster/rollout-ownership.yaml" |
  kubectl --context "$context" apply --server-side --force-conflicts \
    --field-manager=auths-workload-rollout -f -

kubectl --context "$context" apply --server-side \
  --field-manager=auths-demo-bootstrap \
  -f "$root/cluster/workload-structure.yaml"

kubectl --context "$context" -n auths-demo rollout status \
  deployment/color-service --timeout=120s
