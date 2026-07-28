#!/bin/sh
set -eu

cluster="${AUTHS_KUBERNETES_LOCAL_CLUSTER:-auths-kubernetes-demo}"
context="kind-$cluster"
node="$cluster-control-plane"
port="${AUTHS_KUBERNETES_LOCAL_PORT:-4173}"
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose="$root/compose.local.yaml"

for command in docker kind kubectl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

case "$port" in
  *[!0-9]*|'')
    echo "AUTHS_KUBERNETES_LOCAL_PORT must be a numeric port" >&2
    exit 2
    ;;
esac

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running" >&2
  exit 1
fi

if ! kind get clusters 2>/dev/null | grep -Fx "$cluster" >/dev/null; then
  echo "Creating local Kind cluster: $cluster"
  kind create cluster --name "$cluster"
fi

echo "Building the two immutable demo workload images"
docker build \
  --provenance=false \
  --build-arg COLOR="#166534" \
  --build-arg LABEL="AUTHORIZED GREEN" \
  --tag auths-kubernetes-color:green \
  "$root/workload"
docker build \
  --provenance=false \
  --build-arg COLOR="#1d4ed8" \
  --build-arg LABEL="AUTHORIZED BLUE" \
  --tag auths-kubernetes-color:blue \
  "$root/workload"

image_a_digest="$(docker image inspect auths-kubernetes-color:blue --format '{{index .RepoDigests 0}}')"
image_b_digest="$(docker image inspect auths-kubernetes-color:green --format '{{index .RepoDigests 0}}')"
image_a="docker.io/library/$image_a_digest"
image_b="docker.io/library/$image_b_digest"

kind load docker-image --name "$cluster" auths-kubernetes-color:blue auths-kubernetes-color:green
docker exec "$node" ctr -n k8s.io images tag --force \
  docker.io/library/auths-kubernetes-color:blue "$image_a"
docker exec "$node" ctr -n k8s.io images tag --force \
  docker.io/library/auths-kubernetes-color:green "$image_b"

echo "Bootstrapping the isolated demo namespace and authorization boundaries"
AUTHS_KUBERNETES_CONTEXT="$context" \
  "$root/scripts/bootstrap-cluster.sh" "$image_a"

ca_data="$(kubectl --context "$context" config view --raw --minify \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
export AUTHS_KUBERNETES_CA_PEM
AUTHS_KUBERNETES_CA_PEM="$(printf '%s' "$ca_data" | base64 --decode)"
export AUTHS_KUBERNETES_EVIDENCE_TOKEN
AUTHS_KUBERNETES_EVIDENCE_TOKEN="$(
  kubectl --context "$context" -n auths-demo create token \
    auths-rollout-inspector --duration=24h
)"
export AUTHS_KUBERNETES_MUTATION_TOKEN
AUTHS_KUBERNETES_MUTATION_TOKEN="$(
  kubectl --context "$context" -n auths-demo create token \
    auths-rollout-executor --duration=24h
)"
export AUTHS_KUBERNETES_API_SERVER="https://$node:6443"
export AUTHS_KUBERNETES_CLUSTER_AUDIENCE="kind://$cluster"
export AUTHS_KUBERNETES_IMAGE_A="$image_a"
export AUTHS_KUBERNETES_IMAGE_B="$image_b"
export AUTHS_KUBERNETES_LOCAL_PORT="$port"

echo "Starting the browser and native service containers"
docker compose -f "$compose" up --build --detach

attempt=0
until curl --fail --silent --show-error "http://127.0.0.1:$port/readyz" >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "Local demo did not become ready; inspect it with:" >&2
    echo "docker compose -f $compose logs" >&2
    exit 1
  fi
  sleep 1
done

echo
echo "Auths Kubernetes demo is ready:"
echo "http://localhost:$port"
