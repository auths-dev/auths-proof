#!/bin/sh
set -eu

context="${AUTHS_KUBERNETES_LOCAL_CONTEXT:-kind-auths-kubernetes-demo}"
state_directory="$(mktemp -d)"
trap 'rm -rf "$state_directory"' EXIT INT TERM

api_server="$(kubectl --context "$context" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
ca_data="$(kubectl --context "$context" config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
evidence_token="$(kubectl --context "$context" -n auths-demo create token auths-rollout-inspector --duration=10m)"
mutation_token="$(kubectl --context "$context" -n auths-demo create token auths-rollout-executor --duration=10m)"

export AUTHS_KUBERNETES_ALLOWED_ORIGIN="http://localhost:4173"
export AUTHS_KUBERNETES_API_SERVER="$api_server"
export AUTHS_KUBERNETES_CA_PEM="$(printf '%s' "$ca_data" | base64 --decode)"
export AUTHS_KUBERNETES_EVIDENCE_TOKEN="$evidence_token"
export AUTHS_KUBERNETES_MUTATION_TOKEN="$mutation_token"
export AUTHS_KUBERNETES_CLUSTER_AUDIENCE="kind://auths-kubernetes-demo"
export AUTHS_KUBERNETES_NAMESPACE="auths-demo"
export AUTHS_KUBERNETES_DEPLOYMENT="color-service"
export AUTHS_KUBERNETES_CONTAINER="color-service"
export AUTHS_KUBERNETES_IMAGE_A="docker.io/library/auths-kubernetes-color@sha256:fb8007ba5347ac9d98232110e0bfc54ed0da57e143e5e9ab65726c3fcf8efd54"
export AUTHS_KUBERNETES_IMAGE_B="docker.io/library/auths-kubernetes-color@sha256:531acc88f8cb8586dd7930abd97b0db1d900c3edd37d2d67d82783a6064a7b54"
export AUTHS_KUBERNETES_EXECUTOR_AUDIENCE="http://127.0.0.1:8080"
export AUTHS_KUBERNETES_STATE_DIR="$state_directory"
export AUTHS_KUBERNETES_RELEASE="local-kind"
export PORT="${PORT:-8080}"

cargo run -p auths-kubernetes-demo
