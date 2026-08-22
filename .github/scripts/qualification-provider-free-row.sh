#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'provider-free qualification row: %s\n' "$*" >&2
  exit 1
}

[[ $# -ge 1 ]] || die "missing command"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${TOOLS:?TOOLS is required}"

row_file="$RUNNER_TEMP/provider-free-row"
[[ -f "$row_file" && ! -L "$row_file" ]] || die "checked provider-free row is absent"
provider_run="$(<"$row_file")"
[[ "$provider_run" =~ ^[a-z][a-z0-9-]{0,127}$ ]] || die "checked provider-free row is invalid"

export MATRIX="$GITHUB_WORKSPACE/provider-free-candidate/product/integrations/auths-stripe/qualification/provider-matrix-v1.json"
export RUNTIME_ROOT="/run/auths-qualification-provider-free-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
export POLICY_ROOT="/run/auths-qualification-provider-free-policy-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
export SOURCE_TRUST="$GITHUB_WORKSPACE/trusted-attester/release/qualification/v1/evidence-source-trust-keys.json"
export DOMAIN=stripe
export AGENT_GID="${AGENT_GID:?AGENT_GID is required}"
export COMMON_ROOT="$GITHUB_WORKSPACE/provider-free-candidate/target/qualification-common-evidence/stripe/linux-x86_64"
export AGENT_CONFIG="/usr/local/libexec/auths-qualification-provider-free-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT/agent.toml"
export QUALIFICATION_PROVIDER_RUN="$provider_run"

services="$GITHUB_WORKSPACE/trusted-attester/.github/scripts/qualification-row-services.sh"
[[ -f "$services" && ! -L "$services" ]] || die "protected row-services script is absent"

case "$1" in
  materialize-agent-key)
    [[ $# == 2 ]] || die "materialize-agent-key requires one role"
    : "${QUALIFICATION_AGENT_SIGNING_SEED:?agent signing seed is absent}"
    bash "$services" materialize-agent-key "$2"
    ;;
  start-source)
    [[ $# == 2 ]] || die "start-source requires one role"
    : "${QUALIFICATION_SOURCE_SEED:?source seed is absent}"
    sudo --preserve-env=TOOLS,MATRIX,RUNTIME_ROOT,SOURCE_TRUST,DOMAIN,AGENT_GID,COMMON_ROOT,QUALIFICATION_PROVIDER_RUN,QUALIFICATION_SOURCE_SEED \
      bash "$services" start-source "$2"
    ;;
  start-appender|start-readers|start-provider-observer-readers)
    [[ $# == 1 ]] || die "$1 accepts no arguments"
    [[ -z "${QUALIFICATION_SOURCE_SEED:-}" && -z "${QUALIFICATION_AGENT_SIGNING_SEED:-}" ]] \
      || die "$1 is a no-seed command"
    sudo --preserve-env=TOOLS,MATRIX,RUNTIME_ROOT,SOURCE_TRUST,DOMAIN,AGENT_GID,COMMON_ROOT,QUALIFICATION_PROVIDER_RUN \
      bash "$services" "$1"
    ;;
  *) die "unsupported command: $1" ;;
esac
