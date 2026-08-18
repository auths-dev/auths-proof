#!/usr/bin/env bash
set -euo pipefail

if [[ "${AUTHS_GITHUB_LIVE:-}" != "1" ]]; then
  echo "refusing GitHub mutation: set AUTHS_GITHUB_LIVE=1 for an isolated repository" >&2
  exit 2
fi

: "${AUTHS_GITHUB_AGENT_ENDPOINT:?AUTHS_GITHUB_AGENT_ENDPOINT is required}"
: "${AUTHS_GITHUB_CANDIDATE_BUNDLE:?AUTHS_GITHUB_CANDIDATE_BUNDLE is required}"
: "${AUTHS_GITHUB_CANDIDATE_REVISION:?AUTHS_GITHUB_CANDIDATE_REVISION is required}"

case "${AUTHS_GITHUB_SDK:-}" in
  typescript)
    exec node "$(dirname "$0")/../examples/typescript/agent.mjs"
    ;;
  python)
    exec python "$(dirname "$0")/../examples/python/agent.py"
    ;;
  *)
    echo "AUTHS_GITHUB_SDK must be exactly 'typescript' or 'python'" >&2
    exit 2
    ;;
esac
