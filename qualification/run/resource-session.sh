#!/usr/bin/env bash
# Hold disposable resources across the source-owned protected journey. The
# command and its arguments come from the reviewed workflow, never an artifact.
# Setup runs once and cleanup runs after the complete journey on every exit.
#
# resource-session.sh <family> <work-dir> <source-command> [arguments...]
set -euo pipefail

family="${1:?usage: resource-session.sh <family> <work-dir> <source-command> [arguments...]}"
work="${2:?}"
shift 2
[ "$#" -gt 0 ] || { echo "qualification.journey-missing" >&2; exit 1; }
root="$(git rev-parse --show-toplevel)"
[[ "${family}" =~ ^[a-z][a-z0-9-]{0,63}$ ]] || { echo "qualification.invalid-family" >&2; exit 1; }
harness="${root}/qualification/families/${family}/harness"
[ -x "${harness}" ] || { echo "qualification.family-unknown" >&2; exit 1; }

invalidate() {
  for phase in commissioning live; do
    rm -f "${work}/${phase}-effects.json" "${work}/cases/"*."${phase}".json
  done
  rm -rf "${work}/proposal" "${work}/evidence"
}

cleanup() {
  status=$?
  trap - EXIT
  # Provider error bodies and private setup/cleanup diagnostics never enter
  # the Actions log. A failed cleanup cannot leave a passing final proposal.
  if ! "${harness}" cleanup "${work}" >/dev/null 2>&1; then
    echo "qualification.cleanup-failed" >&2
    status=1
  fi
  if [ "${status}" -ne 0 ]; then
    invalidate
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! "${harness}" prepare-live "${work}" >/dev/null 2>&1; then
  echo "qualification.live-setup-failed" >&2
  exit 1
fi
"$@"
