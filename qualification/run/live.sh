#!/usr/bin/env bash
# Execute protected live stages and tear down disposable resources on every
# exit, including a failed setup or runner. Cleanup must be idempotent.
set -euo pipefail

family="${1:?usage: live.sh <family> <work-dir>}"
work="${2:?usage: live.sh <family> <work-dir>}"
root="$(git rev-parse --show-toplevel)"
[[ "${family}" =~ ^[a-z][a-z0-9-]{0,63}$ ]] || { echo "qualification.invalid-family" >&2; exit 1; }
harness="${root}/qualification/families/${family}/harness"
[ -x "${harness}" ] || { echo "qualification.family-unknown" >&2; exit 1; }
tool="${AUTHS_QUALIFICATION:-${root}/target/release/auths-qualification}"

cleanup() {
  status=$?
  # The family writes scan sources privately. Never relay child output,
  # which may contain credentials, to Actions logs.
  if ! "${harness}" cleanup "${work}" >/dev/null 2>&1; then
    echo "qualification.cleanup-failed" >&2
    exit 1
  fi
  exit "${status}"
}
trap cleanup EXIT

if ! "${harness}" prepare-live "${work}" >/dev/null 2>&1; then
  echo "qualification.live-setup-failed" >&2
  exit 1
fi
"${tool}" run-stage --phase live \
  --corpus "${root}/qualification/families/${family}/corpus-manifest.json" \
  --harness "${harness}" --tuple "${work}/tuple.json" --work-dir "${work}"
