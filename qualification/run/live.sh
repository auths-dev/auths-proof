#!/usr/bin/env bash
# Execute one protected phase inside resource-session.sh. Resource preparation
# and cleanup belong to the complete journey, so commissioning cannot destroy
# the resources or author session needed by ordinary qualified execution.
set -euo pipefail

family="${1:?usage: live.sh <family> <work-dir>}"
work="${2:?usage: live.sh <family> <work-dir>}"
stage="${3:-live}"
[[ "${stage}" = commissioning || "${stage}" = live ]] \
  || { echo "qualification.invalid-stage" >&2; exit 1; }
export AUTHS_QUALIFICATION_STAGE="${stage}"
root="$(git rev-parse --show-toplevel)"
[[ "${family}" =~ ^[a-z][a-z0-9-]{0,63}$ ]] || { echo "qualification.invalid-family" >&2; exit 1; }
harness="${root}/qualification/families/${family}/harness"
[ -x "${harness}" ] || { echo "qualification.family-unknown" >&2; exit 1; }
tool="${AUTHS_QUALIFICATION:-${root}/target/release/auths-qualification}"
rm -f "${work}/${stage}-effects.json" "${work}/cases/"*."${stage}".json

"${tool}" run-stage --phase "${stage}" \
  --corpus "${work}/corpus.json" \
  --harness "${harness}" --tuple "${work}/tuple.json" --work-dir "${work}"
