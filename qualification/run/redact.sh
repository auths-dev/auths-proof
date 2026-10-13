#!/usr/bin/env bash
# Scans everything a run kept for the run's planted canaries, then removes
# the canaries. Runs in the live job, the only place the canaries exist, so
# nothing unscanned and no canary leaves that job.
#
#   redact.sh <work-dir> [commissioning|live]
#
# Writes <work-dir>/cases/redaction.scan.json and deletes <work-dir>/canaries.
set -euo pipefail

work="${1:?usage: redact.sh <work-dir>}"
phase="${2:-live}"
[[ "${phase}" = commissioning || "${phase}" = live ]] \
  || { echo "qualification.invalid-stage" >&2; exit 1; }
root="$(git rev-parse --show-toplevel)"
tool="${AUTHS_QUALIFICATION:-${root}/target/release/auths-qualification}"

[ -s "${work}/canaries" ] || { echo "qualification.evidence-incomplete canaries" >&2; exit 1; }
arguments=(--work "${work}" --tool "${tool}")
if [[ "${phase}" = commissioning ]]; then
  arguments+=(--keep-canaries)
fi
python3 "$(dirname "${BASH_SOURCE[0]}")/scan_publication.py" "${arguments[@]}"
echo "redaction scan passed for ${phase}"
