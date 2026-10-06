#!/usr/bin/env bash
# Scans everything a run kept for the run's planted canaries, then removes
# the canaries. Runs in the live job, the only place the canaries exist, so
# nothing unscanned and no canary leaves that job.
#
#   redact.sh <work-dir>
#
# Writes <work-dir>/cases/redaction.scan.json and deletes <work-dir>/canaries.
set -euo pipefail

work="${1:?usage: redact.sh <work-dir>}"
root="$(git rev-parse --show-toplevel)"
tool="${AUTHS_QUALIFICATION:-${root}/target/release/auths-qualification}"

[ -s "${work}/canaries" ] || { echo "qualification.evidence-incomplete canaries" >&2; exit 1; }
# One canary per line; a carriage return is not part of a canary.
tr -d '\r' < "${work}/canaries" > "${work}/canaries.clean"
mv "${work}/canaries.clean" "${work}/canaries"

sources=()
for kind in log trace metric support-bundle; do
  while IFS= read -r -d '' file; do
    sources+=(--source "${kind}=${file}")
  done < <(find "${work}/scan/${kind}" -type f -print0 2>/dev/null | sort -z)
done
# Everything else the run publishes: the case reports and the facts that
# enter the record.
while IFS= read -r -d '' file; do
  sources+=(--source "evidence=${file}")
done < <(find "${work}/cases" -type f -name '*.json' -print0 | sort -z)
for published in tuple.json packages.json resources.json live-effects.json; do
  [ -s "${work}/${published}" ] && sources+=(--source "evidence=${work}/${published}")
done

rm -f "${work}/cases/redaction.scan.json"
"${tool}" stage-redaction --canaries "${work}/canaries" "${sources[@]}" \
  --out "${work}/redaction.cases.json"
mv "${work}/redaction.cases.json" "${work}/cases/redaction.scan.json"
rm -f "${work}/canaries"
echo "redaction scan passed; canaries removed"
