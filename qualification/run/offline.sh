#!/usr/bin/env bash
# Candidate and offline evidence for one recipe family. Needs no secret.
#
#   offline.sh <family> <work-dir>
#
# Uses the credential-free job's exact candidate from a clean source revision,
# runs the family harness and runs the trust stages for its reported tuple.
# Writes into <work-dir>: tuple.json, packages.json, cases/*.json, facts.json.
set -euo pipefail

family="${1:?usage: offline.sh <family> <work-dir>}"
work="${2:?usage: offline.sh <family> <work-dir>}"
root="$(git rev-parse --show-toplevel)"
directory="${root}/qualification/families/${family}"

[[ "${family}" =~ ^[a-z][a-z0-9-]{0,63}$ ]] || { echo "qualification.invalid-family" >&2; exit 1; }
[ -x "${directory}/harness" ] || { echo "qualification.family-unknown ${family}" >&2; exit 1; }

# A qualification is about a commit. Anything uncommitted is not in it.
if [ -n "$(git -C "${root}" status --porcelain)" ]; then
  echo "qualification.source-not-clean" >&2
  exit 1
fi

mkdir -p "${work}/cases"
export AUTHS_GATEWAY="${AUTHS_GATEWAY:?qualification.candidate-not-supplied}"
export AUTHS_QUALIFICATION="${AUTHS_QUALIFICATION:?qualification.issuer-not-supplied}"
# Candidate bytes are built once by the credential-free job and kept outside
# the public evidence directory; the tuple binds that exact executable.

"${directory}/harness" prepare "${work}"
# Derive the planned production identity without custody or provider access.
# The protected live runner must compare its actual installation byte-for-byte
# before importing a permit. This command grants no execution authority.
"${AUTHS_GATEWAY}" qualification-candidate \
  --recipe "${work}/recipe.json" --profile-lock "${work}/profile.lock.json" \
  --recipe-family "${family}" \
  --provider-contract-id "$("${AUTHS_QUALIFICATION}" contract-id --contract "${directory}/contract.json")" \
  > "${work}/tuple.json"
for required in tuple.json packages.json; do
  [ -s "${work}/${required}" ] || { echo "qualification.harness-incomplete ${required}" >&2; exit 1; }
done

[ "$(jq -r .provider_contract_id "${work}/tuple.json")" = \
  "$("${AUTHS_QUALIFICATION}" contract-id --contract "${directory}/contract.json")" ] \
  || { echo "qualification.contract-changed" >&2; exit 1; }
"${AUTHS_QUALIFICATION}" run-stage --phase offline \
  --corpus "${work}/corpus.json" --harness "${directory}/harness" \
  --tuple "${work}/tuple.json" --work-dir "${work}"

"${AUTHS_QUALIFICATION}" stage-trust --tuple "${work}/tuple.json" \
  --out "${work}/cases/rotation.trust.json"

# The finite permit consumes actual canonical offline evidence, not a case
# list or an arbitrary report's passing flag.
mkdir -p "${work}/offline"
for member in conformance differential; do
  "${AUTHS_QUALIFICATION}" evidence --member "${member}" \
    --tuple "${work}/tuple.json" --commit "$(git -C "${root}" rev-parse HEAD)" \
    --cases "${work}/cases/${member}.offline.json" --out "${work}/offline/${member}.json"
done

digest() { shasum -a 256 "$1" | cut -d' ' -f1; }
jq -n \
  --arg commit "$(git -C "${root}" rev-parse HEAD)" \
  --arg source_closure "$(git -C "${root}" ls-tree -r HEAD | shasum -a 256 | cut -d' ' -f1)" \
  --arg generated "$(cat "${AUTHS_GATEWAY}" "${AUTHS_QUALIFICATION}" | shasum -a 256 | cut -d' ' -f1)" \
  --arg decision "$(digest "${directory}/decision-record.md")" \
  --arg corpus "$(digest "${work}/corpus.json")" \
  '{commit: $commit, source_closure_sha256: $source_closure,
    generated_artifacts_sha256: $generated,
    recipe_decision_record_sha256: $decision, corpus_manifest_sha256: $corpus}' \
  > "${work}/facts.json"
echo "offline evidence for ${family} at $(jq -r .commit "${work}/facts.json")"
