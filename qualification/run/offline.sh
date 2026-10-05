#!/usr/bin/env bash
# Candidate and offline evidence for one recipe family. Needs no secret.
#
#   offline.sh <family> <work-dir>
#
# Builds the release candidate from a clean tree, runs the family's offline
# harness, and runs the trust stages for the tuple the harness reported.
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
cargo build --locked --release -p auths-gateway --bin auths-gateway
cargo build --locked --release -p auths-recipe-qualification-issuance --bin auths-qualification
export AUTHS_GATEWAY="${root}/target/release/auths-gateway"
export AUTHS_QUALIFICATION="${root}/target/release/auths-qualification"

"${directory}/harness" offline "${work}"
for required in tuple.json packages.json; do
  [ -s "${work}/${required}" ] || { echo "qualification.harness-incomplete ${required}" >&2; exit 1; }
done

"${AUTHS_QUALIFICATION}" stage-trust --tuple "${work}/tuple.json" \
  --out "${work}/cases/rotation.trust.json"

digest() { shasum -a 256 "$1" | cut -d' ' -f1; }
jq -n \
  --arg commit "$(git -C "${root}" rev-parse HEAD)" \
  --arg source_closure "$(git -C "${root}" ls-tree -r HEAD | shasum -a 256 | cut -d' ' -f1)" \
  --arg generated "$(cat "${AUTHS_GATEWAY}" "${AUTHS_QUALIFICATION}" | shasum -a 256 | cut -d' ' -f1)" \
  --arg decision "$(digest "${directory}/decision-record.md")" \
  --arg corpus "$(digest "${directory}/corpus-manifest.json")" \
  '{commit: $commit, source_closure_sha256: $source_closure,
    generated_artifacts_sha256: $generated,
    recipe_decision_record_sha256: $decision, corpus_manifest_sha256: $corpus}' \
  > "${work}/facts.json"
echo "offline evidence for ${family} at $(jq -r .commit "${work}/facts.json")"
