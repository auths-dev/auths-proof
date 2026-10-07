#!/usr/bin/env bash
# Assembles one family's unsigned proposal from the evidence of a run.
# Needs no secret.
#
#   assemble.sh <family> <work-dir> <environment> <run-identifier>
#
# Reads what offline.sh, the family's live harness, and redact.sh wrote into
# <work-dir>, runs the trust stages, builds one evidence artifact per member,
# and assembles the record. Refuses unless the record closes.
# Writes <work-dir>/proposal.
set -euo pipefail

family="${1:?usage: assemble.sh <family> <work-dir> <environment> <run-identifier>}"
work="${2:?}"
environment="${3:?}"
run="${4:?}"
stage="${5:-live}"
[[ "${stage}" = commissioning || "${stage}" = live ]] \
  || { echo "qualification.invalid-stage" >&2; exit 1; }
root="$(git rev-parse --show-toplevel)"
directory="${root}/qualification/families/${family}"
tool="${AUTHS_QUALIFICATION:-${root}/target/release/auths-qualification}"

# Downloaded artifacts do not retain directory modes. Only this job's owned,
# real work directory may receive the reconstructed public proposal inputs.
[ -d "${work}" ] && [ ! -L "${work}" ] && [ -O "${work}" ] \
  || { echo "qualification.unsafe-work-directory" >&2; exit 1; }
chmod 0700 "${work}"

# A failed rerun must not leave an earlier proposal available to a signer.
rm -rf "${work}/proposal" "${work}/evidence"
rm -f "${work}/provider-resources.json"

for required in tuple.json packages.json facts.json "${stage}-effects.json" resources.json cases/redaction.scan.json; do
  [ -s "${work}/${required}" ] || { echo "qualification.evidence-incomplete ${required}" >&2; exit 1; }
done
commit="$(jq -r .commit "${work}/facts.json")"
[ "${commit}" = "$(git -C "${root}" rev-parse HEAD)" ] || { echo "qualification.commit-changed" >&2; exit 1; }
[ -z "$(git -C "${root}" status --porcelain)" ] \
  || { echo "qualification.source-not-clean" >&2; exit 1; }

# The tuple names this family and nothing else's.
[ "$(jq -r .recipe_family "${work}/tuple.json")" = "${family}" ] \
  || { echo "qualification.tuple-names-another-family" >&2; exit 1; }

# The ledger is a closed family/run-bound object, not a caller-selected array
# of record strings. Reconstruct the native record summary from its exact IDs.
env -i PATH="${PATH}" PYTHONNOUSERSITE=1 python3 \
  "${root}/qualification/reference/resource_summary.py" \
  --family "${family}" --resources "${work}/resources.json" \
  --out "${work}/provider-resources.json"

# The trust stages are run here, by the tool this job built, whatever the
# harness left under that name.
"${tool}" stage-trust --tuple "${work}/tuple.json" --out "${work}/cases/rotation.trust.json"

mkdir -p "${work}/evidence"
for member in conformance differential hostile live recovery rotation restart multi-instance redaction installed-consumer; do
  reports=()
  # Only the current runner's phase reports and release-owned trust/scan
  # outputs are inputs. Extra harness-authored or stale reports are ignored.
  for phase in offline "${stage}"; do
    file="${work}/cases/${member}.${phase}.json"
    [ ! -f "${file}" ] || reports+=(--cases "${file}")
  done
  case "${member}" in
    rotation) reports+=(--cases "${work}/cases/rotation.trust.json") ;;
    redaction) reports+=(--cases "${work}/cases/redaction.scan.json") ;;
  esac
  [ "${#reports[@]}" -gt 0 ] || { echo "qualification.member-missing ${member}" >&2; exit 1; }
  live=()
  if [ "${member}" = live ]; then
    live=(--live-entered "$(jq -r .entered "${work}/${stage}-effects.json")"
          --live-confirmed "$(jq -r .confirmed_by_read_back "${work}/${stage}-effects.json")")
  fi
  "${tool}" evidence --member "${member}" --commit "${commit}" \
    --tuple "${work}/tuple.json" "${reports[@]}" ${live[@]+"${live[@]}"} \
    --out "${work}/evidence/${member}.json"
done

now="$(date -u +%s)"
identifier="qlf_$(printf '%s\n%s\n%s\n%s' "${family}" "${commit}" "${run}" "${stage}" | shasum -a 256 | cut -c1-32)"
jq -n \
  --arg identifier "${identifier}" \
  --argjson now "${now}" \
  --arg environment "${environment}" \
  --arg stage "${stage}" \
  --slurpfile record "${directory}/record.json" \
  --slurpfile tuple "${work}/tuple.json" \
  --slurpfile packages "${work}/packages.json" \
  --slurpfile facts "${work}/facts.json" \
  --slurpfile resources "${work}/provider-resources.json" \
  '{qualification_id: $identifier,
    provider_kind: $record[0].provider_kind,
    tuple: $tuple[0],
    not_before: $now,
    not_after: ($now + (if $stage == "commissioning" then 7200 else ($record[0].validity_days * 86400) end)),
    provenance: {repository: "github.com/auths-dev/auths-proof", commit: $facts[0].commit,
                 workflow: ".github/workflows/recipe-qualification.yml", environment: $environment},
    source_closure_sha256: $facts[0].source_closure_sha256,
    generated_artifacts_sha256: $facts[0].generated_artifacts_sha256,
    installed_packages: ($packages[0] | sort_by(.name)),
    recipe_decision_record_sha256: $facts[0].recipe_decision_record_sha256,
    corpus_manifest_sha256: $facts[0].corpus_manifest_sha256,
    not_applicable: $record[0].not_applicable,
    provider_resources: ($resources[0] | sort),
    custody_descriptor: $record[0].custody_descriptor,
    store_descriptor: $record[0].store_descriptor,
    residual_assumptions: ($record[0].residual_assumptions | sort),
    excluded_claims: (($record[0].excluded_claims +
      (if $stage == "commissioning" then
        ["First-run commissioning: ordinary installed clients were refused; their qualified effect and production readiness require the subsequent live phase."]
       else [] end)) | unique | sort)}' \
  > "${work}/draft.json"

"${tool}" assemble --draft "${work}/draft.json" --evidence-dir "${work}/evidence" \
  --out-dir "${work}/proposal"
cp "${work}/tuple.json" "${work}/proposal/tuple.json"
echo "unsigned proposal ${identifier} for ${family}"
