#!/usr/bin/env bash
set -euo pipefail

required=(
  CANDIDATE_REVISION
  QUALIFICATION_CANDIDATE_REPOSITORY
  GITHUB_REPOSITORY
  GITHUB_REPOSITORY_ID
  GITHUB_TOKEN
  OFFICIAL_RELEASE_BUILD_RUN_ID
  OFFICIAL_RELEASE_BUILD_ARTIFACT_ID
  OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST
  QUALIFICATION_RELEASE_VERIFIER
  QUALIFICATION_RELEASE_VERIFIER_SHA256
  QUALIFICATION_GH_CLI
  QUALIFICATION_GH_CLI_SHA256
  QUALIFICATION_GH_TRUSTED_ROOT
  QUALIFICATION_GH_TRUSTED_ROOT_SHA256
  AUTHS_QUALIFICATION_RETENTION_DAYS
  QUALIFICATION_ATTESTER_TOOLS_VERIFICATION
  QUALIFICATION_ATTESTER_TOOLS_MANIFEST
  QUALIFICATION_RELEASE_OUTPUT
)
for name in "${required[@]}"; do
  [[ -n "${!name:-}" ]] || { echo "missing required input: $name" >&2; exit 1; }
done
[[ "$CANDIDATE_REVISION" =~ ^[0-9a-f]{40}$ ]]
[[ -d "$QUALIFICATION_CANDIDATE_REPOSITORY" && ! -L "$QUALIFICATION_CANDIDATE_REPOSITORY" ]]
[[ "$GITHUB_REPOSITORY_ID" =~ ^(0|[1-9][0-9]{0,31})$ ]]
[[ "$OFFICIAL_RELEASE_BUILD_RUN_ID" =~ ^(0|[1-9][0-9]{0,31})$ ]]
[[ "$OFFICIAL_RELEASE_BUILD_ARTIFACT_ID" =~ ^(0|[1-9][0-9]{0,31})$ ]]
OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST="${OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST#sha256:}"
[[ "$OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]
[[ "$QUALIFICATION_RELEASE_VERIFIER_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ -f "$QUALIFICATION_RELEASE_VERIFIER" && ! -L "$QUALIFICATION_RELEASE_VERIFIER" ]]
[[ "$(sha256sum "$QUALIFICATION_RELEASE_VERIFIER" | cut -d' ' -f1)" == "$QUALIFICATION_RELEASE_VERIFIER_SHA256" ]]
[[ "$QUALIFICATION_GH_CLI_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ -f "$QUALIFICATION_GH_CLI" && ! -L "$QUALIFICATION_GH_CLI" && -x "$QUALIFICATION_GH_CLI" ]]
[[ "$(sha256sum "$QUALIFICATION_GH_CLI" | cut -d' ' -f1)" == "$QUALIFICATION_GH_CLI_SHA256" ]]
[[ "$QUALIFICATION_GH_TRUSTED_ROOT_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ -f "$QUALIFICATION_GH_TRUSTED_ROOT" && ! -L "$QUALIFICATION_GH_TRUSTED_ROOT" ]]
[[ "$(sha256sum "$QUALIFICATION_GH_TRUSTED_ROOT" | cut -d' ' -f1)" == "$QUALIFICATION_GH_TRUSTED_ROOT_SHA256" ]]
[[ "$AUTHS_QUALIFICATION_RETENTION_DAYS" =~ ^[0-9]{2,3}$ ]]
(( AUTHS_QUALIFICATION_RETENTION_DAYS >= 90 && AUTHS_QUALIFICATION_RETENTION_DAYS <= 365 ))
[[ -f "$QUALIFICATION_ATTESTER_TOOLS_VERIFICATION" && ! -L "$QUALIFICATION_ATTESTER_TOOLS_VERIFICATION" ]]
[[ -f "$QUALIFICATION_ATTESTER_TOOLS_MANIFEST" && ! -L "$QUALIFICATION_ATTESTER_TOOLS_MANIFEST" ]]
GH_VERSION="$("$QUALIFICATION_GH_CLI" version | sed -n '1s/^gh version \([^ ]*\).*/\1/p')"
[[ "$GH_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]

umask 077
mkdir -p "$QUALIFICATION_RELEASE_OUTPUT/downloads" \
  "$QUALIFICATION_RELEASE_OUTPUT/projection" \
  "$QUALIFICATION_RELEASE_OUTPUT/artifacts"

api() {
  "$QUALIFICATION_GH_CLI" api --method GET -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' "$1"
}

artifact_api_path() {
  printf 'repos/%s/actions/artifacts/%s' "$GITHUB_REPOSITORY" "$1"
}

download_artifact() {
  local artifact_id="$1" destination="$2" expected_digest="$3" expected_bytes="$4" maximum_bytes="$5"
  [[ "$expected_bytes" =~ ^[1-9][0-9]{0,9}$ ]]
  (( expected_bytes <= maximum_bytes ))
  local file_blocks=$(( (expected_bytes + 511) / 512 + 1 ))
  ( ulimit -f "$file_blocks"; timeout 600 "$QUALIFICATION_GH_CLI" api --method GET \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      "$(artifact_api_path "$artifact_id")/zip" > "$destination" )
  [[ "$(stat -c '%s' "$destination")" == "$expected_bytes" ]]
  local actual_digest
  actual_digest="$(sha256sum "$destination" | cut -d' ' -f1)"
  [[ "$actual_digest" == "$expected_digest" ]] || {
    echo "uploaded archive digest mismatch for artifact $artifact_id" >&2
    exit 1
  }
}

extract_exact_projection() {
  local archive="$1" destination="$2"
  local expected=(
    release-build.json
    release-build.provenance.sigstore.json
    release-build.verification.json
    qualification-surface.json
    members.json
  )
  mapfile -t entries < <(timeout 10 zipinfo -1 "$archive" | head -n 7)
  [[ "${#entries[@]}" -eq "${#expected[@]}" ]]
  for wanted in "${expected[@]}"; do
    local maximum=1048576
    [[ "$wanted" == "release-build.json" || "$wanted" == "qualification-surface.json" || "$wanted" == "members.json" ]] && maximum=262144
    local matches=()
    for entry in "${entries[@]}"; do
      [[ "$entry" != /* && "$entry" != *'\'* && "$entry" != *'../'* ]]
      [[ "${entry##*/}" == "$wanted" ]] && matches+=("$entry")
    done
    [[ "${#matches[@]}" -eq 1 ]] || {
      echo "projection archive does not contain exactly one $wanted" >&2
      exit 1
    }
    local file_blocks=$(( (maximum + 511) / 512 + 1 ))
    ( ulimit -f "$file_blocks"; timeout 60 unzip -p "$archive" "${matches[0]}" > "$destination/$wanted" )
    [[ -s "$destination/$wanted" ]]
    (( $(stat -c '%s' "$destination/$wanted") <= maximum ))
  done
}

RUN_METADATA="$QUALIFICATION_RELEASE_OUTPUT/run.json"
api "repos/$GITHUB_REPOSITORY/actions/runs/$OFFICIAL_RELEASE_BUILD_RUN_ID" > "$RUN_METADATA"
jq -e \
  --arg repositoryId "$GITHUB_REPOSITORY_ID" \
  --arg candidate "$CANDIDATE_REVISION" \
  --arg runId "$OFFICIAL_RELEASE_BUILD_RUN_ID" '
    (.id|tostring) == $runId and
    (.repository.id|tostring) == $repositoryId and
    .head_sha == $candidate and
    .status == "completed" and
    .conclusion == "success" and
    .path == ".github/workflows/release.yml"
  ' "$RUN_METADATA" >/dev/null

PROJECTION_METADATA="$QUALIFICATION_RELEASE_OUTPUT/projection-metadata.json"
api "$(artifact_api_path "$OFFICIAL_RELEASE_BUILD_ARTIFACT_ID")" > "$PROJECTION_METADATA"
jq -e \
  --arg artifactId "$OFFICIAL_RELEASE_BUILD_ARTIFACT_ID" \
  --arg digest "sha256:$OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST" \
  --arg runId "$OFFICIAL_RELEASE_BUILD_RUN_ID" \
  --arg candidate "$CANDIDATE_REVISION" '
    (.id|tostring) == $artifactId and
    .digest == $digest and
    .name == ("auths-qualification-" + $candidate + "-official-release-build") and
    (.size_in_bytes > 0 and .size_in_bytes <= 16777216) and
    .expired == false and
    (.workflow_run.id|tostring) == $runId
  ' "$PROJECTION_METADATA" >/dev/null

PROJECTION_ZIP="$QUALIFICATION_RELEASE_OUTPUT/downloads/release-build.zip"
download_artifact "$OFFICIAL_RELEASE_BUILD_ARTIFACT_ID" "$PROJECTION_ZIP" \
  "$OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST" \
  "$(jq -r '.size_in_bytes' "$PROJECTION_METADATA")" 16777216
extract_exact_projection "$PROJECTION_ZIP" "$QUALIFICATION_RELEASE_OUTPUT/projection"

RELEASE_BUILD="$QUALIFICATION_RELEASE_OUTPUT/projection/release-build.json"
SURFACE="$QUALIFICATION_RELEASE_OUTPUT/projection/qualification-surface.json"
MEMBERS="$QUALIFICATION_RELEASE_OUTPUT/projection/members.json"
PROVENANCE="$QUALIFICATION_RELEASE_OUTPUT/projection/release-build.provenance.sigstore.json"
CANDIDATE_PROVENANCE_VERIFICATION="$QUALIFICATION_RELEASE_OUTPUT/projection/release-build.verification.json"
PROVENANCE_RAW="$QUALIFICATION_RELEASE_OUTPUT/provenance-verification.raw.json"
PROVENANCE_VERIFICATION="$QUALIFICATION_RELEASE_OUTPUT/provenance-verification.json"
"$QUALIFICATION_GH_CLI" attestation verify "$RELEASE_BUILD" \
  --repo auths-dev/auths-proof \
  --bundle "$PROVENANCE" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --signer-workflow auths-dev/auths-proof/.github/workflows/release-builder.yml \
  --signer-digest "$CANDIDATE_REVISION" \
  --source-digest "$CANDIDATE_REVISION" \
  --deny-self-hosted-runners \
  --custom-trusted-root "$QUALIFICATION_GH_TRUSTED_ROOT" \
  --format json > "$PROVENANCE_RAW"

PROVENANCE_MISMATCH_FILTER='map({statement:{predicateType:.verificationResult.statement.predicateType,subject:.verificationResult.statement.subject},certificate:{sourceRepositoryIdentifier:.verificationResult.signature.certificate.sourceRepositoryIdentifier,sourceRepositoryUri:.verificationResult.signature.certificate.sourceRepositoryUri,sourceRepositoryDigest:.verificationResult.signature.certificate.sourceRepositoryDigest,sourceRepositoryRef:.verificationResult.signature.certificate.sourceRepositoryRef,buildSignerUri:.verificationResult.signature.certificate.buildSignerUri,buildSignerDigest:.verificationResult.signature.certificate.buildSignerDigest,issuer:.verificationResult.signature.certificate.issuer,runnerEnvironment:.verificationResult.signature.certificate.runnerEnvironment,runnerInvocationUri:.verificationResult.signature.certificate.runnerInvocationUri}})'
jq -e -cS "$PROVENANCE_MISMATCH_FILTER" "$CANDIDATE_PROVENANCE_VERIFICATION" \
  > "$QUALIFICATION_RELEASE_OUTPUT/provenance-candidate-projection.json"
jq -e -cS "$PROVENANCE_MISMATCH_FILTER" "$PROVENANCE_RAW" \
  > "$QUALIFICATION_RELEASE_OUTPUT/provenance-protected-projection.json"
cmp "$QUALIFICATION_RELEASE_OUTPUT/provenance-candidate-projection.json" \
  "$QUALIFICATION_RELEASE_OUTPUT/provenance-protected-projection.json"

RAW_PROVENANCE_SHA256="$(sha256sum "$PROVENANCE_RAW" | cut -d' ' -f1)"
PROVENANCE_BUNDLE_SHA256="$(sha256sum "$PROVENANCE" | cut -d' ' -f1)"
TIMESTAMPS="$QUALIFICATION_RELEASE_OUTPUT/provenance-verified-timestamps.json"
jq -cS '.[0].verificationResult.verifiedTimestamps' "$PROVENANCE_RAW" > "$TIMESTAMPS"
TIMESTAMPS_SHA256="$(sha256sum "$TIMESTAMPS" | cut -d' ' -f1)"
jq -e -cS \
  --arg repositoryId "$GITHUB_REPOSITORY_ID" \
  --arg candidate "$CANDIDATE_REVISION" \
  --arg runId "$OFFICIAL_RELEASE_BUILD_RUN_ID" \
  --arg runAttempt "$(jq -r '.run_attempt' "$RUN_METADATA")" \
  --arg subjectSha256 "$(sha256sum "$RELEASE_BUILD" | cut -d' ' -f1)" \
  --arg timestampsSha256 "$TIMESTAMPS_SHA256" \
  --arg rawSha256 "$RAW_PROVENANCE_SHA256" \
  --arg bundleSha256 "$PROVENANCE_BUNDLE_SHA256" \
  --arg trustedRootSha256 "$QUALIFICATION_GH_TRUSTED_ROOT_SHA256" \
  --arg verifierSha256 "$QUALIFICATION_GH_CLI_SHA256" \
  --arg releaseBuildVerifierSha256 "$QUALIFICATION_RELEASE_VERIFIER_SHA256" \
  --arg verifierVersion "$GH_VERSION" '
    if length == 1 and
      .[0].verificationResult.statement.predicateType == "https://slsa.dev/provenance/v1" and
      (.[0].verificationResult.statement.subject | length) == 1 and
      .[0].verificationResult.statement.subject[0].name == "release-build.json" and
      .[0].verificationResult.statement.subject[0].digest.sha256 == $subjectSha256 and
      (.[0].verificationResult.signature.certificate.sourceRepositoryIdentifier | tostring) == $repositoryId and
      .[0].verificationResult.signature.certificate.sourceRepositoryUri == "https://github.com/auths-dev/auths-proof" and
      .[0].verificationResult.signature.certificate.sourceRepositoryDigest == $candidate and
      .[0].verificationResult.signature.certificate.sourceRepositoryRef == "refs/heads/main" and
      .[0].verificationResult.signature.certificate.buildSignerUri == "https://github.com/auths-dev/auths-proof/.github/workflows/release-builder.yml@refs/heads/main" and
      .[0].verificationResult.signature.certificate.buildSignerDigest == $candidate and
      .[0].verificationResult.signature.certificate.issuer == "https://token.actions.githubusercontent.com" and
      .[0].verificationResult.signature.certificate.runnerEnvironment == "github-hosted" and
      .[0].verificationResult.signature.certificate.runnerInvocationUri == ("https://github.com/auths-dev/auths-proof/actions/runs/" + $runId + "/attempts/" + $runAttempt) and
      (.[0].verificationResult.verifiedTimestamps | type) == "array" and
      (.[0].verificationResult.verifiedTimestamps | length) >= 1
    then {
      schema: "auths.qualification-release-provenance-verification/1",
      verificationTool: "gh-attestation-verify",
      repositoryId: $repositoryId,
      sourceRepositoryUri: "https://github.com/auths-dev/auths-proof",
      sourceRepositoryDigest: $candidate,
      sourceRepositoryRef: "refs/heads/main",
      signerWorkflowUri: "https://github.com/auths-dev/auths-proof/.github/workflows/release-builder.yml@refs/heads/main",
      signerWorkflowDigest: $candidate,
      oidcIssuer: "https://token.actions.githubusercontent.com",
      runnerEnvironment: "github-hosted",
      runnerInvocationUri: ("https://github.com/auths-dev/auths-proof/actions/runs/" + $runId + "/attempts/" + $runAttempt),
      predicateType: "https://slsa.dev/provenance/v1",
      subjectName: "release-build.json",
      subjectSha256: $subjectSha256,
      verifiedTimestampsSha256: $timestampsSha256,
      rawVerificationSha256: $rawSha256,
      provenanceBundleSha256: $bundleSha256,
      trustedRootSha256: $trustedRootSha256,
      verifierSha256: $verifierSha256,
      verifierVersion: $verifierVersion,
      releaseBuildVerifierSha256: $releaseBuildVerifierSha256
    } else error("verified provenance does not match the protected release build") end
  ' "$PROVENANCE_RAW" > "$PROVENANCE_VERIFICATION"
truncate -s -1 "$PROVENANCE_VERIFICATION"

jq -e \
  --arg repositoryId "$GITHUB_REPOSITORY_ID" \
  --arg candidate "$CANDIDATE_REVISION" \
  --arg runId "$OFFICIAL_RELEASE_BUILD_RUN_ID" \
  --argjson runAttempt "$(jq '.run_attempt' "$RUN_METADATA")" '
    .provider == "github-actions" and
    .repositoryId == $repositoryId and
    .workflowPath == ".github/workflows/release-builder.yml" and
    .workflowRevision == $candidate and
    .runId == $runId and
    .runAttempt == $runAttempt and
    .runLabel == "official" and
    (.artifacts|length) == 9
  ' "$RELEASE_BUILD" >/dev/null

HOSTED_ROWS="$QUALIFICATION_RELEASE_OUTPUT/hosted-rows.jsonl"
: > "$HOSTED_ROWS"
for row in $(seq 0 8); do
  role="$(jq -r ".artifacts[$row].role" "$RELEASE_BUILD")"
  artifact_id="$(jq -r ".artifacts[$row].artifactId" "$RELEASE_BUILD")"
  archive_digest="$(jq -r ".artifacts[$row].uploadedArchiveSha256" "$RELEASE_BUILD")"
  member_path="$(jq -r ".artifacts[$row].memberPath" "$RELEASE_BUILD")"
  member_digest="$(jq -r ".artifacts[$row].memberSha256" "$RELEASE_BUILD")"
  member_bytes="$(jq -r ".artifacts[$row].bytes" "$RELEASE_BUILD")"
  [[ "$role" =~ ^[a-z][a-z0-9-]{0,63}$ ]]
  [[ "$artifact_id" =~ ^(0|[1-9][0-9]{0,31})$ ]]
  [[ "$archive_digest" =~ ^[0-9a-f]{64}$ ]]
  [[ "$member_path" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$ ]]
  [[ "$member_digest" =~ ^[0-9a-f]{64}$ ]]
  [[ "$member_bytes" =~ ^[1-9][0-9]{0,8}$ ]]
  (( member_bytes <= 536870912 ))

  metadata="$QUALIFICATION_RELEASE_OUTPUT/downloads/$role.metadata.json"
  api "$(artifact_api_path "$artifact_id")" > "$metadata"
  jq -e \
    --arg artifactId "$artifact_id" \
    --arg digest "sha256:$archive_digest" \
    --arg runId "$OFFICIAL_RELEASE_BUILD_RUN_ID" \
    --arg name "auths-qualification-$CANDIDATE_REVISION-official-$role" '
      (.id|tostring) == $artifactId and
      .digest == $digest and
      .name == $name and
      (.size_in_bytes > 0 and .size_in_bytes <= 536870912) and
      .expired == false and
      (.workflow_run.id|tostring) == $runId
    ' "$metadata" >/dev/null

  archive="$QUALIFICATION_RELEASE_OUTPUT/downloads/$role.zip"
  download_artifact "$artifact_id" "$archive" "$archive_digest" \
    "$(jq -r '.size_in_bytes' "$metadata")" 536870912
  mapfile -t entries < <(timeout 10 zipinfo -1 "$archive" | head -n 3)
  [[ "${#entries[@]}" -eq 1 ]]
  entry="${entries[0]}"
  [[ "$entry" != /* && "$entry" != *'\'* && "$entry" != *'../'* ]]
  [[ "${entry##*/}" == "$member_path" ]]
  mkdir -p "$QUALIFICATION_RELEASE_OUTPUT/artifacts/$role"
  destination="$QUALIFICATION_RELEASE_OUTPUT/artifacts/$role/$member_path"
  file_blocks=$(( (member_bytes + 511) / 512 + 1 ))
  ( ulimit -f "$file_blocks"; timeout 300 unzip -p "$archive" "$entry" > "$destination" )
  [[ "$(stat -c '%s' "$destination")" == "$member_bytes" ]]
  [[ "$(sha256sum "$destination" | cut -d' ' -f1)" == "$member_digest" ]]
  jq -cS \
    --arg role "$role" \
    --arg artifactId "$artifact_id" \
    --arg digest "$archive_digest" '
      {
        role: $role,
        name: .name,
        artifactId: $artifactId,
        uploadedArchiveSha256: $digest,
        sizeInBytes: .size_in_bytes,
        createdAtUnixSeconds: (.created_at | fromdateiso8601),
        expiresAtUnixSeconds: (.expires_at | fromdateiso8601),
        expired: .expired
      }
    ' "$metadata" >> "$HOSTED_ROWS"
done

NOW="$(date +%s)"
HOSTED_METADATA="$QUALIFICATION_RELEASE_OUTPUT/hosted-metadata.json"
jq -n -cS \
  --slurpfile projection "$PROJECTION_METADATA" \
  --slurpfile run "$RUN_METADATA" \
  --slurpfile artifacts "$HOSTED_ROWS" \
  --arg repositoryId "$GITHUB_REPOSITORY_ID" \
  --arg candidate "$CANDIDATE_REVISION" \
  --arg runId "$OFFICIAL_RELEASE_BUILD_RUN_ID" \
  --arg projectionId "$OFFICIAL_RELEASE_BUILD_ARTIFACT_ID" \
  --arg projectionDigest "$OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST" \
  --argjson checkedAt "$NOW" \
  --argjson retentionDays "$AUTHS_QUALIFICATION_RETENTION_DAYS" '
    {
      schema: "auths.qualification-release-hosted-metadata/1",
      checkedAtUnixSeconds: $checkedAt,
      repositoryId: $repositoryId,
      workflowPath: ".github/workflows/release-builder.yml",
      workflowRevision: $candidate,
      runId: $runId,
      runAttempt: $run[0].run_attempt,
      retentionDays: $retentionDays,
      projection: {
        role: "release-build",
        name: $projection[0].name,
        artifactId: $projectionId,
        uploadedArchiveSha256: $projectionDigest,
        sizeInBytes: $projection[0].size_in_bytes,
        createdAtUnixSeconds: ($projection[0].created_at | fromdateiso8601),
        expiresAtUnixSeconds: ($projection[0].expires_at | fromdateiso8601),
        expired: $projection[0].expired
      },
      artifacts: $artifacts
    }
  ' > "$HOSTED_METADATA"
truncate -s -1 "$HOSTED_METADATA"

env -i "$QUALIFICATION_RELEASE_VERIFIER" verify-hosted \
  "$RELEASE_BUILD" \
  "$SURFACE" \
  "$MEMBERS" \
  "$QUALIFICATION_RELEASE_OUTPUT/artifacts" \
  "$QUALIFICATION_CANDIDATE_REPOSITORY" \
  "$HOSTED_METADATA" \
  "$PROVENANCE_VERIFICATION" \
  "$QUALIFICATION_ATTESTER_TOOLS_VERIFICATION" \
  "$QUALIFICATION_ATTESTER_TOOLS_MANIFEST" \
  "$CANDIDATE_REVISION" \
  "$NOW" \
  "$QUALIFICATION_RELEASE_OUTPUT/verified-release-build.json"
