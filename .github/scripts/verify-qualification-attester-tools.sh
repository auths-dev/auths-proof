#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 4 ]]
root="$1"
expected_revision="$2"
expected_manifest_sha256="$3"
source_trust="$4"
[[ "$expected_revision" =~ ^[0-9a-f]{40}$ ]]
[[ "$expected_manifest_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ -d "$root" && ! -L "$root" ]]
[[ -f "$source_trust" && ! -L "$source_trust" ]]
[[ "$(stat -c '%h' "$source_trust")" == 1 ]]

expected=(auths-qualification-supervisor gh gitleaks manifest.json qualification-agent-launcher qualification-attestation-signer qualification-crash-controller qualification-observation-signer qualification-release-build-verifier qualification-source-client-proxy qualification-source-credential-broker qualification-source-journal-reader qualification-source-profile-state-reader qualification-source-provider-observer qualification-source-provider-proxy qualification-source-receipt-verifier qualification-source-supervisor trusted-root.jsonl xtask)
mapfile -t actual < <(find "$root" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
[[ "${#actual[@]}" -eq "${#expected[@]}" ]]
for index in "${!expected[@]}"; do
  [[ "${actual[$index]}" == "${expected[$index]}" ]]
done

manifest="$root/manifest.json"
[[ -f "$manifest" && ! -L "$manifest" ]]
[[ "$(stat -c '%h' "$manifest")" == 1 ]]
[[ "$(sha256sum "$manifest" | cut -d' ' -f1)" == "$expected_manifest_sha256" ]]
canonical="$root/manifest.canonical"
jq -cS . "$manifest" > "$canonical"
truncate -s -1 "$canonical"
cmp "$manifest" "$canonical"
rm -f "$canonical"

jq -e \
  --arg revision "$expected_revision" '
    .schema == "auths.qualification-attester-tools/1" and
    .attesterRevision == $revision and
    (.ghVersion | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and
    .retentionDays == 90 and
    .runnerLabel == "ubuntu-24.04" and
    (.runnerImageOs | test("^[ -~]{1,128}$")) and
    (.runnerImageVersion | test("^[ -~]{1,128}$")) and
    (.members | map(.path)) == ["auths-qualification-supervisor","gh","gitleaks","qualification-agent-launcher","qualification-attestation-signer","qualification-crash-controller","qualification-observation-signer","qualification-release-build-verifier","qualification-source-client-proxy","qualification-source-credential-broker","qualification-source-journal-reader","qualification-source-profile-state-reader","qualification-source-provider-observer","qualification-source-provider-proxy","qualification-source-receipt-verifier","qualification-source-supervisor","trusted-root.jsonl","xtask"] and
    (.members | map(.mode)) == ["0755","0755","0755","0755","0755","0755","0755","0755","0755","0755","0755","0755","0755","0755","0755","0755","0600","0755"] and
    all(.members[]; (.sha256 | test("^[0-9a-f]{64}$")))
  ' "$manifest" >/dev/null

source_canonical="$root/source-trust.canonical"
jq -cS . "$source_trust" > "$source_canonical"
truncate -s -1 "$source_canonical"
cmp "$source_trust" "$source_canonical"
rm -f "$source_canonical"

jq -e --slurpfile trust "$source_trust" '
  def member($manifest; $path): first($manifest.members[] | select(.path == $path) | .sha256);
  def source_member($source):
    if $source == "supervisor" then "qualification-source-supervisor"
    elif $source == "client-proxy" then "qualification-source-client-proxy"
    elif $source == "journal-reader" then "qualification-source-journal-reader"
    elif $source == "credential-broker" then "qualification-source-credential-broker"
    elif $source == "profile-state-reader" then "qualification-source-profile-state-reader"
    elif $source == "provider-proxy" then "qualification-source-provider-proxy"
    elif $source == "receipt-verifier" then "qualification-source-receipt-verifier"
    elif $source == "provider-observer" then "qualification-source-provider-observer"
    else null end;
  def fixed_reader($source):
    $source != "supervisor" and $source != "journal-reader";
  . as $manifest |
  ($trust | length) == 1 and
  $trust[0].schema == "auths.profile-qualification-evidence-source-trust/1" and
  ($trust[0].keys | length) >= 8 and
  ([$trust[0].keys[].source] | unique | sort) ==
    ["client-proxy","credential-broker","journal-reader","profile-state-reader","provider-observer","provider-proxy","receipt-verifier","supervisor"] and
  all($trust[0].keys[];
    (source_member(.source)) as $path |
    $path != null and
    .sourceArtifactSha256 == member($manifest; $path) and
    if fixed_reader(.source)
    then .readerArtifactSha256 == member($manifest; $path)
    else .readerArtifactSha256 == null
    end)
' "$manifest" >/dev/null

for index in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do
  member="$(jq -r ".members[$index].path" "$manifest")"
  expected_digest="$(jq -r ".members[$index].sha256" "$manifest")"
  expected_mode="$(jq -r ".members[$index].mode" "$manifest")"
  path="$root/$member"
  [[ -f "$path" && ! -L "$path" ]]
  [[ "$(stat -c '%h' "$path")" == 1 ]]
  [[ "$(sha256sum "$path" | cut -d' ' -f1)" == "$expected_digest" ]]
  actual_mode="$(stat -c '%a' "$path")"
  [[ "$actual_mode" == "${expected_mode#0}" || "$actual_mode" == 644 ]]
  chmod "${expected_mode#0}" "$path"
  [[ "$(stat -c '%a' "$path")" == "${expected_mode#0}" ]]
done
[[ "$("$root/gitleaks" version)" == '8.28.0' ]]
