#!/usr/bin/env bash
# Builds a scratch repository for the verify-git-signatures action self-test:
#   main     trust pinned to a did:key root
#   signed   main + one agent-signed commit
#   unsigned signed + one unsigned commit
# Usage: git-signing-scratch-repo.sh <bin-dir> <repo-dir>
set -euo pipefail
bin="$1"
repo="$2"
repository="github.com/auths-dev/scratch"
export AUTHS_GIT_HOME="$RUNNER_TEMP/auths-git-home"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

mkdir -p "$repo"
cd "$repo"
git init -q -b main
git config user.name "Scratch Agent"
git config user.email "agent@example.invalid"
git config gpg.format x509
git config gpg.x509.program "$bin/auths-git-sign"
git config user.signingkey auths:agent
git config auths.repository "$repository"

"$bin/auths-git" key init --label root > /dev/null
agent=$("$bin/auths-git" key init --label agent)
"$bin/auths-git" trust init --root root --repository "$repository" --out .auths/git
git add .auths/git/trust.cbor
git commit -q -m "pin git signing trust"

"$bin/auths-git" grant --root root --subject "$agent" --repository "$repository" \
  --capability sign-commit --expires-in 86400 --out "$RUNNER_TEMP/agent.grant.json"
"$bin/auths-git" install-grant --label agent "$RUNNER_TEMP/agent.grant.json"

git switch -q -c signed
echo signed > signed.txt
git add signed.txt
git commit -q -S -m "agent-signed change"

git switch -q -c unsigned
echo unsigned > unsigned.txt
git add unsigned.txt
git commit -q --no-gpg-sign -m "unsigned change"
