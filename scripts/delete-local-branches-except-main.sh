#!/usr/bin/env bash
set -euo pipefail

readonly protected_branch="main"
readonly repository_root="$(git rev-parse --show-toplevel)"

cd "$repository_root"

if ! git show-ref --verify --quiet "refs/heads/$protected_branch"; then
  echo "Refusing to continue: local branch '$protected_branch' does not exist." >&2
  exit 1
fi

git switch "$protected_branch"

# Remove metadata for worktrees whose directories no longer exist. Git refuses
# to delete branches that remain associated with stale worktree records.
git worktree prune

deleted=0
while IFS= read -r branch; do
  if [[ "$branch" == "$protected_branch" ]]; then
    continue
  fi

  git branch -D -- "$branch"
  deleted=$((deleted + 1))
done < <(git for-each-ref --format='%(refname:short)' refs/heads)

echo "Deleted $deleted local branches; kept '$protected_branch'."
