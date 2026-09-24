# Code review passes

A pass reruns the review prompts in `prompts/` against the current commit and
turns what they find into organized work. Run one every 3–6 weeks, or before a
release. Everything here is run by hand.

A pass is not the independent human review described in `REVIEW_SCOPE.md` and
never counts toward it.

## Files

| Path | Purpose |
| --- | --- |
| `prompts/00-how-to-use.md` | Shared preamble and severity scale. Paste it above every reviewer prompt. |
| `prompts/01-*.md` to `07-*.md` | One reviewer per area. |
| `prompts/90-verify.md` | Re-checks each reported finding against the code and the docs. |
| `prompts/91-plan-work.md` | Sorts the confirmed findings into work. |
| `settled.md` | Findings already decided. Reviewers read it first so they don't raise them again. |
| `passes/<date>/findings.md` | Every finding from one pass, with its verdict and severity. Local only. |
| `passes/<date>/work.md` | How that pass's work was split, with links. Local only. |

`passes/` is ignored by git and never published. A finding that changes the
design becomes a spec under `docs/specs/`; everything else lives in the
issues, advisories, and PRs a pass files.

## Run a pass

1. Record the commit (`git rev-parse --short HEAD`) and create `passes/<date>/`.
2. Run prompts 01–07 in parallel, one agent each, with the preamble on top.
3. Run `90-verify.md` on everything they report: one agent per area's findings,
   and one per P0 or P1 finding.
4. Write every verdict to `passes/<date>/findings.md`. Add rejected findings and
   documented limits to `settled.md`.
5. Run `91-plan-work.md` on the confirmed findings to write
   `passes/<date>/work.md`. Then act on it: file advisories and issues, add
   board lines for work that joins an epic, and open the cleanup PR.

## Rules

- Security findings go to a private GitHub security advisory (see
  `SECURITY.md`). Tracked files carry only the advisory ID until the advisory
  is published.
- Link to issues and PRs; don't copy their status here. GitHub tracks it.
- Cite code as `path:line @ <short sha>`. Line numbers drift; the SHA pins them.
- Don't edit a past pass. Corrections go in the next one.
