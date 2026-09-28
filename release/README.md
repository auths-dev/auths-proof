# Auths release directory

This directory owns the frozen release contract and the evidence needed to
prepare, authorize, promote, verify, or withdraw an Auths release candidate.
Preparation is not authorization, and GitHub prerelease promotion is not
registry publication.

Start with:

- [`RELEASE_RUNBOOK.md`](RELEASE_RUNBOOK.md) for the exact operator procedure;
- [`RELEASE_CONTROL.md`](RELEASE_CONTROL.md) for the security architecture and
  trust boundaries;
- [`CANDIDATE_CLOSURE.md`](CANDIDATE_CLOSURE.md) for the current candidate and
  remaining gates;
- [`RELEASE_CANDIDATE_NOTES.md`](RELEASE_CANDIDATE_NOTES.md) for the text that
  will become the GitHub prerelease description; and
- [`SLSA_BUILD_LEVEL_3_ASSESSMENT.md`](SLSA_BUILD_LEVEL_3_ASSESSMENT.md) for
  the assessed build-platform boundary; and
- [`../docs/product/COMPATIBILITY_AND_SUPPORT.md`](../docs/product/COMPATIBILITY_AND_SUPPORT.md)
  for the generated cross-language evolution, support, and retirement contract.

The JSON schemas, fixtures, subject catalogue, naming authority, and semantic
freeze are machine-enforced inputs. `cargo xtask evolution-policy` validates
the five version axes, mock classifications, mixed-version behavior, lifecycle
metadata, and the stable-publication gate. Do not hand-edit generated evidence
merely to make a release pass.
