# Candidate assurance threat model

## Protected claims

The assurance boundary protects the claim that one named artifact set was
tested—not that Auths is universally safe in every deployment. The manifest
binds the source commit, image, language packages, hosted-build provenance,
configuration commitment, database schema, semantic freeze, profile set, and
runtime matrix.

The verifier must prevent:

- evidence from one candidate being replayed for another;
- an omitted, failed, or untested evidence family appearing as passed;
- a partial qualification interval appearing as thirty days;
- undisclosed qualification gaps appearing continuous;
- an author-controlled review appearing independent;
- open critical or high findings being ignored;
- modified or unavailable evidence artifacts retaining validity;
- a changed manifest retaining an old signature; and
- release promotion from bypassing the assurance result.

## Trust boundaries

- The Rust verifier owns parsing, bounds, candidate linkage, evidence-kind
  completeness, review blockers, artifact digests, canonical statement bytes,
  and Ed25519 signature verification.
- CI and the release environment provide isolated build provenance and protect
  the final promotion authority.
- Qualification operators provide truthful timestamps, fault execution, and
  retained artifacts. The manifest makes those statements inspectable but
  cannot make a dishonest operator truthful.
- Independent reviewers provide expertise and organizational independence.
  Their public report remains an input, not a cryptographic theorem.
- Users remain responsible for their own identity providers, provider
  configuration, infrastructure hardening, keys, backups, monitoring, and
  business intent.

## Reset conditions

Executable bytes, dependencies, build workflow, container image, SDK package,
production configuration meaning, database schema, profile identity, or frozen
semantic fixture changes invalidate the candidate. Documentation corrections
may retain the candidate only when they cannot alter executable meaning and are
recorded in the evidence history.
