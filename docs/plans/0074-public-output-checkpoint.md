# AP074 public-output cutover checkpoint

The user requested a committed, pushed pause on 30 October 2026. AP074 is incomplete.
This branch preserves unfinished implementation work; it is not a qualification or
merge candidate. PR213 remains on `codex/effect-recovery-foundation` with the last
completed public mutation-evidence cutover and a separate bounded CI repair.

## Saved work

- Native hiding effect and full journal-record commitments under the existing
  protected immutable nonce; the nonce is excluded from the sealed message.
- Public signed outcome `/3`, redacted pre-entry history and app observe `/4`.
- Operator-only `audit-export`, writing a new private 0600 file. The private
  signed outcome `/1` retains the complete existing outcome presence predicate
  and audit checks. This avoids exporting the journal nonce or adding a second
  journal decoder. No journal schema or entry transition changes are intended.
- Python/TypeScript public pre-entry types and parser changes, native public `/3`
  and private `/1` reference-vector constructors, and native sentinel assertions.

## Construction evidence and limits

The actual file-backed signed-public-output privacy constructor passed (1 passed,
0 ignored, 0.74 s), including the existing private evidence and native-signature
checks. The new public `/3` vector constructor passed (1 passed, 0 ignored,
0.04 s). A later small source edit consumed the public stage field and adjusted
Debug output; it has not been rebuilt. No SDK suite or broad gate ran locally.
These are artifact-construction checks, not complete acceptance or CI evidence.

## Required before integrating this cutover

1. Reconcile this checkpoint against the completed CI-repair commits on the PR.
   Preserve the redacted Debug/assertion repairs and updated SDK API snapshot.
2. Finish native private export integration and all SDK/demo/example/template
   consumers. Public app history must never carry raw protected pre-entry bytes
   or private outcomes. Complete private audit bundles at the operator boundary;
   keep existing offline audit, recount, basis, pre-entry and tamper checks.
   Do not restore raw public echoes/digests or weaken any existing assertion.
3. Finish the direct schema/fixture cutover. Remove superseded public `/2`
   fixtures/readers; keep full private fact fixtures explicitly private. Regenerate
   all affected native catalogs, CLI inventory and Unix interface artifacts.
   The new command must be covered by Linux wrong-UID and private-output probes.
4. Update the specification, compliance inventory, acceptance ledger, binding
   documentation, source closure, semantic freeze and public API snapshot
   atomically. The existing generated metadata is stale on this checkpoint.
5. Generate the required file and TLS PostgreSQL artifacts, commit the coherent
   change, and give the CI subagent the exact SHA to publish and qualify.
6. Continue the remaining full AP074 acceptance work from the main status ledger.
   Do not claim A17 or the entire specification complete from this checkpoint.

AP070 remains the independent application-owned reference. AP073 remains paused
and untouched. No additional delegation is authorized. Resume only on a new user
request; the current main goal is paused after the stable PR checkpoint is pushed.
