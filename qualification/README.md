# Recipe qualification

What a protected run needs to qualify a recipe family, and where it finds it.
The specification is
[AP-SPEC-066](../docs/specs/0066-production-gateway-polish-and-recipe-qualification.md)
§7 and §8; the run is described in
[the protected-run plan](../docs/plans/RECIPE_QUALIFICATION_PROTECTED_RUN_PLAN.md).

No production family is qualified. The owner-directed disposable bootstrap and
Stripe/Airtable harnesses are in [simulation/](simulation/README.md); they run
without external credentials and publish explicitly simulated evidence. Proposed provider decisions
are [ADR 0014](../docs/adr/0014-stripe-refund-recipe-qualification.md) and
[ADR 0015](../docs/adr/0015-airtable-record-update-recipe-qualification.md).
They explicitly remain proposed until their executable corpora and protected
evidence exist. A separate [live operator rehearsal](simulation/live/README.md)
has now passed against Airtable using downloaded gateway/SDK artifacts,
disposable records and development custody; it does not qualify a production tuple.

`cargo xtask release-check` generates `target/release-evidence/launch-readiness.json`.
Its `stable_launch_ready` value comes from the gateway build's pinned public
root, current signed inputs and their actual evidence; no checked-in flag can
set it. The current build pins the public ceremony root but has no signed qualification inputs, so it derives false. Missing
qualification permits a prerelease while preventing a stable launch claim.

The release builder reads public signed inputs from
`target/qualification-release/<exact-candidate-commit>/`. These downloaded
public artifacts are build inputs, not a source commit containing a reference
to itself. The signing tool includes
the canonical evidence at `evidence/<artifact-digest>.json`, alongside the
index, records, attestations, certificate and revocation list. The projection
verifies every referenced artifact and requires two distinct families,
contracts and provider kinds on the same production candidate. Its clock
must pass the maintained synchronization check. Human release review remains
a separate requirement.

Finalization re-evaluates the projection against current candidate inputs before
binding it into the final manifest. An edited readiness value, another commit,
drifted target or missing projection cannot become a signed launch claim. The
manifest contract requires exactly one digest-bound projection.

## Bootstrap rehearsal and production evidence

The owner assigned the agent an independent operator simulation, including the
first signing ceremony and both provider harnesses. `simulation/run.py` performs
that work with fresh in-memory signing keys, explicit placeholder trust-machine
records and measured provider-driver reports. Detached simulation signatures
bind the measured report bytes and are verified after publication. Their keys
are explicitly self-signed and have no protected-run authority. It imports signed fixtures under
required test trust and measures real engine credential-store calls. No private
keys or production trust inputs are written. This work does not wait for a human
ceremony or real provider credentials.

The current production gateway refuses every lease without a current exact-tuple
attestation. The protected workflow gathers live effects before it can sign that
attestation. Therefore its first qualification cannot bootstrap itself. A
development installation or `testkit-production-unqualified` executable changes
the target or shipped bytes and cannot establish the required production claim.
That real-production authority question remains separate from the requested
simulation; the shipping lease gate has no bypass. The implemented commissioning authority is
[ADR 0016](../docs/adr/0016-bounded-qualification-commissioning-authority.md):
a finite signed permit for an authenticated private qualification-run session,
with exact action commitments, durable lease accounting and a fixed expiry.
Its verifier, durable budget and private operator commands are implemented. It cannot qualify a family or enable an ordinary application lease. The [reviewed references](reference/README.md) independently derive exact resource/action bindings; the protected family setup and workflow still need to execute them.

The current executable corpus also fixes exact request/evidence digests before
running, while disposable live resource identifiers may be created during setup.
Family harnesses need a reviewed, bounded resource-binding and oracle expansion
before executing their cases. Copying the candidate's observed digest into an
expected result would invalidate the differential evidence.

The rehearsal fixes synthetic resource IDs before execution, so its independent
oracles do not copy digests observed from candidate output. The offline production
root, protected signer and provider credentials remain prerequisites for real
protected evidence, not for the simulation.

A `production-readiness` case is additionally required for each stable launch
claim. It runs only in the protected live phase against PostgreSQL and
production custody, without a lease or provider entry. The reviewed harness
must run the candidate's doctor and check every required typed row, including
qualification, then return `production-readiness-passed` and the digest of its
actual report. Development `not-ready` reports cannot satisfy it. This case
is optional for intermediate qualification records; its absence always makes
the stable launch projection false.

## `families/<family>/`

One directory per recipe family, named by its `RecipeFamilyId`.

| File | Holds |
| --- | --- |
| `decision-record.md` | The family's decision record. Its digest goes into the record. |
| `contract.json` | The canonical `auths.provider-contract/1` the run qualifies against. |
| `corpus-manifest.json` | The corpus the differential, hostile, and live stages run. |
| `record.json` | What the record states that no run decides: `provider_kind`, `validity_days` (at most 90), `not_applicable` (each capability the family lacks, with the reason the decision record fixes), `custody_descriptor`, `store_descriptor`, `residual_assumptions`, `excluded_claims`. |
| `harness` | A reviewed executable implementing `prepare`, `prepare-live`, `step` and `cleanup`. |

The harness owns the provider-specific operations and pure oracle. The release
runner owns sequencing, assertions, counters, and the resulting case reports.
No family harness writes `passed` reports or `live-effects.json`.

`corpus-manifest.json` is `auths.qualification-corpus/3`, decoded as
`execution::RunCorpus` by `auths-qualification run-stage`. It contains at most
256 unique cases. Each case has `id`, `scenario`, `capabilities`, `phase`
(`offline`, `commissioning` or `live`), and at most 32 ordered `steps`. Each step has a closed
`operation` and an `expected` observation: exact verdict (outcome, stable code,
request and evidence digests), credential leases, provider entries, and writes
confirmed by fresh read-back. All required non-trust/non-redaction scenarios
must have executable cases. Capabilities must belong to their scenarios.

The runner calls the reviewed executable as:

```text
harness prepare <work-dir>
harness prepare-live <work-dir>
harness step <case-id> <step-index> <operation> <work-dir> <output-file>
harness cleanup <work-dir>
```

`prepare` writes the reviewed recipe and lock into `<work-dir>`, installs the
consumer packages, and writes `packages.json`. The candidate gateway itself
prints its planned production `tuple.json` through `qualification-candidate`,
without custody or provider access; the release tool checks the declared contract ID against
`contract.json`. `prepare-live` installs production custody for the disposable resources and
compares `qualification-status --tuple` with that planned tuple before any
permit import or submission. A changed installation fails closed. `run/live.sh` always calls `cleanup`, including after setup or stage
failure; cleanup must remove disposable resources idempotently, and its failure
fails the run. Both setup commands receive `AUTHS_GATEWAY` and
`AUTHS_QUALIFICATION`. Only the protected live environment supplies
`AUTHS_QUALIFICATION_PROVIDER_CREDENTIAL`.

Each `step` executes the named corpus operation against that candidate and
writes one `execution::RunObservation`: tuple digest, measured verdict and
counters, unauthorized entries, secret exposure, repository imports, and
provider-token receipt. Unknown fields, missing output, wrong tuples, failed
processes, oversized observations, mismatches and timeouts produce no passing
report. Output is limited to 16 KiB and each step to 60 seconds (bounded to
1–120 seconds for a reviewed run). Child stdout and stderr are not published.
Counters must come from the credential-store and provider witnesses, not from
expected corpus values. The family harness is trusted reviewed release code;
these observations are evidence, not cryptographic proof of provider behavior.

The runner independently compares oracle and gateway verdicts and request/
evidence commitments; accepted differential cases require a request digest.
Replay, race, restart, crash, ambiguity and recovery cases may enter once only.
Replay never enters write transport again. An unresolved entered attempt may take one read-only lease to complete its declared observation; an already observed attempt takes none. Forged/altered inputs cannot
lease. Recovery runs loss/delay followed by read-back and must remain `unknown`
when no recovery capability is declared. Live effects count only successful
writes with fresh read-back. Installed-consumer steps run outside the source
checkout with a cleared environment: no provider credential or repository
import path is inherited. Their executable must use installed packages.

`run-stage` writes `cases/<member>.offline.json` or `.live.json` only after
all cases in that phase pass, and derives `live-effects.json` from measured
live-member observations. The family additionally writes:

- `resources.json`: sanitized identifiers of the disposable resources;
- `canaries`: every secret and provider datum planted for the run, one per line;
- `scan/log/`, `scan/trace/`, `scan/metric/`, `scan/support-bundle/`: actual
  outputs from the candidate. Missing categories prevent closure; a family
  must export the gateway's real support bundle once Epic 4 provides it.

`run/redact.sh` scans the outputs and evidence and removes canaries before
upload. The release tool itself executes signer rotation and freshness; the
family cannot replace those reports. Assembly re-verifies scenario, candidate,
capability, counter and digest closure before signing can begin.

## `trust/`

Public artifacts of the offline root ceremony, committed by the owner:

- `qualification-trust-root.json`: the root a gateway release pins;
- `signer-certificate.json`: the current release signer's certificate;
- `revocation-list.json`: the current revocation list.

No private key is ever in this repository. `ceremony.json` records the first
offline ceremony and the exact public-artifact hashes. It is an explicitly
delegated technical assessment, not a human release review or provider
qualification. No qualification record or release index has been issued.

The first qualification uses the separate finite authority in
[ADR 0016](../docs/adr/0016-bounded-qualification-commissioning-authority.md).
`auths-qualification certify-commissioner` certifies a separate key with only
the commissioning-permit purpose; normal `certify` grants only release purposes.
The root key remains offline and never enters either provider runner. Both purpose-separated signer keys were provisioned on 7 October 2026 into the reviewer-protected, main-only `recipe-qualification-signing` environment. No private root material was uploaded.

After the protected reference expands disposable resources and exact actions,
`auths-qualification commissioning-sign` takes `--binding`, `--conformance`,
`--differential`, `--signer-key`, `--certificate`, `--not-before`, `--not-after`
and `--out`. It rechecks both canonical offline members, candidate/tuple/digest
closure and all mandatory scenarios before signing. The permit lasts at most
two hours and is never a qualification record or release-index member. The
reviewed protected reference must independently derive resources/actions;
successful issuance by itself does not establish that reference's correctness.

The operator receives `commissioning-permit.json`, `signer-certificate.json`
and the current `revocation-list.json` in one artifact directory. Only the
gateway's private `commissioning-init` and `commissioning-submit` commands use
them, with `--from`, `--state-dir`, `--protected-run` and `--resource-binding`.
Ordinary application requests require current qualification throughout.

## `run/`

The scripts the workflow's jobs call. `offline.sh` and `assemble.sh` need no
secret and can be run on a development host. `redact.sh` runs in the live
job.

## Environments

Each family's live environment, `recipe-qualification-live-<family>`, must be
created with a required reviewer and the default branch only **before** its
credential is stored in it. The signing environment already has both rules.
The harness of a family is trusted as reviewed code on the default branch;
the run does not execute anything a harness leaves behind as a program in
the jobs that assemble, sign, or verify.

## First qualification and ordinary validation

One reviewed corpus contains three closed phases. `offline` establishes native
proof, recipe and oracle agreement without custody. `commissioning` exercises
the exact production candidate through finite private operator authority; its
installed-client journey must show an ordinary qualification refusal with zero
leases/entries. It cannot include a production-readiness case.

Assembly selects offline reports and exactly one protected phase, never mixes
stale commissioning and ordinary live reports. Commissioning records last at
most two hours and explicitly exclude ordinary installed-client success and
production readiness. They permit the existing qualification chain to unlock
the subsequent `live` phase on the same candidate/contract/recipe tuple.
That phase must show a confirmed effect from the installed ordinary client; a
refusal cannot satisfy it. Only that phase can contribute production doctor
evidence to a stable launch projection. A permit or an initial record alone
never establishes stable readiness.

### Measured execution boundaries

The private `auths-gateway execution-witness` command reads process-local
`auths.gateway-execution-witness/1` counters without consulting custody, the
store or the provider. The application channel cannot request or reset them.
Subtract snapshots only with the same random scope, after all measured calls
complete; reject decreasing or saturated counters. Aggregate each separately
scoped host for a two-instance race. Restart establishes a fresh scope.

`commissioning-submit` returns `auths.gateway-commissioning-execution/1` with
its result and before/after snapshots from its own short-lived engine. A
credential lease count is an actual store call, including a failing call;
a write entry is the HTTP client's execution boundary, including ambiguity.
Neither is a claim that a provider received or performed a mutation. Reads,
including credential probes, are counted separately. First qualification must
still independently read back the reviewed disposable resource.

### Fresh evidence comparisons

Every corpus step declares `evidence_comparison`: `static`,
`independent-read-back` with a reviewed `subject_sha256`, or
`production-doctor`. Static comparisons require the complete precomputed
verdict and forbid a fresh witness. Dynamic comparisons require an absent
precomputed evidence digest; every other expected field remains exact.

An independent read-back is allowed only for an observed protected operation.
The separate fresh witness must name the exact reviewed resource/action/state
subject, and its raw response digest must equal the candidate's evidence
digest. Different bytes fail the run, even if both responses appear successful.
The reference validates fresh provider state and echo before creating this
witness; it never accepts the candidate's locator or digest as the oracle.
A doctor witness is confined to a read-only production-readiness probe in the
ordinary live phase and must name the actual tuple. Unknown sources, omitted
witnesses, mismatched subjects/digests and extra fields fail closed.

The runner retains closed actual observations under `scan/trace`, separately
from the pass reports. They contain no provider body or secret and undergo the
existing protected redaction scan before export.

The credential-free `candidate` job builds and retains the actual shipping
Linux gateway and issuer without simulation features, even before a protected
family corpus is admitted. Its manifest binds exact file hashes, source commit
and workflow run. Native read-only recipe review exercises both maintained
recipes; no installation, custody lease or qualification is claimed. This
artifact is a candidate for operator inspection, not a GitHub release.
