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
set it. The current build pins no root and therefore derives false. Missing
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
simulation; the shipping lease gate has no bypass. A proposed solution is
[ADR 0016](../docs/adr/0016-bounded-qualification-commissioning-authority.md):
a finite signed permit for an authenticated private qualification-run session,
with exact action commitments, durable lease accounting and a fixed expiry.
It is not implemented, cannot qualify a family, and cannot enable an ordinary
application lease.

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

`corpus-manifest.json` is `auths.qualification-corpus/1`, decoded as
`execution::RunCorpus` by `auths-qualification run-stage`. It contains at most
256 unique cases. Each case has `id`, `scenario`, `capabilities`, `phase`
(`offline` or `live`), and at most 32 ordered `steps`. Each step has a closed
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

`prepare` installs the candidate in `<work-dir>/gateway-state`, installs the
consumer packages, and writes `packages.json`. The candidate gateway itself
prints `tuple.json`; the release tool checks the declared contract ID against
`contract.json`. `prepare-live` acquires disposable resources, starts the live
candidate. `run/live.sh` always calls `cleanup`, including after setup or stage
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
Replay operations cannot lease or enter again. Forged/altered inputs cannot
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

No private key is ever in this repository. The directory is empty until the
first ceremony, and until then the signing job refuses to run.

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
