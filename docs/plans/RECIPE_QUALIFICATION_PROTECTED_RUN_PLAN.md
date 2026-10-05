# Recipe qualification: protected-run plan

- **Status:** the verifier, the issuance tooling, the evidence wall, the
  runtime gate, and the workflow exist; AP-SPEC-066 §20 records them and
  where they differ from this plan. No trust root, signer, family, or
  qualification exists, and the run has never been started.
- **Spec:** [AP-SPEC-066](../specs/0066-production-gateway-polish-and-recipe-qualification.md)
  §7 and §8, Epics 3 and 5. Abstraction case
  [0008](../research/domains/abstraction-cases/0008-provider-secret-custody-and-recipe-qualification.md).
- **Frozen inputs:** `bindings/fixtures/qualification/schema-vectors.json` and
  `verification-vectors.json`, both driven: the verifier and the gateway's
  gate each decide all 57 verification cases as frozen.
- **Where things are:** [`qualification/README.md`](../../qualification/README.md)
  describes what a family provides and what the trust directory holds.

## 1. Keys and who holds them

| Key | Signs | Held | Used |
| --- | --- | --- | --- |
| Qualification trust root | signer certificates, revocation lists | offline, by the owner; never in a repository, a pull-request job, or a qualification runner | in a recorded ceremony |
| Release signer | qualification attestations, the release index | a software key in the protected signing environment, released after manual approval and removed when the job ends | once per protected run |

The root's public key and identifier are a canonical
`auths.qualification-trust-root/1` file pinned in the release verifier. The
release signer is labelled `protected-software-release-key-v1`. That label
claims neither hardware protection nor non-exportability, and no other label
decodes. Moving either key to KMS or PKCS#11 is the post-launch work of issue
#190 and changes no record, attestation, or application interface.

Neither key is an Auths grant root, an observer key, the provider-secret
workload identity, or an application identity.

## 2. The run

One workflow, started by hand on an immutable commit of the default branch.
Jobs run in this order, and a failure in any job ends the run with no record.

| Job | Secrets | Does |
| --- | --- | --- |
| 1. candidate | none | Builds the release candidate from clean source; rederives the compiled recipe digest, the profile-lock digest, the provider contract identifier, and the gateway semantic-closure digest; installs the gateway and SDK packages and records their digests. |
| 2. offline evidence | none | Runs the conformance, differential, and hostile members on the candidate. The pure oracle runs here and only here. |
| 3. live evidence | the qualification provider credential and the store roles, in the live environment | Runs the live, recovery, rotation, restart, multi-instance, redaction, and installed-consumer members against disposable provider resources through the candidate gateway and the production credential store. Reads every successful write back. Deletes what it created. |
| 4. assemble | none | Builds the canonical `auths.recipe-qualification/1` record from the evidence digests and counters. Refuses unless every member passed, every capability is accounted for, unauthorized provider entries are zero, and every live effect has its read-back. |
| 5. sign | the release signer key, in the signing environment, after manual approval | Re-verifies the record's evidence closure, signs the attestation, adds the entry to the release index, and signs the index. Signs nothing else. |
| 6. verify | none | Verifies the certificate, revocation list, index, attestation, and record with the pinned root exactly as a gateway would, and publishes them as release artifacts. |

A pull request runs jobs 1 and 2 only. It cannot reach the live or signing
environments, so it cannot gather live evidence; without the live member no
record closes, so it cannot assemble a proposal either, and it cannot update
the release index. This is narrower than the first version of this plan,
which let a pull request assemble.

The index a signer issues lists exactly the records of one run, so one run
qualifies every family together.

The redaction scan runs inside job 3, where the canaries are, and they are
deleted before the job uploads anything. Jobs 4, 5, and 6 each build the
release tool from the commit and run no program another job produced.

The qualification provider credential is scoped to the disposable resources of
the run and is not a production connection credential. The runtime gateway
never calls this workflow, and this workflow never serves runtime traffic.

## 3. Evidence wall to record

Every row of AP-SPEC-066 §7.5 lands in a named member or capability of the
record. A capability the family lacks is listed `not-applicable` with the
reason its decision record fixes; nothing is omitted.

| §7.5 row | Record member | Capabilities it accounts for |
| --- | --- | --- |
| 1 clean source, digests rederive | `conformance` | |
| 2 compiler and interpreter vectors | `conformance` | |
| 3 oracle and gateway agree | `differential` | |
| 4 application cannot read the secret | `hostile` | |
| 5 forgery, replay, direct attempt, race, restart, crash, ambiguity | `hostile`, `multi-instance`, `restart` | |
| 6 store kind, generation, commitment, version drift | `rotation` | |
| 7 secret and signer rotation | `rotation` | `observer-rotation` |
| 8 declared provider capabilities | `live` | `credential-guard`, `version-pin`, `account-binding`, `denied-reads`, `ceiling`, `budget`, `idempotency`, `response-locator`, `echo`, `observation` |
| 9 live writes confirmed by read-back | `live`, with `live_effects` | `observation` |
| 10 response loss and delayed visibility | `recovery` | `recovery` |
| 11 secret and provider-data scans | `redaction` | |
| 12 installed consumer journey | `installed-consumer` | |

Within a row, the cases are tagged with one of 36 scenarios, and a record
closes only when every scenario the wall always requires has a case;
AP-SPEC-066 §20.3 reading 3 lists them. The release tooling runs the
differential comparison, the redaction scan, and the freshness and
signer-rotation stages itself. A family's harness reports the rest.

Each member carries the digest of its evidence artifact, its case count, and
its unauthorized-provider-entry count, which must be zero. `live_effects`
carries the writes that entered and the writes confirmed by read-back, which
must be equal and at least one. A complete HTTP response without its read-back
is `response-recorded` and does not count.

## 4. Before a family can run

A family runs only after a provider-specific decision record names its
`RecipeFamilyId`, defines its pure oracle and why it is test-only, lists every
provider assumption with the evidence that tests it, fixes the reason for each
capability that does not apply, sets expiry and requalification cadence and
revocation triggers, publishes its hostile and live corpus, and states the
claims that stay with the provider. The provider contract's inputs come from
that record. Two families are required before launch: the Stripe refund
journey and one independently authored recipe from the field lab.

## 5. Freshness and the root's cadence

Freshness comes only from signed fields: an attestation lasts at most 90 days,
a signer certificate at most 365, and a revocation list at most 72 hours.

**The 72-hour bound is an operating commitment for the offline root.** A
gateway under production policy disables every required recipe when its
revocation list passes `next_update`. Someone must therefore bring the root
online in a ceremony often enough that a fresh list always exists. The plan is
a ceremony every 48 hours, leaving 24 hours for a missed one.

Signing several future-dated lists in one ceremony would relax that, and it is
not planned, for this reason. A revocation is published as a list with a
higher sequence. A list signed earlier for a later window also has a higher
sequence than today's and does not contain the revocation. Whoever holds such
a list holds a time-limited way to present a newer list without the
revocation. So:

1. The root signs only the next list. It signs no list whose `issued_at` is
   more than a few minutes ahead.
2. A verifier keeps every signer and qualification that any verified list has
   named and treats it as revoked permanently, whatever a later list says.
   The verification vectors `revocation-dropped-by-later-list` and
   `signer-revocation-dropped-by-later-list` pin this.
3. A verifier refuses a list whose sequence is lower than the highest it has
   accepted (`revocation-list-rolled-back`).

If a 48-hour ceremony proves unworkable, the choice is the owner's: accept the
ceremony, or amend the bound in the spec. It is not to be relaxed by
configuration, which the spec forbids and the schema has no member for.

## 6. Rotation and revocation

- **Signer rotation.** The root certifies a new signer. The new signer
  re-signs each still-current record after re-verifying its evidence closure;
  no provider effect is rerun because key storage changed. The old
  certificate expires or is revoked.
- **Signer compromise.** The root revokes the signer. Every attestation it
  issued is invalid regardless of issue time and stays revoked. A recipe it
  attested is disabled until a new signer attests its record again after
  re-verifying the evidence closure; that new attestation is a new
  qualification lifecycle, not the revoked one restored.
- **Qualification revocation.** The root names the qualification in the next
  list. The family's decision record says what triggers this.
- **Root rotation.** A separately reviewed release pins the successor root.
  It is never a runtime or network operation.

## 7. What a gateway receives

The certificate, the revocation list, the release index, and the attestations
and records it references, as local files updated through the operator plane.
The gateway verifies each once per input digest, keeps the verified result in
memory, and before every lease compares the connection's tuple with it and
evaluates the signed time bounds and revocations against trusted time. It
performs no provider call, no network trust fetch, and no qualification run.

## 8. Vector mapping

| Verification case group | What the verifier must show |
| --- | --- |
| forged, outsider-signed, another root, lacking permission | a broken chain never yields `qualified`; an unusable certificate or index is `unavailable` |
| signer-signed certificate or revocation list | a release signer cannot sign what only the root may sign |
| expired, not yet valid, issued ahead, past next update, untrusted clock | each signed time bound is enforced; a window that has ended is `expired`, one that has not started is `missing` |
| revoked signer or qualification, alone and combined | revocation is reported before every later fault and is permanent |
| two faults at once, one case per adjacent pair | the order in which faults are reported |
| wrong recipe, lock, contract, closure, target, store, credential store | any tuple difference is stale, digest members before target members |
| second target, another qualification revoked | a correct deployment is `qualified` and nothing else is disturbed |

## 9. Credentials and decisions for the owner

1. A protected environment for signing with manual approval, and the release
   signer key in it.
2. A protected environment for live evidence with a disposable provider
   account per family and the store roles of the custody plan.
3. The root ceremony: who holds the key, where, and how each use is recorded.
4. The 48-hour cadence of section 5.

Each is an owner decision under the program board's credential rule. None is
granted by this plan, and no credential was created or requested to write it.
