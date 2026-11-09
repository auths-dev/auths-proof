# Composed invariants: source trace and remaining premises

Target: `ac5fcabe9c6300e46789b4e847bb1991f9f9d66f`. This is a review/test map,
not an end-to-end theorem. Final case and qualification results remain required.

## Authorization → exact durable grant → provider entry

`core/crates/auths-verifier/src/lib.rs::verify_v1` and gateway native compilation
derive verified action/command data under installed inputs. `BoundEffect` binds
the closed request, original native authority, recipe/connection/configuration,
partition/epoch and selected charges. The exact compiled-effect approval signs
that identity, separately from the portable financial quorum.

`store.rs:2991::ClaimedGatewayAttempt::grant_entry` derives dependency/counter/
prerequisite/ancestor keys, requires the retained Reserved record and exact
binding equality, and calls `entry.rs:221::EntryValidation::validate` under
`fenced_replace`. That method checks current connection/configuration and
qualification, samples after-lock time, validates enrollment/lineage and reruns
the native effect/approval check. Retained reservations and preconditions must
still validate before the durable transition yields a permit.

`submit.rs::Run::grant_entry` retains the permit only after acknowledgement;
`Run::send` consumes it with `take()`. Transport receives that closed capability,
not app-supplied HTTP fields. An ambiguous grant acknowledgement reads retained
state and does not manufacture a permit.

The new raw-frame campaign changes proof/action/approval bytes, substitutes
another exact approval and supplies attacker-chosen top-level trust, time,
credential and request fields. No such input caused provider I/O; the corrected
valid control did. Native configuration/entry/revocation regressions supplement
this with the actual stored dependencies and final writer fence.

**Premises/gaps:** cryptographic commitment integrity; complete dependency-key
derivation; faithful codec/record validation; participating writers and correct
file/SQL fence implementation; OS/custody isolation. A valid grant before
withdrawal may finish. There is no promise that later revocation cancels an
already granted request or that the provider applies it atomically.

## Correct origin/units → conserved ancestor capacity

`effect/engagement.rs` derives the actor and authorized recipient paths from
native enrolled scope. Capacity keys use the retained `capacity_origin` through
supported successor chains; a new instance cannot choose an unrelated origin.
Typed declarations identify count/byte/source units and immutable ceilings.

`store/engagement.rs::insert` plans append-only allocation slots and admits them
with the operation under one fenced batch. `validate_entry` at line 235 checks
every retained reference's commitment, claim, effect and exact reservation against
the actual snapshots. Ordinary window counters are additional checks, not a
replacement origin or a second grant authority.

The new independent flat-budget race observes one write and at most 1000 units
across 16 contenders. It does not by itself establish arbitrary delegation.
Native file/TLS ancestor, rollback, alias and successor cases plus the installed
multi-hop corpus are required for that larger relation.

**Premises/gaps:** correct path-to-key/origin derivation, complete append-only
prefix, exact unit/window selection, faithful atomic adapter behavior and no
unauthorized coherent rollback. The existing checked-add/sum refinements establish
their input arithmetic, not that the caller chose the correct ancestor. No
universal concurrent product theorem is claimed.

## Retained history/recovery → no recreated entry

Native history lookup identifies the original operation and bound authority;
it returns snapshots rather than a transport capability. A replay or reopened
process must not turn an entered/uncertain record into Reserved with a new permit.
Acquisition and disclosure have distinct typed grants and source bindings.

The new campaign independently observes one applied refund with a lost response,
then restarts the gateway and observes Unknown with no additional provider I/O.
An additional installed drill holds the provider's successful response after
independently observed apply, SIGKILLs the actual gateway, restarts it and observes
Unknown without provider replay. A second delayed response arrives after caller
disconnect and is retained without a duplicate write.
Separately authorized observation of a known source produces a recovery report
without a mutation. Twenty-four concurrent duplicate requests also produce one
provider entry and converge to retained response history.

The response-lost Stripe source can remain unresolved because the returned refund
locator was never recorded. The provider double's private log knows the actual
effect; that is laboratory ground truth, not new application authority. A safe
operator must retain the uncertain charge and obtain appropriate independent
evidence or escalate, rather than repeat the refund.

**Premises/gaps:** durable acknowledgement fidelity, non-cloneable permits within
the process, correct late-result merge and current independent read/disclosure
authority. A process crash is not a physical-power-loss experiment. A coherent
old store cannot authenticate its own freshness; independent checkpoints and
quarantine remain necessary. Source-linked transition theorems do not prove
these deployment/provider premises.
