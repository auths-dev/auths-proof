# ADR 0015: Independently qualify one Airtable field update

**Status:** Proposed. No family is a candidate or qualified. Acceptance requires
the executable family corpus, independent oracle and protected evidence below.

**Date:** 6 October 2026

## Scope and identity

The proposed family is `airtable-record-update-v1`. Start with the independently
authored field-lab recipe and profile under
[`bindings/fixtures/gateway/airtable/`](../../bindings/fixtures/gateway/airtable/).
The existing `appTEST...` and `tblTEST...` fixture values are synthetic and cannot
be used as live evidence. Substitute one dedicated disposable base and table
through a reviewed recipe construction, then approve and attest its actual
compiled digest. Changing either fixed identifier changes qualification.

The provider contract is an explicitly reviewed Airtable Web API v0 slice in
`disposable-live-resources`; the recipe has no API version header. Bind the
contract to reviewed documentation and assumptions rather than treating `v0` as
an immutable provider implementation. The candidate target is the same shipped
Linux x86_64 gateway, PostgreSQL schema and production AWS custody used by the
Stripe family. The shared runtime gains no Airtable operation or provider branch.

## Independent oracle and provider assumptions

The test-only oracle derives exactly PATCH `/v0/<base>/<table>/<record>` with
`fields.DemoStatus` and the declared echo, and GET of the same record with the
declared status/echo pointers. It must independently validate allowed replacement
values, field bounds, segment encoding and request/evidence commitments.
It must not call the candidate to generate expected decisions or requests.

| Assumption | Required protected observation |
| --- | --- |
| The operator's token reaches only disposable resources | Configure the personal access token with the necessary record read/write scopes and one base; inspect refusal against an excluded base. |
| The fixed table and record belong to that base | Retain sanitized base/table/record identifiers; inspect a fresh record read before and after each successful action. |
| The write changes the intended field | Compare the exact PATCH body with the independent oracle; fresh GET must return the declared replacement and echo. |
| Invalid actions enter nothing | Forge, alter, unknown-field, replacement-enum, path-injection and wrong-recipe cases show zero credential leases and provider entries. |
| Persisted admission survives process changes | Replay, fresh challenge, race, crash and restart witnesses show no second authorized entry for the logical operation. |
| Reconciliation needs fresh matching evidence | Lose the response after entry and delay visibility; the verified record locator permits read-back, but only matching value and echo can establish observed success. No retry sends another PATCH. |

Airtable's token permissions depend on both scopes and selected resources
([personal access tokens](https://support.airtable.com/articles/9934989703-creating-personal-access-tokens)).
This family must observe its configured restrictions; possession of a token is
not evidence that they were configured. The current recipe has no credential
guard or account-binding probe, so the ADR cannot claim the gateway enforces
those capabilities on every lease.

## Corpus, exclusions and publication gates

The maintained offline seeds are `airtable/vectors.json`, the profile lock and
gateway hostile, attempt and outcome corpora. Publish a family-owned executable
`auths.qualification-corpus/2` covering the complete evidence wall, including
an oracle-accepted update, all refused mappings, real application isolation and
credential drift. These seeds alone are not the missing protected family corpus.

The protected live corpus must exercise a fresh confirmed update, echo,
production doctor, provider-secret rotation, two hosts, restart/recovery,
actual support/log/trace/metric scans and installed Python/TypeScript journeys.
Create records with no personal data; cleanup removes only resources whose
identifiers were recorded by this run and must also execute after partial setup.

The recipe declares no provider idempotency. Its derived gateway recovery
capability is linked read-back: the fixed record locator and declared echo permit
read-only reconciliation after a lost response. The simulation exercises this
through the native driver and persistent claims; it sends no second PATCH.
This is not provider deduplication or compare-and-swap. Version pin, credential guard, account
binding, denied reads, relative ceiling, sum budget, response locator and
pre-entry read are also not applicable because they are absent from this recipe.
Observer rotation is required only if the installed target declares one.

The owner-directed [simulation](../../qualification/simulation/README.md) uses
fixed synthetic resources and disposable signing trust. Production qualification
still requires reviewed live resource bindings and real protected evidence.
Do not rename a development tuple as the production target.

Use a maximum 14-day attestation, reflecting the absence of a fixed API release
header, and rerun before renewal or any tuple change. Revoke on unexpected
provider entries, secret/evidence compromise, changed response behavior, token
scope widening or invalid observation assumptions. Publish signed artifacts,
bounded evidence and sanitized resource identifiers. Atomic compare-and-swap,
isolation from another writer, provider idempotency, recovery without a fresh
matching value and echo, and
generic account-binding guarantees are excluded. No live evidence is claimed.
