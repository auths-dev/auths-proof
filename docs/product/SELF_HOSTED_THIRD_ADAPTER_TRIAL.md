# Packaged-SDK third-adapter trial — inventory status

On 2026-09-21, a separate zero-context agent used the packaged Python SDK and
public quickstart to choose and build an `inventory/set-status_v1` adapter. This
was an engineering clean-room participant, **not** an outside human or evidence
of market adoption. It used a local fake HTTP provider; no disposable live
third-provider credential was available. Airtable and Todoist were not reused.

The first run exposed two SDK issues: before a lock existed, `profile diff`
said “no field changes” despite a new action identity, and `profile test`
accepted reports missing mandatory cases. Auths fixed those issues and added
four checkpoint/restart cases. The same participant then reran from a newly
created consumer workspace using only the hosted Python wheel built from
`f5992baf269872e0917ec69ff8324a7ad96d4f1e` ([package run](https://github.com/auths-dev/auths-proof/actions/runs/35658997720)),
SHA-256 `67ca5f42e4a7ce4826fafa814f4fb3e47901f26335e676a3c16d5523c9b17daa`.
The corrected wheel was an intervention between runs; no maintainer supplied
or repaired the consumer's adapter implementation.

| Boundary | Rerun observation |
| --- | --- |
| Action | Exact arguments `{"item_id":"sku-42","status":"quarantined"}`; action SHA-256 `b9dba95a87e33fc2ed5dcf9977638d3905ad0414a2e8994a4a83f2004c4be2b1`. |
| Proof and projection | Disposable `auths.testkit` proof under a self-trusting context returned `authorized`; the SDK projected typed `SetInventoryStatus(item_id='sku-42', status='quarantined')` from the verified action bytes. No consumer CBOR/action parser was written. |
| One-use claim | `FileAttemptStore` claimed commitment `d8e0918dd094afdb01e4814ba49adab74eb0811b498411230fc8ba402da75130` and key `inventory-status-sku-42-001` before credential access. Its final local state was `confirmed` (adapter acceptance, not independently proven effect). |
| Provider result | The local provider received exactly one authenticated `PATCH /v1/items/sku-42/status` with body `{"status":"quarantined"}`. The developer adapter classified its response as `accepted`, revision 1. |
| Observation | A GET returned matching item/status; separate `reconcile_read_only` also returned `observed`. Total traffic was one PATCH and two GETs, with no reconciliation write. |
| Denial and replay | A mismatched expected command returned `denied` before credential or HTTP entry. Reusing the proof/action/key returned `replay` without a second credential or HTTP entry. |

The new profile's first `diff` reported `profile.contract.new` and “no prior
generated lock”; `generate` and `check` succeeded. `profile test` passed all
fourteen mandatory cases, including claim failure before credential, finish
failure after entry, replay after restart, and post-entry interruption. No
Auths source edit, Rust helper, custom action parser, live token, or `.env`
was used. The initial run took about four minutes to its write/read-back; the
corrected-wheel rerun reached write/read-back in about 51 seconds. The local
sandbox required a narrow approval to bind a loopback HTTP port in both runs;
this was environment access, not an SDK workaround. The consumer's adapter
and fake provider remained application-owned.

This meets AP-SPEC-054 Epic 5's **engineering trial** acceptance when paired
with the original unfamiliar-agent run. It does not establish production
authority, independent trust provenance, live provider semantics, human
adoption, or non-bypassability. An application holding its own provider token
can still make a direct call outside `run_once`. The local read-back is the
developer adapter's observation, not an Auths-qualified effect receipt.
