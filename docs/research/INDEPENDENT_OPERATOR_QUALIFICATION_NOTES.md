# Independent operator qualification notes

7 October 2026. Repository-owner-delegated technical work; no independent human
audit or real-user trial is claimed.

| Issue found | Correction and status |
| --- | --- |
| First production qualification required its own pre-existing attestation. | Separate signed, finite commissioning authority; private operator session; durable shared budget and retained host floor. Implemented on PR #206, ordinary application authority unchanged. |
| Offline evidence attempted custody installation before protected setup. | The actual candidate derives a planned production tuple without installation; live setup must compare its installation with that tuple. Implemented. |
| Disposable identifiers and exact actions needed independent expansion. | Closed Stripe/Airtable resources, reconstruction of the whole reviewed recipe/lock, native proof review and independent request oracles. Implemented release-only expansion; protected family setup still needs integration. |
| An installed ordinary client could not succeed before first qualification. | Separate commissioning and ordinary live phases. First records have a two-hour maximum and explicit exclusions; ordinary live evidence requires a confirmed installed-client effect. Implemented runner/assembly controls, protected sequencing still needs integration. |
| The runner prohibited a legitimate read-only recovery lease on replay. | One lease may finish an unresolved entered attempt's observation. A replay cannot write again or reacquire after observation. Implemented with regression cases. |
| A live provider response's exact digest cannot be predicted before creating the effect. | Next: a closed independent fresh-evidence witness, compared with the candidate evidence digest. No wildcard, copying candidate output into expectations or fabricated response is acceptable. |
| The production CLI does not expose independently counted custody/transport boundary observations. | Implemented: private process-scoped counters at the actual custody lease call and HTTP execution boundaries, including failures. Commissioning commands return before/after snapshots; ordinary clients cannot reset them. Remote effects still require separate fresh read-back. |
| Existing AWS roles trust the `gateway-custody-live` environment, while the qualification template names separate family environments. | Next: use an explicitly reviewed protected-environment arrangement that matches the actual OIDC trust, with required reviewer, main-only policy and family-specific credential injection. No role trust or gate is weakened. |
| Main-only protected code must be deployed before the first protected qualification run. | A bounded prerequisite rollout of the completed runner is needed before collecting evidence. Epic acceptance stays open until actual runs, signed closure and CI are complete. |

The public offline root ceremony and purpose-separated certificates are pinned.
Both signer keys are provisioned in the existing reviewer-protected main-only
signing environment; the root key remains outside CI and every Git checkout.
No production family has yet been qualified by this work. Development live
reports remain explicitly separate from protected production evidence.
