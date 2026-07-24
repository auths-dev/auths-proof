# Verification Algorithm — V1

The algorithm returns `Authorized`, `Denied`, or `Indeterminate` with a stable
reason code.

## Inputs

- encoded `ProofBundle`;
- current time;
- expected audience;
- expected 32-byte challenge;
- exact action body bytes;
- one or more local trust anchors;
- explicit verification policy;
- explicit principal and authority-state adapter registry;
- decode limits.

## Algorithm

1. Reject a bundle over the configured or hard byte limit.
2. Strictly decode deterministic CBOR using `auths-proof.cddl`.
3. Recompute every `EvidenceId`; reject a mismatch.
4. Recompute every `GrantId` and the `ActionId`.
5. Require exactly one principal-evidence binding per signed statement.
6. Reject unknown bindings and unreferenced evidence.
7. Check action body digest, audience, challenge, and live validity.
8. Select a local trust anchor:
   - exact principal equality;
   - anchor permission contains the first grant permission set, or the
     zero-grant action permission;
   - anchor validity contains the first grant or zero-grant action validity.
9. Initialize effective authority from the selected anchor.
10. For each grant from root to terminal actor:
    - issuer equals current authorized principal;
    - parent equals the previous `GrantId` and the first parent is null;
    - permission set is a subset;
    - issue time does not move backwards;
    - validity is contained by parent validity and contains current time;
    - remaining delegation depth strictly decreases;
    - signed adapter, method, and algorithm select exactly one allowlisted
      principal adapter;
    - the adapter verifies the domain-separated signing bytes and evidence;
    - required assurance claims pass;
    - required grant-status evidence passes, or the result is
      `Indeterminate`;
    - update effective authority to the child grant.
11. Require the action actor to equal the terminal authorized principal.
12. Require the action permission to be in the effective permission set.
13. Require action issue time and validity to be contained by effective
    authority.
14. Verify the action principal-control proof through the exact selected
    adapter.
15. Apply terminal and global assurance requirements.
16. Return `Authorized` with root, actor, chain length, common assurance
    claims, and explicit limitations.

## Decision classes

`Denied` means the supplied proof contradicts authorization, including:

- malformed/non-canonical data;
- invalid signature or evidence digest;
- untrusted root;
- expanded or broken delegation;
- body, audience, or challenge mismatch;
- expired grant/action;
- permission absence.

`Indeterminate` means policy requires a trustworthy fact the bundle cannot
establish, including:

- unsupported adapter;
- missing principal or grant-status evidence;
- stale status evidence;
- missing assurance required by local policy.

`Authorized` is returned only when all mandatory checks pass. There is no
policy-free `is_valid()` result.

## Time and replay

The verifier uses only caller-supplied time. The challenge is normally issued
and consumed by the execution service. Auths verifies challenge equality but
does not operate the replay cache.

An asserted `issued_at` is not proof of statement existence at that time.
Acceptance of a signature from a now-revoked historical key additionally
requires statement-specific timestamp, seal, or transparency evidence.
