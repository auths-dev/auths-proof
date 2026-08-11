# Python attach and delegation workflow

**Status:** Milestone B implemented; release review pending

**Scope:** AP35-PR4 through AP35-PR6

## UX

The application supplies typed provider ports and native Auths values:

```python
async with AuthsClient(
    signer=parent_signer,
    trusted_authority=trusted_authority,
) as auths:
    parent = await auths.attach_agent(
        name="research-agent",
        profile=Profile("auths.mcp", 1),
        authority=signed_root_grant,
        approval=approval,
    )

    async with await parent.delegate(
        name="records-child",
        authority=DelegatedAuthority(...),
        signer=child_signer,
    ) as child:
        review(child.authority, child.delegation)
```

The workflow exposes authority summaries, attenuation differences, and
over-granting warnings. It does not expose grant CBOR, build signing
preimages in Python, accept private keys, or bundle a production signer.

Provider cancellation propagates as `asyncio.CancelledError`. Provider
failures cross the SDK only as typed, sanitized Auths errors. Root and child
signers are closed exactly once on normal exit, failure, cancellation, and
partial construction.

## Architecture

```text
+------------------------ Python application -------------------------+
| signer + approval ports | attach agent | request narrower authority |
+-------------------------+--------------+----------------------------+
                          |
                          v
+---------------------- Python orchestration -------------------------+
| async calls | cancellation | ownership | sanitized provider errors  |
+--------------------------+------------------------------------------+
                           |
                           v
+------------------------ native ABI v1 ------------------------------+
| typed identity | root binding | attenuation | transaction binding   |
| authority summary | exact request phases | signed-grant completion  |
+--------------------------+------------------------------------------+
                           |
                           v
+---------------- canonical Rust semantic owners --------------------+
| auths-author | auths-model | auths-codec | auths-sdk                |
+---------------------------------------------------------------------+
```

Python owns callback scheduling and lifetime management. Rust owns principal
and descriptor parsing, trusted-authority checks, root and delegated grant
bindings, authority projection, every attenuation dimension, policy
commitments, signing preimages, transaction identity, response matching, and
signed-object construction.

## APIs

- `Signer` is an async `Protocol` with a typed public identity, one exact
  signing operation, and deterministic `aclose`.
- `ApprovalProvider` is an async `Protocol` over immutable approval requests
  and typed responses.
- `Approval` builds one of the four AP-SPEC-035 modes from a Rust-owned policy
  commitment: grant-only, risk-based, every-action, or registered custom.
- `TrustedAuthority` binds an authority identifier, native root principal,
  native trusted context, and exact required approval policy.
- `AuthsClient` owns the root signer and invalidates every attached agent when
  closed.
- `attach_agent` accepts a native signed grant or a typed signed-grant source,
  then asks Rust to bind the root, subject, and profile before returning an
  agent.
- `delegate` accepts a closed `DelegatedAuthority` type. Profile and critical
  extensions are inherited; issuer and parent linkage are derived by Rust.
- Native signing transactions move once from awaiting approval to awaiting
  signature to terminal. A mismatched, rejected, expired, duplicated, failed,
  or cancelled response cannot be reused.

This milestone does not assemble proof bundles, authorize profile actions,
mint profile commands, call gateways, ship provider adapters, or promote the
package beyond its verifier-binding release claim.

## Task list

- [x] Add typed signer, approval, authority-source, response, and error contracts.
- [x] Add native principal descriptors and Rust-owned approval commitments.
- [x] Add native exact-response signing transactions with terminal-state enforcement.
- [x] Add native trusted-authority, root-grant, and delegated-grant bindings.
- [x] Add `AuthsClient`, async context management, and deterministic signer cleanup.
- [x] Add `attach_agent` with native root-authority summaries.
- [x] Add `delegate` with native attenuation, semantic diff, warnings, approval, and signing.
- [x] Prove mismatch, widening, cancellation, duplicate, expiry, and cleanup behavior.
- [x] Add typing, installed-wheel, differential, ABI, architecture, and compliance evidence.

## Exit

A Python application can attach an agent and delegate narrower authority
without handling protocol bytes or private keys. No provider response can be
substituted across a principal, descriptor, policy, request, transaction, or
provider call, and every failed partial workflow ends in a closed state.
