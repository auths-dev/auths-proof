# Assurance Model

Cryptographic validity and authorization are not synonyms.

Each successful principal adapter returns typed assurance claims, such as:

- `SelfCertifyingIdentifier`;
- `OfflineVerifiable`;
- `ControllerStateCurrentAt`;
- `ControllerStateHistoricalAt`;
- `StatementExistenceProvenAt`;
- `RotationAware`;
- `RevocationCheckedAt`;
- `WitnessThresholdMet`;
- `PkiChainValidated`;
- `HardwareAttested`.

The verifier requires every principal in a chain to satisfy the global policy.
The root must additionally satisfy its trust anchor's requirements. The
verdict reports only assurance common to all verified principals, preventing a
strong root from masking a weak terminal actor.

## Historical state is not statement time

`ControllerStateHistoricalAt(t)` says a key was valid at `t`.
`StatementExistenceProvenAt(t)` says the exact Auths statement existed by `t`.

A revoked key can backdate `issued_at`; therefore an archival policy accepting
historical keys needs both facts.

## Milestone 1 raw-key assurance

Raw Ed25519 and P-256 principals produce:

```text
SelfCertifyingIdentifier
OfflineVerifiable
```

They do not produce rotation, revocation, current status, historical state, or
hardware claims. The verifier reports `IrrevocablePrincipal` as a limitation.

## Milestone 2 embedded KERI assurance

The `did-keri-v1` adapter always produces:

```text
SelfCertifyingIdentifier
OfflineVerifiable
```

It produces `RotationAware` only when the accepted state retains valid next-key
commitments. Non-transferable and abandoned identifiers remain subject to the
verifier's irrevocable-principal policy. `RotationAware` means the adapter
replayed and validated the rotations included in the bounded KEL. It does not
mean that the KEL is globally current. An attacker can present a valid prefix
of a KEL that omits a later rotation, so the adapter does not claim current
state, historical state at a supplied time, witness quorum, statement
existence, or revocation checking.

Current-state KERI policy therefore requires a separate, authenticated
freshness/status mechanism above this adapter. The offline kernel does not
silently fetch one.

## Milestone 3 DID assurance

`did:key` has the same assurance ceiling as raw-key identities:
`SelfCertifyingIdentifier` and `OfflineVerifiable`, with no rotation or
history.

`did:web` never emits `SelfCertifyingIdentifier`. A bare document has no
authority because anyone can construct one with a chosen `id`. With a matching
host-controlled current-resolution record, the adapter emits:

```text
OfflineVerifiable
RotationAware
ControllerStateCurrentAt(observed_at)
RevocationCheckedAt(observed_at)
```

A historical document pin emits `ControllerStateHistoricalAt`. It emits
`StatementExistenceProvenAt` only when the pin also commits to the exact Auths
signing bytes. Default policies reject historical key state without that
separate existence fact as indeterminate.

## Policy profiles

`VerificationPolicy` intentionally has no `Default`.

- `live_action()` requires offline-verifiable principal evidence and checks
  current action/grant validity.
- `offline_audit()` relaxes live assurance but does not skip cryptographic,
  authority, body, audience, challenge, or explicit-time checks.

Applications should define stricter named profiles as their adapters mature.
