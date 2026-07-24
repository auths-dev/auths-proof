# V1 `did:keri` Principal Adapter Profile

## Purpose

The `did-keri-v1` adapter proves that the signer of an Auths statement controls
a key in an embedded KERI event log. It does not decide what the principal is
allowed to do and it does not resolve or assert globally current KERI state.

```text
KERI evidence + exact Auths signing bytes + signature
                            |
                            v
              verified principal control
                            |
                            v
              authority verifier (separate)
```

## Registry values

| Field | Value |
| --- | --- |
| Adapter ID | `did-keri-v1` |
| Principal form | `did:keri:<44-character E-qualified prefix>` |
| Evidence media type | `application/vnd.auths.did-keri-kel.v1` |
| Ed25519 algorithm | `ed25519` |
| P-256 algorithm | `p256-sha256` |

The verification method is:

```text
<principal>#key-<establishment-sequence-hex>-<key-index-decimal>
```

Both numbers use their shortest representation. The establishment sequence
binds a statement to the exact key-establishment event selected by the
evidence; it is not inferred from signature length or algorithm.

## Evidence encoding

The evidence bytes are a closed binary envelope:

```text
"auths-proof/did-keri/evidence/v1\0"
u16-be event_count
repeat event_count times:
    u32-be event_json_length
    event_json bytes
    u32-be attachment_length
    CESR controller-signature attachment bytes
```

No trailing bytes are permitted. Standard limits are 64 events, 64 KiB per
JSON event, 16 KiB per attachment, and 16 keys per establishment event.

Each JSON event must be byte-for-byte equal to its compact insertion-order
serialization. Its KERI version byte count and Blake3-256 self-addressing
digest are recomputed. Evidence is content-addressed by the ordinary Auths
`EvidenceId` rule.

## Supported KERI subset

- KERI 1.0 JSON `icp`, `rot`, and `ixn`;
- self-addressing Blake3-256 (`E`) identifiers;
- simple numeric signing and next-key thresholds;
- Ed25519 (`D`/`B`) and P-256 (`1AAJ`/`1AAI`) keys;
- indexed and dual-indexed Ed25519/P-256 controller signatures;
- pre-rotation commitment validation;
- zero-witness KELs.

The adapter rejects delegated events, weighted thresholds, non-zero witness
thresholds, witness lists/receipts, unsupported event/key/signature codes,
broken sequence or prior links, threshold failures, commitment mismatches,
non-canonical JSON, and evidence beyond its bounds.

## Assurance and freshness

A valid result always emits:

```text
SelfCertifyingIdentifier
OfflineVerifiable
```

It additionally emits `RotationAware` only while the accepted state retains
valid next-key commitments. A non-transferable or deliberately abandoned
identifier is correctly treated as irrevocable by the authority verifier.

The adapter does not emit `ControllerStateCurrentAt`, `ControllerStateHistoricalAt`,
`WitnessThresholdMet`, `StatementExistenceProvenAt`, or
`RevocationCheckedAt`.

This distinction is security-critical. A complete, valid embedded KEL proves
that the selected key follows the rotations present in that KEL. It cannot
prove that no later rotation exists elsewhere. Applications requiring current
controller state must obtain separately authenticated freshness evidence and
use a policy that requires the corresponding assurance claim.

## Interoperability requirement

Conformance must include fixtures produced independently of this adapter.
Milestone 2 pins keripy 1.3.4 bytes for a threshold-2, three-key inception and
a threshold-2 rotation to two keys with dual-index signatures. The adapter
must accept that KEL and reject forged signatures, unmet thresholds, altered
SAIDs, broken prior links, and commitment mismatches.
