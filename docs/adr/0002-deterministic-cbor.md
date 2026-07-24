# ADR 0002: Deterministic CBOR

**Status:** Accepted

## Decision

V1 uses a closed deterministic-CBOR schema with integer map keys. The project
implements a small bounded codec rather than deriving signed bytes through
Serde.

## Rationale

Signature interoperability requires exactly one byte representation. Unknown
fields, non-minimal values, indefinite lengths, duplicate keys, and
non-canonical collection order are rejected.

The CDDL and golden vectors, not Rust struct layout, define the wire protocol.
