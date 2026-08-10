# Auths for Python

The `auths` package embeds the Auths Proof Protocol V1 verifier. Verification is
deterministic, performs no I/O, and accepts exactly three byte strings:

```python
from auths import verify

result = verify(proof_cbor, canonical_action_cbor, trusted_context_cbor)
if result.kind == "authorized":
    execute(profile.decode_verified(result.action))
else:
    log(result.explanation.code, result.explanation.message)
```

Release wheels include the native verifier; consumers do not need Rust or a C
compiler.

## Adoption layer

This binding currently exposes the deterministic delegated-authority verifier
(Level 3 of the repository's adoption ladder). Importing `auths` performs no
identity exchange, approval, profile-gateway, receipt, or lifecycle setup. The
neutral identity protocol is owned by the smaller Rust `auths-identity` surface
and its TypeScript/WASM binding; Python does not claim an independent identity
encoding implementation.
