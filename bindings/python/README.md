# auths-proof for Python

`auths-proof` embeds the Auths Proof Protocol V1 verifier. Verification is
deterministic, performs no I/O, and accepts exactly three byte strings:

```python
from auths_proof import verify

result = verify(proof_cbor, canonical_action_cbor, trusted_context_cbor)
if result.kind == "authorized":
    execute(profile.decode_verified(result.action))
else:
    log(result.explanation.code, result.explanation.message)
```

Release wheels include the native verifier; consumers do not need Rust or a C
compiler.
