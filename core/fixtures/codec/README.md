# Codec and carrier vectors

`snapshot-uniqueness-v1.json` is shared by the native Rust snapshot decoder,
the independent Go decoder, and the independent TypeScript verifier. The
signature bytes are synthetic shape witnesses and confer no authority.

The vectors cover empty snapshots, distinct statements sharing the partial
sorting key, different sequences, adjacent and separated duplicate statements,
identical statements with different signature bytes, and invalid snapshot or
statement validity windows. Accepted vectors use canonical content-ID order;
separated-duplicate vectors intentionally retain the adversarial input order.

The snapshot constructors must enforce global uniqueness of complete unsigned
statements. Their sorting key omits fields such as state and validity, so an
adjacent comparison cannot establish that property. Signature differences do
not change statement identity. Distinct statements with the same sorting key
remain representable; the status selector owns their deciding interpretation.

`generate_snapshot_uniqueness.py` deterministically writes the corpus using
independent CBOR and documented content-ID framing. It does not execute or
validate a verifier. Regenerate it when intentionally changing the corpus,
then run all three consumers in the final validation pass. The separate frozen
native constructor oracle records the former behavior, including the specific
`A, B, A` acceptance gap. Existing valid snapshot bytes are intended to remain
unchanged; the new constructor refusal is deliberate.
