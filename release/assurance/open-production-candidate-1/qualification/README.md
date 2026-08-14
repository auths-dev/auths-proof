# Sustained qualification evidence

Place redacted, candidate-bound evidence below this directory for lifecycle,
custody, provider profiles, installed SDKs, operations/privacy, restore/failover,
and supply chain. Every record uses `auths.assurance-evidence/1`, names the exact
candidate digest, and points to a retained artifact by SHA-256.

The aggregate observed duration must reach 2,592,000 seconds. If operation was
not continuous, every gap is published and the summary must not call the run
uninterrupted. Failed and not-tested results remain distinguishable and block
the production claim.

No qualification evidence has been claimed for this candidate.

Record individual test outcomes with `auths.assurance-evidence/1`. After the
window ends, record one `auths.assurance-qualification/1` object containing the
exact candidate digest and a `complete` qualification value. The Rust verifier
calculates the wall-clock interval, subtracts sorted non-overlapping disclosed
gaps, and requires that result to equal the claimed observed seconds. A label
cannot turn a shorter interval into thirty days.
