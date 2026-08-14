# Open production assurance

This directory contains public, offline-verifiable evidence for named Auths
release candidates. A candidate is not production-eligible merely because it
exists here. The release gate requires an immutable binding, every required
evidence family, an exact thirty-day qualification window, completed
independent review, and a statement made by a checked-in trusted signer.

The lifecycle is:

```text
candidate --bind  ->  record evidence, qualification, and review
                  ->  sign complete manifest
                  ->  verify before promotion
```

`trusted-signers.json` is the offline trust root. It starts empty because no
release assurance key has yet been established. Adding a signer is an explicit,
reviewed source change; a manifest signed by an unlisted key is rejected.

Start with
[`open-production-candidate-1/summary.md`](open-production-candidate-1/summary.md).
The summary deliberately describes the current candidate as incomplete.
