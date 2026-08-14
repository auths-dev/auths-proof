# Same-candidate rolling restart

1. Verify the image, configuration, schema, fixture, and semantic-freeze
   digests match the running candidate.
2. Set `maxUnavailable: 1` and keep at least two ready replicas.
3. Drain one pod. Readiness must fail before termination while liveness remains
   available through the grace period.
4. Confirm another replica can inspect and resume recoverable work.
5. Replace each pod and compare `/version` before continuing.
6. Abort on any schema or semantic mismatch.

Changing executable bytes, configuration meaning, schema, or semantic
fixtures is not a rolling restart of this candidate. Freeze and qualify a new
candidate instead.
