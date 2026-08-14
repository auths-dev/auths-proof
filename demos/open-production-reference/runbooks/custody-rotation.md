# Custody disable and rotation drill

1. Record the active non-secret key version from readiness.
2. Disable signing for that version at KMS or PKCS#11.
3. Confirm readiness becomes false and liveness stays true.
4. Confirm new authority and receipt signing is unavailable and no unsigned
   artifact is returned.
5. Configure and verify the replacement public descriptor before enabling it.
6. Roll the same candidate configuration with the new key reference.
7. Preserve old public verification material for existing artifacts.
8. Re-enable traffic only after a signed canary verifies offline.

Never export or copy private key material during rotation. A changed signature
suite or semantic contract is a new candidate, not a rotation.
