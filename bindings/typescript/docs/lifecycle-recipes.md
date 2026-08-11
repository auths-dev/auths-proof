# Trust and lifecycle recipes

## Withdraw a delegation

Author a grant-status statement with `state: "revoked"`, a strictly higher
sequence, a bounded validity window, and the trusted status issuer. Build a new
grant snapshot and compile a new offline trust bundle. Old offline decisions do
not become retroactively false; new decisions using the required fresh
snapshot deny the grant.

## Rotate identity evidence

Keep the stable identity ID and publish a new relationship or verification
material ID. Preserve the old resolved descriptor and provenance for
historical verification. New authentication selects the exact new relationship
and suite version; no “latest compatible” fallback is allowed. Mark the prior
principal status `superseded` when the trust policy requires that fact.

## Record compromise

Publish a principal status of `revoked` with a higher sequence and short
validity, refresh every trusted context that requires principal status, and
stop accepting cached evidence past its `validUntil`. Missing, conflicting, or
unavailable required evidence remains denied or indeterminate according to the
Rust verdict; applications must not convert it to authorized.

## Migrate policy or profile version

Publish the new exact profile and policy identifiers alongside the old version
during the deprecation window. Author narrower replacement grants, update the
trusted registry and approval commitment, then supersede the old grants. A
profile-version mismatch fails closed. Remove the old public version only
after its migration guide, compatibility fixture, and SemVer window complete.
