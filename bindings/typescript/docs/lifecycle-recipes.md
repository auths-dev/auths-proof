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
validity, and re-publish it before it expires. Refresh every trusted context
whose trust anchor requires principal status. The revocation stops the
principal wherever it appears in a chain: as the trust anchor, as a delegate
that issued a grant, or as the actor. Keep it in every snapshot until each
grant that names the principal as subject has expired: a stale revocation
makes the verdict indeterminate, and a removed one makes the principal active
again. Stop accepting cached evidence past its `validUntil`. Missing,
conflicting, or unavailable required evidence remains denied or indeterminate
according to the Rust verdict; applications must not convert it to authorized.

## Replace a policy or profile before launch

Assign the replacement an exact semantic identifier, update its grants,
trusted registry, approval commitment, examples, and fixtures in one source
cutover, and delete the superseded implementation. Existing mismatched local
state fails closed. Do not add a second reader, converter, alias, shim,
deprecation window, or runtime switch.
