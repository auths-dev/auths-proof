# External custody lifecycle runbook

This runbook applies to the open AWS KMS P-256 and PKCS#11 P-256 adapters.
It never requires an operator to copy private key material into Auths.

## Readiness

The candidate is ready only when startup freezes the configured adapter,
`p256-sha256-v1` suite, public key version commitment, and an active lifecycle
state. Readiness output may contain those bounded public facts. It must not
contain the key ARN, account, region, module path, token, object, PIN,
principal, credentials, signing preimage, signature, or provider text.

## Planned rotation

1. Enrol the new provider key without changing the active descriptor.
2. Read and verify its public key, provider policy, and immutable provider
   identity through the adapter startup path.
3. Run the custody conformance corpus against the new descriptor.
4. Mark the old descriptor `rotation-pending` and the new descriptor `ready`.
5. Atomically publish the new descriptor as `active-current`; publish the old
   descriptor as `retiring-previous`.
6. Observe new signatures using only the new key-version commitment.
7. Retire or revoke the previous descriptor after its governed verification
   window. Never fall back to it after a failed new-key signing request.

Existing signed objects continue to verify against their exact historical
trust and status evidence. Rotation does not rewrite them.

## Emergency disablement

1. Disable the provider key and publish the descriptor state as `disabled` or
   `revoked`.
2. Stop new signing immediately. Do not retry with another key unless a new
   governed descriptor has become active.
3. Keep verification, receipt access, and recovery observation available.
4. Reconcile in-flight requests by request ID and transaction commitment.
   Treat an ambiguous provider response as `custody.provider-unknown`; never
   silently repeat it.
5. Preserve bounded incident evidence and rotate through the planned process.

## Provider outage

- Before provider entry, report a retryable unavailable result only when the
  adapter proves no signing request was sent.
- After a request may have reached the provider, report the stable conditional
  or unknown outcome and require operator reconciliation.
- Do not convert transport recovery, successful authentication, or a provider
  health check into evidence that a signature was or was not produced.

## Qualification evidence

SoftHSM proves the PKCS#11 software integration, not hardware security. AWS KMS
qualification runs only in a dedicated sandbox using short-lived workload
credentials, a disposable asymmetric signing key, cost limits, cleanup, and
redacted evidence. A real hardware claim requires a separately recorded device
and ceremony qualification.
