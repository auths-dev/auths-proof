# AWS Secrets Manager credential store: implementation and conformance plan

- **Status:** plan. No adapter, emulator, AWS account, role, or credential
  exists. Nothing here is implemented or claimed.
- **Spec:** [AP-SPEC-066](../specs/0066-production-gateway-polish-and-recipe-qualification.md)
  §5, Epic 2. Abstraction case
  [0008](../research/domains/abstraction-cases/0008-provider-secret-custody-and-recipe-qualification.md).
- **Frozen inputs:** `bindings/fixtures/gateway/custody-hostile.json` and
  `production-codes.json`. The adapter is done when it drives every pending
  section of the first and the pending assertion in
  `pending_vectors/production.rs` has been replaced by those tests.

## 1. What is built

`aws-secrets-manager-v1`, one implementation of the existing
`auths_connections::ConnectionCredentialStore`. It stores and leases opaque
bytes for one connection identity and one credential generation. It is not
told the provider, recipe, origin, header, or action, and it has no
configuration that names any of them.

It lives in a new product crate, `auths-credentials-aws-secrets-manager`,
beside `auths-custody-aws-kms`. `auths-connections` keeps no network
dependency. The `auths-gateway` binary depends on the adapter; the testkit
double of section 6 is a separate crate that no production feature graph may
reach, enforced by a dependency boundary in `architecture.toml`.

## 2. External naming

One Secrets Manager secret per credential generation, holding exactly one
version. Both names are derived, so the gateway stores no external location
anywhere:

```text
name       = "auths-gateway/" || hex(SHA-256(
                 "auths.gateway-secret-name/1" || 0x00 ||
                 namespace || 0x00 || connection_id || 0x00 ||
                 generation as 8 bytes big-endian))

version_id = hex(SHA-256(
                 "auths.gateway-secret-version/1" || 0x00 ||
                 connection_id || 0x00 ||
                 generation as 8 bytes big-endian ||
                 reference_commitment (32 bytes)))
```

`namespace` is the operator's deployment namespace, `[a-z][a-z0-9-]{0,63}`,
fixed at startup. `reference_commitment` is the value the shared connection
record already seals. The fixture section `secret_names` pins five derivations.

A secret per generation, not a version per generation, because Secrets
Manager may delete a version that carries no staging label. Retention of the
old generation must not depend on a label the gateway does not control.

The version identifier is supplied as the request token when the secret is
created, so it is known before the write and is the only version the secret
ever has. Section 8 lists this as an assumption the first conformance test
must confirm against the live service.

## 3. Operations

| Store method | Service call | Rule |
| --- | --- | --- |
| `install` | `CreateSecret` with the derived name, the derived version as request token, and the bytes as binary | An existing name is `Conflict`. The reference commitment is computed locally and returned; no location is returned. |
| `lease_secret` | `GetSecretValue` with the derived name and the exact derived version | Never a stage, never the default version. The returned version must equal the requested one, the returned bytes must be 1 to 65,536 long, and their commitment must equal the binding's in constant time. Any difference is `Unavailable` or `Substitution` and no byte reaches the caller. |
| `replace` | `CreateSecret` for the new generation's name | The old generation's secret is untouched. `new == old + 1` as today. |
| `revoke` | `DeleteSecret` with immediate deletion | Called only for an exact generation, and for a superseded generation only after `CredentialRetirementDelay` has passed since the shared commit. |

No `ListSecrets`, `UpdateSecret`, `PutSecretValue`, `RotateSecret`, or stage
movement is ever issued. The fixture section `version_references` lists what
the adapter must refuse to treat as a version: `AWSCURRENT`, `AWSPENDING`,
`AWSPREVIOUS`, `latest`, the empty string, a traversal, a wrong width, an
uppercase form, and a Unicode look-alike.

## 4. Identity and permissions

The gateway authenticates with workload identity only. Three sources are
accepted, each a closed module with no fallback between them: a projected web
identity token exchanged with the regional STS endpoint, the container
credentials endpoint, and instance metadata version 2. A static access key in
the process environment is refused under production policy: it is a long-lived
secret in exactly the place this work removes one from.

Two roles, never one:

- **Runtime role** (the gateway workload): `secretsmanager:GetSecretValue` on
  `auths-gateway/*` in its own account and region, and `kms:Decrypt` on the
  one customer-managed key that encrypts them. Nothing else.
- **Operator role** (install, rotate, revoke): `CreateSecret` and
  `DeleteSecret` on the same prefix, `kms:GenerateDataKey` on the same key.
  It is assumed by the operator plane, not by the serving path.

The qualification signer, the observer, the application, and the Auths grant
root use other identities. A resource policy on the prefix denies every other
principal. Network egress from the gateway is limited to the pinned provider
origins and the regional Secrets Manager and STS endpoints.

## 5. Bounds and failure mapping

- Connect timeout 2 seconds. The whole call is bounded by the lease deadline
  the gateway passes; the client makes one attempt and never retries past it.
- Response body at most 128 KiB, read with a hard limit before parsing.
- Secret at most 65,536 bytes, which is also the service's own limit.
- TLS to the regional endpoint with the existing `rustls` stack. No proxy, no
  redirect, no endpoint override in production.

| Failure | Where | Stable code |
| --- | --- | --- |
| Unknown store kind | install, serve | `gateway.credential.adapter-unsupported` |
| Local file kind under production policy | install, serve | `gateway.credential.production-plaintext-refused` |
| Store unreachable or identity refused at install | install | `gateway.install.credential-store-unavailable` |
| Store unreachable or identity refused at startup | serve | `gateway.serve.credential-store-unavailable` |
| No secret at the sealed generation, known before the claim | submit | `gateway.connection.credential-generation-missing` |
| Timeout, partial or oversized response, version or commitment mismatch, expired lease, after the claim | submit | `gateway.credential.unavailable`, recorded `not-entered` |

A failed lease is never answered from another generation, the local file, an
environment variable, or cached bytes. The fixture section `lease` holds
twelve scenarios for this.

## 6. Conformance

One conformance suite over the trait, run against three stores: the in-memory
store, the local file store, and the adapter. It covers install, exact lease,
commitment substitution, a missing generation, replace, retained old
generation, revoke, and redacted debug forms.

**Ordinary CI** runs the adapter against a bounded in-repository double: a
loopback HTTP server that implements only `CreateSecret`, `GetSecretValue`,
and `DeleteSecret`, checks that each request is signed and addressed as
section 2 derives, and injects faults by case (no answer, a short body, an
oversized body, another version, other bytes, a throttling error). It follows
the precedent of the Stripe counting double: a testkit crate behind a
development feature that the default gateway build lacks. It is evidence that
the adapter refuses hostile answers, not that the service behaves as the
double does.

Request signing is checked against the service's published signature test
vectors, committed as fixtures.

**The protected release workflow** runs the same suite against a real account:
the workflow assumes the operator and runtime roles through the repository's
identity provider (no static key), uses a namespace unique to the run, writes
and reads disposable secrets, runs rotation, restart, and two-instance cases
from the fixture section `rotation`, and deletes everything it created. Its
artifacts feed the `rotation`, `restart`, `multi-instance`, and `redaction`
members of a qualification record.

| Fixture section | Driven by |
| --- | --- |
| `store_kinds`, `secret_bounds`, `recipe_selection`, `frame_selection`, `retirement`, `redaction.debug` | driven today in `pending_vectors/production.rs` |
| `secret_names`, `version_references` | adapter unit tests |
| `lease` | adapter against the double; gateway scenario tests for stage and code |
| `rotation` | two gateway processes against the double, then the protected account |
| `redaction.canaries` | the support bundle and telemetry scans of the operator-polish epic |

## 7. Rotation

`connection rotate prepare` reads new bytes from the authenticated operator
channel, calls `replace`, and runs the recipe's declared credential checks
against the new bytes without changing the shared record. `rotate commit`
replaces the credential generation and commitment in the shared record with
one compare-and-swap. A collector may revoke the old generation at or after
`committed_at + 20 s`; `CredentialRetirementDelay::earliest_revocation` is
that time. The emergency flow is disable, wait 20 seconds, rotate, revoke the
old generation, enable.

A prepared generation that is never committed is an orphan secret. The
collector deletes a generation newer than the record's credential generation
once it is older than one hour, so an abandoned prepare does not leave provider
material in the account.

## 8. Assumptions to confirm, and decisions for the owner

1. **Request token as version identifier.** The plan assumes `CreateSecret`
   accepts a 64-character lowercase hexadecimal request token and uses it as
   the version identifier. The first test against the protected account
   confirms it. If the service refuses that form, the version identifier is
   instead the first 32 bytes of the same digest formatted as the identifier
   form the service documents, and the fixture changes with it.
2. **Client.** The recommendation is a minimal closed client over the
   existing `reqwest` and `rustls` stack with request signing built from
   `hmac` and `sha2`, both already workspace dependencies. Only three calls
   are needed, the gateway must own the retry and deadline behavior exactly,
   and the vendor SDK's default TLS backend needs a build script and a native
   dependency, both of which `architecture.toml` forbids without explicit
   approval. The alternative is the vendor SDK configured with the existing
   TLS stack; it removes hand-written signing and credential-source code at
   the cost of a much larger dependency graph. This is a dependency-policy
   decision for the owner at the start of the custody epic.
3. **Credentials.** The emulator needs nothing. The protected run needs an AWS
   account, an identity-provider trust for the release workflow, two roles,
   and one key. Creating them is an owner decision under the program board's
   credential rule and is not granted by this plan.
