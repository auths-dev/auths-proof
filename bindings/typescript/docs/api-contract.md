# TypeScript public API contract

## Application path

The AP-SPEC-040 application surface is deliberately small:

```text
@auths-dev/sdk                    local session, operations, errors, receipts
@auths-dev/profile-stripe         generated Stripe domain client
@auths-dev/profile-postgresql     generated PostgreSQL domain client
@auths-dev/profile-opentofu       generated OpenTofu domain client
```

An application calls `connect()`, constructs one or more generated domain
clients with non-secret connection aliases, and calls typed domain methods.
The root does not choose domain semantics. It accepts no Auths application
token, remote executor URL, provider credential, profile callback, or dynamic
plugin.

## Generated-package extension surface

`@auths-dev/sdk/profile-runtime` is a public, versioned compatibility surface
between the root SDK and generated domain packages. Its exported descriptor,
binding, and outcome types may be used by Auths-generated distributions. It is
not an application-facing generic effect API and does not authorize a caller
to define runtime semantics.

Generated packages expose direct success methods and adjacent discriminated
outcome methods. One session can be borrowed by multiple domain clients. A
domain client binds at construction to one provider connection alias for its
entire lifetime.

## Durable operations

Effect requests use the agent's prepare, execute, status, and recovery
protocol. Opaque recovery handles identify durable operations; applications
do not reconstruct them. `client.operations` exposes domain-neutral pending,
recovery, and receipt tooling, while generated methods regain typed domain
results.

## Other public utilities

Effect-free identity and verification have explicit subpaths. Mechanism and
testkit subpaths remain purpose-labelled. They do not provide a second effect
launch path. The exact export inventory and layer ownership are frozen in
`package.json`, `api/public-api.txt`, and
`bindings/public-topology-v1.json`.

## Clean prelaunch cutover

This is a relaunch. There is no backward-compatibility window, deprecation
shim, old/new execution branch, or migration alias. Removed token-and-endpoint
and callback-based launch claims are inventoried in
`bindings/security-evidence-cutover-v1.json` with their AP-SPEC-040 evidence.
