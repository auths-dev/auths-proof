# Adapter authoring and qualification

The base package owns versioned ports and conformance, not vendor
implementations. Third parties can publish signer, approval, identity-method,
signature-suite, resolver, status, clock, store, telemetry, transport, and
gateway adapters independently.

An adapter package publishes `AdapterMetadata`: implementation ID/version,
contract kind/version, runtimes, support owner, and narrowly worded security
claims. It runs `adapterConformance` with every mandatory case for its port.
Custody and profiles additionally run their specialized conformance suites.

Identity methods return a parsed descriptor without changing canonical fields.
Resolvers return bounded bytes plus source, fetch time, expiry, and version.
Signature suites authenticate the exact Rust-produced signing preimage and
echo the stable identity, relationship, and application bytes. No adapter may
mint grants, verdicts, or commands, reinterpret profile semantics, or register
an unversioned fallback.

Remote KMS/HSM adapters receive `SigningRequest.signingPreimage`, enforce the
request’s expiry and principal descriptor, and return the same request ID and
transaction digest. Web Crypto and WebAuthn adapters follow the same custody
contract; WebAuthn evidence remains public control evidence, not a private key.

Resolver adapters deny private-network access by default, cap redirects and
response bytes, honor cancellation and timeout, and report provenance and
freshness. Durable stores implement atomic reserve and compare-and-set across
their documented deployment scope. Gateways require domain idempotency and
reconciliation. Adapter documentation must say who supports it and which
claims remain outside Auths’ review boundary.
