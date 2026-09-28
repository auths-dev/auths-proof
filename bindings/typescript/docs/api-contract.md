# TypeScript public API contract

## Application path

The AP-SPEC-040 application surface is deliberately small:

```text
@auths-dev/sdk                    shared errors, receipts, and runtime facts
@auths-dev/sdk/gateway            proof/action-only provider-write client
@auths-dev/sdk/self-hosted        exact-tool generation and command verification
@auths-dev/sdk/verify             effect-free proof and receipt verification
@auths-dev/sdk/identity           identity authoring and authentication
```

The operator-run gateway is the single provider-write path. An application
authors a proof for one exact action and calls `GatewayClient.submit` with the
proof bytes and the canonical action bytes. The gateway holds the provider
credential, verifies the proof against its installed trust, and returns a
closed result that distinguishes refusal, non-entry, an unknown write, a
recorded response, and a provider observation. The SDK accepts no Auths
application token, remote executor URL, provider credential, profile callback,
or dynamic plugin.

## Unknown writes

An `unknown` result means the provider write may have happened. Applications
do not retry it blindly: they ask the gateway for the operation's signed
outcome (`observeOutcome`) or read the provider field back through the
gateway (`observeReadBack`). Both return gateway-signed bytes that can be
attached to a later action or kept for audit.

## Other public utilities

Effect-free identity and verification have explicit subpaths. Mechanism and
testkit subpaths remain purpose-labelled. They do not provide a second effect
path. The exact export inventory and layer ownership are frozen in
`package.json`, `api/public-api.txt`, and
`bindings/public-topology-v1.json`.

## Clean prelaunch cutover

This is a relaunch. There is no backward-compatibility window, deprecation
shim, old/new execution branch, or migration alias. The local-agent session
client, its generated domain packages, and the `./profile-runtime` subpath
were removed in one cutover when the gateway became the single provider-write
path. Removed launch claims are inventoried in
`bindings/security-evidence-cutover-v1.json` with their replacement evidence.
