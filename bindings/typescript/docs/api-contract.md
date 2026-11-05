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

An unknown outcome means the provider write may have happened. Read retained
local history with `observeOutcome`. Acquire new evidence only with a separately
verified read proof/action and exact approval through `recover(sourceOperation, { proof, action, approval })`. Recovery
returns bounded native JSON bytes distinguishing source facts, acquisition
facts and the evidence decision. It does not return provider content, authorize
a write retry, or acknowledge recipient disclosure. Unapproved provider read-back
requests are no longer part of the application protocol.

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
