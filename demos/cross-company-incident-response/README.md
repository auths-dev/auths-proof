# Auths cross-company incident response

This production-shaped demo proves that Northstar Commerce and EdgeShield can
resolve one shared outage without sharing an identity provider or granting an
agent broad infrastructure credentials.

## Run locally

From the repository root:

```sh
demos/cross-company-incident-response/scripts/launch-local.sh
```

Open <http://localhost:7100>. The launcher generates disposable local
client-certificate material, creates isolated temporary state for each
service, builds the TypeScript assets, and starts:

- control room: `http://localhost:7100`
- Northstar OIDC and provider service: `http://localhost:7101`
- EdgeShield client-certificate, key, provider, and Iroh service: `http://localhost:7102`
- Python agent/orchestration service: `http://localhost:7103`

No Fly, Vercel, GitHub, or other cloud credential is needed. `Ctrl-C` stops the
stack and removes its disposable local state. Docker users may alternatively
run `docker compose -f demos/cross-company-incident-response/infrastructure/compose.yaml up --build`.

## Hosted proof

- control room: <https://auths-incident-demo-control-room.vercel.app>
- Northstar: <https://auths-incident-demo-northstar.fly.dev>
- EdgeShield: <https://auths-incident-demo-edgeshield.fly.dev>
- agent/orchestrator: <https://auths-incident-demo-agent.fly.dev>

The hosted services use one auto-stopping shared-CPU machine apiece and no
persistent volume. The control room is reset to the deterministic starting
state after deployment validation.

## Happy path

1. Inspect the Northstar P-256/OIDC humans, EdgeShield Ed25519/client-
   certificate human, distinct diagnostic/remediation agents, and compromised
   attack actor.
2. Inspect the diagnostic agent's bounded read-only metrics/log evidence. It
   proposes remediation but has no execution authority.
3. Select **Review & execute plan**. The TypeScript SDK asks Rust to
   canonicalize two `auths.edge/1` actions and commit their exact order.
4. EdgeShield delegates only the two named `eu-west-2` resources for ten
   minutes. The plan is committed to one use per member and one remaining
   delegation level used only by the widening test.
5. Auths threshold approval requests one exact response from Northstar's
   incident commander and one from EdgeShield's on-call engineer. Review,
   approval, signing, authorization, delivery, and execution remain distinct.
6. Only the successful SDK branch produces sealed commands accepted by the
   profile gateway. The firewall operation is delivered over HTTPS. The cache
   envelope is delivered over a real Iroh connection and then executed through
   EdgeShield's client-certificate adapter.
7. Inspect both receipts. They show plan, authority, idempotency, transport,
   provider result, observation, and the explicit fact that transport did not
   evaluate authorization.

## Attack lab

Run every control at the bottom of the control room. The panel reports the
typed stage/code and concrete evidence:

- all-region child authority: native child planning returns
  `authority/delegation-expanded` with zero signer calls;
- changed action byte: Python and TypeScript verifier bindings both deny;
- replay: `RuntimeKernel.replay` returns `exact-replay`, with no second effect;
- expired grant and compromised approver: runtime/lifecycle gates stop before
  credentials or provider entry;
- EdgeShield key rotation: the old Ed25519 principal becomes `superseded` and
  the new principal becomes `active`;
- unauthorized Iroh: delivery succeeds under the exact ALPN while Auths denies
  and EdgeShield provider state does not change;
- provider failure before, after, and unknown: runtime transitions respectively
  release, commit, or retain `outcome-unknown` for reconciliation;
- approval withdrawal: the first step is reported complete and the second
  remains unresolved after the bounded plan session is disposed.

## Trust boundaries

Northstar owns its OIDC issuer, P-256 key, actor mapping, outage data, and
firewall state. EdgeShield owns its Ed25519 keys, client-certificate adapter,
cache state, and Iroh endpoint. The Python service owns no organization root
key; it owns incident orchestration, replay/execution state, and receipts. The
control room holds only disposable session agent custody. There is no shared
user table, signing key, or provider credential.

The Rust `auths-iroh` adapter carries bounded opaque bytes. It records ALPN,
path, and endpoint observations but has no Auths decision API. The Python and
TypeScript bindings independently evaluate the same P-256/WebAuthn portable
artifact and surface the same explicit packaged-registry mismatch; the live
effect path separately uses the packaged Ed25519 raw-key authority workflow.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
and [feature evidence](docs/feature-matrix.md).

## Validation

Run the focused local suite:

```sh
demos/cross-company-incident-response/scripts/test-local.sh
```

It covers Python SDK unit/adversarial tests, service integration, all browser
controls, a real Iroh exchange, TypeScript compilation, and Rust tests. The
repository-wide authoritative gate remains GitHub CI on the exact pushed
revision, per `AGENTS.md`.

The same integration suite and all eleven browser attack controls were also
run against the hosted deployment. Both effect receipts were produced, every
attack reported `BLOCKED`, and the browser console reported no errors.

## Deployment

Every cloud object uses the `auths-incident-demo` prefix. Fly configuration for
the three independently deployed services and Vercel configuration for the
control room are contained in this directory. `scripts/deploy.sh` refuses to
touch an existing same-named Fly app or Vercel project. It creates shared-CPU
machines with auto-stop, uses isolated
ephemeral hosted state (the local stack retains deterministic persistence), and
sets random secrets that are never written to the repository. It does not
create paid persistent volumes.

## SDK gap found

The demo exposed one reusable TypeScript binding gap: Rust/WASM returns
canonical domain JSON maps as JavaScript `Map` objects, but the domain decoder
accepted only plain objects when deriving a sealed post-verification command.
The fix is limited to the TypeScript domain-profile boundary: validate
string-only Map keys, normalize the Map to a frozen record, and preserve typed
decoder errors. No protocol, Rust semantic, fixture, or wire change was needed.
