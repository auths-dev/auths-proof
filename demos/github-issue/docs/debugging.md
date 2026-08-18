# Deployment and Debugging Notes

This document records operational lessons from deploying the GitHub issue workflow demo to Vercel, Fly.io, and GitHub. It intentionally contains no secrets or private key material.

## Deployment endpoints

Endpoint names are deployment configuration, not source-code defaults. The
browser now uses its own origin for the native API unless
`window.AUTHS_GITHUB_API_BASE` is deliberately set before `app.js` loads. This
prevents a retired service hostname from disabling every meaningful control.

Prefer serving the frontend and API from one origin. If they are split, treat
the frontend origin, API origin, Content Security Policy, native CORS allowlist,
and pull-request receipt base URL as one reviewed configuration change. A
frontend deployment is not live merely because its static document loads: its
health route and session-creation route must succeed from the browser.

## Vercel

### Deep links need an explicit rewrite

Static hosting serves `/` successfully but returns a platform 404 for a path such as:

```text
/receipts/demo-<workflow-id>
```

The receipt page therefore has an explicit rewrite in `web/vercel.json`.

When `cleanUrls` is `true`, the rewrite destination must use the clean path:

```json
{
  "source": "/receipts/:sessionId",
  "destination": "/receipt"
}
```

Using `"/receipt.html"` as the destination produced a Vercel `NOT_FOUND` response even though `receipt.html` was present and `/receipt` worked.

Always validate a deep link by opening the literal generated URL in a fresh navigation. Testing `/`, testing `/receipt`, or manually removing the `demo-` prefix does not validate the link embedded in a pull request.

### Keep route assets absolute

The receipt document is rendered under a nested URL. Its stylesheet and module paths must be absolute:

```html
<link rel="stylesheet" href="/styles.css" />
<script type="module" src="/receipt.js"></script>
```

Relative paths such as `./styles.css` would resolve beneath `/receipts/`.

### CSP and CORS must agree

The checked-in frontend Content Security Policy allows same-origin connections
only. A deliberately split deployment must replace that policy with the exact
native API origin and configure the native service with the exact frontend
origin.

If the frontend loads but every API request fails, inspect both:

- `connect-src` in `web/vercel.json`;
- `AUTHS_GITHUB_ALLOWED_ORIGIN` in `fly.toml`;
- the browser network error and response headers.

Do not solve this by using wildcard CORS or a broad CSP.

### Deployment

The Vercel project is linked through `web/.vercel/project.json`. Deploy from the web directory:

```sh
cd demos/github-issue/web
npx vercel --prod --yes
```

Confirm the final output says the production deployment is ready and has been aliased to the public domain.

Useful checks:

```sh
node --check app.js
node --check receipt.js
```

Then open both:

```text
https://auths-github-demo.vercel.app/
https://auths-github-demo.vercel.app/receipts/demo-<id>
```

## Fly.io

### App naming

The original Fly application name containing `github` was rejected by Fly's automated abuse/phishing filter. The deployed service uses:

```text
auths-issue-workflow
```

Changing the Fly application name requires updating:

- the frontend API base;
- the Vercel CSP `connect-src`;
- the Fly application name;
- health-check and debugging commands.

### Dockerfile resolution

`fly.toml` lives in `demos/github-issue`. Fly resolves its Dockerfile path relative to that configuration file. The correct build stanza is:

```toml
[build]
dockerfile = "Dockerfile"
```

Using `demos/github-issue/Dockerfile` from inside this configuration caused Fly to look for a duplicated nested path.

The Docker build context is still the monorepo root because the Rust crate depends on workspace packages.

### Persistent-volume ownership

The container runs the service as the unprivileged `auths` user. Fly mounts the volume at runtime, after image construction, so ownership set only in the Dockerfile is not sufficient for every mounted volume.

`entrypoint.sh` sets ownership on `/data` and then uses `gosu` to execute the service as `auths:auths`.

If startup fails around workflow or receipt persistence, check:

- the volume is attached to the active machine;
- `/data/github` is writable by the runtime user;
- `AUTHS_GITHUB_DATA_DIR=/data/github`;
- the machine is running in the volume's region.

### Single-writer constraint

The current persistent adapters use local JSON and JSONL files. Keep:

```text
one Fly machine
one mounted volume
one writer region
```

Do not scale this deployment horizontally without replacing the state adapters with transactionally safe shared storage.

### Deployment and health

Deploy from the monorepo root:

```sh
fly deploy --config demos/github-issue/fly.toml --remote-only
```

Verify the configured service origin:

```sh
curl -fsS https://<configured-native-service>/healthz
```

Expected fields include:

```json
{
  "status": "ok",
  "mode": "live-github-app",
  "writer": "single-region"
}
```

Do not consider deployment complete merely because the image built. Wait for the machine health checks and then exercise a real API route.

## GitHub App setup

### Required installation scope

The demo uses a dedicated GitHub App installed only on the configured demo repository. The minimum intended repository permissions are:

- contents: write;
- issues: read;
- pull requests: write;
- metadata: read, implicitly.

Webhooks and user OAuth are not required for the current interactive demo.

### Read and write credentials are separate requests

Fly shared egress exhausted GitHub's anonymous API rate limit during evidence reads. The robust fix was not to give the agent a token. The native service now mints:

- a repository-scoped, read-only installation token for fresh evidence;
- a separately requested mutation token only after exact authorization and a durable claim.

The UI's “write token requested” count refers to mutation credentials, not the read-only evidence token.

### Private key handling

GitHub App PEM keys may contain literal newlines or escaped `\n` sequences depending on how a secret is loaded. Startup normalizes escaped newlines before parsing.

Safe handling rules:

- never print the PEM in logs or shell output;
- validate the local file without displaying its contents;
- store it only as an encrypted Fly secret;
- delete temporary local copies after a successful production test;
- revoke unused GitHub App keys that were generated but never deployed;
- rotate immediately if the key appears in terminal output, build logs, Git history, or frontend assets.

The browser, Vercel deployment, candidate fixture, and agent boundary must never receive the private key or an installation token.

## GitHub API behavior

### Shared anonymous rate limits

A public repository does not guarantee reliable anonymous evidence reads from a cloud service. Shared egress IPs may already be rate-limited.

Symptoms:

- session creation returns an unavailable GitHub-base error;
- `/healthz` remains healthy;
- the same unauthenticated API call works locally but fails from Fly.

Use the GitHub App's read-only installation token for evidence. Do not silently fall back to stale or browser-supplied facts.

### Mutation success can be temporarily invisible

After publishing a ref or opening a pull request, an immediate read may not yet show the new state. The adapter performs short, bounded postcondition polling.

The permitted outcomes are:

- exact postcondition observed: commit success;
- conflicting postcondition observed: fail;
- still unavailable after the bound: mark reconciliation required.

Never repeat a mutation simply because its first read-back was inconclusive. Reconciliation must observe before deciding whether another write is safe.

### Deterministic effects simplify recovery

The target branch, pull-request title, body, base, head, draft status, and candidate revision are derived from the grant and inspected evidence. This permits exact postcondition lookup after a network failure.

If a new field can affect the GitHub mutation, include it in:

- the validated action type;
- canonical action bytes and digest;
- Auths proof;
- durable claim;
- write adapter command;
- postcondition check;
- decision and execution receipts.

## Receipt links

### Live session receipts are not durable

Interactive sessions expire after 15 minutes and live in process memory. The route:

```text
/v1/demo/sessions/{id}/receipts
```

is for the active UI only.

Pull-request links use:

```text
/v1/demo/receipts/{id}
```

This endpoint reads the signed JSONL log on the persistent volume, verifies signatures, and works after session expiry or service restart.

### Preserve the generated identifier exactly

Pull-request bodies use the workflow identifier:

```text
demo-<32 lowercase hexadecimal characters>
```

The public route accepts both the full workflow ID and the raw session ID, then normalizes to the canonical `demo-…` workflow ID.

### Tamper behavior

The durable reader fails closed if:

- the log or an envelope exceeds its hard limit;
- a JSONL line does not match the closed schema;
- the signer differs from the configured receipt signer;
- an Ed25519 signature fails;
- an execution receipt does not link to a matching decision receipt.

A receipt page should never label unverified bytes as verified.

## Common symptoms

| Symptom | Likely cause | Check |
| --- | --- | --- |
| Vercel platform `404 NOT_FOUND` on a receipt link | Missing rewrite or `.html` destination used with `cleanUrls` | `web/vercel.json`; open the exact deep link directly |
| Receipt page renders but says the identifier is invalid | Route parser does not accept the `demo-` prefix | `RECEIPT_PATH` in `receipt.js` |
| Frontend says native service unavailable | Fly is unhealthy, CSP blocks it, or CORS origin differs | Fly health, browser console/network, Vercel CSP, Fly origin |
| Session creation fails but health is green | GitHub evidence read failed or was rate-limited | GitHub App installation, read token minting, Fly logs |
| Exact flow stops after a GitHub mutation | Postcondition read is delayed or ambiguous | workflow state, Fly logs, reconciliation endpoint |
| Replay creates another branch or PR | Claim identity or workflow persistence is broken | `workflows.json`, exact action digest, replay tests |
| Receipt link worked briefly and later disappeared | UI was using the expiring session route | use the persistent receipt endpoint and Fly volume |
| Fly cannot write state | volume ownership or region mismatch | mount, `/data` ownership, entrypoint, machine region |
| GitHub App token request is rejected | wrong App ID, installation ID, PEM, or permissions | GitHub App installation and Fly secrets |

## Verification checklist

Before declaring the demo healthy:

```sh
cargo fmt --all -- --check
cargo test -p auths-github
cargo test -p auths-github-demo
node --check demos/github-issue/web/app.js
node --check demos/github-issue/web/receipt.js
git diff --check
```

Then validate production:

1. `/healthz` reports `ok`.
2. The Vercel homepage creates a session.
3. A denied case requests zero write credentials and performs zero mutations.
4. The exact case publishes one branch and opens one draft PR.
5. Replay reports zero credentials and zero mutations.
6. The literal receipt link in the PR opens directly.
7. The receipt page reports verified signatures and all expected envelopes.
8. The receipt page still works after a Fly restart.
