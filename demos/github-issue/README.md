# Auths GitHub agent launch path

Give one agent authority to address one operator-approved GitHub issue without
giving that agent a GitHub mutation credential. The existing Auths executor
inspects the candidate, authorizes two exact effects, claims each effect before
requesting a GitHub App token, publishes one branch, opens one draft pull
request, and leaves signed receipts.

This is the launch golden path for Auths. It extends the existing GitHub
vertical; it is not a second verifier, GitHub adapter, lifecycle engine, or
receipt implementation.

## What is bounded

The deployment operator pins the repository, issue, base ref, allowed and
protected paths, GitHub App installation, executor configuration, and receipt
key. A client may accept that exact boundary or refuse it; it cannot widen it.
One delegated task carries:

- one repository and issue;
- the current exact base revision;
- the operator-approved path policy;
- an expiry between one and fifteen minutes;
- one branch publication and one draft pull request; and
- a visible agent label.

The agent process creates a Git bundle. It receives no GitHub credential.

From a credential-less clone pinned to the base revision returned by
`boundary()`, make the candidate commit and export it:

```sh
git branch -f auths-candidate HEAD
git bundle create candidate.bundle refs/heads/auths-candidate
git rev-parse HEAD
```

Pass the printed object id as `AUTHS_GITHUB_CANDIDATE_REVISION`. The executor
does not check out or run candidate code.

## TypeScript quickstart

Install the packed/published SDK and run the maintained example:

```sh
npm install @auths-dev/sdk@1.0.0-rc.1
AUTHS_GITHUB_AGENT_ENDPOINT=https://your-executor.example \
AUTHS_GITHUB_CANDIDATE_BUNDLE=./candidate.bundle \
AUTHS_GITHUB_CANDIDATE_REVISION=<git-object-id> \
AUTHS_GITHUB_LIVE=1 \
node examples/typescript/agent.mjs
```

## Python quickstart

```sh
python -m pip install auths==1.0.0rc1
AUTHS_GITHUB_AGENT_ENDPOINT=https://your-executor.example \
AUTHS_GITHUB_CANDIDATE_BUNDLE=./candidate.bundle \
AUTHS_GITHUB_CANDIDATE_REVISION=<git-object-id> \
AUTHS_GITHUB_LIVE=1 \
python examples/python/agent.py
```

Both examples discover the approved boundary, delegate it, load the candidate
from a file, inspect it, execute only after inspection, handle reconciliation,
prove replay causes no second write, and ask the existing signed-receipt reader
to verify the resulting receipt timeline. They contain no CBOR, proof bytes,
canonicalization logic, or GitHub token.

Use `AUTHS_GITHUB_FIXTURE=prohibited-path` without `AUTHS_GITHUB_LIVE=1` to
exercise the denial path. The fixture must report zero credential requests and
zero mutations.

For a release-candidate smoke test, use the maintained opt-in wrapper. It
refuses to start without both the live guard and an explicit SDK choice:

```sh
AUTHS_GITHUB_LIVE=1 AUTHS_GITHUB_SDK=typescript \
  ./tests/live-github-opt-in.sh
```

The endpoint, bundle, revision, and installed SDK must already be configured
as shown above. This script is intentionally absent from routine CI.

## Operator boundary

The native service is configured through the existing `AUTHS_GITHUB_*`
environment contract documented in [architecture.md](docs/architecture.md).
Run it only with an isolated fixture repository and a GitHub App whose
installation and permissions are scoped to that repository. Routine tests use
in-memory ports and server-owned fixtures; live GitHub mutation is always
explicitly opt-in.

The generic `auths-node` reference stack and this live GitHub executor have
different jobs. `auths-node` proves the general production transport contract;
this service composes the complete GitHub-specific candidate/evidence/write
workflow. The SDK surface here is profile-specific and does not add arbitrary
JSON execution to the generic node.

## Browser demo modes

Do not open `web/index.html` through `file://`. Start the checked-in local
launcher from the repository root:

```sh
./demos/github-issue/run-local.sh preview
```

Then open `http://127.0.0.1:4173`. Preview mode needs only Python and explains
the boundaries without claiming that Auths or GitHub ran.

For the real workflow, export the documented `AUTHS_GITHUB_*` deployment
configuration and run:

```sh
./demos/github-issue/run-local.sh live
```

The native Rust service serves both the web application and API at
`http://127.0.0.1:8080`, so live mode does not depend on a second static server.
The browser uses its own origin for the native API by default. A split
frontend/API deployment may set `window.AUTHS_GITHUB_API_BASE` before `app.js`
loads, but its Content Security Policy and native CORS allowlist must name that
exact origin.

If the native API cannot create a session, the page switches visibly to
**guided preview**. Test-case selection and boundary explanations remain
interactive, while inspection, execution, GitHub effects, and receipts are
explicitly reported as not run. Preview mode never fabricates an Auths verdict.
