# Adoption Readiness

Assessment date: 15 August 2026. Product checkout: `auths-proof` on branch
`dev-cleanup`; documentation checkout: `auths-docs` on branch
`codex/docs-gold-pages`. Both working trees already contained unrelated local
changes. I preserved them and evaluated the checked-out bytes rather than
constructing a clean revision.

## First-run report

This section is intentionally chronological and minimally interpreted. Times are
wall-clock times from entering the product repository at 20:44:31 BST, except
where a command's own `real` time is shown. The first attempts ran in a restricted
network sandbox; every network-dependent failure was retried with registry access.
Those environment-only failures are labelled as such. Product failures reproduced
after access was available.

### 00:00 — the repository README is a kernel inventory, not a start

The first thirty seconds do explain the differentiator:

> Auths is an open protocol and SDK for proof-carrying, bounded machine
> authority.

The next 76 lines enumerate the sealed verifier and 35 target packages. There is
no install command, language choice, documentation link, agent example, or
deliberate denial. The first runnable command at `auths-proof/README.md:91-99` is
an **identity without authorization** browser workbench. The first authorization
command is one item in “Focused validation” at `README.md:101-109`:

```text
cargo run -p auths-proof-offline-example
```

At this point a newcomer knows that the implementation is sophisticated, but not
which package belongs in an application or how Auths sits in front of an effect.
The README does honestly say “prelaunch and pre-audit” at lines 122-123.

### 01:58 — first Rust authorization succeeds from the checkout

Following the only authorization-shaped README command produced:

```console
$ cargo run -p auths-proof-offline-example
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.13s
     Running `target/debug/auths-proof-offline-example`
verdict=Authorized code=authorized stage=Complete retryable=false work_units=312
proof=[…] action=[…] context=[…] required_configuration=Some([…]) local_configuration=[…]
```

The first cold build reached that verdict 1 minute 58 seconds after opening the
README. A warm measurement was:

```text
real 6.31
user 0.10
sys 0.06
```

This proves the offline verifier. It does not create authority, protect a handler,
execute an effect, emit a receipt, or offer a failure switch. Reading
`demos/offline-verification/src/main.rs:4-61` was necessary to learn that it always
loads the positive fixture.

### 03:57 — the advertised TypeScript package installs, but it is another product

The language README at `bindings/typescript/README.md:6-12` says:

```text
npm install @auths-dev/sdk
```

The first restricted-network attempt failed after 70.36 seconds. This error is an
evaluation-environment limitation, not an Auths defect:

```text
npm error code ENOTFOUND
npm error syscall getaddrinfo
npm error errno ENOTFOUND
npm error network request to https://registry.npmjs.org/@auths-dev%2fsdk failed, reason: getaddrinfo ENOTFOUND registry.npmjs.org
```

With registry access, install succeeded in 5.39 seconds. It installed
`@auths-dev/sdk@0.1.16`. That artifact exposes only `.` and conformance JSON; its
README describes decentralized identity and Git-native storage. Running the exact
“Protect one MCP action” imports from `bindings/typescript/README.md:14-43` failed
in 0.13 seconds:

```console
$ node quickstart.mjs
node:internal/modules/esm/resolve:313
  return new ERR_PACKAGE_PATH_NOT_EXPORTED(
         ^

Error [ERR_PACKAGE_PATH_NOT_EXPORTED]: Package subpath './integrations' is not defined by "exports" in <clean-temp>/node_modules/@auths-dev/sdk/package.json imported from <clean-temp>/quickstart.mjs
    at exportsNotFound (node:internal/modules/esm/resolve:313:10)
    at packageExportsResolve (node:internal/modules/esm/resolve:660:9)
    at packageResolve (node:internal/modules/esm/resolve:773:12)
    at moduleResolve (node:internal/modules/esm/resolve:853:18)
    at defaultResolve (node:internal/modules/esm/resolve:983:11)
    at #cachedDefaultResolve (node:internal/modules/esm/loader:731:20)
    at ModuleLoader.resolve (node:internal/modules/esm/loader:708:38)
    at ModuleLoader.getModuleJobForImport (node:internal/modules/esm/loader:310:38)
    at ModuleJob._link (node:internal/modules/esm/module_job:182:49) {
  code: 'ERR_PACKAGE_PATH_NOT_EXPORTED'
}

Node.js v22.23.1
real 0.13
```

No authorization or denial is possible through the documented registry path.

### 06:00 — the repository-local TypeScript RC works immediately once found

The checkout contains `target/npm-package/auths-dev-sdk-1.0.0-rc.1.tgz`, but no
newcomer-facing page points to it. The first install hit a machine-local npm cache
ownership problem:

```text
npm error code EPERM
npm error syscall mkdtemp
npm error path /Users/bordumb/.npm/_cacache/tmp/…
npm error Your cache folder contains root-owned files…
real 0.53
```

Using a disposable cache installed it in 0.81 seconds. A complete program based
on the README, with an allowed `publish_report` call followed by a disallowed tool
call, then produced:

```console
$ node quickstart.mjs
{"attempt":"allowed","kind":"completed","calls":1}
{"attempt":"denied","kind":"denied","code":"permission-not-granted","calls":1}
real 0.20
```

The `calls` counter remaining at one makes the value visible: denied bytes never
entered the provider. The intended `1.0.0-rc.1` tarball has all seven declared
entry points, and its export map pairs each runtime entry with a declaration file.
The exercised implementation works; distribution and discovery do not.

### 08:00 — the advertised Python package has the same predecessor mismatch

With registry access, `python -m pip install auths` completed in 10.79 seconds and
installed `auths==0.1.16`. The wheel is the former identity product. A runnable
wrapper around `bindings/python/README.md:15-38` failed in 0.73 seconds:

```console
$ python quickstart.py
Traceback (most recent call last):
  File "<clean-temp>/quickstart.py", line 3, in <module>
    from auths.integrations import development
ModuleNotFoundError: No module named 'auths.integrations'
real 0.73
```

Installing the local
`target/python-wheels/auths-1.0.0rc1-cp39-abi3-macosx_11_0_arm64.whl` took 0.96
seconds. The documented one-argument handler did not complete the effect; it
returned:

```text
RecoveryResult(kind='recoverable', execution_id='…', reference=<…>)
real 0.55
```

Source inspection at
`bindings/python/python/auths/profiles/_mcp.py:441-528` was necessary to discover
that the handler contract is `(arguments, context)`, while the README supplies
only `(arguments)`. Correcting the temporary program—not shipping code—made both
paths work:

```console
$ python quickstart.py
{"allowed": "completed", "denied": "denied", "code": "permission-not-granted"}
real 0.16
```

### 10:00 — crates.io also resolves to the predecessor

The documentation site's guide says `cargo add auths-sdk` at
`auths-docs/app/guides/protect-rest-effect/protect-rest-effect.mdx:21`. With
registry access the command completed in 7.40 seconds and selected
`auths-sdk v0.1.16`, locking 433 packages. The site then tells the reader to use
`RestAction::post` at line 37. No `RestAction` exists in the checked-out product,
and it does not exist in the public crate. A clean compile spent 197.25 seconds
building the dependency graph, then failed:

```console
$ cargo check
error[E0432]: unresolved import `auths_sdk::RestAction`
 --> src/main.rs:1:5
  |
1 | use auths_sdk::RestAction;
  |     ^^^^^^^^^^^^^^^^^^^^^ no `RestAction` in the root

For more information about this error, try `rustc --explain E0432`.
error: could not compile `auths_adoption` (bin "auths_adoption") due to 1 previous error
real 197.25
user 181.96
sys 50.91
```

This is especially costly: the engineer learns only after a full cold Rust build
that the guide describes an API which neither the registry artifact nor current
source implements.

### 14:46 — first deliberate Rust denial requires source and fixture work

The offline example has no denial argument. I located
`core/fixtures/v1/denied/action-permission-not-granted.*.cbor`, read the verifier
API, and wrote a temporary external Rust program. Its first dependency attempt
was blocked by the restricted network after 22.40 seconds:

```text
Updating crates.io index
warning: spurious network error…
error: failed to get `minicbor` as a dependency of package `auths-rust-denial`

Caused by:
  download of config.json failed

Caused by:
  failed to download from `https://index.crates.io/config.json`

Caused by:
  [6] Couldn't resolve host name (Could not resolve host: index.crates.io)
```

Re-running from the local cache with `--offline` produced the intended result:

```console
$ cargo run --offline
verdict=Denied code=permission-not-granted
real 74.38
user 0.08
sys 0.24
```

The denial arrived about 14 minutes 46 seconds after opening the README and about
13 minutes after the first positive verdict. Most of that gap was discovery and
writing a consumer the repository should already provide.

### Recipes — real implementations, an undisclosed runner, and one broken Python import

The brief's suggested top-level `examples/` starting point does not exist in this
checkout. The runnable material is split between `bindings/recipes/` and
`demos/`.

`bindings/recipes/manifest.json` declares five TypeScript/Python recipe pairs.
Recipes 3 and 4 contain meaningful denied paths. There is no README or top-level
run command under `bindings/recipes/`; generated product docs say only “install
the single Auths package.” The TypeScript recipe package has no scripts.

After compiling the TypeScript sources, recipe 3 ran against the local RC:

```console
$ node bindings/recipes/typescript/build/03-execute-exact-action.js
{"recipe":"03-execute-exact-action","outcome":"completed","denied":true,"calls":1}
real 0.18
```

The all-recipe runner initially received a relative interpreter path. Because it
changes to a temporary working directory, it reported only:

```text
Error: python/01-authenticate-identity: undefined
    at run (bindings/recipes/tools/run.mjs:51:34)
real 0.26
```

Using an absolute interpreter path reached Python recipe 3 and reproduced a
shipping-source error:

```text
Error: python/03-execute-exact-action: Traceback (most recent call last):
  File "…/bindings/recipes/python/03_execute_exact_action.py", line 6, in <module>
    from auths import verify_receipt
ImportError: cannot import name 'verify_receipt' from 'auths' (…/bindings/python/python/auths/__init__.py)
    at run (bindings/recipes/tools/run.mjs:51:34)
real 1.00
```

`verify_receipt` is intentionally public from `auths.verify`, as recorded in
`bindings/python/api/public-api.txt:59-95`; recipe 5 already imports it there.
The current recipe evidence file is also candid:
`bindings/recipes/experience-evidence.json:22-28` says the unfamiliar-developer
cohort is awaiting, with zero participants.

### Documentation — it builds, while its code examples remain unchecked

The brief's statement that the site has no MDX is stale. The primary guide is
`auths-docs/app/guides/protect-rest-effect/protect-rest-effect.mdx`. It promises a
“10 MINUTE GUIDE” and a refund integration at lines 1-12, but every language
sample uses a REST profile/API absent from shipping source. The site test asserts
that those strings render; it does not compile them.

The complete documented validation passed:

```console
$ npm test
…
Build complete. Run `vinext start` to start the production server.
…
# tests 3
# suites 0
# pass 3
# fail 0
# duration_ms 742.298792
```

Passing means the inaccurate install commands and examples rendered successfully.
It does not mean any SDK snippet ran.

### MCP demo — authentic semantics, slow cold path, success only

The Rust MCP profile genuinely maps the official `rmcp` call type at
`product/profiles/auths-profile-mcp/src/lib.rs:72-90`. The demo compiled and ran:

```console
$ cargo run -p auths-mcp-demo -- demo --transport memory
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 02s
     Running `target/debug/auths-mcp-demo demo --transport memory`
transport              in-memory
outcome                Completed { result: [123, 34, 110, 97, 109, 101, 34, 58, 34, 113, 51, 34, 44, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 97, 112, 112, 114, 111, 118, 101, 100, 34, 125] }
proof_bytes            883
total_micros           3801
verification_micros    1911
execution_micros       450
request_id             c9a39cc890ceda5393c33001677c9c5addad697c82050b291782166018383a81
real 123.61
user 0.23
sys 0.38
```

Even with `--transport memory`, the cold build compiles the Iroh stack. The output
shows the result as a byte array, and the CLI has no denial or replay subcommand.
It is protocol evidence, not a persuasive first demo.

### Reference deployment — setup ambiguity, very large cold start, compile failure

The “Fifteen-minute path” at
`demos/open-production-reference/README.md:15-36` says to copy an already checked-in
configuration, “provide” a specially encoded seed without a generation command,
and create certificates through another runbook. Running the shown Compose command
literally first failed before contacting Docker:

```text
error while interpolating x-auths-node.environment.AUTHS_LOCAL_SEED: required variable AUTHS_LOCAL_SEED is missing a value: provide a 32-byte unpadded base64url seed
```

Docker Desktop was initially stopped; the independent environment error was:

```text
Cannot connect to Docker daemon at unix:///Users/bordumb/.docker/run/docker.sock. Is docker daemon running?
```

After starting Docker, generating a disposable seed, and using the checked-in
local certificates, the cold build pulled PostgreSQL, Prometheus, Grafana,
OpenTelemetry, nginx, a Rust base image, a second Rust 1.97.1 toolchain inside that
image, and the complete crate dependency graph. Before any Auths service started,
the `auths-node` release build failed. The Docker log recorded 305.3 seconds for
the Rust base-image stage and failed 127.1 seconds into its compile step, after the
earlier infrastructure-image pulls. I did not capture a reliable single wrapper
time for the whole attempt, so I do not present an invented total.

```text
error[E0277]: `?` couldn't convert the error: `KeriError: std::error::Error` is not satisfied
  --> product/runtime/auths-node/src/main.rs:46:54
   |
38 | fn kernel(config: &NodeConfig) -> Result<NodeKernel, Box<dyn std::error::Error>> {
   |                                   ---------------------------------------------- required `KeriError: std::error::Error` because of this
...
46 |         Box::new(auths_did_keri::DidKeriMethod::new()?),
   |                  ------------------------------------^ the trait `std::error::Error` is not implemented for `KeriError`
   |                  |
   |                  this has type `Result<_, KeriError>`
   |
   = note: required for `Box<dyn std::error::Error>` to implement `From<KeriError>`

error: could not compile `auths-node` (bin "auths-node") due to 1 previous error
```

The cause is concrete: the workspace dependency disables default features at
`auths-proof/Cargo.toml:150`; `KeriError` implements `std::error::Error` only under
the `std` feature at `core/adapters/auths-did-keri/src/lib.rs:1235-1236`; and
`product/runtime/auths-node/Cargo.toml:13` does not re-enable it. The failed build
created no Compose containers. The full doctor and installed-SDK tests therefore
could not run.

### Public demos — the flagship is live; the smaller lab is half-live

Reachability was checked from an unrestricted network on 15 August 2026:

- `https://auths-incident-demo-control-room.vercel.app/` returned 200.
- Northstar, EdgeShield, and agent `/healthz` endpoints each returned 200.
- `https://auths-live-demo.vercel.app/` returned 200, but its configured backend
  `auths-live-demo.fly.dev` did not resolve in DNS, including `/healthz`. The UI
  therefore advertises a native execution it cannot currently reach.

The cross-company incident-response demo is the strongest implemented story: it
has separate trust domains, humans and agents, exact ordered effects, replay and
widening attacks, outcome-unknown recovery, and disclosure-controlled receipts.
Its README also says cloud URLs must be redeployed at the exact revision before
being treated as implementation evidence. I verified service health, not the
complete browser ceremony.

## Time to first success

| Language | Clone → first authorization | Clone → first deliberate denial | Blocked at |
|----------|------------------------------|----------------------------------|------------|
| Rust | 1m 58s, checkout-only offline fixture | approximately 14m 46s; required locating a negative fixture and writing a temporary consumer | Public `auths-sdk@0.1.16` lacks the docs site's API; the checkout example has no denial switch |
| TypeScript | Documented registry path: **blocked**. Repository-local RC: 0.81s install + 0.20s allowed/denied run after finding the tarball | Same 0.20s local run | npm resolves to predecessor `0.1.16`; `./integrations` and `./profiles` are not exported |
| Python | Documented registry path: **blocked**. Repository-local RC: 0.96s install + 0.16s corrected allowed/denied run | Same 0.16s corrected local run | PyPI resolves to predecessor `0.1.16`; then the current README's handler arity is stale |

“Blocked” is not converted into a synthetic time. A newcomer following the
documented package path never reaches either outcome.

## Verdict

**A competent engineer should not adopt Auths into a service from the public
developer path today.** They can evaluate the checkout and the intended local RC,
and those bytes demonstrate a strong closed execution model. They cannot install
the product described by the docs from npm, PyPI, or crates.io. The primary site
then presents an invented REST API, while the real recipes are undiscoverable and
one Python recipe is broken. That combination makes a working implementation look
like vaporware.

The single change most likely to increase adoption is: **make one denial-first MCP
quickstart truthful from registry to provider call.** After the existing release
gates authorize an RC, a newcomer must be able to run the advertised install
command, copy one complete program, observe one allowed tool call, mutate it, and
observe a denial with an unchanged provider-call count in under five minutes. All
three home surfaces—repository README, documentation home, and package
README—must point to that same tested program. Until publication is authorized,
those surfaces must say “not publicly installable” instead of resolving silently
to the predecessor.

## Summary table

| ID | Title | Impact | Area | Est. effort | Depends on |
|----|-------|--------|------|-------------|------------|
| AD-001 | Make the advertised package coordinates resolve to the documented SDK | critical | packaging | 3 days after release authorization | AD-003, AD-010, release authorization |
| AD-002 | Replace the fictional REST guide with one executable denial-first MCP guide | critical | docs | 2 days | AD-001 |
| AD-003 | Repair and expose the installed-artifact recipe runner | high | onboarding | 1 day | — |
| AD-004 | Turn the repository README into a five-minute application front door | high | onboarding | 1 day | AD-001, AD-002 |
| AD-005 | Ship drop-in MCP server enforcement middleware | high | integrations | 4 days for TypeScript, 3 days for Python | AD-001 |
| AD-006 | Make the reference deployment start with one command and add a lite evaluator | high | demos | 3 days | — |
| AD-007 | Publish a healthy two-minute allowed/mutated/replay demonstration | high | demos | 4 days | AD-002, AD-005 |
| AD-008 | Give security evaluators one candidate-bound evidence index | high | evidence | 2 days | AD-001 |
| AD-009 | Turn private integration crates into a discoverable adoption catalogue | medium | integrations | 2 days | AD-004 |
| AD-010 | Complete the unfamiliar-engineer recipe cohort before claiming time-to-value | high | evidence | 1 engineering day plus cohort time | AD-003 |

## Recommendations

### AD-001 — Make the advertised package coordinates resolve to the documented SDK

- **Impact:** critical — every first-time Rust, TypeScript, and Python user
- **Area:** packaging
- **Estimated effort:** 3 days after release authorization
- **Depends on:** AD-003, AD-010, and the existing release authorization gates
- **Files:** `auths-proof/release/public-naming.toml:74-98`,
  `auths-proof/bindings/typescript/package.json:1-79`,
  `auths-proof/bindings/typescript/sdk-capability.json:10-16`,
  `auths-proof/bindings/python/pyproject.toml:5-31`,
  `auths-proof/bindings/python/sdk-capability.json:23-57`,
  `auths-proof/product/sdk/auths-sdk/Cargo.toml:1-35`,
  `auths-proof/.github/workflows/release.yml:286-348`,
  `auths-proof/.github/workflows/release-builder.yml:137-216`,
  `auths-docs/app/lib/sdk-languages.ts:9-13`, and
  `auths-docs/app/guides/protect-rest-effect/protect-rest-effect.mdx:15-25`

**What a user hits today**

You run the exact install command and get the predecessor at all three
coordinates:

```text
npm:    @auths-dev/sdk@0.1.16
PyPI:   auths==0.1.16
Cargo:  auths-sdk v0.1.16
```

The current repository declares the intended artifacts as `1.0.0-rc.1` /
`1.0.0rc1` and explicitly marks publication as blocked. npm then fails on
`@auths-dev/sdk/integrations`; Python fails on `auths.integrations`; Rust fails on
the site's nonexistent `RestAction` import.

**Why this costs adoption**

An engineer adding authority to an MCP server or refund path reasonably assumes a
successful registry install is the product. The package name, organization, and
README agree. Discovering that it is an unrelated earlier product looks like an
abandoned rename or supply-chain mistake. Nothing in the SDK can recover trust
after the first import fails.

**Required end state**

There are two honest states, never a mixture:

1. Before release authorization, public docs say:

   > Auths 1.0 RC is not yet published. The names below currently resolve to the
   > predecessor identity SDK. Evaluate the candidate from a release artifact or
   > the source checkout; do not use the bare registry commands yet.

2. After the existing promotion gate authorizes publication, docs use exact RC
   pins:

   ```text
   cargo add auths-sdk@1.0.0-rc.1
   npm install @auths-dev/sdk@1.0.0-rc.1
   python -m pip install auths==1.0.0rc1
   ```

Each coordinate returns the new exact-authority product, and a post-publication
smoke test exercises the installed artifact rather than a workspace path or local
tarball. This recommendation does not weaken or bypass the release, assurance, or
independent-review gates; it makes public claims switch atomically when those
gates permit them.

**How to implement**

1. Add `publicationStatus` as an input to the docs build, sourced from the two
   `sdk-capability.json` files and the Rust release manifest. Render the pre-release
   warning whenever any surface is blocked.
2. In `.github/workflows/release.yml`, keep publication downstream of the current
   candidate verification and explicit environment authorization. After each
   registry publish, create a new empty consumer and install the exact version
   from the public registry with caches disabled.
3. In that consumer, import every npm export from `package.json:9-37`, every Python
   public module, and the Rust facade. Run the same allowed/denied MCP fixture and
   assert provider calls equal one.
4. Query the registry metadata again and assert package version, repository URL,
   description, and README all identify the same candidate. Fail before the docs
   deployment if any coordinate still returns `0.1.16`.
5. Only then change `sdk-languages.ts` and the package READMEs from the warning to
   the exact pinned commands. Do not advertise an unpinned bare coordinate during
   the RC period.

**How to verify it worked**

From three empty directories with no workspace links:

```bash
npm view @auths-dev/sdk@1.0.0-rc.1 version
npm install --ignore-scripts @auths-dev/sdk@1.0.0-rc.1
node -e 'Promise.all([import("@auths-dev/sdk"),import("@auths-dev/sdk/profiles"),import("@auths-dev/sdk/integrations")]).then(() => console.log("ok"))'

python -m pip install --no-cache-dir auths==1.0.0rc1
python -c 'import importlib.metadata, auths, auths.profiles, auths.integrations; print(importlib.metadata.version("auths"))'

cargo add auths-sdk@1.0.0-rc.1
cargo check
```

The denial-first smoke described in AD-002 must print `completed`, then
`denied: permission-not-granted`, with `provider_calls=1` in each supported
language. Before publication, the docs build must instead contain the warning and
must not contain a bare install command.

**Blast radius**

Registry metadata, package lockfiles, release subjects, SPDX/CycloneDX SBOMs,
SLSA provenance subjects, docs.rs links, generated SDK docs, the predecessor
supersession notice, and every quickstart must switch together. A partial publish
is a failed release, not a docs-only incident.

### AD-002 — Replace the fictional REST guide with one executable denial-first MCP guide

- **Impact:** critical — application engineers and agent builders entering through the documentation home
- **Area:** docs
- **Estimated effort:** 2 days
- **Depends on:** AD-001
- **Files:** `auths-docs/app/page.tsx:5-31,64-100`,
  `auths-docs/app/guides/protect-rest-effect/protect-rest-effect.mdx:1-77`,
  `auths-docs/public/guides/protect-rest-effect.md`,
  `auths-docs/app/components/SdkReference.tsx:32-185`,
  `auths-docs/public/sdk/sections/*.md`,
  `auths-docs/tests/rendered-html.test.mjs:32-70`,
  `auths-proof/bindings/recipes/typescript/03-execute-exact-action.ts`, and
  `auths-proof/bindings/recipes/python/03_execute_exact_action.py`

**What a user hits today**

The home page says “Protect your first effect” and sends you to a “10 MINUTE
GUIDE.” It then offers:

```rust
let action = RestAction::post("/v1/refunds/rf_82k")?
```

The TypeScript and Python tabs similarly use `rest.post`, `actor`, `gateway`, and
object-shaped `auths.create` calls that are not the qualified API in the current
packages. The docs test passes because it checks rendered phrases, not compiled
programs. The page also claims replay returns `replay-detected` and changed bytes
return `commitment-mismatch`; the executable RC path observed
`permission-not-granted` for the undeclared action.

**Why this costs adoption**

An engineer evaluating Auths for an existing Node MCP server reaches the primary
CTA, copies code, and fails before seeing a denial. A security product with
nonexistent security examples loses more trust than one with no examples. The
fictional REST abstraction also hides the best current wedge: the repository has
a real, qualified MCP profile using official request types.

**Required end state**

Rename the route and page to **Protect one MCP tool call**. The first screen must
state:

> Allow `publish_report` once. Then ask for an undeclared tool and watch Auths
> deny it before your handler runs. You will finish with one provider call and a
> verifiable receipt.

The page's final expected output must be:

```json
{"attempt":"allowed","kind":"completed","providerCalls":1}
{"attempt":"undeclared-tool","kind":"denied","code":"permission-not-granted","providerCalls":1}
```

Use recipe 3 as the only source of executable example bytes. Initially show only
language tabs whose **installed public artifact** passes the snippet. Do not show
a Rust tab containing pseudocode; add it when an external-crate recipe with the
same behavior exists.

For TypeScript, the complete displayed program must use the current API shape:

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

let providerCalls = 0;
const provider = mcp.developmentProvider({
  tools: {
    async publish_report(arguments_) {
      providerCalls += 1;
      return { published: true, arguments: arguments_ };
    },
  },
});
const auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
try {
  const allowed = await auths.execute({
    action: mcp.callTool({ name: "publish_report", arguments: { period: "weekly" } }),
    provider,
  });
  console.log(JSON.stringify({ attempt: "allowed", kind: allowed.kind, providerCalls }));

  const denied = await auths.execute({
    action: mcp.callTool({ name: "delete_report", arguments: { period: "weekly" } }),
    provider,
  });
  console.log(JSON.stringify({
    attempt: "undeclared-tool",
    kind: denied.kind,
    code: denied.kind === "denied" ? denied.code : undefined,
    providerCalls,
  }));
} finally {
  await auths.close();
}
```

The Python version must be a complete `asyncio.run(main())` program and its
handler must accept `(arguments, context)`.

**How to implement**

1. Rename the route to `/guides/protect-one-mcp-tool`; leave a permanent redirect
   from `/guides/protect-rest-effect` so existing links do not break.
2. Import or generate the code blocks from recipe 3 instead of duplicating them in
   MDX and `SdkReference.tsx`. Extend `bindings/recipes/tools/generate-docs.mjs`
   to emit a small JSON/Markdown artifact consumed by the docs repository.
3. Replace the REST hero, refund mock receipt, and invented stable codes with the
   exact tool name, arguments, provider counter, result kinds, and receipt
   projection emitted by the installed recipe.
4. Add a docs fixture job that downloads the promoted tarball/wheel, runs each
   displayed file in an empty directory, captures stdout, and compares it with the
   rendered expected output.
5. Make the rendered-HTML test assert the MCP commands and add a separate
   executable-snippet test. Rendering alone must not satisfy the guide gate.

**How to verify it worked**

```bash
# auths-proof: build packages and execute the maintained sources
npm --prefix bindings/typescript run test:examples
AUTHS_RECIPE_PYTHON="$(pwd)/bindings/python/.venv/bin/python" \
  node bindings/recipes/tools/run.mjs

# auths-docs: render and execute imported snippets
npm test
```

In a clean, network-enabled consumer, start the timer before install. Both
supported language paths must reach the two exact JSON lines in under five
minutes, and the second line must still say `providerCalls:1`. A repository-wide
search of the public docs must find no `RestAction::post` or unimplemented
`rest.post` claim.

**Blast radius**

Home-page copy and links, route redirects, social cards, SDK navigation, package
READMEs, generated Markdown for “Copy for LLM,” search indexes, recipe docs, and
release notes all need the same MCP terminology and output.

### AD-003 — Repair and expose the installed-artifact recipe runner

- **Impact:** high — evaluators who find the strongest runnable examples, and maintainers relying on the recipe gate
- **Area:** onboarding
- **Estimated effort:** 1 day
- **Depends on:** —
- **Files:** `auths-proof/bindings/recipes/python/03_execute_exact_action.py:6`,
  `auths-proof/bindings/recipes/tools/run.mjs:10-19,38-57`,
  `auths-proof/bindings/recipes/typescript/package.json:1-8`,
  `auths-proof/bindings/recipes/tools/generate-docs.mjs:21-29`,
  `auths-proof/docs/product/recipes/README.md`, and
  `auths-proof/.github/workflows/sdk-recipes.yml`

**What a user hits today**

There is no `bindings/recipes/README.md`, no package script, and no command in the
generated recipe page. Guessing the runner with a relative interpreter yields:

```text
Error: python/01-authenticate-identity: undefined
```

Using an absolute interpreter reaches recipe 3 and fails:

```text
ImportError: cannot import name 'verify_receipt' from 'auths'
```

The runner hides `spawnSync().error`, so a missing executable is rendered as the
word `undefined`.

**Why this costs adoption**

An evaluator who goes beyond the glossy guide has found the best product proof:
ten installed-artifact programs, adversarial assertions, and cross-language
receipt verification. The lack of a command and the first broken pair tell that
motivated engineer the examples are internal test debris. The same defect also
undermines the `timeToValue: verified` metadata claim.

**Required end state**

`bindings/recipes/README.md` must begin with one command for a source checkout:

```text
npm run recipes
```

It must state prerequisites, build/install the local tarball and wheel into clean
temporary consumers, run all 12 checks, and print a table with recipe, language,
outcome, and elapsed milliseconds. A missing interpreter must say, for example:

```text
python/01-authenticate-identity: could not start /path/to/python (ENOENT)
```

**How to implement**

1. Change recipe 3 line 6 to:

   ```python
   from auths.verify import verify_receipt
   ```

2. Resolve `AUTHS_RECIPE_PYTHON` before any per-recipe `cwd` change. If it is not
   absolute, resolve it against the repository root or use `command -v` once.
3. At `run.mjs:50-51`, check `result.error` first and include its `code`, `path`,
   and message. Then handle signal and numeric status separately; never interpolate
   absent stdout/stderr as `undefined`.
4. Add `build` and `recipes` scripts to the recipe package. The `recipes` script
   must compile TypeScript, build/install the candidate artifacts into temporary
   environments, and invoke the runner with the interpreter it created.
5. Generate `bindings/recipes/README.md` and `docs/product/recipes/*.md` from the
   same manifest. Replace “install the single Auths package” at
   `generate-docs.mjs:23` with the literal command and the expected last JSON line.
6. Make `sdk-recipes.yml` run the public `npm run recipes` entry point, so CI and a
   newcomer use the same path.

**How to verify it worked**

```bash
git clean -ndx bindings/recipes  # inspection only; do not delete source
npm --prefix bindings/recipes/typescript ci
npm --prefix bindings/recipes/typescript run recipes
```

The command must exit zero, report five TypeScript recipes, five Python recipes,
and two cross-language receipt checks, and include the denied branch for recipes
3 and 4. Re-run with `AUTHS_RECIPE_PYTHON=/does/not/exist`; the error must contain
`ENOENT` and the exact path. Add a CI assertion that
`experience-evidence.json.automated.timings` has the same schema and row count as
the runner output.

**Blast radius**

The generated recipe Markdown, timing evidence, customer-journey matrix, SDK
capability scorecards, CI workflow, and both package example tests must be
regenerated after the import and runner contract change.

### AD-004 — Turn the repository README into a five-minute application front door

- **Impact:** high — every engineer landing on the source repository
- **Area:** onboarding
- **Estimated effort:** 1 day
- **Depends on:** AD-001, AD-002
- **Files:** `auths-proof/README.md:3-123`,
  `auths-proof/docs/product/recipes/03_EXECUTE_ONE_ACTION.md:1-118`, and
  `auths-proof/docs/product/PRODUCTION_SDK_QUICKSTART.md:1-81`

**What a user hits today**

After a good two-sentence definition, you receive a package inventory from lines
43-79. The first runnable path is explicitly “Identity without authorization,”
and the authorization example is the last line of a five-command validation
block. There is no package install, expected output, denial, agent use case, or
link to the public docs. A reader has to infer whether they are an SDK user,
protocol implementer, or repository contributor.

**Why this costs adoption**

An engineer considering protection for an existing agent tool has perhaps one
minute to decide whether this is an embeddable product or a research kernel. The
README leads with mechanism breadth and presents the actual effect workflow as an
internal repository detail. The engineer who would value the formal work most
never reaches it because the application boundary is missing.

**Required end state**

Replace the content before the current sealed-pipeline section with this front
door, substituting the exact promoted version from AD-001:

> # Auths
>
> Auths lets a person or agent prove it may perform one exact action—then denies
> changed, broader, expired, or replayed actions before provider credentials are
> used. Successful execution leaves a signed, independently verifiable receipt.
>
> **Best first use:** put Auths in front of one MCP `tools/call` handler. Keep
> your existing identity provider, MCP server, and provider credentials.
>
> ## See the boundary in five minutes
>
> Install the SDK for your language, run the complete program below, and observe
> one completed call followed by one denied call. The provider counter remains
> one. [Open the denial-first quickstart](<canonical AD-002 URL>).
>
> Auths 1.0 RC is prelaunch and has not completed independent security review.
> See [release status](<candidate evidence URL>) before production evaluation.

Immediately below it, embed the TypeScript program and expected two-line output
from AD-002. Follow with three links labelled **Use the SDK**, **Understand the
protocol**, and **Contribute to the repository**. Move the package inventory under
an “Architecture and protocol implementation” heading after the quickstart.

**How to implement**

1. Preserve the current definition, sealed pipeline, and package list, but move
   them below the application quickstart. Do not delete the accurate kernel
   boundary.
2. Make the quickstart source a generated include or checked digest of recipe 3;
   do not hand-copy a third version.
3. Render package-publication state from `sdk-capability.json`. Before AD-001 is
   promoted, replace install commands with the honest pre-release warning and a
   source-checkout evaluator command.
4. Add links to the docs guide, exact versioned API reference, security policy,
   compatibility/support page, and candidate evidence summary.
5. Add a README check that extracts and runs fenced blocks marked
   `auths-executable`, using only packed artifacts.

**How to verify it worked**

Give a fresh clone to a runner that has Node but no Rust toolchain. Starting at
the README, the runner must install the promoted tarball from npm and reach:

```text
completed providerCalls=1
denied permission-not-granted providerCalls=1
```

in under five minutes without opening another source file. CI must byte-compare
the README code with recipe 3 and fail if either diverges. Before publication, CI
must instead prove the README does not contain a runnable bare registry command.

**Blast radius**

Repository description, package READMEs, docs home, social preview, generated
recipe pages, and any “getting started” links must use the same persona, promise,
status warning, and canonical quickstart URL.

### AD-005 — Ship drop-in MCP server enforcement middleware

- **Impact:** high — Node and Python teams that already operate an MCP server
- **Area:** integrations
- **Estimated effort:** 4 days for TypeScript, then 3 days for Python
- **Depends on:** AD-001
- **Files:** `auths-proof/product/profiles/auths-profile-mcp/src/lib.rs:15-90`,
  `auths-proof/bindings/typescript/src/profiles/mcp/index.ts:445-560`,
  `auths-proof/bindings/typescript/src/integrations.ts:1-239`,
  `auths-proof/bindings/typescript/src/integrations/mcp-server.ts` (new),
  `auths-proof/bindings/python/python/auths/profiles/_mcp.py:441-528`,
  `auths-proof/bindings/python/python/auths/integrations.py:1-672`,
  `auths-proof/bindings/python/python/auths/_mcp_server.py` (new), and
  `auths-proof/bindings/recipes/typescript/06-protect-existing-mcp-server.ts` (new), and
  `auths-proof/bindings/recipes/python/06_protect_existing_mcp_server.py` (new)

**What a user hits today**

The Rust profile correctly converts an official `rmcp::CallToolRequestParams`.
The TypeScript and Python SDKs provide a development provider into which a user
registers Auths-owned handlers. There is no maintained adapter for an existing MCP
server, no middleware entry point, and no LangChain, CrewAI, or OpenAI Agents SDK
adapter in the checkout. To adopt Auths, an MCP operator must understand provider
sessions, profile canonicalization, handler contracts, lifecycle reservation, and
receipts before wrapping one request.

**Why this costs adoption**

The highest-urgency persona is a platform engineer whose agent already calls MCP
tools with a broad service credential. That engineer is not choosing an
authorization framework from scratch; they need one interception point that keeps
their existing server and handler. Requiring an Auths-specific provider rewrite
makes the safer path harder than leaving the API key in place.

**Required end state**

The TypeScript integration must support a shape this small:

```ts
import { secureMcpToolHandler } from "@auths-dev/sdk/integrations";

server.setRequestHandler(CallToolRequestSchema, secureMcpToolHandler({
  auths,
  service: "reports",
  async handle(request, extra) {
    return existingToolRouter(request, extra);
  },
  onReceipt(receipt) {
    receiptStore.append(receipt);
  },
}));
```

Python must offer the same concepts in idiomatic async form. The wrapper must:

1. accept the official immediate `tools/call` request type;
2. reject MCP task and `_meta` extensions exactly as the V1 profile does;
3. canonicalize service, name, and arguments once;
4. authorize and durably reserve before calling the existing handler;
5. pass the **verified decoded arguments**, not the original mutable object;
6. invoke the handler at most once;
7. persist a receipt or recoverable reference; and
8. map denied/recoverable/indeterminate states to explicit MCP errors without
   pretending transport success is authorization.

It must not acquire or own the downstream provider credential; the existing
handler keeps that application responsibility.

**How to implement**

1. Define the public wrapper contract in TypeScript using the official MCP SDK's
   request/response types. Put profile meaning behind existing `mcp.callTool` and
   Auths execution; the wrapper must not reproduce canonicalization.
2. Add a conformance harness with a fake existing handler and an invocation
   counter. Cover allowed, changed arguments, changed name, undeclared tool,
   exact replay, concurrent replay, cancellation, handler failure, and
   outcome-unknown.
3. Export only the high-level wrapper from `/integrations`; keep reservation and
   command handles non-constructible.
4. Add recipe 6 as a complete minimal MCP server with one `publish_report` tool.
   The recipe must be executable against the packed artifact, not a source alias.
5. Port the contract to Python after TypeScript behavior is frozen. Keep the
   two-argument `(arguments, context)` handler shape and run the same fixture
   corpus in both languages.
6. Document how the wrapper composes alongside an existing OAuth session or API
   key: those authenticate/access the provider; Auths gates the exact tool call.

**How to verify it worked**

```bash
npm --prefix bindings/typescript test -- --test-name-pattern='MCP server middleware'
python -m pytest -q bindings/python/tests -k mcp_server_middleware
node bindings/recipes/tools/run.mjs
```

The packed-artifact recipe must start an MCP server, complete exactly one allowed
call, deny a mutated call and a replay, leave the existing handler count at one,
and verify the resulting receipt. A consumer example must contain no imports from
`framework`, `testkit`, internal paths, or Rust crates.

**Blast radius**

Public API snapshots, npm/Python type declarations, topology manifests, MCP
profile conformance, error docs, recipe evidence, package READMEs, and the agent
guide all change. Adding a third-party MCP SDK dependency also affects lockfiles,
SBOMs, licenses, and the release subject digest.

### AD-006 — Make the reference deployment start with one command and add a lite evaluator

- **Impact:** high — platform engineers evaluating deployability and security reviewers reproducing evidence
- **Area:** demos
- **Estimated effort:** 3 days
- **Depends on:** —
- **Files:** `auths-proof/Cargo.toml:150`,
  `auths-proof/product/runtime/auths-node/Cargo.toml:10-23`,
  `auths-proof/demos/open-production-reference/Dockerfile:1-8`,
  `auths-proof/demos/open-production-reference/README.md:15-36`,
  `auths-proof/demos/open-production-reference/config/local.toml:16-28`,
  `auths-proof/demos/open-production-reference/compose/compose.yaml:3-113`,
  `auths-proof/demos/open-production-reference/compose/compose.lite.yaml` (new),
  `auths-proof/demos/open-production-reference/scripts/evaluate-local.sh` (new), and
  `auths-proof/.github/workflows/open-production-reference.yml:1-136`

**What a user hits today**

The literal Compose command first fails because the required seed is not set. On
a cold machine, the full operator topology is mandatory: three Auths nodes,
PostgreSQL, SoftHSM, OpenTelemetry, Prometheus, Grafana, and nginx. The Dockerfile
starts from Rust 1.91, while the checkout pins 1.97.1, so it downloads a second
toolchain. It then fails to compile `auths-node` because `auths-did-keri` has
`default-features = false` in the workspace and the node does not request `std`.

Even after that compile fix, source inspection shows a second startup blocker:
`local.toml:28` points at `/run/config/trusted-context.cbor`, but no such file is
checked into the reference directory or mounted by `compose.yaml:11-13`.

**Why this costs adoption**

A platform engineer uses the reference deployment to answer “what will I have to
operate?” The current fifteen-minute path spends most of its time downloading
observability infrastructure and then fails before `doctor`. It makes the
intrinsic production concerns—durable lifecycle, custody, TLS, exact gateways—
look inseparable from accidental demo setup work.

**Required end state**

The README starts with:

```text
./demos/open-production-reference/scripts/evaluate-local.sh
```

That script generates disposable seed and certificates, generates or copies a
canonical trusted-context fixture, starts **one node + PostgreSQL + ingress**,
runs `doctor`, runs the installed TypeScript and Python allowed/denied/replay
flow, prints elapsed time, and tears down on request. The lite stack is explicitly
an evaluator, not the production topology.

The current three-node, HSM, and observability stack remains as `--full` for an
operator review. Both modes use the repository-pinned Rust toolchain directly in
the builder image and share the same `auths-node` binary.

**How to implement**

1. Change `product/runtime/auths-node/Cargo.toml:13` to:

   ```toml
   auths-did-keri = { workspace = true, features = ["std"] }
   ```

   Add a binary compile test that constructs `kernel()` so feature unification in
   unrelated workspace packages cannot hide this failure.
2. Update the pinned Docker builder to the exact `rust-toolchain.toml` version and
   a reviewed digest. Add a check that rejects drift between those values.
3. Generate the local trusted context through the existing canonical Rust codec;
   write it under a gitignored evaluator state directory and mount it read-only at
   `/run/config/trusted-context.cbor`.
4. Have `evaluate-local.sh` call the existing certificate generator, generate 32
   random bytes as unpadded base64url, store evaluator environment in a mode-0600
   gitignored file, and validate `docker compose config` before building.
5. Add `compose.lite.yaml` with one node, PostgreSQL, and ingress. Provide a local
   telemetry sink or an explicit disabled telemetry setting; do not leave a
   hostname for a service absent from the lite topology.
6. Build candidate npm/wheel artifacts or download the candidate-bound versions
   before running `tests/installed-sdk-e2e.mjs` and
   `tests/test_installed_sdk.py`. Explicitly install/provide
   `auths-sandbox-request`, which those tests invoke at lines 24 and 32.
7. Keep the full Compose file and runbooks, but move them after the successful
   evaluator path and state their cold-pull size/time variability honestly.

**How to verify it worked**

On a CI runner after pruning Auths reference images and caches:

```bash
/usr/bin/time -p demos/open-production-reference/scripts/evaluate-local.sh --lite --wait
AUTHS_LOCAL_SEED=… docker compose \
  -f demos/open-production-reference/compose/compose.lite.yaml \
  exec auths-1 auths-node /etc/auths/local.toml doctor
node demos/open-production-reference/tests/installed-sdk-e2e.mjs
python -m pytest -q demos/open-production-reference/tests/test_installed_sdk.py
```

The first command must reach a healthy node and deliberate replay/widening denial
in under fifteen minutes on the documented minimum machine. The tests must use
installed artifacts only. Then run the same semantic flow with `--full`; all three
nodes and the observability health checks must pass. CI must fail if the trusted
context is missing or the node binary is built without the KERI `std` feature.

**Blast radius**

The node dependency graph, Docker digest, SBOM, Compose policy tests, Kubernetes
image reference, local runbook, release evidence, trusted-context fixture, and
reference CI workflow all change. The lite topology must never be promoted as the
production availability or custody recommendation.

### AD-007 — Publish a healthy two-minute allowed/mutated/replay demonstration

- **Impact:** high — skeptical developers, security engineers, and technical buyers
- **Area:** demos
- **Estimated effort:** 4 days
- **Depends on:** AD-002, AD-005
- **Files:** `auths-proof/demos/cross-company-incident-response/control-room/src/app.ts:17-347`,
  `auths-proof/demos/cross-company-incident-response/README.md:1-173`,
  `auths-proof/demos/cross-company-incident-response/tests/browser-smoke.mjs:1-64`,
  `auths-proof/demos/live-lab/web/index.html:1-20`,
  `auths-proof/demos/live-lab/web/app.js:52-86,418-494`,
  `auths-proof/demos/live-lab/tests/web-smoke.mjs:1-179`,
  `auths-proof/docs/target-state/LIVE_DEMO_PLAN.md:13-74`,
  `auths-docs/app/page.tsx:64-83`, and
  `auths-proof/.github/workflows/ci.yml:1-861`

**What a user hits today**

The incident-response demo is the strongest real implementation, but its first
happy path has seven conceptual stages and four services. The smaller Live Lab
claims browser/native execution and returns a healthy UI, while its configured
Fly backend does not resolve. The repository's simple MCP CLI completes only the
positive path and prints provider output as a byte array. None gives a skeptic a
healthy, guided, allowed-then-denied proof in two minutes.

**Why this costs adoption**

A staff engineer or buyer needs the product's irreducible “aha” before investing
in the multi-organization architecture. A long ceremony invites debate about
simulated identities and infrastructure. A dead backend makes all live claims
suspect. The shortest convincing fact is much smaller: exact allowed bytes enter
the handler once; changed and replayed bytes do not; the receipt verifies.

**Required end state**

Add a **Two-minute tour** mode to the incident control room, backed by real Auths
semantics and the existing live services:

1. Show one agent request:
   `publish_report {"period":"weekly","destination":"board"}`.
2. Click **Authorize & run**. Show handler counter `0 → 1` and a completed receipt.
3. Automatically change `destination` to `public`. Show the stable denial, highlight
   the changed field, and keep handler counter at `1`.
4. Replay the original exact request. Show lifecycle replay denial and keep the
   counter at `1`.
5. Verify the first receipt independently and finish with three large facts:
   **one approved effect, zero unauthorized entries, one verifiable receipt**.

The default tour hides CBOR, graph internals, deployment topology, and advanced
attacks behind **Inspect how**. The full incident scenario remains available as
**Open the attack lab**.

If the standalone Live Lab backend is not restored and health-gated, remove it
from public navigation rather than serving a half-live experience.

**How to implement**

1. Reuse the MCP middleware and fixture from AD-005. Do not add a demo-only verdict
   switch or hand-authored denial JSON.
2. Add a bounded guided-state machine to the control room. Each transition waits
   for the real API response and reads provider-entry count from server evidence.
3. Add release ID and source commit to the UI. The backend must reject a frontend
   built for different semantics.
4. Add browser tests that inspect network responses, provider count, stable codes,
   and receipt verification—not only visible text.
5. Add a scheduled health check for UI, all API `/healthz` endpoints, one complete
   tour, and release-ID agreement. On failure, mark the demo unavailable in docs
   or page the owner; do not leave the CTA green.
6. Make the docs home primary CTA **Watch one changed action fail** and deep-link
   directly to the guided mode.

**How to verify it worked**

```bash
node demos/cross-company-incident-response/tests/browser-smoke.mjs --mode two-minute
python demos/cross-company-incident-response/tests/integration.py
```

On the deployed candidate, start a stopwatch at first paint. An unauthenticated
visitor must complete the tour within 120 seconds. The browser test must observe
one provider entry, a denial for changed bytes, a denial for replay, and a verified
receipt. All four service health checks and the exact revision check must pass
before the docs CTA is published.

**Blast radius**

Demo API schema, frontend state, receipt presentation, deployment health checks,
docs and site CTAs, telemetry, test fixtures, release metadata, and the Live Demo
plan need updating. Keep the full attack lab's stronger claims and caveats intact.

### AD-008 — Give security evaluators one candidate-bound evidence index

- **Impact:** high — security reviewers, procurement teams, and platform owners deciding whether to run a pilot
- **Area:** evidence
- **Estimated effort:** 2 days
- **Depends on:** AD-001
- **Files:** `auths-proof/SECURITY.md:1-51`,
  `auths-proof/docs/threat-model.md:1-84`,
  `auths-proof/release/SLSA_BUILD_LEVEL_3_ASSESSMENT.md:1-87`,
  `auths-proof/release/assurance/open-production-candidate-1/summary.md:1-39`,
  `auths-proof/release/assurance/open-production-candidate-1/manifest.json:1-43`,
  `auths-proof/docs/product/COMPATIBILITY_AND_SUPPORT.md:1-31`,
  `auths-docs/content/assurance-status.json` (new generated file),
  `auths-docs/app/security/page.tsx` (new), and
  `auths-docs/tests/rendered-html.test.mjs:1-71`

**What a user hits today**

The repository contains unusually strong evidence machinery: dual licenses, a
security policy, a detailed threat model, conformance and formal artifacts,
release manifests, SPDX/CycloneDX generation, signed hosted-build provenance,
runbooks, and an executable assurance gate. It is scattered across source,
`release/`, `target/`, and an in-progress candidate directory.

The most decision-relevant status exists only deep in the tree:

```text
Immutable candidate binding        Pending
Sustained qualification            0 of 2,592,000 seconds
Required evidence families         0 of 7
Independent security review        Pending
Signed statement                   Absent
Production release eligible        No
```

Meanwhile, the SLSA assessment says it passes Build Level 3 for one exact reusable
builder and observed execution, but explicitly is not an independent security
review or production-readiness claim.

**Why this costs adoption**

A security reviewer cannot reward evidence they cannot locate or bind to the
package under evaluation. If a marketing or docs page says only “machine-checked”
while the candidate record says “0 of 7,” the reviewer has to reconcile the claim
manually. The likely result is a long questionnaire or a rejected pilot despite
the repository having better raw material than many projects.

**Required end state**

Publish `/security` as an automatically generated evidence index for one exact
candidate. The first screen contains:

- candidate version, source commit, package/image digests, and update time;
- **Evaluation only / Production eligible** derived from the signed assurance
  manifest, never authored by the docs site;
- independent review status and link to scope/report when present;
- qualification duration and evidence-family count;
- links and digests for threat model, SBOM, SLSA provenance, conformance/formal
  manifest, release notes, compatibility policy, known limitations, and security
  reporting; and
- a plain statement of what is not covered.

When the manifest is incomplete, the page must lead with:

> This candidate is for evaluation only. It has no completed independent security
> review, sustained qualification, or signed production statement. Do not use it
> as the sole authorization control for high-value production actions.

**How to implement**

1. Add a generator in the product release process that reads only the verified
   assurance manifest and release manifest, resolves each digest-bound artifact,
   and emits a redacted `auths.assurance-public-index/1` JSON file.
2. Copy that generated file into `auths-docs/content/assurance-status.json` during
   the candidate docs build. Record the source digest; fail on hand-edited status
   fields or an unbound package set.
3. Render the page from the JSON. Do not infer “pass” from file existence and do
   not collapse pending, absent, failed, and out-of-scope into one badge.
4. Add downloadable links to retained evidence. If an artifact exists only in a
   short-lived CI run, mark it unavailable rather than linking to a plan or fixture.
5. Add a security contact/response-expectation section. If there is no response
   SLA, say so; do not invent one.
6. Link `/security` from the docs header, package READMEs, release page, and the
   reference-deployment README.

**How to verify it worked**

```bash
cargo xtask assurance summarize release/assurance/open-production-candidate-1/manifest.json
npm --prefix ../auths-docs test
```

For the current manifest, the rendered page must contain “Evaluation only,”
`0 of 2,592,000 seconds`, `0 of 7`, “Independent security review: Pending,” and
“Production release eligible: No.” A fixture that changes the candidate digest
without regenerating evidence must fail the docs build. A future eligible fixture
must render “Production eligible” only after the existing assurance verifier also
passes.

**Blast radius**

Release retention, artifact hosting, docs deployment, security policy, package
metadata, candidate notes, and any marketing assurance claims are affected. The
public index is a projection of signed evidence, never a new source of truth.

### AD-009 — Turn private integration crates into a discoverable adoption catalogue

- **Impact:** medium — Rust platform teams evaluating GitHub, Kubernetes, OpenTofu, PostgreSQL, Stripe, Radicle, did:web, KMS, or PKCS#11 fit
- **Area:** integrations
- **Estimated effort:** 2 days
- **Depends on:** AD-004
- **Files:** `auths-proof/product/integrations/auths-custody-aws-kms/Cargo.toml:1-22`,
  `auths-proof/product/integrations/auths-custody-pkcs11/Cargo.toml:1-22`,
  `auths-proof/product/integrations/auths-custody/Cargo.toml:1-19`,
  `auths-proof/product/integrations/auths-enforcement/Cargo.toml:1-16`,
  `auths-proof/product/integrations/auths-evidence-assemblers/Cargo.toml:1-21`,
  `auths-proof/product/integrations/auths-github/Cargo.toml:1-35`,
  `auths-proof/product/integrations/auths-kubernetes/Cargo.toml:1-31`,
  `auths-proof/product/integrations/auths-opentofu/Cargo.toml:1-31`,
  `auths-proof/product/integrations/auths-postgresql/Cargo.toml:1-34`,
  `auths-proof/product/integrations/auths-radicle/Cargo.toml:1-40`,
  `auths-proof/product/integrations/auths-records-api/Cargo.toml:1-34`,
  `auths-proof/product/integrations/auths-resolver-did-web/Cargo.toml:1-19`,
  `auths-proof/product/integrations/auths-stripe/Cargo.toml:1-40`,
  `auths-proof/product/integrations/auths-custody-aws-kms/README.md` (new),
  `auths-proof/product/integrations/auths-custody-pkcs11/README.md` (new),
  `auths-proof/product/integrations/auths-custody/README.md` (new),
  `auths-proof/product/integrations/auths-enforcement/README.md` (new),
  `auths-proof/product/integrations/auths-evidence-assemblers/README.md` (new),
  `auths-proof/product/integrations/auths-github/README.md` (new),
  `auths-proof/product/integrations/auths-kubernetes/README.md` (new),
  `auths-proof/product/integrations/auths-opentofu/README.md` (new),
  `auths-proof/product/integrations/auths-postgresql/README.md` (new),
  `auths-proof/product/integrations/auths-radicle/README.md` (new),
  `auths-proof/product/integrations/auths-records-api/README.md` (new),
  `auths-proof/product/integrations/auths-resolver-did-web/README.md` (new),
  `auths-proof/product/integrations/auths-stripe/README.md` (new),
  `auths-proof/product/integrations/README.md` (new),
  `auths-proof/docs/product/integrations/catalog.json` (new generated file),
  `auths-docs/app/integrations/page.tsx` (new), and
  `auths-docs/tests/rendered-html.test.mjs:1-71`

**What a user hits today**

`product/integrations/` contains 13 substantive crates, but none has a README.
Their only discovery metadata is a one-line Cargo description. Most are
`publish = false`, and none appears as a copyable integration on the docs site.
The names also mix different layers: effect gateways (Stripe, PostgreSQL),
resource adapters (GitHub, Kubernetes, OpenTofu, Radicle), custody (AWS KMS,
PKCS#11), evidence assembly, enforcement, and did:web resolution.

**Why this costs adoption**

A platform engineer evaluating a PostgreSQL update or Stripe operation cannot
tell whether the crate is a supported public dependency, a reference adapter, a
demo-only gateway, or internal runtime code. They therefore assume adopting Auths
requires replacing their provider client or operating a separate control plane.
The repository misses its strongest positioning fact: these gateways can sit next
to existing OAuth, TLS, API-key, database, and cloud controls and narrow one
effect.

**Required end state**

Publish a generated catalogue with one row per integration:

| Field | Required meaning |
| --- | --- |
| Status | `qualified`, `reference`, `experimental`, or `internal`; machine-sourced |
| Layer | profile/gateway, custody, evidence, resolver, enforcement, or demo |
| Existing system retained | e.g. Stripe credential and client remain application-owned |
| Exact effect | the operation/body/resource committed by Auths |
| Failure boundary | when provider credentials may be acquired and handler entered |
| Runtime needs | state store, resolver, KMS/HSM, network, TLS |
| Public package | exact package/import, or “not publicly packaged” |
| Runnable proof | one command and expected allowed/denied output |
| Evidence | conformance suite, fixture, limitations, supported versions |

Every directory README must answer “Can I use this outside this monorepo today?”
in its first paragraph. A `publish = false` crate must not be labelled installable.

**How to implement**

1. Add explicit integration metadata beside each `Cargo.toml`; do not derive
   qualification merely from the directory name or compilation success.
2. Generate `catalog.json` and the repository README. Validate every listed demo,
   profile ID, package coordinate, and evidence path.
3. Author one short README per crate with architecture boundary, minimal composition
   code, credential ownership, failure semantics, production requirements, and a
   link to a runnable demo. Generate repeated status fields from the catalogue.
4. Render `/integrations` with filters by existing system and maturity. Lead with
   MCP, then the currently qualified/reference effect verticals; put custody and
   evidence helpers in separate sections.
5. Add an “adopt alongside” diagram/text for each gateway. For example: OAuth or
   workload identity authenticates the process to GitHub; Auths determines whether
   this exact issue action may be released to that process-owned client.
6. Add a catalogue validation command to `cargo xtask product`.

**How to verify it worked**

```bash
cargo xtask product
test "$(find product/integrations -mindepth 2 -maxdepth 2 -name README.md | wc -l | tr -d ' ')" = "13"
npm --prefix ../auths-docs test
```

The generated catalogue must have exactly one entry per integration crate, reject
an install command for every `publish = false` entry, and resolve every runnable
proof. A first-time reader must be able to identify the MCP path, one existing
provider path, and whether each is public without opening Rust source.

**Blast radius**

Crate metadata, docs navigation/search, release qualification labels, demo links,
support policy, SBOM package descriptions, and future publication decisions must
stay consistent with the catalogue.

### AD-010 — Complete the unfamiliar-engineer recipe cohort before claiming time-to-value

- **Impact:** high — release decision-makers and every newcomer represented by current time-to-value claims
- **Area:** evidence
- **Estimated effort:** 1 engineering day plus time to recruit and run five sessions
- **Depends on:** AD-003
- **Files:** `auths-proof/bindings/recipes/experience-evidence.json:1-28`,
  `auths-proof/bindings/customer-journey-matrix-v1.json:1-513`,
  `auths-proof/bindings/typescript/sdk-capability.json:41-50`,
  `auths-proof/docs/product/COMPATIBILITY_AND_SUPPORT.md:3-8`, and
  `auths-proof/.github/workflows/sdk-recipes.yml:1-91`

**What a user hits today**

The SDK capability metadata calls time-to-value “verified,” and the automated
evidence records sub-second recipe execution. The human gate says:

```json
{
  "status": "awaiting-independent-cohort",
  "requiredCompletions": 4,
  "requiredCohort": 5,
  "maximumMinutes": 15,
  "participants": []
}
```

The compatibility page correctly lists `moderated-recipe-three-cohort` as a
stable-publication blocker. Automated runtime is not newcomer setup time; this
evaluation reproduced the difference.

**Why this costs adoption**

Release owners otherwise optimize for a green internal runner while unfamiliar
engineers spend time finding artifacts, interpreting `undefined`, or reading
source. The missing cohort is not cosmetic research: it is the only current gate
that measures the adoption question directly.

**Required end state**

Run recipe 3 with five people who have not worked on Auths and do not have an
Auths-prepared machine. Give each only the same public README/URL. Record, without
fabricating or smoothing:

- runtime, OS, language choice, and prior relevant experience category;
- wall time from first page to allowed outcome and deliberate denial;
- every command and verbatim failure;
- every source file or secondary page opened;
- whether the provider-call count stayed one; and
- completion/abandonment plus the first blocking step.

The gate passes only if at least four of five independently reach both outcomes in
15 minutes with no maintainer intervention. Publish anonymized aggregate timings
and failure categories; retain raw session evidence privately if it contains
identifying machine paths.

**How to implement**

1. Fix AD-003 and freeze one candidate tarball/wheel plus digest. Do not change the
   guide during the five measured sessions.
2. Write a facilitator script containing only start/stop criteria and allowed
   safety interventions. It must not teach Auths concepts or provide hidden setup.
3. Add an append-only cohort record schema with participant IDs, candidate digest,
   timestamps, outcomes, intervention count, and redacted transcript artifact
   digests.
4. Update the generator so `timeToValue` distinguishes
   `automated-execution-verified` from `unfamiliar-developer-verified`.
5. If the gate fails, rank the observed blockers, fix the highest-frequency first,
   cut a new candidate digest, and run a new cohort. Do not merge cohorts across
   changed instructions or artifacts.

**How to verify it worked**

```bash
cargo xtask sdk-experience
cargo xtask evolution-policy
```

The commands must reject empty participants, duplicate participants, a mismatched
candidate digest, missing denial, intervention-dependent completion, or fewer than
four sub-15-minute completions. The public evidence must report median/range only
from the completed, digest-matched cohort and retain the failure count. No adoption
number beyond this five-person test may be inferred.

**Blast radius**

Stable-publication policy, SDK capability scorecards, documentation claims,
release notes, customer-journey metadata, and any “five/ten/fifteen minute” copy
must derive from the same cohort status.

## Recommended execution order

1. **AD-003 — repair the recipe gate first.** It is a one-day fix to the canonical
   executable sources and makes all later quickstart, middleware, and cohort work
   measurable. Do not build a new guide on a failing runner.
2. **AD-006 — restore the reference binary and lite stack.** The one-line feature
   fix, missing trusted-context mount, and one-command setup are independent of
   public package authorization. They re-establish a deployable integration
   target for the SDK smoke tests.
3. **AD-005 — add the existing-server MCP wrapper.** This converts the real MCP
   semantics into the shortest useful integration and fixes the product boundary
   before documentation freezes it.
4. **AD-002 — generate the denial-first guide from the wrapper recipe.** Build it
   against candidate artifacts and keep it unpublished or clearly labelled until
   registry coordinates are truthful.
5. **AD-004 and AD-009 — change discovery after the canonical path is real.** Point
   the README and integration catalogue to one tested guide; do not create more
   competing entry points.
6. **AD-010 — run the unfamiliar-engineer cohort on the frozen candidate.** Feed
   only observed blockers back into steps 3-5. The cohort is part of release
   evidence, not a post-launch survey.
7. **AD-001 — publish atomically after all existing authorization gates pass.**
   Immediately run public-registry smokes, then switch docs from the pre-release
   warning to exact pinned install commands.
8. **AD-007 — promote the two-minute live story.** It depends on the same public
   middleware and guide, and it must be health-gated before receiving the primary
   CTA.
9. **AD-008 — publish the candidate-bound evidence index with the release.** The
   page can be built earlier, but its public status and artifact links must bind
   the actually published package set.

## The agent wedge

Auths is well aimed at the agent-authority problem semantically and poorly exposed
to agent builders operationally.

The strong part already exists. `auths.mcp/1` commits the exact service, tool name,
arguments, audience, and optional channel binding. It maps the official Rust MCP
request, rejects unsupported task/metadata extensions, releases a non-constructible
verified command, couples execution to one-use lifecycle state, and produces
receipts. The local TypeScript and Python RCs can run one allowed handler and deny
an undeclared tool before another handler call. This is materially more specific
than giving an agent a broad service token.

The missing part is the insertion point. Existing MCP operators have a server and
handlers; Auths currently asks them to construct an Auths provider. There is no
drop-in server middleware and no maintained integration with a named agent
framework. The public packages do not contain the RC at all. Consequently, the
path from “my agent uses MCP” to “this tool is protected” requires source reading
and an application rewrite.

The shortest concrete path is **TypeScript MCP server middleware**, not a bespoke
LangChain/CrewAI/OpenAI abstraction:

```text
existing agent
    → official MCP tools/call request
    → Auths secureMcpToolHandler
        → canonical auths.mcp/1 action
        → verify + atomic reserve
        → existing handler, using verified arguments
        → receipt / recovery reference
    → existing provider client and credential
```

MCP is the common low-level boundary that multiple agent frameworks can call. One
official-SDK wrapper lets those frameworks adopt Auths without Auths owning their
planning model, memory, authentication, or provider client. After the middleware
is stable, framework packages should be tiny recipes that configure it, not new
semantic implementations.

The credible path to framework-default authority is:

1. a public, versioned SDK with the middleware and a five-minute denial demo;
2. conformance proving one handler entry under replay/concurrency/mutation;
3. a no-Auths-server development composition and an explicit production port;
4. one framework-maintainer-quality example showing OAuth/API keys remain behind
   the handler; and
5. a stable error/receipt projection suitable for agent traces.

What stands in the way today is distribution, missing middleware, no unfamiliar
developer evidence, and incomplete production qualification—not MCP semantics.

## The two-minute demo

The most persuasive existing demonstration is the **cross-company incident
response** control room. It proves a problem OAuth scopes handle awkwardly:
separate organizations authorize an exact ordered plan without sharing an identity
provider or broad infrastructure credential; widened, replayed, compromised, and
ambiguous paths remain visible. On the assessment date, its UI and all three
service health endpoints responded successfully.

It is not the best first two minutes. Its seven-stage happy path, approval
ceremony, two transports, disclosure tiers, and attack lab are evidence after the
viewer understands the primitive. The smaller Live Lab would be closer, but its
backend DNS was absent while the UI remained public.

The single most persuasive two-minute sequence is therefore:

```text
Agent asks: publish_report weekly → board
Auths: authorized → handler count becomes 1 → signed receipt

Agent changes one field: destination = public
Auths: denied before handler → changed field highlighted → count remains 1

Agent replays the approved request
Auths: replay denied → count remains 1

Independent verifier: first receipt valid
```

Auths can show all underlying behaviors today in separate recipes and demos, but
cannot show this cohesive sequence through a healthy public two-minute path. AD-007
specifies the build. The success criterion is not visual polish: it is one real
provider entry, two real denials, and a real receipt, all bound to the displayed
release.

## Essential vs self-inflicted friction

| Friction | Essential or self-inflicted | Why |
| --- | --- | --- |
| Defining a canonical action profile | Essential | Exact authority needs a deterministic statement of the bytes/fields being authorized. A generic bearer token avoids this work by providing a weaker guarantee. |
| Selecting trusted identity evidence, anchors, time, audience, and verifier configuration | Essential | A proof cannot decide whom or what the application trusts. These are deployment decisions, though safe profiles can package defaults. |
| Durable replay/use reservation | Essential for one-use or budgeted effects | Stateless verification cannot by itself prove that an effect has not already consumed authority. |
| Closed gateway and outcome-unknown recovery | Essential for side effects | Authorization must cover the bytes actually executed, and an ambiguous provider response must not invite blind retry. |
| Production key custody and independent review | Essential for high-value deployment | Software fixture keys and author-controlled review cannot establish production assurance. |
| npm, PyPI, and crates.io serving predecessor `0.1.16` under advertised names | Self-inflicted | The intended RC works locally; the public coordinate and docs are out of sync. |
| A primary guide built around nonexistent REST APIs | Self-inflicted | The repository already has a qualified MCP profile and runnable recipe. |
| Positive-only Rust and MCP demos | Self-inflicted | Negative fixtures and denial semantics already exist; there is no user-facing switch. |
| Python handler arity and recipe import drift | Self-inflicted | Both failures are one-line documentation/source mismatches, not protocol complexity. |
| No recipe command and `undefined` runner error | Self-inflicted | The runner exists; discovery and process-error handling are missing. |
| Full observability/HSM topology on the first reference path | Self-inflicted | Those are legitimate operator concerns, but not prerequisites for proving one local exact effect. A lite evaluator can preserve semantics. |
| Missing KERI feature and trusted-context mount in the reference stack | Self-inflicted | These are build/composition defects. |
| No existing-MCP-server wrapper | Self-inflicted | Official MCP request mapping already exists; the high-level interception adapter does not. |
| Public Live Lab UI pointing at an unresolvable backend | Self-inflicted | Health gating can hide or repair a partially unavailable demo. |

### Where Auths is easier—and where it should not pretend to be

Auths is genuinely easier than composing OAuth scopes, short-lived tokens,
application idempotency, delegation attenuation, cross-organization approvals,
and audit receipts separately when the effect is destructive, agent-initiated,
cross-trust-domain, or expensive. The proof travels with the action, can be checked
offline, and expresses “this exact thing” rather than “this client has a broad
scope.” It can sit alongside an existing IdP and provider credential.

Auths is genuinely harder for an ordinary read endpoint inside one trust domain.
The application must define canonical action meaning, arrange issuance/trust,
reserve use, and operate a closed gateway. That cost is justified only when
widening, replay, confused-deputy behavior, or independent evidence matters. The
positioning should say this explicitly. “Use Auths for every authorization” is a
weaker claim than “use Auths at the few effect boundaries where an agent must not
inherit a broad credential.”

## What a buyer will ask for

Status here is about the checked-out repository and candidate record, not an
external certification claim.

| Artifact or answer | Status | Verified location / gap | What to do before a serious production evaluation |
| --- | --- | --- | --- |
| License and redistribution terms | **Exists** | `LICENSE-MIT`, `LICENSE-APACHE`, package manifests use `MIT OR Apache-2.0` | Include both licenses and notices in every released package/image and evidence index. |
| Vulnerability reporting | **Exists, limited** | `SECURITY.md` directs private GitHub Security Advisories and lists scope/limitations; it gives no response SLA | Publish supported-version policy and response expectations when support exists. |
| Threat model and trust boundary | **Exists** | `docs/threat-model.md`, product/reference threat models, explicit host responsibilities in `SECURITY.md` | Bind the reviewed threat-model digest to the candidate and link it from packages/docs. |
| Known limitations | **Exists** | `release/assurance/open-production-candidate-1/limitations.md` and reference runbook | Surface them on the public candidate page; keep evaluator sandbox limits distinct from production claims. |
| Deterministic conformance/formal evidence | **Exists in repository** | Canonical fixtures, Lean/Kani/Aeneas-related manifests and release gates are present | Provide retained, candidate-bound reports and independent-review interpretation, not only source generators. |
| SBOM | **Generator and schema exist; current production candidate not bound** | `xtask/src/release.rs` generates SPDX 2.3 and CycloneDX; release manifest requires SPDX. Candidate summary says no package set/evidence family is bound | Publish downloadable candidate SBOMs and verify subject coverage against every crate, wheel, tarball, WASM, and image. |
| Build provenance | **Exists for an exact preparation workflow; scope is limited** | `release/SLSA_BUILD_LEVEL_3_ASSESSMENT.md` records two GitHub attestations and a self-assessed SLSA 1.2 Build L3 result | Retain and expose attestations for the actually published candidate; keep “not a security audit” adjacent. |
| Reproducible/independent build | **Partly evidenced** | Two hosted preparations matched according to the SLSA assessment; both are within the project-controlled workflow/platform boundary | Give evaluators the offline verification command and retained bundles; distinguish independent reproduction from independent security review. |
| Immutable candidate binding | **Claimed process, currently missing result** | Candidate manifest status is `pending`; no image/package set bound | Bind exact package/image/config/schema/source/semantic digests before pilot approval. |
| Independent security review | **Explicitly missing** | Candidate status `pending`; `SECURITY.md` says none completed | Commission review over the scope already enumerated at manifest lines 25-32, publish scope, report or attestation, findings status, and candidate digest. |
| Sustained qualification | **Explicitly missing** | `0 of 2,592,000 seconds` | Run and retain the candidate-bound 30-day program across the supported runtime/profile matrix. |
| Required evidence families | **Explicitly missing** | `0 of 7`, empty `testEvidence` | Populate only through the executable assurance recorder and retained artifacts. |
| Signed production statement | **Absent** | Candidate `statement` is null | Sign only after the existing verifier passes all required gates. |
| Package/runtime support matrix | **Declared and CI-configured; not independently verified here** | Python workflow spans Linux/macOS/Windows and CPython 3.9-3.14; local checkout held only a macOS arm64 wheel | Retain per-platform installed-wheel results for the candidate and link them from `/security`. |
| Compatibility and retirement | **Policy exists; stable publication blocked** | `docs/product/COMPATIBILITY_AND_SUPPORT.md` records 12-month/90-day targets and blockers | Attach the policy to the released major and name who provides maintenance. |
| Deployment/runbooks | **Substantial but reference path currently broken** | TLS, rotation, restore, privacy, rolling restart, and provider-unknown runbooks exist; first Compose build failed | Complete AD-006 and give an immutable known-good deployment digest. |
| Operational telemetry/privacy | **Design and runbooks exist** | Reference includes OTLP/Prometheus/Grafana and a privacy-audit runbook | Provide example redacted events, retention assumptions, and tested no-secret/no-payload assertions for the candidate. |
| Support owner, SLA, incident communications | **Absent for the open candidate** | Business plans discuss future support; no enforceable public SLA or named support channel was found | State community-only support honestly, or publish contractual terms/contact/escalation for paid pilots. |
| Compliance certifications, pen-test letter, SOC 2/ISO evidence | **Absent; not claimed** | No such completed artifact was found | Do not imply certification. Supply only if a target buyer requires it and after independent completion. |
| Data processing/subprocessor answer | **Not packaged as a buyer artifact** | The core is offline and the reference is self-operated; public demos use hosted services | Publish a deployment/data-flow statement separating offline SDK, operator runtime, docs telemetry, and hosted-demo data. |

The evidence posture is better than the adoption surface suggests: the project is
careful not to overclaim. The immediate buyer task is not to manufacture badges;
it is to bind, retain, index, and expose what exists while keeping the missing
independent review and qualification impossible to miss.

## Coverage statement

### Executed

- Read the repository instructions, root README, language READMEs, package
  manifests/capability files, public naming policy, recipe sources/runner/evidence,
  primary docs-site pages and tests, MCP profile/demo source, integration manifests,
  reference deployment/config/tests/runbooks, live-demo plans, security policy,
  threat/evidence summaries, release workflows, and compatibility policy.
- Timed the checkout Rust offline positive example and a temporary external Rust
  negative-fixture consumer.
- In clean temporary environments, installed the public npm, PyPI, and crates.io
  coordinates after registry access was allowed; recorded the actual `0.1.16`
  artifacts and reproduced their import/compile failures against current docs.
- Installed the local `1.0.0-rc.1` npm tarball and macOS arm64 Python wheel; ran
  allowed and deliberate denied MCP calls with provider counters.
- Ran TypeScript recipe 3 and the cross-language recipe runner far enough to
  reproduce both its relative-interpreter diagnostic and Python recipe 3 import
  failure.
- Built and tested the docs site: all three rendered-page tests passed.
- Built and ran the Rust MCP memory demo successfully.
- Attempted the README's identity workbench command; stopped after repeated local
  Cargo build-lock contention before the server started. This was local concurrent
  build interference, not classified as a product failure.
- Started Docker Desktop, followed the open-production reference path with a
  disposable seed, pulled/built the stack, and captured the `auths-node` compile
  failure. Inspected the unmounted trusted-context path that would block the next
  stage. Confirmed the failed Compose project left no containers.
- Checked public-demo reachability on 15 August 2026: incident UI and three service
  health endpoints returned 200; Live Lab UI returned 200 and its configured
  backend failed DNS resolution.

### Not executed or not established

- I did not run all roughly 25 demo directories or `cargo xtask demos`. The MCP
  demo ran; the reference deployment failed; incident-demo service health was
  checked, but its complete OIDC/PKCE browser ceremony and attack lab were not
  replayed locally.
- I did not complete the identity/Iroh browser workbench, the full Rust validation
  suite, fuzzing, formal proofs, release check, long benchmarks, or 30-day
  qualification. Existing evidence was inspected, not re-derived.
- I tested one platform: macOS arm64 with Node 22.23.1 and CPython 3.10.7. I did
  not execute Linux, Windows, browser-engine, Node 20, or CPython 3.9/3.11-3.14
  package matrices. I inspected the npm runtime/declaration export pairs but did
  not run every public type through an external-project compiler. CI configuration
  is not reported as a local pass.
- I did not query GitHub check history or independently verify the hosted SLSA
  attestations. The assessment's exact scope and caveats are reported from the
  checked-in evidence.
- I did not commission or simulate user research. The repository's five-person
  cohort remains empty; this document's timings are one evaluator, not adoption
  statistics.
- The product working tree was already dirty, including fixture, Stripe, lifecycle,
  and xtask changes, and the docs tree had an untracked TypeScript build-info file.
  I did not clean, revert, or commit them. Runtime findings apply to the checked-out
  bytes, not a claimed clean release candidate.
- Restricted-network `ENOTFOUND`/DNS errors from initial registry attempts were
  retried with network access and are labelled environment limitations. The public
  Live Lab backend DNS failure reproduced with unrestricted access and is reported
  as deployment state.

No shipping code was changed to obtain these results. Temporary consumer programs
and generated recipe JavaScript were used only for evaluation and were not
committed.
