# Auths SDK product surface and Python Full Workflow parity

**Status:** EPM product-surface assessment and delivery recommendation
**Snapshot:** `main` at `c47af745` on 2026-08-10
**Decision:** Python is a target **Full Workflow SDK**, not a verifier-only binding
**Primary references:** [AP-SPEC-027](../specs/0027-product-grade-typescript-sdk.md), [AP-SPEC-035](../specs/0035-python-full-workflow-sdk.md), [AP-SPEC-036](../specs/0036_sdk_ergonomics.md), [AP-SPEC-037](../specs/0037_sdk_ergonomics_2.md), [issue 72](https://github.com/auths-dev/auths-proof/issues/72), and [issue 73](https://github.com/auths-dev/auths-proof/issues/73)

## 1. Executive summary

Auths has three different language-product states today:

| Surface | Functional product state | Release-claim state | EPM assessment |
| --- | --- | --- | --- |
| Rust core and SDK ecosystem | Semantic reference and complete building blocks | Release candidate; exact claims remain gate-controlled | The source of truth and capability ceiling |
| TypeScript SDK | Repository-local Full Workflow implementation exists | Still labeled Verifier Binding in capability metadata; promotion and publication remain blocked | Functionally close to the intended V1 SDK; remaining work is mainly release reconciliation, evidence, and breadth |
| Python SDK | Deterministic three-input verifier only | Correctly limited to verifier behavior | Far from Full Workflow; requires a native-boundary and workflow product build, not a wrapper-only enhancement |

The most important planning conclusion is:

> Python should reuse the Rust semantic owners and reproduce the TypeScript product contract idiomatically. It should not reproduce TypeScript implementation details or implement Auths semantics in Python.

The desired Python experience is:

```text
create/load principal
  -> attach agent to signed root authority
  -> delegate strictly narrower authority
  -> construct an exact profile-owned action
  -> approve and sign through external providers
  -> assemble proof and trusted context in Rust
  -> verify locally
  -> authorized | denied | indeterminate
  -> hand a native-sealed profile command to a closed gateway
```

Today Python implements only the `verify locally` and result-projection portion of that path.

## 2. Product vocabulary

This assessment uses the cross-language tiers defined by AP-SPEC-027 and issue 72.

| Tier | Customer can do | Customer must not have to do |
| --- | --- | --- |
| Verifier Binding | Submit proof, canonical action, and trusted-context bytes; receive one of three verdicts | Reimplement verification semantics |
| Authoring SDK | Create principals, grants, delegations, actions, status objects, signing requests, and trusted contexts | Hand-author protocol CBOR, signing preimages, or attenuation rules |
| Full Workflow SDK | Attach, delegate, authorize, explain, and pass a sealed profile command to a closed gateway | Assemble protocol objects or create effect-capable commands from unverified data |

“Full Workflow” is a product capability claim, not merely an API-shape claim. A language does not reach the tier until its normal installed-package path crosses the supported Rust semantics and only successful native verification can release a gateway-accepted command.

## 3. How to read the Rust comparison

Rust is not one monolithic SDK with every workflow behind one client class. Its product surface is deliberately split across small semantic crates, the integrated `auths-sdk` facade, profile packages, and optional runtime packages.

Therefore, “compared with Rust” means compared with the supported Rust capability system—not that TypeScript and Python need one-for-one copies of every Rust type.

This distinction matters because TypeScript is already more cohesive at the application-workflow layer: it has the `loadAuths -> attachAgent -> delegate -> authorize` facade that the Rust `auths-sdk` crate itself does not expose as one equivalent object graph. Rust owns the semantics and primitives; TypeScript currently owns the most polished integrated developer journey.

## 4. Cross-language capability map

Legend:

- **Complete:** supported by the current public product surface.
- **Partial:** meaningful support exists, but not the full reference capability.
- **Missing:** no supported public path exists.
- **Unsafe for effects:** data may be useful for inspection, but it cannot safely authorize a gateway effect.

| Product capability | Rust core/SDK ecosystem | TypeScript SDK | Python SDK | Importance for Python Full Workflow |
| --- | --- | --- | --- | --- |
| Deterministic local verification | Complete | Complete | Complete | Already present |
| Three distinct verdicts | Complete | Complete | Complete | Already present |
| Stable stages, codes, commitments, and metrics | Complete | Complete | Complete | Already present |
| Neutral identity representation and validation | Complete | Partial: packaged raw-key identity path | Missing | Medium for the first authority workflow; high for full layered adoption |
| Signed-message authentication independent of authority | Complete | Partial: Ed25519 raw-key adapter | Missing | Medium; not required to ship the first MCP authority vertical |
| Provider-neutral principal/signer boundary | Complete | Complete | Missing | **Blocker** |
| Transaction-bound signing requests | Complete | Complete | Missing | **Blocker** |
| Root authority preparation/loading | Complete building blocks | Complete for signed sources and self-contained raw-key bootstrap | Missing | **Blocker** |
| Trusted-context construction/loading | Complete | Complete loading and raw-key bootstrap; narrower than Rust's generic composition | Missing | **Blocker** |
| Attach an agent to exact signed authority | Building blocks; no equivalent single high-level facade | Complete | Missing | **Blocker** |
| Strictly non-widening child delegation | Complete | Complete | Missing | **Blocker** |
| Authority diff and over-granting warnings | Complete | Complete | Missing | **Blocker** for safe delegation UX |
| Approval-policy commitment and provider orchestration | Semantic commitments and composition primitives | Complete | Missing | **Blocker** for the promised workflow |
| Profile-owned action construction | Complete, broad profile set | Complete for MCP and application-defined profiles | Missing | **Blocker** |
| Proof and request-context assembly | Complete | Complete through packaged Rust/WASM | Missing | **Blocker** |
| Profile-owned command decoding | Complete | Complete | Missing | **Blocker** |
| Non-forgeable gateway command | Complete native type | Complete package-owned sealed path | Unsafe for effects | **Blocker and first security dependency** |
| Ordered multi-action plan authorization | Complete primitives and profile commitments | Complete ordered profile plans | Missing | High for TypeScript feature parity; can follow the first single-action vertical |
| General all-of, any-of, and threshold proof plans | Complete | Not exposed as the same general public authoring surface | Missing | Medium; not required for first Full Workflow vertical |
| Principal/grant status authoring and lifecycle inputs | Complete | Native ABI support exists, but public workflow coverage is narrower | Missing | High before production lifecycle claims; not the first vertical blocker |
| Deterministic cleanup and ephemeral-signer lifecycle | Rust ownership/RAII | Complete explicit async disposal | Missing | **Blocker** for async provider safety |
| Advanced raw verification and bounded inspection | Complete | Complete under `advanced` | Partial: raw verification plus decoded result | High, but should be delivered after the safe normal path is established |
| Custom profile development and conformance | Complete | Complete application profile kit and testkit | Missing | High for SDK extensibility; not required for first MCP vertical |
| Receipts, replay, budgets, lifecycle stores, and effect runtimes | Available in optional Rust product packages | Command handoff exists; operational runtime remains external | Missing | Not a base-SDK parity blocker; integrate through explicit ports later |
| Production custody/provider adapters | Rust ports and selected product integrations | Intentionally not bundled in the base SDK | Intentionally absent | Ecosystem work, not a Full Workflow SDK blocker |
| Installed artifact and cross-platform evidence | Rust release machinery exists | Strong packed Node/browser evidence; promotion gates remain | Wheels exist for verifier only | **Blocker** for shipping the Python claim after implementation |

## 5. Rust core and SDK product surface

### 5.1 What Rust supports

Rust is the semantic owner and supports the full mechanism needed by every language SDK.

#### Identity and authentication

- Bounded, method- and suite-labelled identity descriptors.
- Distinct decoded, validated, and authenticated identity states.
- Simple raw keys plus composite, rotating, or resolver-shaped verification relationships.
- Neutral identity-method and signature-verifier ports.
- Canonical identity packets and signed application-message preimages.
- Raw-key and Ed25519 reference adapters.
- An explicit, optional validated-identity-to-authority bridge.

#### Authority authoring

- Canonical principals, grants, permissions, resources, audiences, validity windows, budgets, status policies, assurance floors, critical extensions, and delegation depth.
- Root and child grant construction through typed Rust objects.
- Child-grant planning that derives issuer and parent linkage and rejects widening before signing.
- Semantic authority diffs and over-granting warnings.
- General proof composition through all-of, any-of, and threshold plans.
- Canonical approval-policy and exact-plan commitments.

#### Signing and custody

- Exact, domain-separated signing preimages for grants, actions, principal status, and grant status.
- Transaction-bound external signing requests.
- A provider-neutral custody trait for WebAuthn, workload, KMS, HSM, and PKCS#11 families.
- Response validation that prevents a provider result from being substituted across transactions.
- No requirement that Auths own or receive private keys.

#### Trusted verification

- Immutable trusted-context construction with explicit roots, registries, status snapshots, assurance policy, limits, supported methods, suites, profiles, and critical extensions.
- Explicit per-request audience, replay challenge, and evaluation time.
- Raw-key, `did:key`, and `did:keri` reference principal verification in the self-contained verifier.
- Ed25519 and P-256 verification suites in the integrated verifier.
- Deterministic, effect-free verification with authorized, denied, and indeterminate outcomes.
- Stable explanations, codes, stages, configuration commitments, and work metrics.

#### Profiles and enforcement

- A neutral `ActionProfile` contract for canonicalization, authority projection, review display, and verified-command decoding.
- MCP plus HTTP, Git, deployment, supply-chain, and edge profile families, with additional domain integrations elsewhere in the product tree.
- A native `VerifiedAction` constructible only by successful verification.
- Profile-decoded commands that can enter a closed executor boundary.
- Optional enforcement, replay, budget, receipt, lifecycle, evidence, and operational packages.

### 5.2 What Rust does not currently optimize

Rust does not provide the exact same high-level application facade as TypeScript. A Rust adopter composes `auths-sdk`, `auths-author`, custody, profiles, and optional runtime packages rather than calling a single `attach_agent` client workflow.

This is primarily an ergonomics difference, not a missing semantic capability. It should not force Python to copy Rust's crate-level composition. Python should follow the proven Full Workflow product journey while delegating each semantic operation to its Rust owner.

## 6. TypeScript SDK product surface

### 6.1 What TypeScript supports now

The repository-local TypeScript implementation supports the normal Full Workflow journey:

- Package-owned Rust/WASM loading in Node and supported browsers.
- A separate identity-only entry point with decoded, validated, and authenticated states.
- Raw-key identity creation and Ed25519 signed-message authentication.
- Provider-neutral `Signer`, approval, signed-grant, and trusted-context ports.
- Self-contained raw-key authority preparation without application-authored grant or context CBOR.
- `loadAuths`, `attachAgent`, narrower `delegate`, `authorize`, and `authorizePlan` workflows.
- Native Rust-owned attenuation checks, authority diffs, and over-granting warnings.
- Typed MCP actions and commands.
- An application profile kit that preserves profile ownership rather than introducing a generic executor.
- Exact ordered action-plan commitments and bounded plan-once approval reuse.
- Authorized, denied, and indeterminate results with stable native details.
- Package-owned command minting and hostile non-forgeability tests.
- Deterministic disposal and explicit ephemeral-signer lifetimes.
- An advanced raw verifier and bounded decision inspection surface.
- Separate development-only signers, approval fixtures, and profile conformance tools.
- Packed-package Node, browser, example, API-snapshot, and external-consumer tests.

### 6.2 What TypeScript is missing compared with Rust

| Gap | Impact | Priority | EPM interpretation |
| --- | --- | --- | --- |
| Capability metadata still says `verifier-binding` and excludes Full Workflow while the implementation and README describe the workflow | Customers and release automation receive contradictory product claims | **Release blocker** | Reconcile only after exact required CI/review evidence; do not solve by changing copy alone |
| Full generic Rust trust-context and adapter composition is not exposed as an equally broad typed TypeScript builder | Non-raw-key and deployment-specific trust integrations require provider-supplied native context | High for ecosystem breadth; not a first MCP V1 blocker | Add ports/fixtures based on real integrations rather than exposing protocol constructors |
| Identity helper coverage is narrower than the Rust port model | Packaged convenience proves raw-key plus Ed25519, not every key, suite, resolver, or composite method | Medium | Correct architectural choice: Auths owns the port and conformance, not every adapter |
| Built-in profile coverage is much narrower than Rust | MCP and application-defined profiles work; Rust has more maintained domain packages | Medium | Expand only behind validated V1 workflows; profile breadth is not core SDK completeness |
| Public lifecycle/status authoring is narrower than Rust's primitives | Applications can consume trusted inputs but do not get the entire native status-authoring surface as a polished workflow | High before production lifecycle/revocation claims | Follow a specific lifecycle product use case |
| Public plan authoring is an ordered profile plan, not Rust's complete general proof-composition API | Advanced all-of/any-of/threshold compositions are not equally ergonomic | Medium | Not required for the first attach/delegate/authorize promise |
| Receipts, replay, durable budgets, and provider effects are not base-SDK workflows | TypeScript hands off a sealed command but does not own operational execution | Intentional | Keep these behind explicit gateways and runtime integrations |
| No bundled production custody provider | A customer must implement or select a signer adapter | Intentional but commercially important | Auths should supply conformance and a small number of reference integrations, not own every adapter |
| Publication and independent-review gates remain open | The implementation cannot yet be promoted as reviewed or generally released Full Workflow | **Release blocker** | Functional readiness and claim readiness must remain separate |

### 6.3 TypeScript assessment

TypeScript is not materially missing the core Full Workflow mechanics. It is the current ergonomic reference for Python.

The most important TypeScript follow-up is to reconcile issue state, `sdk-capability.json`, documentation, exact-platform CI evidence, and release claims. The next most important product work is validating whether real users need broader trust-context, lifecycle, or profile support—not automatically matching every Rust crate.

## 7. Python SDK product surface

### 7.1 What Python supports now

The installed `auths` package currently provides:

- A Maturin/PyO3 native extension using the stable `abi3-py39` floor.
- One synchronous, deterministic, effect-free operation:
  `verify(proof_cbor, canonical_action_cbor, trusted_context_cbor)`.
- The canonical Rust self-contained V1 verifier rather than a Python rewrite.
- Authorized, denied, and indeterminate result dataclasses.
- Stable result code, verification stage, safe explanation, work metrics, required configuration, local configuration, and canonical result CBOR.
- Bounded canonical result decoding with version, shape, depth, and trailing-data rejection.
- Inline type information and `py.typed`.
- Native wheels as the intended distribution shape, so consumers do not need Rust or C to run verification.

This is a useful Verifier Binding. It is not an Authoring SDK or a Full Workflow SDK.

### 7.2 Critical current security limitation

Python's `VerifiedAction` is protected by an accessible module-level sentinel:

```python
_AUTHORIZED_TOKEN = object()
```

Application code can import or inspect that sentinel and construct a `VerifiedAction` around arbitrary bytes. The current object is therefore useful as an authorized-result data wrapper, but it is **not a non-forgeable capability** and must not be accepted by a protected gateway.

This is the first implementation dependency because building `attach_agent`, delegation, and profile facades on top of the current object would create a workflow that looks complete but has a bypass at its most important boundary.

### 7.3 What Python is missing compared with Rust

| Missing Python capability | Customer consequence | Importance |
| --- | --- | --- |
| Native-only authorized action and profile-command handles | Python code can forge the object that a gateway might trust | **P0 — security and Full Workflow blocker** |
| Native authoring ABI for principals, grants, status, trusted context, and exact signing requests | Applications would have to recreate protocol semantics or cannot author at all | **P0 — Full Workflow blocker** |
| Provider-neutral async signer protocol | No safe way to create/load an agent or sign grants/actions without exporting keys | **P0 — Full Workflow blocker** |
| Approval provider and committed policy execution | No safe supervised, headless, risk-based, every-action, or plan-once workflow | **P0 — Full Workflow blocker** |
| Trusted-authority and trusted-context source APIs | No supported normal path for roots, registries, status, assurance, and limits | **P0 — Full Workflow blocker** |
| `AuthsClient` and `attach_agent` | Python cannot begin the normal product journey | **P0 — Full Workflow blocker** |
| Root grant preparation/loading and effective-authority summary | Python cannot attach exact authority without raw CBOR | **P0 — Full Workflow blocker** |
| Narrower child delegation with diffs and warnings | Python cannot express the flagship Auths value proposition | **P0 — Full Workflow blocker** |
| Profile-owned MCP action construction | Python cannot bind authority to an exact application action safely | **P0 — first vertical blocker** |
| Native proof/context assembly | Python callers must supply the three protocol byte strings themselves | **P0 — Full Workflow blocker** |
| `authorize` returning a sealed MCP command | Python cannot safely cross from verification to an effect gateway | **P0 — Full Workflow blocker** |
| Async cancellation and deterministic signer/agent cleanup | Provider calls can leave partial or reusable security state | **P0 — workflow safety blocker** |
| Ordered multi-action plans and plan-once approval | Python cannot match the TypeScript reference workflow for compound actions | **P1 — feature-parity blocker, after single-action vertical** |
| Advanced API separation and bounded inspection | Raw bytes and effect-capable objects cannot be kept in visibly different product surfaces | **P1** |
| Mypy and Pyright misuse fixtures | Python users cannot rely on types to distinguish verdicts and profile commands | **P1** |
| Identity-only and authenticated-message surface | Python cannot participate in the lower, independently adoptable identity layers | **P2 for first authority vertical; P1 for complete layered parity** |
| Application profile kit and conformance tooling | Customers cannot add their own closed action vocabulary without bespoke native work | **P1 for extensibility** |
| Clean-wheel Full Workflow tests across CPython, macOS, Linux, and Windows | A source-tree success cannot become a supportable SDK claim | **P0 release blocker after implementation** |
| Cross-language Full Workflow fixtures | Drift can exist above the raw verifier even when verdict fixtures agree | **P0 release blocker** |

### 7.4 Python assessment

Python currently covers roughly the last third of the internal authorization pipeline but only the first product tier. It can evaluate already-assembled inputs; it cannot safely create those inputs or release a protected effect.

The missing work is substantial but bounded. Most semantic machinery already exists in Rust, and TypeScript has already tested the product vocabulary. The Python program is primarily:

1. exposing the existing Rust operations through a safe native ABI;
2. designing an idiomatic asynchronous Python workflow around them;
3. enforcing native capability ownership at the gateway boundary; and
4. producing wheel, typing, adversarial, and cross-language evidence.

It should not require new protocol semantics.

## 8. Recommended Python delivery sequence

The existing AP-SPEC-035 nine-unit plan is directionally correct. From an EPM perspective, it should be managed as four customer-visible milestones.

### Milestone A — Establish a safe native waist

Includes AP35-PR1 through AP35-PR3.

Deliver:

- Freeze the Python API, threat model, supported runtimes, and exact exclusions.
- Replace the sentinel-protected `VerifiedAction` with an opaque native type or native-owned handle.
- Bind the Rust authoring, trusted-context, status, plan, profile, and signing-request operations required by the workflow.
- Establish ABI versioning and Python/Rust/TypeScript differential fixtures.

Exit outcome:

> Python can call every required semantic operation without implementing Auths meaning in Python, and arbitrary Python code cannot mint an effect-capable authorization object.

This milestone is the hard dependency for every later workflow API.

### Milestone B — Make agent attachment and delegation real

Includes AP35-PR4 through AP35-PR6.

Deliver:

- Async signer and approval `Protocol` interfaces.
- Exact request/response binding, typed provider failures, cancellation, and cleanup.
- `AuthsClient`, trusted-authority loading, `attach_agent`, and root-authority summaries.
- `delegate` with Rust-owned attenuation, semantic diff, warnings, approval, and signing.

Exit outcome:

> A Python application can attach an agent and delegate narrower authority without handling protocol bytes or private keys.

### Milestone C — Close the first end-to-end MCP vertical

Includes AP35-PR7 and the minimum normal-path portion of AP35-PR8.

Deliver:

- An MCP profile facade with exact action construction.
- Native proof and trusted-context assembly.
- Local three-valued authorization.
- Native profile-command decoding.
- A closed MCP gateway contract that accepts only the native-sealed command.
- Safe explanations and normal/advanced API separation.

Exit outcome:

> From an installed development wheel, Python can attach, delegate, authorize one MCP tool call, reject an unauthorized call with zero gateway effect, and execute only the successful native-sealed command.

At this point Python has the minimum functional Full Workflow vertical, but it should not yet receive the release claim.

### Milestone D — Reach feature and release parity

Includes ordered plans, the remainder of AP35-PR8, and AP35-PR9.

Deliver:

- Ordered multi-action plans and exact plan-once approval.
- Complete result inspection and advanced raw verifier support.
- Mypy and Pyright consumer contracts.
- Application profile-kit and conformance path, or an explicit documented deferral.
- Shared Rust/TypeScript/Python workflow fixtures.
- Adversarial native-handle, provider, cancellation, widening, and mutation suites.
- Isolated installed-wheel workflows on the supported CPython and OS matrix.
- Package-content, architecture, compliance, SBOM, provenance, API, and documentation gates.
- Capability metadata promotion only after the evidence passes.

Exit outcome:

> Python can be truthfully labeled and shipped as a Full Workflow SDK with the same semantic contract as TypeScript.

## 9. Recommended priority and dependency order

| Order | Workstream | Why now |
| ---: | --- | --- |
| 1 | Reconcile AP-SPEC-035's entry-gate policy | The current specification says implementation is blocked on independent review. If repository-local pre-review implementation is now authorized, record the same bounded claim model used for TypeScript before coding begins. |
| 2 | Fix issue 73 with a native non-forgeable design | Every effect-capable Python workflow depends on this boundary. |
| 3 | Expose the Rust authoring and trusted-input ABI | This removes the temptation to implement protocol meaning in Python. |
| 4 | Build async provider protocols and lifecycle | Attachment and delegation need safe external signing and approval. |
| 5 | Implement attach and root authority | First recognizable SDK activation step. |
| 6 | Implement narrower delegation | The central Auths product value. |
| 7 | Implement MCP authorize and sealed gateway command | First complete customer-visible vertical. |
| 8 | Add ordered plans, advanced inspection, and profile extensibility | Brings Python toward TypeScript product parity. |
| 9 | Close wheel, type, platform, and cross-language evidence | Converts repository code into a supportable SDK claim. |
| 10 | Promote capability metadata after the gate | Claims must follow evidence, never precede it. |

## 10. Full Workflow definition of done for Python

Python is complete only when an external consumer, using an installed wheel and no Auths source checkout, can:

1. Configure an external signer and approval provider without exporting a private key.
2. Load or prepare exact trusted authority without authoring protocol CBOR.
3. Attach an agent to a signed root grant.
4. Delegate a child that Rust proves is no wider in every authority dimension.
5. Construct an exact MCP action through the profile API.
6. Receive authorized, denied, or indeterminate without collapsing outcomes.
7. Pass only the authorized native profile command to a matching closed gateway.
8. Demonstrate that forged, copied, pickled, reflected, mutated, substituted, denied, and indeterminate objects cannot reach the gateway.
9. Dispose ephemeral signers and partial workflow state on success, failure, timeout, and cancellation.
10. Produce the same semantic projection as Rust and TypeScript for shared workflow fixtures.
11. Run from the exact supported wheel matrix without Rust installed.
12. Pass architecture, API, compliance, semantic-freeze, SBOM, provenance, and authoritative CI gates on the same revision.

## 11. Explicit non-goals

Python Full Workflow parity does not require Auths to:

- rewrite Rust canonicalization, attenuation, verification, or profile semantics in Python;
- bundle private keys or a development signer into the production import root;
- own every KMS, HSM, wallet, key, identity, or transport adapter;
- expose every Rust profile before the first MCP vertical works;
- make approval or capabilities mandatory for identity-only users;
- execute arbitrary provider operations automatically after authorization;
- build a generic operation-tag executor;
- require an Auths-hosted service;
- claim exactly-once external effects; or
- claim stable V1, production readiness, or independent review merely because the workflow compiles.

## 12. EPM recommendation

Treat TypeScript as the **ergonomic reference**, Rust as the **semantic reference**, and Python as the next **full product implementation**.

Do not plan Python as a parity checklist against every Rust crate. Plan it around one complete customer journey, then expand breadth:

```text
P0: safe native command
  -> native authoring/trust ABI
  -> async signer and approval ports
  -> attach
  -> delegate narrower
  -> authorize one MCP action
  -> closed gateway

P1: ordered plans + inspection + custom profiles + lifecycle ergonomics

P2: broader identity, suite, profile, custody, and transport adapters driven by adoption
```

The first Python milestone is successful when it proves the security boundary. The program is successful when a normal Python developer can use that boundary without knowing it exists.
