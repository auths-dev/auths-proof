# AP-SPEC-029: Human approval and platform custody

**Status:** Specified as an umbrella contract — provider-neutral Phase 10 work
is blocked on AP-SPEC-033; deployable custody and packaging are Phase 11 work

**Governs:** Provider-neutral approval and custody contracts in Phase 10 and
deployable custody work within Phase 11 of the
[Post-Milestone 6 Productization and Release Plan](../target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md)

**Source strategy:** [Auths Product and Go-to-Market Strategy](../plans/GO_TO_MARKET_STRATEGY.md)

**Aligned with:** [Post-Milestone-6 Technical and Go-to-Market
Alignment](../plans/POST_MILESTONE_6_TECHNICAL_AND_GO_TO_MARKET_ALIGNMENT.md)

**Depends on:** AP-SPEC-032, AP-SPEC-033, AP-SPEC-027, `auths-author`, and
`auths-custody`; integration into the MCP reference vertical also depends on
AP-SPEC-028; deployable providers depend on the applicable Phase 11 runtime,
recovery, packaging, and security-assessment gates

**Scope:** An umbrella for platform-neutral approval and signer contracts,
committed supervision policy, deterministic fake providers, a macOS Secure
Enclave and user-presence reference provider, an explicit software fallback,
a headless signer path, platform packaging, and approval records bound to exact
Auths objects

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 1. Decision

Auths will separate three concepts:

1. **Identity evidence** says how control of a principal is established.
2. **Custody** controls how a private key is stored and used.
3. **Approval** determines when a human or host policy permits an otherwise
   valid signing or execution request to proceed.

Touch ID is an approval mechanism for use of a protected key. A fingerprint is
not an Auths identity and is never key material.

The first interactive provider will use a macOS Secure Enclave P-256 key where
available. Named parent agents use durable keys by default. Child or
task-specific agents use short-lived or ephemeral signers by default.

All contracts remain platform-neutral. Native macOS, Linux, and Windows SDK
consumers, headless CI, on-premises deployments, HSMs, KMSs, WebAuthn, and
future operating-system providers MUST be possible without changing authority
or profile semantics. The first release does not require identical
hardware-backed custody on every operating system.

### 1.1 Phase and change boundaries

This specification is not one implementation unit.

Phase 10 may implement only:

- provider-neutral approval, policy-commitment, record, and custody contracts;
- pure approval-requirement evaluation;
- deterministic fake approval and custody providers;
- adversarial contract and transaction-binding tests; and
- integration into the local, reversible AP-SPEC-028 reference application.

The macOS helper protocol, Secure Enclave provider, encrypted software
fallback, deployable headless provider, native packaging, key recovery and
rotation, and platform security assessment belong to Phase 11. They MUST NOT
be represented as Phase 10 developer-preview evidence.

Any provider used during Phase 9 or Phase 10 is limited by AP-SPEC-033's
restricted-preview effect boundary.

## 2. Product claim

The bounded claim is:

> A human can approve issuance or use of an exact Auths authority object, the
> selected custody provider can sign it without exporting a protected private
> key, and the resulting approval is bound to that exact transaction.

This stage does not claim:

- that a biometric identifies a legal person;
- that macOS biometric enrollment is an Auths trust root;
- that software fallback is hardware-backed;
- that every operating system offers equivalent protection;
- that approval expands authority;
- that a successful prompt proves the external action succeeded.

## 3. Goals

Across its separately gated Phase 10 and Phase 11 work, this specification MUST
provide:

- one platform-neutral `ApprovalProvider` contract;
- one platform-neutral external signer/custody contract aligned with
  `auths-custody`;
- explicit provider capability discovery before custody selection;
- exact approval requests for grant issuance, delegation, and action use;
- configurable `grant-only`, `risk-based`, `every-action`, and `custom` modes;
- a macOS reference provider using Secure Enclave P-256 and user presence;
- a Keychain-backed or passphrase-protected software-key fallback;
- one headless provider contract and reference integration tested on macOS,
  Linux, and native Windows;
- durable parent and ephemeral child lifecycle support;
- explicit cancellation, unavailable, rejected, and transaction-mismatch
  outcomes;
- signed or otherwise tamper-evident approval records;
- tests proving identity adapters remain independent of custody providers.

## 4. Non-goals

Conforming work under this specification MUST NOT:

- couple Auths to KERI, `did:key`, WebAuthn, or any single identity method;
- store a fingerprint, biometric template, or biometric result;
- claim Touch ID is multifactor authentication without a separately specified
  factor model;
- expose general-purpose signing from an Auths custody provider;
- pass arbitrary bytes or user-supplied signature descriptors to a protected
  key;
- put platform I/O in `core/`;
- make desktop UI dependencies part of headless builds;
- make the portable SDK depend on any platform-specific native helper;
- read production passphrases from environment variables or command-line
  arguments;
- silently fall back from hardware to software custody;
- convert user cancellation into authorization denial;
- build a general CLI.

## 5. Approval experience

### 5.1 Grant approval

The macOS approval sheet SHOULD present the authority a human is actually
granting:

```text
+--------------------------------------------------------------+
| Auths · Approve agent authority                              |
+--------------------------------------------------------------+
| Agent       research-agent                                   |
| May         call records/update_demo_record                  |
| Resource    configured demo record                           |
| Audience    mcp://records                                    |
| Valid       10 minutes                                       |
| Delegation  may create one child with less authority         |
| Supervision grant-only                                       |
+--------------------------------------------------------------+
| Transaction  7b3d...                                         |
| [Cancel]                         [Approve with Touch ID]       |
+--------------------------------------------------------------+
```

The displayed fields MUST be derived from the same canonical Auths object
whose digest is signed. The provider MUST return that transaction digest with
its result. The caller MUST reject a mismatch.

### 5.2 Every-action approval

When `every-action` applies, the approval sheet MUST distinguish an action from
a grant:

```text
+--------------------------------------------------------------+
| Auths · Approve exact action                                 |
+--------------------------------------------------------------+
| Agent       records-child                                    |
| Action      update_demo_record                               |
| Change      value digest 8f62...                             |
| Audience    mcp://records                                    |
| Expires     30 seconds                                       |
+--------------------------------------------------------------+
| [Deny]                           [Approve with Touch ID]       |
+--------------------------------------------------------------+
```

The UI MUST not show raw secrets or claim that approval means the provider
effect completed.

### 5.3 Headless behavior

A headless deployment receives the same structured `ApprovalRequest`. Its
configured provider may:

- approve according to a local policy;
- call an on-premises approval system;
- require an externally supplied signed approval artifact;
- reject because interactive approval is unavailable.

The SDK MUST not open a GUI or switch modes implicitly.

## 6. Architecture

```text
                         exact Auths object
                                 |
                                 v
+---------------------- approval policy -----------------------+
| grant-only | risk-based | every-action | custom              |
+---------------|-------------------------------|---------------+
                | prompt required               | no prompt
                v                               |
+---------------------- ApprovalProvider ----------------------+ |
| renders semantic fields | binds transaction | user presence  | |
+-------------------------------|------------------------------+ |
                                v                                |
                         ApprovalRecord                          |
                                |                                |
                                +---------------+----------------+
                                                v
+-------------------------- auths-custody -----------------------+
| ExternalSigningRequest -> exact SigningIntent -> signature     |
| verifies descriptor and transaction binding                    |
+---------------------------|------------------|------------------+
                            |                  |
                            v                  v
                 macOS custody helper     headless signer
                 Secure Enclave/Keychain  KMS/HSM/local policy
                            |
                            v
                      public signature

Identity-method adapter verifies principal control independently.
```

### 6.1 Ownership

`auths-author` continues to own exact signing-request construction.

`auths-custody` owns:

- provider-neutral signing intent;
- closed supported custody families;
- transaction-bound provider output;
- signer protocol errors;
- signed artifact assembly.

A new product-layer approval package SHOULD own:

- approval mode and decision contracts;
- exact approval request and record carriers;
- the pure mode-selection function;
- risk classification inputs without profile-specific risk meaning;
- approval-provider ports.

The profile or trusted authority owns:

- the minimum permitted supervision requirement;
- domain-specific risk categories and their canonical inputs;
- required human-readable action details; and
- the schema of approval freshness and reuse constraints.

The signed grant or trusted context owns the exact selected approval-policy
identity, evaluator version, configuration digest, and applicable freshness or
reuse limit. A host MAY select an equal or stricter permitted policy before the
grant is committed. It MUST NOT weaken or substitute that policy afterward.

The host owns provider configuration and execution of the committed policy. It
MUST present the required policy and configuration to the runtime as executed
configuration, and the runtime MUST establish exact equality before approval,
signing, credential acquisition, or provider I/O.

The macOS provider belongs in a dedicated product integration. It MUST NOT
introduce reverse dependencies into core, exchange, or profile packages.

### 6.2 Approval-policy enforcement

Approval requirement evaluation is a pure, fail-closed step before provider
invocation:

```text
profile minimum + trusted grant selection
                  |
                  v
required policy ID + version + configuration digest
                  |
                  v
registered deterministic evaluator
                  |
                  v
required approval rule + freshness
                  |
                  v
required configuration == executed configuration
                  |
          +-------+-------+
          |               |
          v               v
       approval        no prompt required
          |               |
          +-------+-------+
                  v
          signing/effect pipeline
```

An organization-specific policy MUST be a registered, versioned evaluator
whose identity and configuration are committed before action use. An
application-supplied callback, display-only `ruleId`, or mutable host function
is not a security boundary.

Evaluator absence, exception, ambiguity, timeout, unknown version, digest
mismatch, or output outside the registered schema MUST return a typed
indeterminate or unavailable result. It MUST produce no approval prompt,
signature, credential request, or provider call.

### 6.3 macOS process boundary

Repository Rust code forbids `unsafe`. The implementation MUST NOT add an
unchecked Rust FFI shim for the native provider boundary.

The preferred design is a small, separately built Swift helper communicating
over a bounded, versioned stdin/stdout protocol with a Rust or Node adapter:

```text
TypeScript SDK
    -> bounded local adapter request
    -> Swift custody helper
    -> CryptoKit / LocalAuthentication / Keychain
    -> bounded signed response
```

The helper:

- creates or loads a named Secure Enclave P-256 key;
- stores only an opaque persistent key reference and public metadata;
- sets an access-control policy requiring user presence;
- signs only an Auths domain-separated preimage;
- returns the signature, public key, custody metadata, and transaction digest;
- never returns private key material.

Adding the native helper requires explicit architecture, dependency, build,
packaging, signing, and release review. The implementation MUST pin the Swift
toolchain expectations and test the packaged artifact, not only source builds.

### 6.4 Software fallback

Fallback MUST be explicit in configuration and visible in approval records.

A conforming fallback:

- generates a supported Ed25519 or P-256 key using a vetted library;
- encrypts private material at rest with reviewed authenticated encryption and
  password-based key derivation parameters;
- stores the encrypted object in Keychain or a protected local store;
- receives passphrases through a callback or protected input channel;
- zeroizes passphrase and plaintext key buffers where the implementation
  language permits;
- never logs fallback reason or secret material;
- refuses to reinterpret a hardware key handle as a software key.

If implementation cannot meet these requirements in TypeScript, the fallback
MUST live in the native helper rather than weaken custody.

### 6.5 Headless provider

The headless reference MUST implement `ExternalSigner`; it MAY adapt an
existing KMS, HSM, PKCS#11, SPIFFE workload signer, or a test-only local signer.

Production examples MUST not accept a secret seed from an environment
variable. They SHOULD accept an opaque provider key identifier and obtain
credentials through the platform's normal workload mechanism.

### 6.6 Platform support and capability discovery

The portable SDK and provider contracts MUST operate on macOS, Linux, and
Windows. A provider MUST report its capabilities before the SDK selects or
opens a signer. Capability discovery MUST be read-only and MUST NOT create a
key, display an approval prompt, or silently select a weaker provider.

The initial platform matrix is:

| Platform | Required Phase 11 path | Optional or later native path |
| --- | --- | --- |
| macOS | headless/software and Secure Enclave reference provider | additional KMS, HSM, or WebAuthn providers |
| Linux | headless/software provider | TPM2, PKCS#11, Secret Service, KMS, or HSM providers |
| Windows | headless/software provider | CNG, TPM, Windows Hello, KMS, or HSM providers |

Absence of a native hardware provider MUST be represented as an unsupported or
unavailable capability. It MUST NOT prevent portable authoring, verification,
or use of an explicitly configured headless or software signer.

## 7. APIs

### 7.1 Approval request

```ts
interface ApprovalRequest {
  readonly version: 1;
  readonly kind: "grant" | "delegation" | "action";
  readonly transactionDigest: Uint8Array;
  readonly expiresAt: bigint;
  readonly actor: PrincipalSummary;
  readonly authority: AuthoritySummary;
  readonly action?: ExactActionSummary;
  readonly display: ReadonlyArray<ApprovalDisplayField>;
}

type ApprovalResponse =
  | { readonly kind: "approved"; readonly transactionDigest: Uint8Array;
      readonly record: ApprovalRecord }
  | { readonly kind: "cancelled"; readonly transactionDigest: Uint8Array }
  | { readonly kind: "rejected"; readonly transactionDigest: Uint8Array;
      readonly code: string }
  | { readonly kind: "unavailable"; readonly code: string };
```

Cancellation is a local approval outcome. It MUST NOT be rewritten as a kernel
denial code.

### 7.2 Approval policy

```ts
interface ApprovalPolicyCommitment {
  readonly policyId: string;
  readonly evaluatorVersion: string;
  readonly configurationDigest: Uint8Array;
}

interface ApprovalContext {
  readonly request: ApprovalRequest;
  readonly effectiveAuthority: EffectiveAuthoritySummary;
  readonly requiredPolicy: ApprovalPolicyCommitment;
  readonly profileRisk?: ProfileRiskClassification;
}

type ApprovalRequirement =
  | { readonly kind: "not-required";
      readonly policy: ApprovalPolicyCommitment;
      readonly ruleId: string;
      readonly evaluationDigest: Uint8Array }
  | { readonly kind: "required";
      readonly policy: ApprovalPolicyCommitment;
      readonly ruleId: string;
      readonly freshnessSeconds: number;
      readonly evaluationDigest: Uint8Array };
```

The pure selection function MUST be testable without invoking a provider.
Every decision MUST report the committed policy, selected rule, and evaluation
digest. `risk-based` and `custom` decisions MUST use only canonical bounded
inputs covered by that digest.

Before acting on the result, the runtime MUST compare the required policy
identity, evaluator version, configuration digest, selected rule, and
evaluation digest with the executed values. Any mismatch fails closed before
approval, signing, credentials, or provider I/O.

### 7.3 Custody provider

The TypeScript and native surfaces MUST align with the provider-neutral Rust
contract:

```ts
interface CustodyProvider {
  readonly id: string;
  capabilities(): Promise<CustodyCapabilities>;
  open(options: CustodyOpenOptions): Promise<CustodySigner>;
}

interface CustodyCapabilities {
  readonly platform: "macos" | "linux" | "windows" | "other";
  readonly available: boolean;
  readonly modes: ReadonlyArray<CustodyModeCapabilities>;
  readonly unavailableCode?: string;
}

interface CustodyModeCapabilities {
  readonly kind: "secure-enclave" | "software" | "headless";
  readonly hardwareBacked: boolean;
  readonly userPresence: boolean;
  readonly durableKeys: boolean;
  readonly ephemeralKeys: boolean;
}

interface CustodySigner extends AsyncDisposable {
  readonly kind: "secure-enclave" | "software" | "headless";
  readonly lifecycle: "durable" | "ephemeral";
  describe(): Promise<CustodyDescriptor>;
  sign(request: SigningRequest): Promise<SigningResponse>;
}
```

Capability claims MUST describe what the provider can establish, not what the
host operating system might support in theory. `open` MUST fail with a stable,
typed error if the requested capabilities are unavailable or changed after
discovery. It MUST NOT choose an unrequested fallback.

`SigningResponse` MUST bind:

- object identifier;
- signature descriptor;
- signature bytes;
- public verification material or reference;
- exact transaction digest;
- acquired evidence;
- hardware-backed and user-presence claims only when established.

## 8. Approval records

An approval record MUST contain:

- schema version;
- approval mode;
- required policy identity, evaluator version, and configuration digest;
- executed policy identity, evaluator version, and configuration digest;
- selected rule identity and evaluation digest;
- required-versus-executed equality result;
- provider kind and implementation identity;
- object kind and object digest;
- transaction digest;
- actor/principal summary;
- approved authority or action summary digest;
- decision time from trusted host input;
- freshness or reuse boundary;
- user-presence result when applicable;
- hardware-backed claim when applicable;
- result kind;
- record signature or integrity commitment.

It MUST NOT contain:

- biometric data;
- passphrases;
- private keys;
- raw provider credentials;
- complete sensitive action bodies unless the profile explicitly permits
  public receipt disclosure.

An approval record is evidence that a configured approval step occurred. It
does not replace the signed grant, proof, verification result, or execution
receipt.

A `not-required` evaluation MUST also produce a policy-evaluation record with
the same required and executed commitments. Absence of a prompt is not absence
of supervision-policy evidence.

## 9. Failure and fallback semantics

| Condition | Required behavior |
| --- | --- |
| User cancels | return `cancelled`; produce no signature |
| Biometric unavailable | return `unavailable`; do not silently fall back |
| Hardware key missing | typed unavailable/not-found result |
| Key reference corrupted | fail closed; do not generate a replacement under the same identity |
| Transaction digest mismatch | reject provider output |
| Descriptor substitution | reject provider output |
| Required/executed approval-policy mismatch | fail before prompting, signing, credentials, or provider I/O |
| Custom evaluator missing, ambiguous, throwing, or timed out | typed indeterminate/unavailable result; no effectful work |
| Helper response malformed or oversized | terminate request and fail closed |
| Helper exits after possible signing | return typed unknown local outcome; do not fabricate approval |
| Passphrase incorrect | generic rejection without secret-dependent detail |
| Headless approval required but unavailable | return unavailable; do not auto-approve |

Fallback may occur only when the host explicitly configured an ordered fallback
policy and the resulting custody kind is shown to the user or operator.

## 10. Security and privacy requirements

- Local helper messages MUST have exact schemas, versions, length bounds, and
  timeouts.
- Helper executable identity and path MUST be pinned by installation.
- Temporary files MUST NOT carry signing preimages, passphrases, or private
  keys.
- Signing and approval prompts MUST resist confused-deputy substitution by
  showing the exact semantic object and transaction digest.
- Registered approval evaluators MUST have immutable IDs, versions, bounded
  input schemas, configuration digests, and deterministic result schemas.
- Required and executed approval commitments MUST be compared before any
  effectful approval, signing, credential, or provider operation.
- Durable key identifiers MUST not contain user PII.
- Logs use opaque request IDs and stable codes.
- Tests and fixtures use unmistakably synthetic keys.
- All secret-bearing Rust types MUST zeroize on drop.
- JavaScript APIs MUST minimize secret residency and document runtime limits on
  guaranteed zeroization.
- Key deletion is a separate explicit destructive operation and is outside
  normal signer disposal.

## 11. Required evidence

Implementation MUST add:

- pure tests for every approval mode and rule order;
- minimum-supervision tests proving host policy can strengthen but cannot
  weaken a committed profile or trusted-authority requirement;
- required/executed approval-policy identity, version, configuration, rule,
  and evaluation-digest mismatch tests;
- missing, throwing, ambiguous, timed-out, unknown-version, and noncanonical
  custom-evaluator tests proving zero prompts, signatures, credentials, and
  provider calls;
- transaction-substitution and descriptor-substitution tests;
- cancellation and unavailable-biometric tests;
- tests proving no signature is returned on failed approval;
- Secure Enclave create/load/sign/restart tests on supported macOS CI or
  release hardware;
- explicit evidence when automated CI cannot exercise real biometrics;
- software fallback encryption, corruption, and wrong-passphrase tests;
- headless build tests proving no desktop dependency is linked;
- the platform-neutral provider contract suite on macOS, Linux, and native
  Windows CI;
- capability-discovery tests proving probes have no signing, prompting, key
  creation, or fallback side effects;
- package tests proving the Swift helper is present and identity-pinned;
- identity-method matrix tests using at least two principal methods with the
  same custody provider;
- custody-provider matrix tests using at least two providers with the same
  principal method;
- redacted logs and receipt fixtures;
- architecture, compliance, secret-scan, and authoritative CI evidence.

The two-dimensional matrix is required evidence that identity and custody are
not coupled.

## 12. Required implementation and pull-request boundaries

This umbrella MUST be delivered as separately reviewed work packages:

1. **Phase 10 contract PR.** Freeze approval request, response, policy
   commitment, evaluation, record, capability, custody, and error contracts.
2. **Phase 10 fake-provider PR.** Implement deterministic approval and custody
   providers and close substitution, mismatch, evaluator-failure, and lifecycle
   tests.
3. **Phase 10 reference-integration PR.** Integrate grant-only and every-action
   behavior into AP-SPEC-028 using only local reversible effects.
4. **Phase 11 helper-protocol PR.** Specify and implement the bounded,
   versioned Swift process protocol and hostile-message tests. No key provider.
5. **Phase 11 Secure Enclave PR.** Implement key creation, persistence,
   public-key export, exact signing, user presence, invalidation, and restart.
6. **Phase 11 software-custody PR.** Implement explicit encrypted fallback,
   passphrase input, corruption handling, lifecycle, and zeroization evidence.
7. **Phase 11 headless-provider PR.** Implement and test the customer-operated
   headless path on macOS, Linux, and native Windows.
8. **Phase 11 packaging and recovery PRs.** Close optional-package loading,
   helper identity, signing, upgrade, rotation, backup, recovery, uninstall,
   architecture, compliance, and release evidence.
9. **Phase 11 security assessment.** Review the deployable surfaces and retest
   remediations before production claims or consequential customer use.

No PR may combine native helper transport, hardware custody, software custody,
and cross-platform packaging merely because they share this specification.

## 13. Phase gates

### 13.1 Phase 10 contract gate

The provider-neutral Phase 10 work is complete only when:

- the profile or trusted authority can impose a minimum supervision policy;
- the selected policy ID, evaluator version, configuration digest, selected
  rule, and evaluation digest are committed and equality-enforced;
- evaluator failure or ambiguity causes no prompt, signature, credential, or
  provider call;
- approval cancellation is distinct from authorization denial;
- deterministic fake providers prove transaction and descriptor binding;
- identity methods remain independent of approval and custody providers;
- AP-SPEC-028 demonstrates grant-only and every-action behavior using only
  local reversible effects; and
- authoritative architecture, compliance, contract, and CI checks pass.

Passing this gate does not establish production custody or permit distribution
of a deployable native provider.

### 13.2 Phase 11 deployable-custody gate

Deployable custody work is complete only when:

- the applicable Phase 11 runtime, recovery, and deployment prerequisites are
  complete;
- approval cancellation and unavailable user presence fail safely;
- protected private keys are never exported;
- provider output is bound to the exact Auths transaction;
- a named parent key survives process restart without changing identity;
- ephemeral child disposal prevents future signing;
- headless builds import no desktop or macOS helper dependency;
- the headless/software reference path passes on native macOS, Linux, and
  Windows;
- unsupported platform custody is discoverable without preventing portable SDK
  use or causing implicit fallback;
- at least two identity methods work independently of at least two custody
  providers in the conformance matrix;
- approval records bind required and executed supervision to the intended
  grant, delegation, or exact action;
- fallback is explicit and observable;
- packaging, upgrade, rotation, backup, recovery, and uninstall exercises pass;
- the deployable surfaces complete their scoped security assessment and
  remediation gate; and
- authoritative repository and platform release checks pass on the exact
  revision.

Phase 11 does not require a CLI, hosted approval service, hardware-backed
Windows or Linux provider, mobile provider, equal native custody features on
every platform, or a general enterprise key-management product.
