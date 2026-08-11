# Python safe native waist

**Status:** Milestone A implementation in progress

**Baseline:** `origin/main` at `670c801`

**Scope:** AP35-PR1 through AP35-PR3 only

## UX

The normal verifier remains small and exhaustive:

```python
result = auths.verify(proof, action, trusted_context)
match result:
    case Authorized():
        record_inert_evidence(result)
    case Denied() | Indeterminate():
        do_not_execute()
```

The public verifier projection is inert and carries no command. Internally,
`VerifiedAction` remains a native Rust-owned object with no Python constructor,
state dictionary, subclass path, copy path, pickle reduction, buffer view, or
bytes-to-handle promotion API. Bounded projections live in `auths.inspection`.

Typed authoring is split by purpose across `auths.authority`, `auths.trust`,
`auths.lifecycle`, and the integrated workflow. Their values remain
native-owned. Python coordinates them; Rust parses identifiers, constructs
protocol objects, applies attenuation, canonicalizes profiles, creates signing
preimages, and compiles trust.

## Architecture

```text
Python result summaries and typed workflow coordination
                         |
                         | no protocol constructors or CBOR decoder
                         v
       opaque PyO3 handles + native ABI version 1
          |              |                 |
          v              v                 v
   auths-author     auths-sdk/profile   auths-verifier
   plan + sign      trust + actions     decision + seal
          \______________|_________________/
                         |
                         v
             canonical auths-model objects
```

The portable decision record and sealed authorized action come from the same
Rust verifier execution. A denial, indeterminate result, decode failure, or
configuration mismatch carries no native authorization handle.

## APIs

The native ABI is versioned independently from the portable result ABI. ABI
version 1 freezes these operation families:

- principal parsing;
- root grant construction and child-grant planning;
- principal and grant status construction;
- authorization-plan construction;
- MCP profile action canonicalization;
- trusted-context template compilation and request binding;
- exact grant, action, principal-status, and grant-status signing requests;
- signature completion into native signed objects; and
- advanced canonical-byte inspection without capability promotion.

Normal Python APIs use closed result unions and native types. Functions reject
unknown variants, invalid lengths, duplicate set members, non-canonical input,
and unsupported identifiers at the native boundary.

## Threat model

The attacker is arbitrary Python code in the same interpreter. It may import
private modules, inspect module globals, call constructors directly, mutate
objects, subclass classes, invoke reflection, copy or deep-copy values, pickle
or reduce objects, retain aliases, and supply malformed or oversized input.

Security invariants:

1. Only the authorized Rust verifier branch creates `VerifiedAction`.
2. Decision data, canonical bytes, digests, and summaries are not capabilities.
3. No Python token, sentinel, module global, constructor argument, or byte
   sequence promotes data into `VerifiedAction`.
4. Denied and indeterminate results contain no effect-capable object.
5. Signing requests expose exact preimages but never private key material or a
   general-purpose signing primitive.
6. Child grants are constructed only after native attenuation succeeds.
7. Trusted context and profile meaning are compiled by their Rust owners.

The boundary does not defend against native-memory corruption, a malicious or
replaced wheel, compromised Rust dependencies, a compromised interpreter
process, or an executor that ignores the required native capability type.
Those are supply-chain, process-isolation, and gateway-integrity concerns.

## Supported runtimes

- CPython 3.9 and newer;
- abi3 wheels with the `abi3-py39` floor;
- Linux, macOS, and Windows wheel families already governed by release CI;
- synchronous, deterministic, offline native operations in Milestone A.

PyPy, free-threaded CPython, WebAssembly Python runtimes, source-only consumer
builds, mobile Python runtimes, and alternative interpreters are not claimed.

## Exact exclusions

This milestone does not add signer or approval providers, async lifecycle,
`AuthsClient`, attach-agent orchestration, complete delegation workflow,
proof-bundle assembly, a sealed profile command or gateway, receipts, hosted
services, private-key custody, production-readiness claims, stable-v1 claims,
or independent-review claims. Those remain AP35-PR4 and later.

The package remains labeled **Verifier Binding** until the later Full Workflow
exit gate passes. Milestone A supplies the safe dependency beneath that claim;
it does not promote the product tier by itself.

## Task list

- [x] Freeze the Milestone A API, ownership model, threat model, runtimes, and exclusions.
- [x] Return portable decision data and sealed authority from one Rust verifier execution.
- [x] Replace the Python sentinel wrapper with a non-constructible native `VerifiedAction`.
- [x] Move portable-result decoding out of Python and into the Rust binding.
- [x] Bind typed principal, grant, attenuation, status, plan, profile, trust, and signing operations.
- [x] Add native ABI version 1 and a committed machine-readable manifest.
- [x] Add direct-construction, subclass, reflection, copy, deepcopy, pickle, reduce, alias, and bytes-promotion attacks.
- [x] Add Rust/Python/TypeScript differential projections for shared fixtures.
- [x] Add type stubs and built-wheel smoke evidence.
- [x] Refresh architecture, compliance, API, and semantic-freeze inventories.

## Exit

Milestone A exits when Python can call every operation needed by later workflow
facades without implementing Auths meaning in Python, all shared fixtures agree
with Rust and TypeScript, and arbitrary Python code cannot mint any object that
a protected Auths effect boundary accepts as authorization.
