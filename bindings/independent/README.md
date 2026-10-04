# Independent implementations

The Go and TypeScript trees must not call the Rust verifier, load its WASM
build, or copy expected verdicts from the manifest. They are written from the
specification (`core/spec/v1`), not from the Rust code. When a vector exposes
a divergence, the specification is settled first and the implementations are
changed to match it.

Each language contains an independent deterministic-CBOR corpus auditor. Both
auditors:

- read the canonical `core/fixtures/v1/manifest.json`;
- check every proof, context, and canonical-action SHA-256 digest;
- independently parse each proof and verifier context as one complete CBOR item;
- treat profile-canonical action bodies as opaque while still checking their
  declared digest, matching the Auths protocol boundary;
- reject non-minimal integers, indefinite forms, tags, floats, duplicate or
  non-canonical map keys, invalid UTF-8, trailing bytes, and resource excess;
- emit the same aggregate corpus digest.

Run them with:

```sh
cd bindings/independent/go
go run ./cmd/auths-corpus-check <manifest>
node --experimental-strip-types \
  ../typescript/auths-corpus-check.ts <manifest>
```

## Raw-input vectors

A vector whose fault is in the encoding of an input other than the proof
carries that input's bytes as they are, and marks them in the manifest with
`"encoding": "raw"` on that input's entry. Today only the canonical action
uses it (`canonical_action.encoding`), for one vector per canonical-action
decode check site (`action-decode-*`). For a raw input:

- the entry's `sha256` is the digest of the raw bytes; the action's metadata
  fields (profile, media type, capability, resource, budget) describe the
  well-formed action the bytes were derived from, and `canonical_body` holds
  that action's body;
- the vector's `expected_result.stage` is `decode`; a raw input in a vector
  at any other stage fails the wire audit;
- the raw input need not parse as CBOR, and the body is not compared with it;
- the proof must parse: the rule that a vector expecting `malformed-proof` or
  `non-canonical-proof` carries a proof that fails to parse applies only to
  vectors without a raw input.

An absent `encoding` means `"canonical"`. Any other value fails the audit.

## Semantic verifiers

Both trees also contain independent target V1 semantic verifiers. They decode
all proof and context objects, resolve the digest graph, verify all seven
principal methods and both signature suites, apply attenuation, status,
assurance, observation-requirement, approval-requirement, and composition rules, and derive the
three-valued result without consulting the expected manifest result:

```sh
cd bindings/independent/go
go run ./cmd/auths-corpus-check --semantic [--report <file>] <manifest>
node --experimental-strip-types \
  ../typescript/auths-corpus-check.ts --semantic [--report <file>] <manifest>
```

Each verifier exposes one per-input entry point: Go `Verify` (`api.go`) and
TypeScript `verify(proof, action, context, adapterContext)`
(`semantic-verifier.ts`). It takes the three portable inputs and the adapter
context and returns the decision, the code, the stage, and the proof, action,
context, and plan digests. It never throws on any byte input. The semantic
runners obtain every verdict through it and decode no input outside it.

The stage is where the first failure occurred, as the specification names it:

| Stage | The failure occurred in |
|---|---|
| `decode` | decoding the context, the canonical action, or the proof |
| `resolve` | reference resolution, from the expected-plan check through the check on proof-carried status statements |
| `principal-control` | principal control, from the registry-manifest and configuration checks on, including evidence consumption |
| `authority` | action binding, a branch (including a statement-control failure a branch needs), the observation stage, or composition |
| `complete` | nothing: the result is authorized |

A `decode` or `resolve` result carries no plan digest.

### Comparison and report

For every vector, a semantic runner compares its decision, code, stage, and
proof, action, context, and plan digests with the manifest's
`expected_decision`, `expected_code`, and `expected_result`. It lists every
mismatching vector and field before it fails; it never stops at the first.
With `--report <file>`, it writes one JSON object per vector, in manifest
order:

```json
{"name": "grant-permission-outside-namespace", "implementation": "go-independent", "decision": "denied", "code": "resource-namespace-mismatch", "stage": "authority", "proof_digest": "…", "action_digest": "…", "context_digest": "…", "plan_digest": "…", "mismatched_fields": []}
```

Digests are lowercase hex, and `plan_digest` is `null` when absent.
`mismatched_fields` lists each of `decision`, `code`, `stage`,
`proof_digest`, `action_digest`, `context_digest`, and `plan_digest` that
differs from the manifest. The implementations are `rust-native`,
`go-independent`, and `typescript-independent`.

On success the runner prints the aggregate semantic digest,
`<vector count>:<sha256 hex>`. It is the SHA-256 of, for each vector in
manifest order, these fields, each followed by a zero byte: the name, the
decision, the code, the stage, the proof digest, the context digest, the
action digest, and the plan digest (empty when absent), each digest in
lowercase hex; then each action identifier, `|`, each authorized branch, `|`,
and for each assurance report its principal, role number, adapter, each claim
kind with its observation time (`-` when absent), and `;`; then a newline
field. The action digest is the SHA-256 of the action bytes as read, raw or
canonical.

`cargo xtask cross-language` runs both wire auditors, the Rust projection,
and the Go and TypeScript semantic verifiers. It requires exact agreement on
all artifact digests and on the aggregate semantic digest, and writes each
runner's report under `target/compliance/conformance/`.

## Checking another implementation

A verifier developed elsewhere can use the same corpus. Run it over every
vector of `core/fixtures/v1/manifest.json`, write a report in the format
above with its own `implementation` name, and check it against the manifest:

```sh
cargo xtask conformance-compare <report.jsonl>
```

The command reports every vector whose decision, code, stage, or digests
differ from the manifest, and every vector missing from the report.
`core/fixtures/v1/check-sites.json` names the check site each single-fault
vector targets, so a divergence can be traced to one specified check.
