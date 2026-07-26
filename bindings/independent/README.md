# Independent implementations

The Go and TypeScript trees must not call the Rust verifier, load its WASM
build, or copy expected verdicts from the manifest.

Each language contains an independent deterministic-CBOR corpus auditor. Both
auditors:

- read the canonical `auths-proof/fixtures/v1/manifest.json`;
- check every proof, context, and canonical-action SHA-256 digest;
- independently parse each proof and verifier context as one complete CBOR item;
- treat profile-canonical action bodies as opaque while still checking their
  declared digest, matching the Auths protocol boundary;
- reject non-minimal integers, indefinite forms, tags, floats, duplicate or
  non-canonical map keys, invalid UTF-8, trailing bytes, and resource excess;
- emit the same aggregate corpus digest.

Run them with:

```sh
cd implementations/go
go run ./cmd/auths-corpus-check <manifest>
node --experimental-strip-types \
  ../typescript/auths-corpus-check.ts <manifest>
```

Both trees also contain independent target V1 semantic verifiers. They decode
all proof and context objects, resolve the digest graph, verify all seven
principal methods and both signature suites, apply attenuation, status,
assurance, and composition rules, and derive the three-valued result without
consulting the expected manifest result:

```sh
cd implementations/go
go run ./cmd/auths-corpus-check --semantic <manifest>
node --experimental-strip-types \
  ../typescript/auths-corpus-check.ts --semantic <manifest>
```

`cargo xtask cross-language` runs both wire auditors, the Rust verifier, and
the independent Go and TypeScript verifiers. It requires exact agreement on
all artifact digests and on a normalized semantic projection containing the
decision, stable code, proof/context/action/plan identifiers, authorized
actions and branches, and role-indexed assurance reports.
