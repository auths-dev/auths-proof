# AP-SPEC-055: Closed enumeration fields in self-hosted argument schemas

- **Status:** Implemented and merged for the self-hosted schema node; provider
  semantics remain unqualified
- **Depends on:** [AP-SPEC-051](0051-self-hosted-developer-profiles.md),
  [AP-SPEC-054 §5](0054-self-hosted-adapter-developer-experience.md) (the
  restricted schema, lock, and vector corpus this node extends)
- **Relates to:** [AP-SPEC-053 §3.2](0053-declarative-credential-isolated-gateway.md),
  whose recipe language may select fixed keys or path segments from a finite
  enumeration
- **Scope:** add exactly one node, `enum`, to the restricted `profile.toml`
  schema, the generated Python and TypeScript command types, the strict
  projection, the lock digest, and the cross-language vector corpus
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

Auths will add a **closed enumeration** node to the self-hosted argument
schema. An `enum` field carries exactly one of a finite, declared,
case-sensitive set of string variants. The variant set is part of the
contract's normalized schema digest, so adding, removing, renaming, or
reordering a variant changes the action identity and requires a contract
version bump.

The claim is unchanged from AP-SPEC-051: a verified proof authorizes the
exact canonical action, and the projected command comes from those verified
bytes. An enum field narrows what the approver must read from "a bounded
string" to "one of these N names". It does not tell Auths what the variant
means to the provider; that remains the adapter's or the operator-approved
recipe's declaration.

An enum is **not** a union. It selects a name, never a shape. It is not an
open set with an `other` variant, not an integer code, and not a policy
construct that grants or denies variants. Grant-level restriction of which
variants a principal may sign belongs to
[AP-SPEC-025](0025-closed-bounded-authorization-policy.md), not to the
schema.

## 2. UX

The developer declares the variants in `profile.toml`. The generated command
type rejects any other value at type-check time in both languages, and the
prepare/preview path shows the selected variant name verbatim.

```toml
[arguments.fields.status]
type = "enum"
variants = ["open", "in_progress", "closed"]
```

```text
$ auths check profile.toml
  PASS  schema and generated files match
  PASS  canonical/hostile vectors match packaged SDK
  NOTE  status: enum of 3 variants; variant meaning is application-owned

$ auths diff profile.toml        # after editing variants
  arguments.fields.status.variants: ["open","in_progress","closed"]
                                 -> ["open","closed"]
  action identity changed; bump [profile].version before generate
```

The prepared-command preview lists the variant name exactly as it will be
signed. It never shows an index, a display label, or a provider value.
Diagnostics distinguish an unknown variant (`contract` stage, before
authoring) from a verified action whose variant is not in the compiled
schema (`verification` stage, projection rejected). Neither prints the
full argument body.

## 3. Contract

### 3.1 Node definition

| Property | Rule |
| --- | --- |
| Source form | `type = "enum"` plus `variants = [ "a", "b", ... ]` on one line; no other keys |
| Variant count | 1 to 32 inclusive |
| Variant syntax | each matches `^[A-Za-z0-9_.-]{1,64}$`; ASCII only; no whitespace or escapes |
| Uniqueness | exact byte comparison; `Open` and `open` are distinct and MAY coexist |
| Order | declaration order is significant for the digest and generated type only; it has no wire meaning |
| Canonical wire form | the variant string as a JSON string; no index, no object wrapper |
| Generated Python | `Literal["a", "b"]` on a frozen dataclass field |
| Generated TypeScript | readonly literal union `"a" \| "b"` via `CommandOf` |
| Composition | permitted as an object field, an array item, and the inner node of `nullable`; an enum MUST NOT wrap another node |
| Budget | counts as one named field toward the 32-field total; variants do not count |

The restricted `profile.toml` parser currently accepts quoted scalar strings
and integers only. This spec permits one additional value form: a
single-line array of quoted strings, accepted **only** for the `variants`
key of an `enum` table. Multi-line arrays, trailing commas, arrays of any
other type, and arrays under any other key remain rejected. The quoted-string
charset already used by the parser (`[A-Za-z0-9_.:-]`) is narrowed for
variants by excluding `:` so that a variant can never be confused with the
scalar bound mini-syntax retired by AP-SPEC-054.

### 3.2 Rejections

The parser, generator, and projection MUST fail closed on:

- zero variants, more than 32, a variant longer than 64 bytes, or a variant
  outside the charset;
- duplicate variants, including duplicates that differ only after Unicode
  normalization (rejected by the ASCII charset rule);
- any key other than `type` and `variants` in the enum table;
- a value that is not a JSON string, including an integer index, `true`,
  `null` in a non-nullable position, or an object;
- a string not byte-equal to a declared variant, including case, leading or
  trailing whitespace, and homoglyphs; and
- a generated file, lock, or vector whose variant list differs from the
  source in any element or position.

No normalization, trimming, case folding, or "closest match" is applied at
any stage.

### 3.3 Lock and version rule

`profile.lock.json` records the enum node as
`{"type":"enum","variants":[...]}` inside `command_schema`, in declaration
order, and the normalized `schema_digest` covers it. `profile check`
rejects a same-version change to the variant list. `profile diff` reports
the before/after list and states that the action identity changed.
`profile generate` refuses to regenerate a changed variant list without a
version bump, exactly as it does for a changed bound.

## 4. Runtime and projection

Python gains `EnumField(variants: tuple[str, ...])` in `auths.self_hosted`
and TypeScript gains `enumField(variants)` in `@auths-dev/sdk/self-hosted`.
Both validate the node rules in §3.1 at construction. The strict projection
(`_field_value` in Python; the typed projection in TypeScript) accepts only
a string byte-equal to a declared variant and rejects everything in §3.2.
Python's `_annotation_matches` MUST require a `Literal` whose arguments
equal the variant tuple in order; TypeScript's `CommandOf` MUST map the node
to the literal union so that a stale generated type fails to compile.

Core and the native verifier are unchanged. The native path continues to
verify the proof and return canonical argument bytes; the enum check is part
of the bindings' post-verification projection, alongside string bounds and
integer ranges. If a native projection helper is introduced by AP-SPEC-054
Epic 1 and becomes the owner of schema nodes, the enum node MUST be added
there before the bindings expose it, so that Rust, Python, and TypeScript
share one implementation of the rules above.

## 5. Vectors

The shared fixture under `bindings/fixtures/self-hosted-profile/` gains an
enum field. The valid vector uses the **first declared variant**, so the
example remains deterministic across generators. The hostile corpus adds, at
minimum:

| Case | Expected result |
| --- | --- |
| Second declared variant | valid; distinct canonical bytes and commitment |
| Undeclared string | projection rejected |
| Declared variant with case flipped | projection rejected |
| Integer index `0` | projection rejected |
| `null` for a non-nullable enum | projection rejected |
| Enum inside `nullable` with `null` | valid |
| Array of enum with a duplicate item | valid unless the array node forbids it; arrays do not imply set semantics |
| Variant list reordered under the same version | `check` and `generate` rejected |

Native Rust, Python, and TypeScript consume the same corpus in the packed
consumer tests from AP-SPEC-052 Epic 4. The vector format from AP-SPEC-054
§5.2 (canonical argument bytes, action bytes, commitment, expected outcome)
applies; `valid_arguments_json` alone is insufficient.

## 6. Relationship to the declared-recipe gateway

AP-SPEC-053 §3.2 allows a recipe to select among fixed keys or path segments
only from a finite operator-approved enumeration whose closed mapping is
represented in the recipe AST. This node is the intended input to that
mapping. A recipe that references an enum field MUST map every declared
variant to exactly one fixed key or segment and MUST fail compilation if any
variant is unmapped or any mapping target is dynamic. The mapping lives in
the recipe, is covered by the recipe digest, and is not part of the schema
or the action bytes. Nothing in this spec depends on AP-SPEC-053 shipping.

## 7. Epic and acceptance

### Epic 1 — Add the enum node end to end

1. Write failing fixtures first: the extended `profile.toml`, `vectors.json`,
   `profile.lock.json`, and hostile cases from §5, plus a Python `Literal`
   mismatch test and a TypeScript compile-fail test for an undeclared
   variant.
2. Add `EnumField` / `enumField` and the projection rules to both bindings;
   add the node to the native projection helper first if AP-SPEC-054 has
   made it the schema owner.
3. Extend the restricted parser with the single-line `variants` array form,
   the generator with `Literal` / literal-union rendering, and the lock,
   check, diff, and generate rules from §3.3.
4. Update `api/public-api.txt` for both packages, `sdk-capability.json`,
   the customer-journey matrix, and the semantic-freeze inventories in the
   same commit as the public surface change.

**Acceptance:** a clean packed Python and npm consumer each generate, type
check, author, verify, and project a command with an enum field; the same
variant yields byte-identical arguments, action, and commitment in every
language; every hostile case in §5 fails in every language; a same-version
variant edit cannot pass `check` or `generate`; and no core or native
verifier change is required unless the native projection helper already
owns schema nodes.

## 8. Non-goals

- Tagged unions, sum types, or variant-dependent shapes.
- Open enumerations, `other`/fallback variants, or forward-compatible
  unknown-variant acceptance.
- Integer-coded, boolean-coded, or bit-flag enumerations.
- Display labels, localization, ordering or comparison semantics, or
  default variants.
- Free-form maps or dynamic keys; the bounded alternative remains an array
  of fixed-shape objects.
- Grant-level restriction of permitted variants, which is AP-SPEC-025 scope.

## 9. Verification and release boundary

Development is fixture-first: the §5 vectors and the type-check failures
exist before the parser, generator, or projection changes. Hosted CI is the
verification gate under the repository policy; this specification does not
run checks or assert their outcome. The node ships only when both packaged
consumers, the native corpus, and the public-surface inventories agree on
one reviewed revision. Adding this node does not change the claim ledger:
what a variant means to a provider remains application-owned and
unqualified.
