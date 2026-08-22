# Profile and provider authoring

Auths profiles are statically linked, typed provider verticals. They are not
runtime plugins and they do not add arbitrary routes to the root SDK. A profile
contributor owns the domain action, evaluator, sealed command, provider result,
reconciliation truth, receipt payload, and stable error mapping. The shared
runtime owns ambient workload authentication, connection lookup, durable
journaling, recovery envelopes, and portable linked receipts.

## Choose the contribution type

- **New account:** run `auths connections add`; no code or regeneration.
- **New operation for an existing domain:** run `cargo xtask profile new` with
  `--existing-domain`.
- **New provider kind:** scaffold a connected domain. This adds one closed,
  statically rostered connection adapter plus its exact profiles.
- **Connectionless operation:** use `--connectionless`; it receives no provider
  credential lease.

## Scaffold

```bash
cargo xtask profile new \
  --domain mailbox \
  --effect send \
  --version 1 \
  --provider gmail \
  --connection-version 1
```

The command validates identifiers before writing, refuses collisions and path
escapes, registers the Rust package, emits both generated SDK distributions,
and leaves every security-sensitive function fail closed with an explicit
`TODO(auths-profile)`. It also creates bounded valid, malformed, maximum, and
maximum-plus-one fixture slots and the qualification evidence skeleton.

For an operation in an existing domain:

```bash
cargo xtask profile new \
  --domain mailbox \
  --effect archive \
  --version 1 \
  --existing-domain
```

## Implement the vertical

Complete the generated TODOs in this order:

1. freeze the restricted API schema and every byte/count/work bound;
2. define the immutable connection descriptor and its exact supported scopes;
3. prove onboarding binds the supplied secret to that descriptor's account;
4. map input to one canonical action and evaluate it without credentials;
5. reserve profile-owned state, then seal one credential-free provider command;
6. re-read authority, connection generation, account, descriptor, and config;
7. lease the least-privilege credential only after all prior checks pass;
8. persist provider entry, call the closed gateway, and persist the raw result;
9. classify/observe the durable result and mint the linked receipt pair; and
10. reconcile the original attempt without blind retry or inferred success.

Do not add callbacks or trait-object dispatch to the shared runtime. If trusted
provider evidence must be discovered first, model it as a separately authorized
preflight profile with a bounded, expiring, principal/connection-bound prepared
record, as PostgreSQL and OpenTofu do.

## Generate and qualify

```bash
cargo xtask profile generate --domain mailbox
cargo xtask profile check --domain mailbox
cargo xtask error-registry
cargo xtask spec-sync
cargo xtask profile qualification check --domain mailbox
```

Generation is deterministic but is not qualification. Before publication, add
the real provider sandbox, denial-before-credential proof, exact request
fixtures, crash tests around every durable checkpoint, replay/recovery tests,
cross-language receipt verification, clean installed-package tests, secret
scan, connected demo, and hosted `cargo xtask ci` evidence required by
AP-SPEC-040 section 19.

The generated package README is the application quickstart. It must remain a
normal `connect()` plus typed domain-method call with no Auths token, provider
credential, arbitrary endpoint, caller evaluator, or receipt plumbing.
