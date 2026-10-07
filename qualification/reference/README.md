# Reviewed commissioning references

These are release-only provider references, outside shipping packages. They
neither hold provider credentials nor publish qualification evidence.

`stripe_platform.py` independently derives the platform-account test refund;
`airtable_record.py` derives the dedicated table's one-field update. The
resource carrier is closed, unique, bounded and tied to one protected run.
Only the dedicated owner-authorized Airtable base/table may replace the two
synthetic fixed path members. Every other recipe member and the exact profile
lock must agree with reviewed source, including guards and ceilings.

`expand.py` receives public packet files, resource bindings, the original
candidate binary, tuple and canonical conformance/differential evidence. It
hashes the candidate without executing it. It invokes only a reviewer binary
that the signing job builds from its own checkout, with an empty environment,
through `qualification-candidate` and `review-submission`. No program from a
downloaded artifact runs with a signing key.

Native proof review supplies the exact actors, canonical action commitments
and decoded arguments. The provider reference supplies the expected request.
Their request mappings must agree byte-for-byte before an action enters the
unsigned binding. All actions must have one exact actor, the installed trust
must match, and the lease ceiling is a source-owned 64 acquisitions. The
native issuer separately rechecks both offline artifacts and their mandatory
scenarios before signing. An expansion is neither a live report nor a permit.

```text
python qualification/reference/expand.py \
  --reviewer <binary-built-in-this-signing-job> \
  --candidate <original-candidate-binary> \
  --tuple <tuple.json> --recipe <recipe.json> --profile-lock <profile.lock.json> \
  --resources <resources.json> --packets <public-packets.json> \
  --conformance <conformance.json> --differential <differential.json> \
  --source-commit <exact-commit> \
  --protected-run recipe-qualification/<run-id>/<attempt> \
  --out-dir <new-output-directory>
```

The public packet carrier is `auths.qualification-public-packets/1`, with
`protected_run`, `trusted_context` (one adjacent filename), and 1–64 `packets`.
Each packet contains `label`, `proof`, `action` (adjacent filenames), and its
expected `arguments`. Unknown fields, path traversal, changed source, wrong
production targets, resource widening, actor changes or an oracle mismatch
prevent output. Filenames never select code. Private author keys are absent.

The protected family setup, complete corpus and live workflow still need to
use these references. No family is qualified by landing this code.

`measure.py` validates and subtracts native execution snapshots: matching fresh
scope, no saturation/decrease, no duplicate host in an aggregate. Restarted
engines must be measured separately. Budget consumption is never substituted
for actual custody calls.

`fresh_evidence.py` is the separate response oracle for the reviewed Stripe
refund and Airtable update. It validates the approved resource, exact intended
value, test-mode success (Stripe) and the action-derived echo, then hashes the
raw independently fetched response. It accepts no candidate response digest
or locator. Its subject binds the full reviewed request, resource ledger,
action and expected state. The corpus runner compares this fresh witness with
the candidate's own digest. Synthetic unit responses test refusals and exact
bytes; they are not qualification evidence.
