# Enrolled writer review fixture

`enrolled-write-review-v1.json` is canonical JSON constructed by the native
`enrolled_writer_review_fixture_matches_native_approval_payload` test. It
bootstraps a task, enrolls a child with native proofs, verifies independent
human approval, and emits the same review formatter used by the task session.
All principals and payloads are synthetic. No private keys, credentials, or
provider content are included.

Regenerate intentionally with:

```sh
AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib --all-features enrolled_writer_review_fixture_matches_native_approval_payload
```

The Python presenter consumes this fixture and compares its signing arguments
with the native canonical bytes. This covers representation parity for the
closed exact-write intent, including the enrolled writer. It does not prove
provider execution, browser signing, isolation, or full task acceptance.
