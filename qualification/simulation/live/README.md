# Live operator rehearsal

`airtable.py` exercises a downloaded gateway operator package and an installed
Python wheel against a dedicated Airtable table. It fixes the base/table in the
recipe before review, creates a disposable record, authors proof/action with
native SDK primitives and the gateway's reviewed verifier configuration, and
runs two separate gateway processes against their shared durable file store.
The application UID receives no provider credential and cannot read the token
file or gateway state. The run checks live read-back/value/echo, proof replay,
altered action, process restart, and the real redacted support bundle. Cleanup
deletes the record even after a failed journey. The dedicated empty table is
retained for later rehearsals.

The report and detached signature use the existing simulation schema and
Ed25519 signature domain. The installed SDK generates a fresh in-memory key,
signs the actual report bytes and re-reads/verifies their published digest and
signature. This signer has no protected release authority. Live provider state
is evidence; the report makes no production qualification, PostgreSQL/AWS,
complete-corpus, token-scope or independently measured lease/entry-counter claim.

Run inside the maintained Docker image after installing the candidate wheel
with `/opt/consumer/bin/pip install --no-deps /wheel/<candidate>.whl`. Mount only
the extracted package, public Airtable recipe/profile lock, this script and an
empty report directory. Supply the operator credential through Docker stdin.
Do not mount a source checkout or give a credential environment variable to the application.

```text
/opt/consumer/bin/python /harness/airtable.py \
  --package /candidate/auths-gateway-operator \
  --inputs /inputs --wheel /wheel/<candidate>.whl --credential-stdin \
  --base <dedicated-base> --table <dedicated-table> \
  --commit <exact-package-source-commit> --out /reports/run
```

The stdin input holds `PERSONAL_ACCESS_TOKEN` in dotenv format. The operator
stages it in a root-owned private directory on the container filesystem, then
sends the token to gateway installation through stdin. Do not mount a credential
file: Docker Desktop's host sharing may make its owner match each caller and
can defeat the expected Unix access check. The application isolation check
must fail to read the staged credential and both gateway state directories.
Child output is bounded and secret-scanned before publication;
provider error response bodies never reach public logs.

Stripe's distinct-account rehearsal additionally requires Connect enabled on
the test platform. A 400 refusal creating a connected account is a failed setup,
not evidence of account-scope qualification. Do not substitute the platform
account and declare that requirement satisfied.

The first successful live rehearsal is preserved in
[`../evidence/airtable-live-2026-10-07/`](../evidence/airtable-live-2026-10-07/).
It used gateway commit `20837b56` and the downloaded `0.0.1rc1` Linux wheel.
The two-process submission returned one provider-observed outcome and one
`gateway.attempt.replay`; the original proof and the same proof after process
restart were refused. Altered action bytes were denied as `malformed-proof`.
An independent fresh GET matched both the approved replacement and the gateway
result's echo. The created record was deleted before the report was signed.
