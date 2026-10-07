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

Run inside the maintained Docker image (`Dockerfile` in this directory) after installing the candidate wheel
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

The owner authorized platform-account Stripe test refunds on 7 October 2026.
`stripe.py` uses the separately generated `stripe-platform/` profile and recipe,
which have no connected-account field or scope header. It checks the restricted
test key, platform identity, denied reads, grant/relative ceilings, currency,
refund value/echo read-back, proof replay, altered action, restart, secret
isolation, support redaction and exact report signature. Setup creates only a
test PaymentIntent; teardown fully refunds its remaining test balance and
independently reads the charge to confirm cleanup. Stripe retains test payment
and refund records. No Connect/account-scope behavior is claimed. The current
platform test profile is different from the existing scoped Connect example.
For Stripe, use the same mounts and installed wheel, with the public
`stripe-platform/` directory at `/inputs`:

```text
/opt/consumer/bin/python /harness/stripe.py \
  --package /candidate/auths-gateway-operator \
  --inputs /inputs --wheel /wheel/<candidate>.whl --credential-stdin \
  --commit <exact-package-source-commit> --out /reports/run
```

Stripe stdin holds `STRIPE_TEST_API_KEY` and `STRIPE_TEST_RESTRICTED_KEY` in
dotenv format. Setup/cleanup use the full test key; gateway installation
receives only the restricted test key. Both keys must be test-mode keys.

The first successful live rehearsal is preserved in
[`../evidence/airtable-live-2026-10-07/`](../evidence/airtable-live-2026-10-07/).
It used gateway commit `20837b56` and the downloaded `0.0.1rc1` Linux wheel.
The two-process submission returned one provider-observed outcome and one
`gateway.attempt.replay`; the original proof and the same proof after process
restart were refused. Altered action bytes were denied as `malformed-proof`.
An independent fresh GET matched both the approved replacement and the gateway
result's echo. The created record was deleted before the report was signed.

The matching platform-only Stripe report, signature and real support bundle
are preserved in
[`../evidence/stripe-platform-live-2026-10-07/`](../evidence/stripe-platform-live-2026-10-07/).
It used the same downloaded gateway and installed `0.0.1rc1` wheel as Airtable.
A newly created 2,000-cent test payment had exactly one 500-cent gateway refund
before teardown, with fresh matching echo/value read-back. Grant ceiling,
relative ceiling and currency partition violations were refused, as were
original-proof replay, altered action and replay after restart. Teardown
refunded the remaining test balance and read the charge to confirm full refund.
The refund object has no `livemode` member; the test-mode evidence is the
credential/balance guard and the PaymentIntent/Charge observations.
