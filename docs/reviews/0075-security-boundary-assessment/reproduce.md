# Reproducing the AP075 experiments

Status: executed local observations are retained under `evidence/`; conclusions
and gaps are in `final-report.md`. Do not interpret a listed command alone as
an executed/passing case.

The initial target is main `ac5fcabe9c6300e46789b4e847bb1991f9f9d66f`.
`evidence-manifest.json` pins the actual GitHub producers and archive hashes.
GitHub Actions is trusted for origin; these are not signed production releases.

From the repository root:

```sh
python3 qualification/security_assessment/acquire.py \
  --manifest docs/reviews/0075-security-boundary-assessment/evidence-manifest.json \
  --destination target/security-assessment/inputs
docker build --platform linux/amd64 \
  -f qualification/security_assessment/Dockerfile -t auths-ap075-stripe:ac5fcabe \
  target/security-assessment/inputs/stripe-package/stripe-gateway-demo
mkdir -p target/security-assessment/evidence/boundary
docker run --rm --init --platform linux/amd64 --network none --cap-add NET_ADMIN \
  --add-host api.stripe.com:1.1.1.1 \
  --security-opt no-new-privileges --memory 1g --cpus 2 --pids-limit 256 \
  --tmpfs /run:rw,nosuid,nodev,size=128m \
  -v "$PWD/qualification/security_assessment:/assessment:ro" \
  -v "$PWD/target/security-assessment/evidence/boundary:/evidence" \
  auths-ap075-stripe:ac5fcabe /assessment/stripe_probe.py --suite boundary
```

Use a fresh container and a separate evidence directory with `--suite reference`
for the existing 23-case installed reference. Run `/assessment/compare.py` in
another fresh container for the six conventional-baseline scenarios. The baseline
uses actual local HTTP ingress, scoped lab JWTs, exact server-side approvals,
transactional SQLite and the same provider double; it is not a deployed OAuth
service and supplies no production-security or customer-demand evidence.

`NET_ADMIN` belongs only to the trusted lab controller configuring per-UID egress
inside the disposable container. The attacker child runs as UID 62004 with zero
effective capabilities and no-new-privileges. No Docker socket, host networking
or host credential directory is mounted. The native binaries and installed SDKs
come from the verified package. The mounted assessment scripts are test code,
not alternative native verification or execution implementations.

The public-address `/etc/hosts` stub is for the native doctor's pinned-transport
construction check only: an otherwise networkless container cannot resolve the
reviewed HTTPS origin. It does not authorize or exercise external DNS/TLS or
Stripe traffic. The simulation transport still uses the counting loopback double,
and both root external networking and application INET egress remain blocked.
Without that prerequisite the existing reference correctly fails its transport
readiness assertion; that is a laboratory setup failure, not a passing reference.

For the final census:

```sh
python3 qualification/security_assessment/validate.py \
  --boundary target/security-assessment/evidence/boundary/independent-stripe.json \
  --comparison target/security-assessment/evidence/comparison/baseline-comparison.json \
  --head ac5fcabe9c6300e46789b4e847bb1991f9f9d66f \
  --output target/security-assessment/evidence/census.json
```

The workflow's `adversarial-assessment` job repeats the installed-path experiments
against its freshly built exact-head package, collects independent failures and
uploads the reports. It does not supply the rest of the SB01–SB32 investigation,
PostgreSQL comparison, source review or external human assessment by itself.
The inventory and census validator refuse absent/duplicate cases, wrong source
or backend, a missing successful provider-reaching control and fabricated market
claims. Mutation controls test those evidence rules; they are not product tests.

Preserve source, image and input/output digests with results. Cleanup is limited
to assessment-owned stopped containers and lab images after retaining required
evidence; never prune unrelated Docker resources or delete other worktrees.

## Native, installed delegation and independent portable verification

The native build used:

```sh
cargo test --locked -p auths-gateway --features loopback-provider,testkit-harness \
  --lib --no-run --message-format=json
```

Resolve the binary from Cargo's emitted compiler artifact, list it with
`--list --format terse`, and save the names in the registry schema consumed by
`native.py`. The retained `evidence/native-census.json` records all selected
names, excluded dedicated peer worker entrypoints and the actual binary hash.
The executed binary is Darwin/arm64, not the Linux package. The fixture is a
fresh copy of `product/stores/auths-stores/tests/postgres_tls` with generated TLS certificates and a
dedicated loopback port/project. Its manifest records that port and private CA
directory. Connect using host `localhost` and expected TLS identity `localhost`;
an IP/name mismatch is deliberately refused.

```sh
python3 qualification/security_assessment/native.py \
  --registry target/security-assessment/native-registry.json \
  --postgres-fixture target/security-assessment/postgres-fixture.json \
  --output target/security-assessment/evidence/native
```

Every selected test must have one successful named final execution with zero
ignored cases. The runner supplies the actual three PostgreSQL variables and
does not inherit peer-command or fixture-update flags. Raw per-case logs stay
private; hashes and outcomes are retained. Missing fixture/registry files are
setup errors, never passing evidence. The original corrected native runner's
hash is frozen in `evidence-manifest.json`.

Build the Airtable lab image from the other verified package using the same
Dockerfile. Run its existing `bin/auths-ap073-journey` as entrypoint, with
`--ignored --exact delegation_process::native_installed_delegation_process_fixture_is_current --nocapture`.
Set `AUTHS_DELEGATION_CONSUMER_DIR=/opt/demo`,
`AUTHS_DELEGATION_PYTHON=/opt/consumer/bin/python`,
`AUTHS_DELEGATION_NODE=/usr/local/bin/node`,
`AUTHS_DELEGATION_DISTINCT_UIDS=1`,
`AUTHS_GATEWAY_OPERATOR_TEST_BINARY=/opt/demo/bin/auths-gateway-simulation`, and
`AUTHS_DELEGATION_EVIDENCE_OUT=/evidence/installed-delegation.json`. Use a fresh
networkless bounded container and mount only its evidence directory.

From the root, the independent portable commands are:

```sh
(cd bindings/independent/go && go run ./cmd/auths-corpus-check --semantic \
  --report "$OLDPWD/target/security-assessment/evidence/go-semantic.jsonl" \
  "$OLDPWD/core/fixtures/v1/manifest.json")
node --experimental-strip-types bindings/independent/typescript/auths-corpus-check.ts \
  --semantic --report target/security-assessment/evidence/typescript-semantic.jsonl \
  core/fixtures/v1/manifest.json
python3 qualification/security_assessment/artifact_probes.py \
  --manifest docs/reviews/0075-security-boundary-assessment/evidence-manifest.json \
  --inputs target/security-assessment/inputs \
  --output target/security-assessment/evidence/artifact-controls.json
python3 qualification/security_assessment/report.py \
  --input target/security-assessment/evidence \
  --output docs/reviews/0075-security-boundary-assessment
python3 qualification/security_assessment/report.py --verify \
  --output docs/reviews/0075-security-boundary-assessment
```

For these observations Go was 1.24.6, Node 22.23.1 and host Python 3.10. Do not
claim those versions alone reproduce the full toolchain; package/source/build
pins and the target repository's toolchain files remain required. The scripts
are not a new verifier or a shipping application policy path.

Cleanup the owned PostgreSQL fixture only after retaining the census:
`docker compose --project-name auths-ap075-9ba04192 -f target/security-assessment/postgres-fixture/compose.yaml down -v`.
That command is specific to this experiment; subsequent runs must use their own
recorded project name. No global prune is part of reproduction.
