# Reproducing the AP075 experiments

Status: commands prepared; execution results are recorded separately. Do not
interpret a command listed here as an executed/passing case.

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
