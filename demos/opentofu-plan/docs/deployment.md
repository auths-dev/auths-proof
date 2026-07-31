# Deployment and sandbox runbook

## Verified local and default Fly sandbox

The default image and Compose deployment use OpenTofu 1.12.5 with
`hashicorp/local` 2.9.0. This is a real provider and backend execution, not
fixture mode. Each session creates one protected file and one isolated
workspace on the persistent volume.

```sh
cd demos/opentofu-plan
docker compose up --build -d
open http://localhost:4174
```

Run `npm run test:live-contract`, `npm run test:live-recovery`, and
`npm run test:e2e` before deployment. The default `fly.toml` uses the same
local-provider sandbox on an encrypted Fly volume. Create the
`auths_opentofu_data` volume before the first deploy. Both provider objects and
non-default workspace state must remain below `/data`.

## Optional Cloudflare sandbox preparation

The image pins OpenTofu 1.12.5 and verifies the Linux AMD64 archive
against the committed SHA-256 checksum. Copy `sandbox/cloudflare/main.tf` into
the protected working directory, then initialize the exact provider lock:

```sh
tofu init -input=false
tofu providers lock -platform=linux_amd64
tofu workspace new auths-demo
```

Commit the resulting `.terraform.lock.hcl` to the protected deployment bundle
or provision it on the mounted volume before application startup. Startup
fails when this file, the module manifest, the absolute OpenTofu path, or any
allowlist is missing.

Build with `OPENTOFU_SANDBOX=cloudflare` only when deliberately selecting this
external-provider variant. The Cloudflare token must be restricted to DNS
write and read access for one
dedicated test zone. Seed `cloudflare_dns_record.authorized_demo` with a value
other than `TF_VAR_AUTHS_RECORD_VALUE`; import it into the `auths-demo`
workspace. The exact success case then performs a real update and observes the
new backend serial. Reset by changing the record back through a separate
operator identity and re-importing/refreshing state. Never reset by replaying an
old authorized action.

## Secrets

Set `AUTHS_OPENTOFU_CREDENTIAL_JSON` through the Fly secret store when it
contains any provider credential. The default local-provider deployment needs
only its closed `TF_VAR_*` input map. A Cloudflare deployment additionally
contains the scoped provider token. Do not put provider secrets in `fly.toml`,
logs, frontend variables, image layers, or plan receipts.

Create an encrypted persistent volume mounted at `/data`. Restrict
`/data/auths-opentofu` and `/workspace/opentofu` to UID 10001. Retain saved
plans until their action expires plus the reconciliation window, then remove
them under an operator-controlled retention job. Retain credential-free
receipts and shared lifecycle records according to the demo audit policy.

This prelaunch source cutover deliberately has no compatibility reader. Before
deploying the shared-lifecycle build, discard any non-production demo volume
that still contains the obsolete `claims.json` database. Startup fails closed
when that file is present; it is never interpreted, migrated, or dual-written.

## Cloud edges

Deploy the native image with `fly.toml`, then deploy `web/` to Vercel. Update
the two explicit origins together:

- `AUTHS_OPENTOFU_ALLOWED_ORIGIN` in Fly;
- the API destinations and CSP `connect-src` in `web/vercel.json`.

Do not enable a wildcard CORS origin. `/readyz` must report
`live-opentofu`; fixture mode is not a production fallback. Test exact apply,
one material denial, replay, state read-back, the inline receipt, and the
designed receipt route through the public frontend before publishing URLs.

## Shutdown and rollback

For an incident, revoke the Cloudflare token first, stop the Fly machines, then
preserve the encrypted state volume for reconciliation. Roll back application
images only when their pinned OpenTofu and profile versions match existing
lifecycle records. If an apply outcome is ambiguous, compare the backend
lineage, serial, canonical state digest, and provider object before any new
plan is issued.
