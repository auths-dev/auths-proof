# Debugging and deployment

## Supported deployment profiles

The demo has two first-class deployment profiles. They use the same frontend,
native service, Auths profile, API schema, and Kubernetes adapter.

- **Cloud:** Vercel serves `web/`, rewrites API calls to Fly.io, and Fly.io
  reaches a cloud Kubernetes API. The existing `web/vercel.json`, `fly.toml`,
  and persistent Fly volume remain the source of truth for this profile.
- **Local Docker:** nginx serves the same `web/` files on localhost and proxies
  to the same native service in Docker. The service reaches a real Kind
  Kubernetes API over Docker's `kind` network.

Neither profile permits a fixture backend. Public and local acceptance sessions
must both report `cluster_mode: live-kubernetes`.

## Run the complete demo locally

Prerequisites are Docker Desktop, Kind, and `kubectl`. Start everything from the
repository root:

```sh
demos/kubernetes-rollout/scripts/local-up.sh
```

Then open:

```text
http://localhost:4173
```

This is an HTTP deployment, not a `file://` preview. The startup script:

1. creates or reuses the `auths-kubernetes-demo` Kind cluster;
2. builds and loads two immutable workload images;
3. applies the namespace, RBAC, admission policy, workload, and managed-field
   ownership split;
4. creates separate, 24-hour inspector and executor ServiceAccount tokens;
5. builds and starts the native service and nginx frontend with Docker Compose;
6. waits for `/readyz` to prove the native service can reach Kubernetes.

Use another localhost port without editing code:

```sh
AUTHS_KUBERNETES_LOCAL_PORT=5173 \
  demos/kubernetes-rollout/scripts/local-up.sh
```

Stop only the demo containers with:

```sh
demos/kubernetes-rollout/scripts/local-down.sh
```

The Kind cluster and the named replay-state volume are deliberately preserved.
Rerun `local-up.sh` after a day to refresh the bounded ServiceAccount tokens.
The backend itself still rejects a direct `docker compose up` with empty
cluster settings; `local-up.sh` is the supported entry point that supplies
them. Inspection and shutdown commands do not require those credentials.

### Inspect the local deployment

```sh
docker compose \
  -f demos/kubernetes-rollout/compose.local.yaml ps
docker compose \
  -f demos/kubernetes-rollout/compose.local.yaml logs backend
curl http://localhost:4173/healthz
curl http://localhost:4173/readyz
kubectl --context kind-auths-kubernetes-demo \
  -n auths-demo get deployment color-service
```

If port `4173` is occupied, set `AUTHS_KUBERNETES_LOCAL_PORT` when starting. If
`/readyz` fails but `/healthz` succeeds, inspect the backend logs and confirm
its container is attached to the external `kind` network. If a session fails
after the containers have been up for 24 hours, rerun `local-up.sh` to issue
fresh tokens.

The following reset is intentionally destructive: it removes local replay
claims and the entire demo cluster. Use it only when a clean-room run is
required:

```sh
demos/kubernetes-rollout/scripts/local-down.sh
docker volume rm auths-kubernetes-demo_auths-kubernetes-state
kind delete cluster --name auths-kubernetes-demo
```

## Validate locally

Run:

```sh
cargo test -p auths-kubernetes --all-features
cargo test -p auths-kubernetes-demo --all-features
npm run check --prefix demos/kubernetes-rollout
cargo xtask compliance
cargo xtask arch
```

The HTTP integration test uses the deterministic Kubernetes adapter but the
real Auths authoring, canonicalization, signature, verification, claim, and
receipt paths. Public acceptance testing must use `cluster_mode:
live-kubernetes`.

## Kubernetes prerequisites

Build and publish the blue and green workload images from `workload/Dockerfile`.
Resolve each registry tag to its immutable `sha256` manifest digest. The
Deployment and both Fly secrets must use digest references, never mutable tags.

Bootstrap the cluster with the exact first digest:

```sh
AUTHS_KUBERNETES_CONTEXT=your-context \
  demos/kubernetes-rollout/scripts/bootstrap-cluster.sh \
  ghcr.io/auths-dev/auths-kubernetes-color-service@sha256:your-image-a-digest
```

The script applies the namespace, RBAC, admission policy, workload, and a
deliberate server-side apply ownership split. `auths-demo-bootstrap` retains
required Deployment structure. `auths-workload-rollout` owns only the image,
replicas, and rollout annotation. Do not bootstrap the full Deployment under
the rollout manager: a later partial apply would otherwise try to delete
required fields. Do not leave the rollout fields co-owned by another manager:
`force=false` would correctly report a managed-field conflict.

Create bounded ServiceAccount tokens for `auths-rollout-inspector` and
`auths-rollout-executor`. Confirm authorization explicitly:

```sh
kubectl auth can-i get deployment/color-service \
  --as=system:serviceaccount:auths-demo:auths-rollout-inspector -n auths-demo
kubectl auth can-i patch deployment/color-service \
  --as=system:serviceaccount:auths-demo:auths-rollout-inspector -n auths-demo
kubectl auth can-i patch deployment/color-service \
  --as=system:serviceaccount:auths-demo:auths-rollout-executor -n auths-demo
```

The inspector’s RBAC answer for patch is necessarily `yes`; Kubernetes uses the
same verb for dry-run. Test the admission policy separately: its dry-run patch
must pass and the same request without `dryRun=All` must be denied.

## Fly.io

The backend needs a persistent volume at `/data`, because the exact-action
claim must survive machine restarts. Set the API server URL, CA PEM, cluster
audience, evidence token, mutation token, and both immutable image references
as encrypted Fly secrets. Do not put kubeconfig files or tokens in the image,
repository, Fly configuration file, logs, receipts, or frontend.

The backend’s Kubernetes API must be reachable from its Fly private network.
`/readyz` is not sufficient acceptance evidence by itself; create a session and
confirm it reports `live-kubernetes` and a real Deployment UID.

The Fly profile is independent from `compose.local.yaml`. Local startup never
modifies Fly secrets, machines, volumes, or `fly.toml`.

## Vercel

Deploy with `demos/kubernetes-rollout/web` as the project root. The included
`vercel.json` rewrites `/api/*` to the Fly backend and supplies restrictive
browser headers. If the page stays in its loading state:

1. inspect `/healthz` and `/readyz` through the Vercel origin;
2. inspect the `POST /api/v1/sessions` response;
3. verify the Vercel rewrite points to the current Fly app;
4. verify Fly CORS allows exactly the deployed Vercel origin;
5. inspect Fly logs for CA, token, admission-policy, or cluster-network errors.

Never accept a `file://` page or a fixture-mode backend as deployment proof.

## Ambiguous Kubernetes outcomes

If the apply request loses its response, the claim becomes `outcome-unknown`.
The service reconciles only by reading the Deployment; it does not blindly send
the patch again. Inspect the claim file, Kubernetes audit ID when available,
Deployment image/generation, and receipt log together.
