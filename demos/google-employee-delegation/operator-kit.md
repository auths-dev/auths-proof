# AP-SPEC-070 operator kit

This source-free archive contains Compose configuration, relay rules, a version
lock, and a blank live acceptance record. `REVISION` identifies the exact Auths
commit used to build the kit. The values in `versions.lock.json` determine
whether this is a CI candidate or a published kit with pinned images.

## Verify the download

Download the archive and adjacent `.sha256` file from the reviewed workflow
run. CI candidates use the `google-read-operator-kit-<REVISION>` artifact;
published kits use the `google-read-operator-release-<REVISION>` artifact.
On a Mac, run:

```sh
shasum -a 256 -c *.tar.gz.sha256
tar -xzf *.tar.gz
cd google-read-operator-kit
shasum -a 256 -c SHA256SUMS
cat REVISION
```

Compare `REVISION` with the reviewed commit in the workflow run. The lock
file's `auths_base_revision` identifies an earlier SDK baseline, not this
kit's build revision. A passing checksum proves the downloaded
bytes match the workflow artifact; review the workflow run and commit before
trusting it. A published kit contains the exact Linux SDK wheel used to build
the images under `artifacts/`; a CI candidate has it in the separate
`google-read-linux-wheel-<REVISION>` artifact. That wheel is not a Mac wheel
and must not be installed on the Mac host.

## Installation gate

The CI candidate lock file has `null` values for `installed_sdk_artifact`,
`broker_image_digest`, and `agent_image_digest`. **Stop while any of these are
null.** A published kit fills them from a reviewed SDK wheel and the registry
manifests of broker and agent images built from this exact revision. Compare
its recorded SDK artifact SHA-256 with `artifacts/` and verify both image
digest references in the registry. The Compose variables `AP070_BROKER_IMAGE` and
`AP070_AGENT_IMAGE` must be full image digest references, not mutable tags.
A complete live `demo_co` Google export is supplied separately; a local or
partial export cannot activate the Google read path.
If the GHCR packages are private, authenticate Docker with an account allowed
to pull them before running Compose. Keep that registry credential outside
the kit and the agent directory.

The operator's Mac needs Docker Desktop with Compose, a dedicated Google
Workspace tenant, a Desktop OAuth client configured for the exact loopback
redirect `http://127.0.0.1:8765`, consent for the required employee accounts,
and an approved model API key. The tenant and export are provisioned by the
`demo_co` setup workflow. The operator must independently review and pin the
company, instance, fixture generation, dataset, Google customer/domain, exact
export digests, and provider verification evidence. These inputs are not
derived from this kit. No Google credential or provider administrator secret
belongs in the agent directory, this archive, or a public evidence report.

## Live layout after publication

Keep the following paths outside the extracted kit. Directories holding
operator secrets and broker state must be private to the host operator. The
model key file and employee/agent keys must have private file permissions.

| Environment variable | Host path or value |
| --- | --- |
| `AP070_BROKER_IMAGE` | Reviewed broker image digest reference |
| `AP070_AGENT_IMAGE` | Reviewed agent image digest reference |
| `AP070_RUNTIME_UID`, `AP070_RUNTIME_GID` | Host operator UID and GID |
| `AP070_BROKER_STATE_DIR` | Private broker database directory |
| `AP070_BROKER_PRIVATE_DIR` | Private broker configuration and custody files |
| `AP070_EXPORT_DIR` | Accepted immutable `demo_co` export directory |
| `AP070_AGENT_DIR` | Separate private agent key and task-package directory |
| `AP070_MODEL_API_KEY_FILE` | Private model API key file |
| `AP070_MODEL_ID` | Operator-approved model identifier |

The live broker private directory contains `pins.json`, `oauth.json`,
`fernet.key`, `trust.json`, and `receipt.seed`. The accepted export directory
contains `connections.json`, `access-expectations.json`,
`google-verification.json`, and independent scenario-result files under
`scenarios/`. The broker mounts these read-only; the agent mounts none of
them. The agent directory contains its own `agent.seed` and active `task.json`.
The relay image defaults to the digest in `versions.lock.json`; review that
digest before installation.

Once all gates are met, validate the resolved configuration before starting:

```sh
docker compose -f compose.yaml -f compose.live.yaml config --quiet
docker compose -f compose.yaml -f compose.live.yaml up -d \
  broker browser-relay agent-relay model-relay
```

The workbench is then available only at `http://127.0.0.1:8765`. The agent is
an on-demand separate process under the `task` Compose profile; run it only
after the employee has reviewed and activated a finite task. The broker image
contains the `auths-google-read-operator` and `auths-google-read-doctor` CLIs;
use their documented commands with private files mounted into a trusted
operator process. The operator root seed must never be mounted into the
long-running broker or agent. Record exact image digests, tenant evidence,
operator actions, and each live outcome in
`evidence/live-acceptance-template.md`. Any unrun or unknown case stays
pending. The `demo_co` independent oracle and Auths signed receipts must both
support the final result.
