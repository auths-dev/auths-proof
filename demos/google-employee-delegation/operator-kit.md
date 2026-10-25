# AP-SPEC-070 operator kit candidate

This archive is a source-free candidate for the employee-to-agent Google read
demo. It contains Compose configuration, relay rules, a version lock, and a
blank live acceptance record. `REVISION` identifies the exact Auths commit
used to build the kit. The matching broker and agent images have been built
and probed in CI, but have **not** been published for an operator install.

## Verify the download

Download both files from the `google-read-operator-kit-<REVISION>` artifact of
the Google read demo installed images workflow. On a Mac, run:

```sh
shasum -a 256 -c google-read-operator-kit.tar.gz.sha256
tar -xzf google-read-operator-kit.tar.gz
cd google-read-operator-kit
shasum -a 256 -c SHA256SUMS
cat REVISION
```

Compare `REVISION` with the reviewed commit in the workflow run. The lock
file's `auths_base_revision` identifies an earlier SDK baseline, not this
kit's build revision. A passing checksum proves the downloaded
bytes match the workflow artifact; review the workflow run and commit before
trusting it. The separate `google-read-linux-wheel-<REVISION>` artifact is the
SDK wheel used to build the Linux images. It is not a Mac wheel and must not
be installed on the Mac host.

## Installation gate

The checked-in lock file has `null` values for `installed_sdk_artifact`,
`broker_image_digest`, and `agent_image_digest`. **Stop here while any of these
are null.** The kit cannot run the live demo without a reviewed published SDK
artifact and digest-pinned broker and agent registry images built from this
exact revision. The Compose variables `AP070_BROKER_IMAGE` and
`AP070_AGENT_IMAGE` must be full image digest references, not mutable tags.
The candidate also lacks a complete live `demo_co` Google export; a local or
partial export cannot activate the Google read path.

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
