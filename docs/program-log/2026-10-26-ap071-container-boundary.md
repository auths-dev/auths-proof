# AP-071 installed Linux container boundary probe — 26 October 2026

The Docker daemon became available after the candidate topology was written.
I built an ARM64 Linux gateway and native Python wheel from clean source commit
`f58e343b66ce8dccefc79c88cc3adfbda74f6dc3`, then built the installed
agent image with the current `isolation_probe.py`. The probe source was an
uncommitted change at image-build time; its SHA-256 was
`d16dbc2f9b06ab65b362666228c8506111ff727e21a3a9e22514a7324e3539e0`.

| Input or image | SHA-256 or local OCI manifest digest |
| --- | --- |
| Linux `auths-gateway` binary | `9ee6e30fd4c091e31d5aa2360777c7dc1d1811f81c6dacf37cd2a59f9cd71dac` |
| `auths-0.0.1rc1-cp39-abi3-manylinux_2_34_aarch64.whl` | `b6828d57f82ece9e22b7b54e3a9ed976bb0138c793705419738d5316e6bb9a19` |
| Gateway image `auths-ap071-gateway` | `sha256:c75199c81c88487e9c71aa482ec998ad88c21b43d2993f4ef28f52e0f46341db` |
| Agent image `auths-ap071-agent` | `sha256:eb5844b3c8ea7121ae19bd374809609aa106bdcfdc6dc541abba4aba72d7810a` |
| Revised Compose file | `e2115133dd0b6254576093a7d142a6c3ee694c63067a98f0f54f6f52635fbca1` |

The gateway build used `rust:1.97.1-bookworm` on `linux/arm64` with
`cargo build --locked --release -p auths-gateway --bin auths-gateway`. The
native wheel used `maturin==1.9.6` and the checked-in `python-extension`
profile. The gateway image verified its binary digest and ran `--help`; the
agent image installed the Linux native wheel and agent wheel, passed
`pip check`, and imported `auths._native` with ABI version 2. Both images
were referenced by their local OCI manifest digests in Compose. These are
local image pins, not registry-published image digests.

The initial host-directory `/channel` mount was **not viable** on Docker
Desktop: the socket path appeared across containers, but `chmod` on the
agent-created Unix socket returned `EINVAL`. The installed receiver requires
that operation before listening. An owner-private external Docker volume
fixed the filesystem behavior. The volume root was initialized to UID 501,
GID 20 and mode `0700` by a one-off root container; both running services
used UID 501 with no added capabilities. The gateway mounted the volume
read-only and the agent mounted it read-write. A real `0600` Unix socket
created by the agent accepted a gateway-container connection and returned an
acknowledgement. The probe socket was removed after the exchange.

The installed agent's `auths.ap071-agent-isolation-probe/1` reported
`passed: true`: `/agent` and `/channel` were owner-private; `/gateway-state`,
`/operator` and the Docker socket were inaccessible; no non-loopback
interface was active; and a direct outbound TCP connect returned network
unreachable. The namespace IDs differed between containers: agent PID
`4026533952`, network `4026533959`; gateway PID `4026533833`, network
`4026533835`. Docker inspection showed `network_mode: none` and a read-only
root filesystem for the agent, while the gateway alone mounted state and
operator inputs and had the provider-egress network. Canary files in those
gateway-only mounts were invisible to the agent; the agent's own canary was
visible. As a negative control, the same installed agent image on the
provider-egress network detected active `eth0`, permitted egress and exited
with `passed: false`.

The two Compose containers, test network, external channel volume and
disposable host canary directories were removed after the probe. The local
image and build-artifact pins remain available for a subsequent task run.

This proves the installed image and Compose **boundary and Unix channel** on
this host. No AP-071 task or provider request ran inside these containers;
there is no container read/write receipt or provider-count claim yet. The
earlier source-free macOS Airtable run established a managed read/write path
under a different OS sandbox. A Linux container task run, production custody
and the revised-recipe Jules Google run remain required for full acceptance.
