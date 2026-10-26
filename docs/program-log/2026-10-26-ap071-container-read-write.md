# AP-071 installed container read and write — 26 October 2026

A source-free installed Airtable task completed across the AP-071 Docker
gateway and agent containers. This extends the earlier [boundary
probe](2026-10-26-ap071-container-boundary.md) from mount and socket checks to
one managed provider read, authenticated delivery and exact-confirmed write.
The human signer was synthetic and the provider credential was an
operator-held PAT. This run establishes the local container mechanism, not an
employee-bound Airtable identity or production credential custody.

The 33-wheel bundle was installed offline from
`/private/tmp/ap071-airtable-container-bundle-v3-20261026`. Its
`manifest.json` SHA-256 was
`7a8875963914f7ede085fea3221fe97f7e110b7ace42cbec6953799f22310c27`.
The installed local OCI image digests were gateway
`sha256:c75199c81c88487e9c71aa482ec998ad88c21b43d2993f4ef28f52e0f46341db`
and agent
`sha256:eb5844b3c8ea7121ae19bd374809609aa106bdcfdc6dc541abba4aba72d7810a`.
The gateway binary in the Linux image had SHA-256
`9ee6e30fd4c091e31d5aa2360777c7dc1d1811f81c6dacf37cd2a59f9cd71dac`.
These are local image pins, not registry publication or production
qualification. The bundle runner checked its manifest before installing and
invoking the container case. No checkout module was imported by the runner or
the installed containers.

The agent container had `network_mode: none`, a read-only root filesystem,
its own `/agent` mount and a private Docker volume for `/channel`. The gateway
alone mounted `/gateway-state` and read-only `/operator`, with provider
egress. `docker inspect` verified those mounts and the installed agent
isolation probe passed before record creation. The operator created a
disposable Airtable record and retained a separate cleanup journal. Its
baseline `DemoStatus` was `Pending`. A synthetic human signed task
`8SgI-xIjgqXWWCjEX7Qj3ZnB` for a different registered agent key, one
record-scoped read and one exact-confirmed write.

The installed agent signed the read inside its container and listened on the
private Unix socket. The Linux gateway made one permitted Airtable GET,
projected the seven-byte field, and recorded `agent-acknowledged`. The agent's
private output contained the expected `Pending` value. It then signed the
listed `Approved` write inside its container. The synthetic human exact-signed
that action after a fresh `Pending` preflight. The Linux gateway submitted one
PATCH. Independent operator GET found `Approved` with the expected effect
echo. The final gateway task ledger recorded one provider read, one release,
seven released bytes and one write. Replaying the same signed read and write
returned `not-entered`; all four counters remained unchanged.

The redacted receipt is
`/private/tmp/ap071-airtable-container-live-20261026/operator/redacted-result.json`,
SHA-256
`b7165d4974cf974af678e12ddaaac8d393139c93ab5c7a8ee18fc7060ebbcdb0`.
A separate manifest-checked cleanup retired the run-owned record and updated
the receipt to `run-owned-record-retired`. The [case
manifest](2026-10-26-ap071-installed-case-manifest.json) joins the bundle,
task and receipt pins. The private PAT, record field bytes, agent key and
provider responses are absent from the committed evidence. The two test
containers, Compose network and private channel volume were removed after
the replay checks; the pinned bundle and private run root remain on this host.

The run used the static development credential path inside the gateway
container. It did not prove the revised Jules Google source-backed custody
materializer, the provider-final v2 observation, or a production multi-host
isolation deployment. Those remain acceptance work.
