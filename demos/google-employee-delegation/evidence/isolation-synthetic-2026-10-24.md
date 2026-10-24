# Synthetic container isolation probe · 24 October 2026

This probe exercised the repository's Compose networks and relay configs with
`python:3.12-slim` as a synthetic broker and agent. The broker returned only
the request path and Host header. The model key file contained a synthetic
placeholder. No Google, model, employee credential or Auths proof was used.

The probe used project name `ap070-isolation-probe`, the pinned Nginx image
`nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`,
and a temporary Compose override to replace only the unavailable installed
broker and agent images. All probe containers and networks were removed after
inspection.

| Observation from agent container | Result |
| --- | --- |
| Connect to `agent-relay:8080` | connected |
| Connect to `model-relay:8080` | connected |
| Connect directly to `broker:8765` | blocked |
| Connect directly to `www.googleapis.com:443` | blocked |
| POST `/api/v1/tasks/challenge` through agent relay | forwarded; mock broker returned 200 |
| POST `/api/v1/tools/call` through agent relay | forwarded; mock broker returned 200 |
| GET `/api/v1/session` through agent relay | 404 |
| POST `/api/v1/session/logout` through agent relay | 404 |
| GET `/api/v1/receipts/example` through agent relay | 404 |
| `/state`, `/private`, `/var/run/docker.sock` in agent | absent |
| `/agent` in agent | present, read-only mount |

The forwarded requests reached the mock broker with Host
`127.0.0.1:8765`. From the Mac host, the browser relay on
`127.0.0.1:8765` returned 200 for `/api/v1/session` with that same Host.
`docker inspect` showed the agent attached only to `agent_private`, with the
read-only `/agent` mount and its own model-key secret, `ReadonlyRootfs=true`,
`CapDrop=[ALL]` and `no-new-privileges:true`.

The first probe exposed a relay startup failure: root-run Nginx attempted
`chown` after all capabilities were dropped. The Compose config now runs all
three relays as UID/GID 101 with UID-owned tmpfs mounts. All relays then stayed
running and the observations above passed.

This proves only the tested synthetic deployment properties. Installed Auths
broker/agent images, actual authorization and denial routes, secret custody,
real model requests, Google access, restart behavior and live provider tests
remain unverified. The full AP-SPEC-070 isolation and live acceptance claims
are still open.
