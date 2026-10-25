# Installed-container isolation probe · 24 October 2026

[Hosted run 40138422959](https://github.com/auths-dev/auths-proof/actions/runs/40138422959)
built the Linux Auths SDK wheel from branch source, verified its SHA-256 while
building separate broker and agent images, and started those images with the
repository's Compose layout. Its CI-only probe ran inside the installed agent
image. Every step in that job passed.

The broker's browser relay returned an `auths.employee-session/v1` response.
From the agent container, the two intended relays accepted connections;
direct connections to `broker:8765` and `www.googleapis.com:443` failed. A
challenge POST reached the unconfigured broker through the agent relay and
returned its expected denial. Session, logout and receipt routes returned
404 from that relay. The broker state and operator paths and Docker socket
were absent in the agent container. Its `/agent` mount was read-only, and its
own model-key secret mount was present. The CI model key contained only a
synthetic placeholder.

This probe used no live Google tenant, OAuth credential, Auths grant, read
proof, provider document or model call. It establishes the tested installed
image and Compose boundary behavior, not a completed AP-SPEC-070 live scenario.
The images were not published to a registry, so the lockfile's broker and
agent manifest digests remain empty.
