# Security Policy

`auths-proof-exchange` `0.1.x` is pre-audit software. Do not use it as the
sole production authorization control.

Report vulnerabilities privately through the repository host's Security
Advisory feature. Include the affected commit, transport, input bytes where
safe, reproduction, expected outcome, actual outcome, and impact.

In scope are framing and sequencing, resource limits, challenge delivery,
peer-observation accuracy, Iroh ALPN and handshake behavior, timeout handling,
transport/protocol error confusion, and transport-independent conformance.

This repository transports opaque proofs. It does not decide Auths authority,
consume replay challenges, execute actions, manage keys, or operate Iroh relay
infrastructure. An authenticated transport peer is not an authorization
decision.
