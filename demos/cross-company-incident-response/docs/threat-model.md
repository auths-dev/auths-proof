# Threat model

| Attack | Real Auths path exercised | Expected boundary |
|---|---|---|
| widen one region to all regions | Rust-owned child grant planner through Python SDK | `delegation-expanded` before signing |
| mutate firewall byte | three-input verifier in Python and TypeScript | `action-mismatch` / invalid signature before execution |
| replay command | Python `RuntimeKernel.replay` plus durable receipt lookup | `exact-replay`; no second provider call |
| expired grant | Rust-owned runtime transition with `not_expired=false` | `grant-expired` before credential/provider entry |
| revoke approver | lifecycle status/rotation authoring projection plus runtime gate | `principal-revoked` before execution |
| rotate EdgeShield key | Python lifecycle `rotate_identity` | old principal superseded, new principal active |
| unauthorized Iroh delivery | real `auths-iroh` byte exchange followed by verifier denial | delivery succeeds; authorization fails |
| remote failure before execution | Rust-owned runtime transition | released, safe retry |
| remote failure after execution | Rust-owned runtime transition | committed receipt, never retry blindly |
| remote unknown outcome | Rust-owned runtime transition | `outcome-unknown`, reconciliation required |
| withdraw approval mid-plan | bounded plan approval session | completed member retained; next member cancelled |

Trust assumptions are deliberately narrow: local dummy keys and certificates
are generated on launch, service endpoints accept only closed incident IDs and
operations, and cloud resources are demo-labelled. The demo does not claim an
independent security review or production custody.
