# Architecture and trust boundaries

Auths owns the authority decision. Demo adapters establish OIDC subjects,
client-certificate possession, transport observations, and provider outcomes.
Those facts never become authorization by themselves.

| Boundary | Owner | Authentication / signing | Persistence | May do |
|---|---|---|---|---|
| Control room | joint incident session | ephemeral bounded agent signer; TypeScript Auths SDK | browser memory only | review, request threshold approval, submit sealed commands |
| Northstar | Northstar Commerce | local OIDC authorization code + PKCE; P-256 OIDC and Auths/WebAuthn identities | `northstar.json` | diagnostics, Northstar approval, one exact firewall change |
| EdgeShield | EdgeShield | client-certificate fingerprint challenge; Ed25519 Auths identities | `edgeshield.json` | EdgeShield approval, one-region cache purge, key rotation |
| Agent service | neutral incident orchestration | per-service bearer values only on closed internal routes | `agent.sqlite3` | evidence synthesis, Python verification, replay/runtime state, receipts |
| Iroh bridge | transport adapter | authenticated Iroh endpoint IDs and ALPN | none | deliver bounded opaque bytes and report delivery evidence |

```text
Northstar OIDC subject --app adapter--> P-256 Auths actor
Edge client certificate --app adapter--> Ed25519 Auths actor
                                          |
                                         grants
                                          v
diagnostic agent (read only)     remediation agent (eu-west-2, 10 min, 2 uses)
                                          |
                            all-of Northstar + Edge approvals
                                          |
                         exact firewall/cache plan commitment
                                /                      \
                             HTTPS                  Iroh ALPN
                               |                        |
                     Northstar provider       EdgeShield provider
                               \                        /
                              independently verifiable receipts
```

The diagnostic agent never receives an execution permission. The remediation
authority names two exact resources in `eu-west-2`, expires after ten minutes,
has a numeric ceiling of two, and has no remaining delegation depth. The plan
is an ordered commitment; approval is bound to the plan and cannot be reused
for different members. Network success is shown as delivery evidence only.
