# Cross-company incident response design

## UX

The control room is one incident workspace with an explicit company switcher. Northstar and EdgeShield see the same committed plan and receipts, while actor cards, authentication evidence, signing suites, and company-owned operations remain visibly separate.

```text
+--------------------------------------------------------------------------------+
| INC-2026-0811 · eu-west-2 · checkout outage             [Northstar|EdgeShield] |
+----------------------+----------------------------------+----------------------+
| actors + lifecycle   | authority graph + exact plan     | live timeline        |
| P-256 / Ed25519      | review -> 2-of-2 -> execute      | transport + receipts |
+----------------------+----------------------------------+----------------------+
| attack lab: widening · mutation · replay · expiry · revoke · rotate · failures |
+--------------------------------------------------------------------------------+
```

The primary flow is inspect the outage, review the diagnostic agent's bounded proposal, ask the trusted backend to construct the two-step firewall/cache plan, obtain one authenticated approval from each company, execute once, and compare Python and TypeScript verification. Review, approval, authorization, reservation, credential acquisition, delivery, provider outcome, and receipt observation are separate states.

## Architecture

```text
                           Rust-generated fixture
                         +-------------------------+
                         | Python verify = TS verify|
                         +------------+------------+
                                      |
+-------------------+       HTTPS     v      HTTPS       +--------------------+
| control room      | -----------> Python trusted <----> | Northstar service  |
| + TS verification |              effect service        | OIDC + P-256       |
+---------+---------+                    |                | own state + key    |
          | no authority handle          |                +--------------------+
          |                              | exact canonical bytes
          v                              v
  portable verification       +----------------------+      +------------------+
                              | real Iroh adapter    | ---> | EdgeShield       |
                              | no Auths semantics   |      | certificate gate |
                              +----------------------+      | Ed25519 + state  |
                                                            +------------------+
```

Northstar, EdgeShield, and the trusted effect service have different data directories, credentials, identity systems, and signing material. The Iroh adapter transports bounded bytes and reports peer/path evidence; it cannot authorize them.

The browser never mints or receives an effect-capable command. The Python service owns native authorization, opaque command consumption, durable replay and execution state, provider credential timing, and native signed receipts. The browser uses TypeScript to verify the same Rust-generated portable artifacts and receipt projections used by Python.

## APIs

- Northstar: OIDC discovery, authorization-code/PKCE token exchange, actor and diagnostic evidence, exact firewall apply, authenticated approval, reset, health.
- EdgeShield: certificate-gated actor authentication, exact cache purge, signed approval, key rotation, Iroh exchange, reset, health.
- Trusted effect service: incident state, proposal, one closed workflow execution, receipt retrieval, deterministic reset, adversarial cases, health.
- Control room: static application that requests the closed workflow and displays decisions, state, effects, and receipts.

All effect routes select one closed demo operation. None accepts arbitrary URLs, methods, headers, credentials, shell commands, firewall text, cache targets, approval booleans, tickets, or serialized verified commands.
