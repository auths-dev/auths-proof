# Cross-company incident response design

## UX

The control room is one incident workspace with an explicit company switcher.
Northstar and EdgeShield see the same committed plan and receipts, while actor
cards, authentication evidence, signing suites, and company-owned operations
remain visibly separate.

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

The primary flow is generate outage, collect read-only diagnostics, construct
the two-step firewall/cache plan, review it, obtain one approval from each
company, execute once, and compare Python and TypeScript verification. Review,
approval, authorization, delivery, provider outcome, and observation are
separate states in the UI.

## Architecture

```text
                           portable Auths fixture
                         +-------------------------+
                         | Python verify = TS verify|
                         +------------+------------+
                                      |
+-------------------+       HTTPS     v      HTTPS       +--------------------+
| Vercel control    | <----------> Python agent  <-----> | Northstar service  |
| room + TS SDK     |              orchestrator          | OIDC + P-256       |
+---------+---------+                    |                | own state + key    |
          | sealed TS command            |                +--------------------+
          | gateway callback             |
          v                              | bounded opaque envelope
  Rust-owned edge profile                v
                              +----------------------+      +------------------+
                              | real Iroh bridge     | ---> | EdgeShield       |
                              | no Auths semantics   |      | client-cert auth |
                              +----------------------+      | Ed25519 + state  |
                                                            +------------------+
```

Northstar, EdgeShield, and the orchestration service have different data
directories, configuration prefixes, service credentials, identity providers,
and signing material. The Iroh bridge transports bounded opaque bytes and
reports peer/path evidence; it cannot authorize them. The browser SDK mints
effect-capable commands only after local Auths verification and passes them to
a closed profile gateway. Provider calls happen inside that gateway callback.
The Python service independently verifies portable artifacts and owns durable
replay, execution, and receipt projections.

## APIs

- Northstar: OIDC discovery, authorization-code/PKCE token exchange, actor and
  diagnostic evidence, exact firewall apply, approval, health.
- EdgeShield: client-certificate actor authentication, exact cache purge,
  approval, key rotation, actor/status inspection, health.
- Agent orchestrator: incident state, deterministic reset, proposal, exact
  operation execution, portable Python verification, attacks, receipts, health.
- Iroh bridge: one closed exchange route accepting a bounded incident envelope
  and returning delivery evidence. It never returns an authorization verdict.
- Control room: static Vercel application. The TS SDK performs profile
  canonicalization, plan commitment, threshold approval, sealed authorization,
  gateway handoff, and portable verification in-browser.

All effect routes select one closed demo operation. None accepts arbitrary
URLs, methods, headers, credentials, shell commands, firewall text, or cache
targets.
