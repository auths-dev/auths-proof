# Architecture and trust boundaries

Auths owns the authority decision. Application adapters establish OIDC identity, certificate possession, approval signatures, delivery observations, and provider outcomes. None of those facts becomes authorization by itself.

| Boundary | Owner | Authentication / signing | Persistence | May do |
| --- | --- | --- | --- | --- |
| Control room | joint incident view | no authority custody; TypeScript verification only | browser memory | propose, request execution, display decisions and receipts |
| Northstar | Northstar Commerce | authorization code + PKCE; P-256 ES256 OIDC tokens | `northstar.json` | diagnostics, exact-plan approval, one exact firewall effect |
| EdgeShield | EdgeShield | certificate fingerprint gate; Ed25519 approval signature | `edgeshield.json` | exact-plan approval, one exact cache effect, key rotation, Iroh delivery |
| Agent service | trusted effect service | process-scoped demo root, agent, and receipt keys | `agent.sqlite3` | native authorization, durable reservation, credential acquisition, provider entry, receipts, reconciliation |
| Iroh adapter | transport only | authenticated endpoint IDs and exact ALPN | none | deliver bounded bytes and report delivery evidence |

```text
untrusted browser request
          |
          v
trusted Python service
  |-- Rust canonical Edge actions + ordered plan
  |-- bounded raw-key grant and native proof assembly
  |-- Northstar OIDC approval -----> P-256 JWT verification
  |-- EdgeShield approval ---------> Ed25519 digest verification
  |-- Rust authorization
  |-- opaque native plan command
  |-- SQLite BEGIN IMMEDIATE reservation
  |-- provider credential acquisition
  |-- provider entry
  |     |-- HTTPS ------> Northstar firewall
  |     `-- exact bytes --> Iroh --> EdgeShield cache
  `-- Rust-owned signed decision and execution receipts
```

The native command exists only between authorization and the profile gateway in the trusted process. The public API does not accept a ticket, approval boolean, serialized verified command, arbitrary provider URL, header, credential, firewall text, or cache target.

## Plan and lifecycle

The remediation authority names two exact resources under `edge://northstar`, one audience, and a ten-minute validity window. The native plan commits the firewall member before the cache member and allows one execution per member.

For each member, the gateway orders operations as follows:

```text
reserve -> authorize credential -> acquire credential -> enter provider
        -> execute -> canonicalize result -> attest receipt -> finish
```

SQLite uses an immediate transaction, unique idempotency keys, unique command commitments, plan-member order, and the Rust `RuntimeKernel` for transitions. Concurrent ownership cannot pass reservation twice.

An ambiguous provider response transitions to `outcome-unknown`. A new command cannot reacquire credentials or enter the provider for the same identity. A fresh matching observation is required to reach `reconciled-committed` or `reconciled-released`.

## SDK boundary

Rust owns canonical action encoding, proof verification, commitment derivation, plan commitment, lifecycle transitions, receipt encoding, receipt IDs, and signing preimages.

TypeScript and Python own idiomatic ports around those semantics:

- durable execution state;
- provider credential acquisition;
- provider invocation;
- canonical result production;
- receipt attestation.

Both SDKs retain exact canonical bytes downstream and expose opaque single-use command handles. Rust-generated differential fixtures freeze the full workflow and receipt projections across both languages.

## Deployment boundary

The local SQLite adapter is deliberately single-process. Hosted state is ephemeral. Production use requires external durable storage, HSM/KMS custody, pinned receipt trust, real organizational identity-provider configuration, certificate termination, reconciliation workers, audit retention, monitoring, and incident operations.
