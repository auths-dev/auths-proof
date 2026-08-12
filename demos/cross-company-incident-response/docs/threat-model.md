# Threat model

| Attack | Executable path | Expected boundary |
| --- | --- | --- |
| widen one region to all regions | Rust child-grant planner through Python | `delegation-expanded` before signing; zero credentials/provider calls |
| mutate a canonical action byte | Python and TypeScript native verifiers | fail closed before execution; zero credentials/provider calls |
| replay a completed workflow | full backend authorization and SQLite reservation | conflict; zero additional credentials/provider calls |
| race two workflow requests | two full authorization and execution attempts | one winner; one provider call per plan member total |
| use expired authority | Rust lifecycle transition | `grant-expired` before credentials/provider entry |
| use a compromised approver | Rust lifecycle status gate | `principal-revoked` before execution |
| rotate the EdgeShield key | Python lifecycle recipe and live Edge service | previous principal superseded; current principal active |
| deliver unauthorized bytes over Iroh | real Iroh exchange followed by native denial | delivery succeeds; no opaque command or provider effect |
| fail before provider effect | Rust lifecycle transition | released; retry may be safe |
| observe a definite effect | Rust lifecycle transition and native receipt | committed; never retry blindly |
| lose response after effect | real Northstar effect plus lost response | `outcome-unknown`; retry blocked; explicit reconciliation required |
| withdraw approval mid-plan | bounded plan approval session | completed approval retained; no second member command |
| read receipts without authentication | unauthenticated or invalid bearer request | verified opaque commitments only; disclosure is not loaded or decrypted |
| use operator access to recover exact material | Northstar commander OIDC request | profile-owned summary only; no command, result, receipt bytes, or key material |
| move disclosure ciphertext across receipts or tenants | AES-GCM reveal with mismatched authenticated context | decryption fails before native inspection |
| mutate disclosed command, result, profile, or receipt binding | Rust-owned disclosure inspection | stable typed failure; no partial summary or full view |

Pre-effect attack responses include the delta of credential acquisitions and provider calls, and are considered blocked only when both remain zero. The ambiguous post-effect case instead proves one provider entry, zero retry entries, and a native transition from `outcome-unknown` to `reconciled-committed`.

Trust assumptions are deliberately narrow: local dummy keys and certificates are generated on launch, the service endpoints accept only one closed incident and two closed effects, and cloud resources are demo-labelled. The hosted agent uses a stable Fly secret for disclosure encryption but does not claim production envelope encryption, independent key rotation, retention policy, an independent security review, production custody, highly available storage, or production identity-provider configuration.
