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

Pre-effect attack responses include the delta of credential acquisitions and provider calls, and are considered blocked only when both remain zero. The ambiguous post-effect case instead proves one provider entry, zero retry entries, and a native transition from `outcome-unknown` to `reconciled-committed`.

Trust assumptions are deliberately narrow: local dummy keys and certificates are generated on launch, the service endpoints accept only one closed incident and two closed effects, and cloud resources are demo-labelled. The demo does not claim an independent security review, production custody, highly available storage, or production identity-provider configuration.
