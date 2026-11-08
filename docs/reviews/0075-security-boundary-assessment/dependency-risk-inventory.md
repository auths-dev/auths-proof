# Dependency advisory scope

Observed 8 November 2026 against main `ac5fcabe`: 15 open GitHub alerts
(eight high, six medium, one low). These are not dismissed or repaired by this
assessment. `dependency-triage.json` retains package/version/manifest/advisory
identities and the selected-path disposition. A successful cargo-deny job is
not evidence that every GitHub/Python advisory has been closed.

## Selected gateway versus other consumers

| Package and current pin | Actual selected-path observation | Disposition |
| --- | --- | --- |
| `hickory-resolver 0.26.1`, `Cargo.lock:3513` | `cargo tree --locked -p auths-gateway -i hickory-resolver` finds no such package in the gateway graph. The workspace inverse graph reaches iroh/iroh-dns/iroh-relay, exchange adapters and demos. | Resolver retry, DNSSEC-status and extra-CNAME advisories remain open for those consumers. No selected gateway exploit is established. The upstream patched version is 0.26.2. |
| `rmcp 1.8.0`, `Cargo.toml:269` | Present through `auths-profile-mcp`; active features are `server` and `transport-async-rw`. `product/profiles/auths-profile-mcp/src/lib.rs:21` consumes the request model. OAuth and Streamable HTTP modules are feature-gated and not enabled in the selected gateway graph. | Session-manager, OAuth metadata and HTTP redirect-header advisories are not demonstrated reachable through this gateway. This is not an assertion about all consumers or future feature combinations. |
| `cryptography 45.0.7` and `pytest 8.4.2` | Pinned by `demos/cross-company-incident-response/agent-service/requirements.txt:1`. The selected installed Auths wheel has no project runtime dependencies on either package in `bindings/python/pyproject.toml`. | Other-service maintenance remains open. Do not credit a narrow gateway assessment with securing that Python service. |

Upstream primary references: [Hickory retry advisory](https://github.com/advisories/GHSA-6w6g-hm98-mhgm),
[DNSSEC advisory](https://github.com/advisories/GHSA-5j98-2g5x-46v6),
[CNAME advisory](https://github.com/advisories/GHSA-6f2x-v7q7-m7m5),
[RMCP session advisory](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-9pj6-vhgr-3mwh),
[RMCP metadata validation](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-33f5-2c5q-wgwj),
[RMCP metadata fetch](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-c9xm-49cp-xcr9),
and [RMCP redirect headers](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-9g45-5xwm-f3wc).
The Rust package source and resolved feature graph corroborate the selected-path
classification. This is source/graph review, not a reproduction of every upstream
exploit or an audit of each affected alternative integration.

## Central maintenance boundary

Upgrade or reduce dependencies through the existing workspace owners and shared
lockfile, with the affected exchange/profile/consumer tests and architecture
snapshots kept together. Do not add per-gateway advisory suppressions or runtime
switches to pretend vulnerable package versions disappeared. Prefer a separate
bounded maintenance change for the affected nonselected consumers; this assessment
does not authorize a universal dependency/API migration to manufacture a clean
alert counter. Reassess applicability if any relevant feature is enabled.

The current prelaunch and unqualified-release recommendation remains unchanged.
No whole-repository clean-advisory or production-security claim is supported.
