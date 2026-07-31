# Security Policy

Auths `0.1.x` is pre-audit software. Do not use it as the sole production
authorization control.

Report vulnerabilities privately through the repository host's Security
Advisory feature. Include the affected commit, exact canonical MCP body and
proof where safe, reproduction, expected outcome, actual outcome, and impact.

In scope are canonical call mapping, MCP-to-Auths permission confusion,
challenge races and replay, authorization-before-execution, transport channel
binding, trust composition, denial semantics, and native/WASM divergence.

V1 supports only immediate `tools/call`. It does not provide key custody,
exactly-once execution, distributed replay storage, MCP task authorization, or
a generic gateway.
