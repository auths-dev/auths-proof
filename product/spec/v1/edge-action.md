# Auths Edge-Control Action Profile V1

**Profile:** `auths.edge/1`  
**Media type:** `application/vnd.auths.edge-action.v1+json`

The closed RFC 8785 JSON schema binds lowercase fleet and device identifiers,
one command (`activate-firmware`, `apply-config`, `execute`, or `restart`), a
non-zero monotonic sequence, and an optional lowercase SHA-256 device-state
digest.

```text
capability = edge/<command>
resource   = edge://<fleet>/devices/<device>
```

Sequence consumption and stale-state prevention are stateful application
checks outside the proof kernel. Offline deployments must persist the sequence
window and required status checkpoints. The verified decoder rechecks the
exact canonical body and permission before producing a command; the approval
display includes fleet, device, command, sequence, and action digest.

