# Auths Deployment Action Profile V1

**Profile:** `auths.deploy/1`  
**Media type:** `application/vnd.auths.deploy-action.v1+json`

The closed RFC 8785 JSON schema binds a lowercase environment and region, one
operation (`activate`, `deploy`, or `rollback`), lowercase SHA-256 artifact,
provenance, and configuration digests, an explicit strategy (`blue-green`,
`canary`, `immediate`, or `rolling`), an inclusive rollout window, and a
non-zero blast-radius request. Defaults, mutable tags, unknown fields, and
non-canonical encodings are rejected.

```text
capability = deploy/<operation>
resource   = deploy://<environment>/<region>/artifacts/<artifact digest>
budget     = numeric-ceiling-v1:<blast radius>
```

The verified decoder re-derives the exact permission and stateful budget.
Approval rendering includes all three digests, region, strategy, rollout
window, and blast radius. Any additional deployment dimension requires a new
reviewed profile version or verifier-local policy and must not be inferred.
