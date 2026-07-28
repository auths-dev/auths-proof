# About the Kubernetes rollout demo

The demo proves that an agent can propose a useful Kubernetes change without
receiving reusable cluster authority. A human authorization covers one exact
Deployment UID, immutable image digest, namespace, replica count, evidence
snapshot, executor audience, and verifier configuration. The protected service
can apply only that exact change once.

The workbench makes the boundary visible. Users can run the exact rollout, then
change one security-relevant fact and see where it stops. Authorized execution
shows the Kubernetes API acceptance, persisted Deployment state, rollout
convergence, and replay claim together. Denied variants show that no mutation
credential was requested and no protected Kubernetes call occurred.

This is not a replacement for Kubernetes authentication, RBAC, admission, or
audit logs. It changes who receives reusable authority: the agent receives
none, while a narrowly scoped executor combines Kubernetes controls with an
exact signed-action check and durable replay protection.

The complete demonstration can run either through Vercel, Fly.io, and a
reachable Kubernetes cluster or entirely on one Docker host with Kind. The
local mode preserves the security-relevant boundaries: separate browser,
executor, and Kubernetes components; separate evidence and mutation
identities; real API admission; durable replay claims; and real workload
convergence. It is not a static-file simulation.

## Future Work

A production product would make the current vertical configurable without
weakening its exact-action semantics:

- support multiple clusters and workload kinds through separately versioned
  profiles rather than one permissive generic patch profile;
- integrate short-lived workload identity and TokenRequest credentials instead
  of long-lived ServiceAccount tokens;
- replace the single-machine claim file with a transactional replicated claim
  store and signed, externally durable receipt log;
- bind Kubernetes audit events back into execution receipts and expose
  verification tooling for operators;
- use watch-based rollout observation with bounded reconnect and
  resourceVersion handling;
- add policy distribution, approval UI, identity lifecycle, revocation, and
  operator-grade incident controls;
- package the dry-run-only inspector admission policy as an installable,
  versioned controller or Helm chart;
- test against several conformant Kubernetes distributions and admission
  stacks;
- add controlled failure injection for API timeouts, executor crashes,
  Deployment recreation, admission changes, and partial rollout failures;
- preserve the Auths site design language while adding an operator view for
  claims, receipts, cluster identity, and configuration drift.

Productization should keep `auths-kubernetes` as one coherent vertical package.
New Kubernetes capabilities should be added as explicit profiles and narrow
ports inside that package, not scattered across generic product folders or
implemented directly in the demo.
