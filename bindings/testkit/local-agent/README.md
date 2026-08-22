# Disposable local-agent installed-artifact proof

This is the repository-owned launch proof for AP-SPEC-040. The runner builds
the separately named synthetic testkit agent, installs the packed TypeScript
and Python SDK/profile artifacts into clean temporary consumers, then proves:

- a fresh generated Stripe call without an application token or credential;
- cross-language exact replay with no second provider mutation;
- changed-input conflict preserving the original possible-effect identity;
- signed portable decision/execution receipt retrieval and verification in
  both SDKs; and
- replay after the local agent is stopped and reopened on its durable state.

The testkit provider result and connection credential are synthetic. This is
not production Stripe evidence and the agent refuses to run as the production
service binary.

Run the complete journey from the repository root:

```bash
node bindings/testkit/local-agent/run.mjs
```
