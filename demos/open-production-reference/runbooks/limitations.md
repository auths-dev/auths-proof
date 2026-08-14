# Public limitations

The reference deployment demonstrates a safe assembly and reproducible
operator path. It does not provide:

- tenant onboarding, billing, fleet management, or a hosted control plane;
- arbitrary provider plugins or arbitrary JSON policy execution;
- managed key recovery, organizational break-glass, or credential issuance;
- an enterprise audit portal, retention service, or compliance certification;
- automatic database migrations or backward-compatible candidate cutovers;
- proof that a customer's provider configuration is correct;
- business-intent decisions or permission that was not explicitly granted; or
- an independent security review or a completed thirty-day qualification run.

The local software signer and deterministic gateways are evaluator-only. They
are rejected by production configuration. Production applications must compose
the node with the qualified PostgreSQL lifecycle store, external KMS or PKCS#11
custody, and explicit exact-effect provider ports.
