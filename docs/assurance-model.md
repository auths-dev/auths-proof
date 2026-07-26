# Assurance model

Cryptographic validity and authorization are not synonyms. A successful
principal adapter returns canonical `AssuranceClaim` values and an
`ParticipantAssurance` report that records the exact principal, chain role,
adapter ID/version, and consumed evidence.

`AssuranceRequirement` has no implicit role-only interpretation. It always
contains:

- a role selector (`Root`, `Intermediate`, `Actor`, or `ExternalIssuer`);
- an explicit `Any` or `Every` quantifier;
- an exact claim kind;
- optional parameter, evidence-source, adapter, adapter-version, and freshness
  constraints.

`Every` requires every report selected by the role to satisfy the requirement.
`Any` requires at least one. Both fail when the selected role has no
participant. The portable result records every satisfaction needed to audit
the chosen quantifier.

## Historical state is not statement time

`historical-at` says a controller key was valid at a time.
`statement-existence-proven-at` says the exact Auths signing preimage existed by
a time. A revoked key can backdate `issued_at`, so an archival policy normally
needs both claims.

## Adapter ceilings

- Raw key and `did:key` establish `self-certifying-identifier` and
  `offline-verifiable`; they do not establish rotation or revocation.
- `did:keri` additionally establishes `rotation-aware` for transferable state.
  A verifier-bound current checkpoint can establish
  `controller-state-current-at`, `revocation-checked-at`, and, where recorded,
  `witness-threshold-met`.
- `did:web` requires verifier-bound trust records. Current records can
  establish current-state and revocation-check claims. Historical records can
  establish historical state, and only an exact statement pin establishes
  statement existence.
- WebAuthn, HSM-attested, and SPIFFE/X.509 claims are limited to the exact
  verifier-bound credential, attestation, trust, and status records.

The executable registry commits all of this decision-affecting configuration
to `VerifierConfigurationId`. A context/configuration mismatch is a stable
denial; the verifier never falls back to a weaker adapter.

Applications construct explicit `AssurancePolicy` values. There is no default
policy profile and no implicit upgrade from `Indeterminate` to authorization.
