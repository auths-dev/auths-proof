# Status issuer scope

A verifier's trusted context lists the status issuers it accepts. Each rule
names a status method, an issuer, a sequence floor, and a **scope**: the trust
anchors under whose branches that issuer's statements count. The normative
definition is [AP-SPEC-064](../specs/0064-status-issuer-scope.md).

Scope matters when several organizations anchor roots at one verifier. Without
it, trusting a partner's root as a status issuer would also let that partner
revoke, or reinstate, your own principals and grants at your own boundary. With
it, a statement whose issuer's scope does not cover the branch's anchor takes
no part in that branch's status evaluation.

## The three scopes

| Scope | Counts in branches under | Use it for |
|---|---|---|
| `own` | anchors whose principal is the issuer | an organization's root, when that root is the organization's only anchor at the verifier |
| `anchors` | the listed trust-anchor IDs | an organization with several anchors, listing all of them; a status service or delegated issuer, listing the anchors it serves |
| `any` | every anchor | only your own organization's status authority, and only if you must also revoke partners' subjects at your boundary |

A statement from an issuer that no rule names is not governed by scope: it stays
visible and untrusted, and can still produce `status-issuer-untrusted`.

## Choosing scopes when you compile a context

1. **Count each organization's trust anchors at the verifier.** One
   organization can have several: approval-quorum members are depth-zero
   anchors, so a root and three managers are four anchors.
2. **One anchor:** give that root's rules scope `own`.
3. **Several anchors:** give the organization's status issuer scope `anchors`,
   listing every one of the organization's anchor IDs. `own` would leave its
   statements out of scope under the other anchors. Those anchors' own
   principals would then be `missing-principal-status`, which fails closed, but
   revocations of their delegates and actors would be silently ignored, which
   fails open.
4. **Partners:** `own` or `anchors`, never `any`.
5. **A status service:** `anchors`, listing the anchors of the organization it
   signs for.

A context is rejected at decode (`malformed-proof`) when an `own` issuer is no
anchor's principal, an `anchors` scope lists an ID the context does not hold,
or one issuer carries two different scopes in one snapshot.

Contexts compiled before scope existed no longer decode. Recompile them with
explicit scopes; there is no default.
