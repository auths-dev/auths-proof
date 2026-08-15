import Auths.Rich.Semantics
import Auths.Rich.Theorems

/-!
The authority model is defined in `Auths.Rich`.  This compatibility import
intentionally contains no scalar authority coordinates: identities are opaque,
sets are extensional `Finset` values, intervals and ceilings use their actual
relations, and chain state is separate from ordered authority scope.

## Root preservation

`ChainState` carries the trust root the authority is anchored at.  The
theorems below state, over all inputs, that a delegated authority still
descends from the same root as its parent — and, crucially, that an authority
which descends from no root can neither delegate nor authorize.
-/

namespace Auths.Authority

open Auths.Rich

/-- Every accepted edge leaves the child under the parent's trust root. -/
theorem delegation_preserves_trust_root {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (edge : delegates parent grantId grant child) :
    child.root = parent.root :=
  delegate_preserves_root edge

/--
Every accepted edge starts from an authority that itself descends from that
root, and leaves the child in the same condition.  This is the inductive
content that `delegation_preserves_trust_root` alone does not carry.
-/
theorem delegation_requires_and_preserves_rootedness {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (edge : delegates parent grantId grant child) :
    rooted parent ∧ rooted child :=
  ⟨delegate_requires_rooted_parent edge, delegate_preserves_rootedness edge⟩

/-- The first edge of a chain is issued by the root principal itself. -/
theorem first_delegation_comes_from_the_root {v : Vocabulary}
    {parent child : ChainState v} {grantId : GrantId v} {grant : Grant v}
    (fresh : parent.lastGrant = none)
    (edge : delegates parent grantId grant child) :
    grant.issuer = parent.root :=
  first_edge_is_issued_by_the_root fresh edge

/--
Every state reachable by any number of delegations descends from the single
root the chain started at.  Delegation can narrow authority; it can never
re-anchor it.
-/
theorem chain_descends_from_one_root {v : Vocabulary}
    {start : ChainState v} {rest : List (ChainState v)}
    (chain : DelegationChain start rest) :
    ∀ state ∈ rest, state.root = start.root ∧ rooted state :=
  fun state member =>
    ⟨chain_preserves_root chain state member,
      chain_preserves_rootedness chain state member⟩

/-- An authority that descends from no root delegates nothing. -/
theorem unrooted_authority_delegates_nothing {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v)
    (unrooted : ¬ rooted parent) :
    evaluateGrant parent grantId grant = .denied .brokenGrantChain :=
  unrooted_parent_delegates_nothing parent grantId grant unrooted

/-- An authority that descends from no root authorizes nothing. -/
theorem unrooted_authority_authorizes_nothing {v : Vocabulary}
    (authority : ChainState v) (action : Action v)
    (unrooted : ¬ rooted authority) :
    evaluateCoverage authority action = .denied .brokenGrantChain :=
  unrooted_authority_covers_nothing authority action unrooted

end Auths.Authority
