import Auths.Base
import Mathlib.Data.Finset.Basic

namespace Auths.Rich

universe u

/--
The opaque carriers used by the authority model.

The model deliberately knows nothing about strings, byte arrays, allocation,
or canonical CBOR.  A production refinement supplies these carriers with the
exact Aeneas-translated Rust model types.
-/
structure Vocabulary where
  PrincipalCarrier : Type u
  ProfileCarrier : Type u
  PermissionCarrier : Type u
  AudienceCarrier : Type u
  DigestCarrier : Type u
  BudgetAlgebraCarrier : Type u
  StatusMethodCarrier : Type u
  AssuranceCarrier : Type u
  GrantIdCarrier : Type u
  principalDecidableEq : DecidableEq PrincipalCarrier
  profileDecidableEq : DecidableEq ProfileCarrier
  permissionDecidableEq : DecidableEq PermissionCarrier
  audienceDecidableEq : DecidableEq AudienceCarrier
  digestDecidableEq : DecidableEq DigestCarrier
  budgetAlgebraDecidableEq : DecidableEq BudgetAlgebraCarrier
  statusMethodDecidableEq : DecidableEq StatusMethodCarrier
  assuranceDecidableEq : DecidableEq AssuranceCarrier
  grantIdDecidableEq : DecidableEq GrantIdCarrier

structure Principal (v : Vocabulary) where
  value : v.PrincipalCarrier

structure Profile (v : Vocabulary) where
  value : v.ProfileCarrier

structure Permission (v : Vocabulary) where
  value : v.PermissionCarrier

structure Audience (v : Vocabulary) where
  value : v.AudienceCarrier

structure Digest (v : Vocabulary) where
  value : v.DigestCarrier

structure BudgetAlgebra (v : Vocabulary) where
  value : v.BudgetAlgebraCarrier

structure StatusMethod (v : Vocabulary) where
  value : v.StatusMethodCarrier

structure AssurancePolicy (v : Vocabulary) where
  value : v.AssuranceCarrier

structure GrantId (v : Vocabulary) where
  value : v.GrantIdCarrier

instance (v : Vocabulary) : DecidableEq (Principal v) :=
  fun left right =>
    match v.principalDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (Profile v) :=
  fun left right =>
    match v.profileDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (Permission v) :=
  fun left right =>
    match v.permissionDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (Audience v) :=
  fun left right =>
    match v.audienceDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (Digest v) :=
  fun left right =>
    match v.digestDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (BudgetAlgebra v) :=
  fun left right =>
    match v.budgetAlgebraDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (StatusMethod v) :=
  fun left right =>
    match v.statusMethodDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (AssurancePolicy v) :=
  fun left right =>
    match v.assuranceDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (GrantId v) :=
  fun left right =>
    match v.grantIdDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

/--
The semantic finite-set carrier.  Rust's sorted bounded vectors are connected
to this extensional value by the production representation bridge.
-/
abbrev FiniteSet (α : Type u) := Finset α

/-- A non-empty inclusive validity interval. -/
structure InclusiveWindow where
  start : Nat
  finish : Nat
  wellFormed : start ≤ finish

/-- A protocol-valid non-zero freshness limit. -/
structure FreshnessLimit where
  seconds : Nat
  positive : 0 < seconds

structure BudgetCeiling (v : Vocabulary) where
  algebra : BudgetAlgebra v
  value : Nat

inductive StatusPolicy (v : Vocabulary) where
  | expiryOnly
  | snapshotRequired (method : StatusMethod v) (maxAge : FreshnessLimit)

inductive ActionConstraint (v : Vocabulary) where
  | anyBody
  | exactBodyDigest (digest : Digest v)
  | allowedBodyDigests (digests : FiniteSet (Digest v))

/--
The profile root set is retained across the chain.  A selected profile carries
its membership proof, making an invalid selected state unrepresentable.
-/
structure ProfileScope (v : Vocabulary) where
  rootAllowed : FiniteSet (Profile v)
  selected : Option (Profile v)
  selectedAllowed :
    ∀ profile, selected = some profile → profile ∈ rootAllowed

structure AuthorityScope (v : Vocabulary) where
  profileScope : ProfileScope v
  permissions : FiniteSet (Permission v)
  validity : InclusiveWindow
  audiences : FiniteSet (Audience v)
  actionConstraint : ActionConstraint v
  budget : Option (BudgetCeiling v)
  status : StatusPolicy v
  assurance : AssurancePolicy v

structure ChainState (v : Vocabulary) where
  root : Principal v
  subject : Principal v
  scope : AuthorityScope v
  remainingDepth : Nat
  lastGrant : Option (GrantId v)

/--
The authority-relevant fields of a validated grant.

The proposed profile is intentionally not packaged as a well-formed selected
`ProfileScope`: a syntactically valid grant may request a profile that the
parent does not permit.  Only an accepted transition can construct the next
well-formed scope.
-/
structure Grant (v : Vocabulary) where
  issuer : Principal v
  subject : Principal v
  profile : Profile v
  permissions : FiniteSet (Permission v)
  validity : InclusiveWindow
  audiences : FiniteSet (Audience v)
  actionConstraint : ActionConstraint v
  budget : Option (BudgetCeiling v)
  remainingDepth : Nat
  parent : Option (GrantId v)
  status : StatusPolicy v
  assurance : AssurancePolicy v

structure Action (v : Vocabulary) where
  actor : Principal v
  terminalGrant : Option (GrantId v)
  profile : Profile v
  permission : Permission v
  validity : InclusiveWindow
  audience : Audience v
  bodyDigest : Digest v
  requestedBudget : Option (BudgetCeiling v)

structure EvidenceFacts (v : Vocabulary) where
  statusMethod : Option (StatusMethod v)
  statusAge : Nat
  assurance : AssurancePolicy v

structure AuthorizationFacts (v : Vocabulary) where
  action : Action v
  evidence : EvidenceFacts v

end Auths.Rich
