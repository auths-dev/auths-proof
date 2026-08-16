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
  ExtensionIdCarrier : Type u
  ExtensionBodyCarrier : Type u
  principalDecidableEq : DecidableEq PrincipalCarrier
  profileDecidableEq : DecidableEq ProfileCarrier
  permissionDecidableEq : DecidableEq PermissionCarrier
  audienceDecidableEq : DecidableEq AudienceCarrier
  digestDecidableEq : DecidableEq DigestCarrier
  budgetAlgebraDecidableEq : DecidableEq BudgetAlgebraCarrier
  statusMethodDecidableEq : DecidableEq StatusMethodCarrier
  assuranceDecidableEq : DecidableEq AssuranceCarrier
  grantIdDecidableEq : DecidableEq GrantIdCarrier
  extensionIdDecidableEq : DecidableEq ExtensionIdCarrier
  extensionBodyDecidableEq : DecidableEq ExtensionBodyCarrier
  /-- Size of an extension payload, in the units Rust bounds.

  `CriticalExtension::new` rejects a payload longer than
  `HARD_MAX_EXTENSION_BYTES`. Without a measure the opaque carrier cannot state
  that bound, so a Lean inhabitant could exceed it and the claim that this type
  is exactly the Rust-constructible image would be too strong. -/
  extensionBodySize : ExtensionBodyCarrier → Nat

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

structure ExtensionId (v : Vocabulary) where
  value : v.ExtensionIdCarrier

structure ExtensionBody (v : Vocabulary) where
  value : v.ExtensionBodyCarrier

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

instance (v : Vocabulary) : DecidableEq (ExtensionId v) :=
  fun left right =>
    match v.extensionIdDecidableEq left.value right.value with
    | isTrue equality => isTrue (by cases left; cases right; simp_all)
    | isFalse different => isFalse (by intro equality; exact different (by cases equality; rfl))

instance (v : Vocabulary) : DecidableEq (ExtensionBody v) :=
  fun left right =>
    match v.extensionBodyDecidableEq left.value right.value with
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

/--
One critical extension: an identifier and its opaque canonical payload.

Mirrors `auths_model::CriticalExtension`.  The payload is an opaque carrier
because the kernel never interprets it — a critical extension is precisely a
constraint an unaware verifier must not ignore, so the only thing the kernel
may do with it is compare it.
-/
structure CriticalExtension (v : Vocabulary) where
  id : ExtensionId v
  body : ExtensionBody v

instance (v : Vocabulary) : DecidableEq (CriticalExtension v) :=
  fun left right =>
    match decEq left.id right.id, decEq left.body right.body with
    | isTrue idEquality, isTrue bodyEquality =>
        isTrue (by cases left; cases right; simp_all)
    | isFalse different, _ =>
        isFalse (by intro equality; exact different (by cases equality; rfl))
    | _, isFalse different =>
        isFalse (by intro equality; exact different (by cases equality; rfl))

/-- Mirrors Rust `auths_model::HARD_MAX_EXTENSIONS`. -/
def hardMaxExtensions : Nat := 32

/-- Mirrors Rust `auths_model::HARD_MAX_EXTENSION_BYTES`. -/
def hardMaxExtensionBytes : Nat := 65536

/--
A canonical critical-extension set.

`CriticalExtensions::new` sorts its input, rejects a repeated identifier with
`ModelError::DuplicateExtension`, and rejects more than
`HARD_MAX_EXTENSIONS` entries.  Both rejections are carried here as
constructor obligations, so a value of this type is exactly a value the Rust
constructor would have accepted.

The entries are an ordered sequence rather than a `FiniteSet` deliberately.
`critical_extensions_equal` compares the two canonical vectors **positionally**;
a set-valued model would identify `[a, b]` with `[b, a]` and therefore report
attenuation on a pair the shipping kernel denies, which is the model being
weaker than the code.  Duplicate-freedom by identifier is what makes the
sequence a faithful map from identifier to payload; the total order Rust sorts
by is a representation-level fact that the opaque carriers cannot state, and
none of the decisions below depend on it.
-/
structure CriticalExtensions (v : Vocabulary) where
  entries : List (CriticalExtension v)
  distinctIds : entries.Pairwise fun left right => left.id ≠ right.id
  bounded : entries.length ≤ hardMaxExtensions
  /-- Every payload is within `HARD_MAX_EXTENSION_BYTES`, as
  `CriticalExtension::new` enforces. -/
  bodiesBounded : ∀ entry ∈ entries,
    v.extensionBodySize entry.body.value ≤ hardMaxExtensionBytes

/-- Two extension sets are equal exactly when their canonical entries are. -/
@[ext] theorem CriticalExtensions.ext {v : Vocabulary}
    {left right : CriticalExtensions v}
    (entries : left.entries = right.entries) : left = right := by
  cases left
  cases right
  cases entries
  rfl

instance (v : Vocabulary) : DecidableEq (CriticalExtensions v) :=
  fun left right =>
    if entries : left.entries = right.entries then
      isTrue (CriticalExtensions.ext entries)
    else
      isFalse fun equality => entries (by rw [equality])

/-- The empty set, the value `CriticalExtensions::empty` constructs. -/
def CriticalExtensions.empty (v : Vocabulary) : CriticalExtensions v where
  entries := []
  distinctIds := List.Pairwise.nil
  bounded := by simp [hardMaxExtensions]
  bodiesBounded := by simp

/-- The one-element set, the smallest thing a delegate could try to drop. -/
def CriticalExtensions.singleton {v : Vocabulary}
    (extension : CriticalExtension v)
    (bodyBounded :
      v.extensionBodySize extension.body.value ≤ hardMaxExtensionBytes) :
    CriticalExtensions v where
  entries := [extension]
  distinctIds := by simp
  bounded := by simp [hardMaxExtensions]
  bodiesBounded := by simpa using bodyBounded

/--
The carrier is not a subsingleton.

Every falsifiability theorem about critical extensions is universally
quantified over a differing pair, so it would be vacuous if
`CriticalExtensions v` had at most one inhabitant.  It does not, for every
vocabulary that can name a single extension.
-/
theorem CriticalExtensions.empty_ne_singleton {v : Vocabulary}
    (extension : CriticalExtension v)
    (bodyBounded :
      v.extensionBodySize extension.body.value ≤ hardMaxExtensionBytes) :
    CriticalExtensions.empty v ≠
      CriticalExtensions.singleton extension bodyBounded := by
  intro equality
  have entries := congrArg CriticalExtensions.entries equality
  simp [CriticalExtensions.empty, CriticalExtensions.singleton] at entries

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
  /--
  The critical-extension set this authority has been pinned to, if any.

  `EffectiveAuthority::from_anchor` starts at `None`: a fresh trust anchor has
  not yet fixed a set, so its first edge may declare one.  Every accepted edge
  stores `Some`, and from then on the set may only be preserved exactly.
  -/
  extensions : Option (CriticalExtensions v)

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
  /-- The complete canonical critical-extension set the grant declares. -/
  extensions : CriticalExtensions v

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
