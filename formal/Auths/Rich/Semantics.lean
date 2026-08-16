import Auths.Rich.Types

namespace Auths.Rich

universe u

def windowContained (child parent : InclusiveWindow) : Prop :=
  parent.start ≤ child.start ∧ child.finish ≤ parent.finish

instance (child parent : InclusiveWindow) :
    Decidable (windowContained child parent) := by
  unfold windowContained
  infer_instance

def budgetLe {v : Vocabulary}
    (child parent : Option (BudgetCeiling v)) : Prop :=
  match child, parent with
  | _, none => True
  | none, some _ => False
  | some child, some parent =>
      child.algebra = parent.algebra ∧ child.value ≤ parent.value

instance {v : Vocabulary}
    (child parent : Option (BudgetCeiling v)) :
    Decidable (budgetLe child parent) := by
  cases child <;> cases parent <;> simp [budgetLe] <;> infer_instance

/--
Terminal budget coverage.

An absent ceiling is the unbounded top scope, so it covers every request.  An
absent *request* under a present ceiling is **not** covered: an action that
declares no bound on what it may spend is exactly the authority the ceiling
exists to deny.  This mirrors `auths_model::optional_budget_covers`, the
`auths-verifier` guard, Go `budgetCovers`, and TypeScript `budgetCovers`.
-/
def budgetCovers {v : Vocabulary}
    (ceiling requested : Option (BudgetCeiling v)) : Prop :=
  match ceiling, requested with
  | none, _ => True
  | some _, none => False
  | some ceiling, some requested =>
      requested.algebra = ceiling.algebra ∧
        requested.value ≤ ceiling.value

instance {v : Vocabulary}
    (ceiling requested : Option (BudgetCeiling v)) :
    Decidable (budgetCovers ceiling requested) := by
  cases ceiling <;> cases requested <;>
    simp [budgetCovers] <;> infer_instance

/--
Whether a profile's canonical actions can state a budget at all.

TRUSTED REGISTRY CONTEXT, not an action-controlled field. An action cannot
declare itself inexpressible to escape a ceiling: the profile registry decides
this, and the action only supplies the requested budget.
-/
inductive BudgetExpression where
  | expressible
  | inexpressible
  deriving DecidableEq, Repr

/--
Terminal budget coverage including profile expressibility.

The capability only ever reclassifies an ABSENT request:

* inexpressible profile, absent request -- the action provably spends zero, and
  zero is within every ceiling including an absent one;
* expressible profile, absent request, present ceiling -- denied, because an
  action that could have stated a bound and did not states no bound at all;
* declared request -- ordinary ceiling comparison, expressibility irrelevant;
* absent ceiling -- covered, nothing is bounded.

Mirrors `auths_model::budget_ceiling_covers_action`.
-/
def budgetCoversAction {v : Vocabulary}
    (ceiling requested : Option (BudgetCeiling v))
    (expression : BudgetExpression) : Prop :=
  match requested, expression with
  | none, BudgetExpression.inexpressible => True
  | _, _ => budgetCovers ceiling requested

instance {v : Vocabulary}
    (ceiling requested : Option (BudgetCeiling v)) (expression : BudgetExpression) :
    Decidable (budgetCoversAction ceiling requested expression) := by
  cases requested <;> cases expression
  · exact inferInstanceAs (Decidable (budgetCovers _ _))
  · exact inferInstanceAs (Decidable True)
  · exact inferInstanceAs (Decidable (budgetCovers _ _))
  · exact inferInstanceAs (Decidable (budgetCovers _ _))

/-- Inexpressible profile with no request spends zero: always covered. -/
@[simp] theorem budgetCoversAction_inexpressible_absent {v : Vocabulary}
    (ceiling : Option (BudgetCeiling v)) :
    budgetCoversAction ceiling none BudgetExpression.inexpressible := by
  simp [budgetCoversAction]

/-- Expressible profile with no request and a bounded ceiling: denied. -/
@[simp] theorem budgetCoversAction_expressible_absent_bounded {v : Vocabulary}
    (ceiling : BudgetCeiling v) :
    ¬ budgetCoversAction (some ceiling) none BudgetExpression.expressible := by
  simp [budgetCoversAction, budgetCovers]

/-- An absent ceiling bounds nothing, whatever the profile can express. -/
@[simp] theorem budgetCoversAction_absent_ceiling {v : Vocabulary}
    (requested : Option (BudgetCeiling v)) (expression : BudgetExpression) :
    budgetCoversAction none requested expression := by
  cases requested <;> cases expression <;> simp [budgetCoversAction, budgetCovers]

/--
An expressible profile adds nothing: the capability only ever reclassifies an
absent request, and an expressible profile never does. This is what keeps every
existing coverage theorem true unchanged.
-/
@[simp] theorem budgetCoversAction_expressible {v : Vocabulary}
    (ceiling requested : Option (BudgetCeiling v)) :
    budgetCoversAction ceiling requested BudgetExpression.expressible =
      budgetCovers ceiling requested := by
  cases requested <;> rfl

/-- A declared request is compared against the ceiling, expressibility aside. -/
theorem budgetCoversAction_declared {v : Vocabulary}
    (ceiling : Option (BudgetCeiling v)) (requested : BudgetCeiling v)
    (expression : BudgetExpression) :
    budgetCoversAction ceiling (some requested) expression =
      budgetCovers ceiling (some requested) := by
  cases expression <;> rfl

/--
The critical-extension delegation relation.

This is the one dimension where delegation must **preserve**, not narrow.  A
critical extension is a constraint an unaware verifier is forbidden to ignore
(the X.509 / JWT sense).  If a delegate could drop one, the mechanism would be
worthless: attach a constraint at the root and the first delegation strips it.
Equality is the point, and it is what
`auths_model::critical_extensions_equal` computes.

A parent that has not pinned a set yet (`none`, the state of
`EffectiveAuthority::from_anchor`) admits any set, matching
`match parent.extensions { Some(parent) => .., None => true }` in
`auths_authority::evaluate_grant_view`.  A child that drops back to `none`
under a parent that has pinned one is rejected — that is precisely the
strip-the-constraint move.
-/
def extensionsLe {v : Vocabulary}
    (child parent : Option (CriticalExtensions v)) : Prop :=
  match child, parent with
  | _, none => True
  | none, some _ => False
  | some child, some parent => child = parent

instance {v : Vocabulary}
    (child parent : Option (CriticalExtensions v)) :
    Decidable (extensionsLe child parent) :=
  match child, parent with
  | _, none => isTrue trivial
  | none, some _ => isFalse fun absurdity => absurdity
  | some child, some parent =>
      if equality : child = parent then isTrue equality else isFalse equality

def statusLe {v : Vocabulary}
    (child parent : StatusPolicy v) : Prop :=
  match child, parent with
  | _, .expiryOnly => True
  | .expiryOnly, .snapshotRequired _ _ => False
  | .snapshotRequired childMethod childAge,
      .snapshotRequired parentMethod parentAge =>
      childMethod = parentMethod ∧ childAge.seconds ≤ parentAge.seconds

instance {v : Vocabulary} (child parent : StatusPolicy v) :
    Decidable (statusLe child parent) := by
  cases child <;> cases parent <;> simp [statusLe] <;> infer_instance

def actionConstraintAllows {v : Vocabulary}
    (constraint : ActionConstraint v) (digest : Digest v) : Prop :=
  match constraint with
  | .anyBody => True
  | .exactBodyDigest expected => digest = expected
  | .allowedBodyDigests allowed => digest ∈ allowed

instance {v : Vocabulary}
    (constraint : ActionConstraint v) (digest : Digest v) :
    Decidable (actionConstraintAllows constraint digest) := by
  cases constraint <;> simp [actionConstraintAllows] <;> infer_instance

def actionConstraintLe {v : Vocabulary}
    (child parent : ActionConstraint v) : Prop :=
  match child, parent with
  | _, .anyBody => True
  | .exactBodyDigest child, .exactBodyDigest parent => child = parent
  | .exactBodyDigest child, .allowedBodyDigests parent => child ∈ parent
  | .allowedBodyDigests child, .exactBodyDigest parent => child ⊆ {parent}
  | .allowedBodyDigests child, .allowedBodyDigests parent => child ⊆ parent
  | _, _ => False

instance {v : Vocabulary}
    (child parent : ActionConstraint v) :
    Decidable (actionConstraintLe child parent) := by
  cases child <;> cases parent <;> simp [actionConstraintLe] <;> infer_instance

/-- Canonical action constraints represent singleton sets with `exactBodyDigest`. -/
def actionConstraintCanonical {v : Vocabulary}
    (constraint : ActionConstraint v) : Prop :=
  match constraint with
  | .allowedBodyDigests allowed => ∀ digest, allowed ≠ {digest}
  | _ => True

/--
The target-V1 profile transition.  The retained root set is invariant; the
first grant may select one member and all later grants preserve it exactly.
-/
def profileLe {v : Vocabulary}
    (child parent : ProfileScope v) : Prop :=
  child.rootAllowed = parent.rootAllowed ∧
    match child.selected, parent.selected with
    | none, none => True
    | some _, none => True
    | some child, some parent => child = parent
    | none, some _ => False

instance {v : Vocabulary} (child parent : ProfileScope v) :
    Decidable (profileLe child parent) := by
  rcases child with ⟨childRoot, childSelected, childAllowed⟩
  rcases parent with ⟨parentRoot, parentSelected, parentAllowed⟩
  cases childSelected <;> cases parentSelected <;>
    simp [profileLe] <;> infer_instance

def profileAllows {v : Vocabulary}
    (scope : ProfileScope v) (profile : Profile v) : Prop :=
  match scope.selected with
  | none => profile ∈ scope.rootAllowed
  | some selected => profile = selected

instance {v : Vocabulary} (scope : ProfileScope v) (profile : Profile v) :
    Decidable (profileAllows scope profile) := by
  rcases scope with ⟨root, selected, allowed⟩
  cases selected <;> simp [profileAllows] <;> infer_instance

def structuralScopeLe {v : Vocabulary}
    (child parent : AuthorityScope v) : Prop :=
  profileLe child.profileScope parent.profileScope ∧
  child.permissions ⊆ parent.permissions ∧
  windowContained child.validity parent.validity ∧
  child.audiences ⊆ parent.audiences ∧
  actionConstraintLe child.actionConstraint parent.actionConstraint ∧
  budgetLe child.budget parent.budget ∧
  statusLe child.status parent.status ∧
  child.assurance = parent.assurance ∧
  extensionsLe child.extensions parent.extensions

instance {v : Vocabulary} (child parent : AuthorityScope v) :
    Decidable (structuralScopeLe child parent) := by
  unfold structuralScopeLe
  infer_instance

def actionCovers {v : Vocabulary}
    (scope : AuthorityScope v) (action : Action v) : Prop :=
  profileAllows scope.profileScope action.profile ∧
  action.permission ∈ scope.permissions ∧
  windowContained action.validity scope.validity ∧
  action.audience ∈ scope.audiences ∧
  actionConstraintAllows scope.actionConstraint action.bodyDigest ∧
  budgetCovers scope.budget action.requestedBudget

def statusSatisfied {v : Vocabulary}
    (policy : StatusPolicy v) (facts : EvidenceFacts v) : Prop :=
  match policy with
  | .expiryOnly => True
  | .snapshotRequired method maxAge =>
      facts.statusMethod = some method ∧ facts.statusAge ≤ maxAge.seconds

instance {v : Vocabulary} (policy : StatusPolicy v) (facts : EvidenceFacts v) :
    Decidable (statusSatisfied policy facts) := by
  cases policy <;> simp [statusSatisfied] <;> infer_instance

def evidenceRequirementsSatisfied {v : Vocabulary}
    (scope : AuthorityScope v) (facts : EvidenceFacts v) : Prop :=
  statusSatisfied scope.status facts ∧ facts.assurance = scope.assurance

def admits {v : Vocabulary}
    (scope : AuthorityScope v) (facts : AuthorizationFacts v) : Prop :=
  actionCovers scope facts.action ∧
  evidenceRequirementsSatisfied scope facts.evidence

/-- Extensional semantic containment of complete authorization facts. -/
def semanticAttenuates {v : Vocabulary}
    (child parent : AuthorityScope v) : Prop :=
  ∀ facts, admits child facts → admits parent facts

/--
A chain state genuinely descends from the root it names.

Either an accepted edge has already been applied — and `acceptedNextState`
copies the root forward, so the root was carried by that edge — or no edge has
been applied yet and the state must still *be* the root.  A state with no
applied grant whose subject differs from its root descends from nothing.
-/
def rooted {v : Vocabulary} (state : ChainState v) : Prop :=
  state.lastGrant.isSome = true ∨ state.root = state.subject

instance {v : Vocabulary} (state : ChainState v) : Decidable (rooted state) := by
  unfold rooted
  infer_instance

/--
The trust-root dimension of the generated attenuation contract: this edge
continues the chain rooted at `parent.root`.

Two independent facts are required and neither implies the other — the parent
must be rooted, and the edge must be issued by the parent's own subject.
-/
def rootPreserved {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) : Prop :=
  rooted parent ∧ grant.issuer = parent.subject

instance {v : Vocabulary} (parent : ChainState v) (grant : Grant v) :
    Decidable (rootPreserved parent grant) := by
  unfold rootPreserved
  infer_instance

def linked {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) : Prop :=
  rootPreserved parent grant ∧ grant.parent = parent.lastGrant

instance {v : Vocabulary} (parent : ChainState v) (grant : Grant v) :
    Decidable (linked parent grant) := by
  unfold linked
  infer_instance

/--
Every scope dimension a delegation must attenuate, ONE NAMED FIELD EACH.

This was a nine-way anonymous conjunction. Two things follow from naming the
fields that did not follow from nesting them.

A caller reaches a dimension by NAME rather than by counting `.2`s, so a proof
cannot silently address the wrong one; the old form produced expressions like
`accepted.2.2.2.2.2.2.2.2` whose meaning depended on position.

More importantly, adding a tenth dimension now forces every constructor and
every pattern match to mention it. The eleventh attenuation dimension was once
reported as `extensionsAttenuate := true` and nobody noticed, because nothing
in the shape of the definition required it to be addressed. A structure
requires it.
-/
structure GrantScopeChecks {v : Vocabulary}
    (parent : AuthorityScope v) (grant : Grant v) : Prop where
  profile : profileAllows parent.profileScope grant.profile
  permissions : grant.permissions ⊆ parent.permissions
  validity : windowContained grant.validity parent.validity
  audiences : grant.audiences ⊆ parent.audiences
  actionConstraint :
    actionConstraintLe grant.actionConstraint parent.actionConstraint
  budget : budgetLe grant.budget parent.budget
  status : statusLe grant.status parent.status
  assurance : grant.assurance = parent.assurance
  extensions : extensionsLe (some grant.extensions) parent.extensions

/-- The named structure spelled as the conjunction, for rewriting. -/
theorem GrantScopeChecks.iff_conjunction {v : Vocabulary}
    (parent : AuthorityScope v) (grant : Grant v) :
    GrantScopeChecks parent grant ↔
      (profileAllows parent.profileScope grant.profile ∧
        grant.permissions ⊆ parent.permissions ∧
        windowContained grant.validity parent.validity ∧
        grant.audiences ⊆ parent.audiences ∧
        actionConstraintLe grant.actionConstraint parent.actionConstraint ∧
        budgetLe grant.budget parent.budget ∧
        statusLe grant.status parent.status ∧
        grant.assurance = parent.assurance ∧
        extensionsLe (some grant.extensions) parent.extensions) := by
  constructor
  · intro checks
    exact ⟨checks.profile, checks.permissions, checks.validity,
      checks.audiences, checks.actionConstraint, checks.budget, checks.status,
      checks.assurance, checks.extensions⟩
  · rintro ⟨profile, permissions, validity, audiences, actionConstraint,
      budget, status, assurance, extensions⟩
    exact ⟨profile, permissions, validity, audiences, actionConstraint,
      budget, status, assurance, extensions⟩

/-- The named structure, as the predicate the rest of the development uses. -/
def grantScopeChecks {v : Vocabulary}
    (parent : AuthorityScope v) (grant : Grant v) : Prop :=
  GrantScopeChecks parent grant

instance {v : Vocabulary} (parent : AuthorityScope v) (grant : Grant v) :
    Decidable (grantScopeChecks parent grant) := by
  unfold grantScopeChecks
  exact decidable_of_iff _ (GrantScopeChecks.iff_conjunction parent grant).symm

def scopeDepthChecks {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) : Prop :=
  0 < parent.remainingDepth ∧
  grant.remainingDepth < parent.remainingDepth ∧
  grantScopeChecks parent.scope grant

instance {v : Vocabulary} (parent : ChainState v) (grant : Grant v) :
    Decidable (scopeDepthChecks parent grant) := by
  unfold scopeDepthChecks
  infer_instance

def profileAllowedMember {v : Vocabulary}
    (scope : ProfileScope v) (profile : Profile v)
    (allowed : profileAllows scope profile) :
    profile ∈ scope.rootAllowed := by
  cases selected : scope.selected with
  | none =>
      simpa [profileAllows, selected] using allowed
  | some selectedProfile =>
      have profileEquality : profile = selectedProfile := by
        simpa [profileAllows, selected] using allowed
      rw [profileEquality]
      exact scope.selectedAllowed selectedProfile selected

def acceptedScope {v : Vocabulary}
    (parent : AuthorityScope v) (grant : Grant v)
    (checks : grantScopeChecks parent grant) :
    AuthorityScope v where
  profileScope :=
    {
      rootAllowed := parent.profileScope.rootAllowed
      selected := some grant.profile
      selectedAllowed := by
        intro profile equality
        have profileEquality : profile = grant.profile := by
          simpa using Option.some.inj equality.symm
        rw [profileEquality]
        exact profileAllowedMember parent.profileScope grant.profile checks.1
    }
  permissions := grant.permissions
  validity := grant.validity
  audiences := grant.audiences
  actionConstraint := grant.actionConstraint
  budget := grant.budget
  status := grant.status
  assurance := grant.assurance
  extensions := some grant.extensions

def acceptedNextState {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v)
    (checks : scopeDepthChecks parent grant) :
    ChainState v where
  root := parent.root
  subject := grant.subject
  scope := acceptedScope parent.scope grant checks.2.2
  remainingDepth := grant.remainingDepth
  lastGrant := some grantId

def delegates {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v)
    (child : ChainState v) : Prop :=
  linked parent grant ∧
  ∃ checks : scopeDepthChecks parent grant,
    child = acceptedNextState parent grantId grant checks

inductive DelegationChain {v : Vocabulary} :
    ChainState v → List (ChainState v) → Prop
  | nil (start : ChainState v) : DelegationChain start []
  | cons
      (parent child : ChainState v)
      (grantId : GrantId v)
      (grant : Grant v)
      (rest : List (ChainState v))
      (edge : delegates parent grantId grant child)
      (tail : DelegationChain child rest) :
      DelegationChain parent (child :: rest)

inductive DelegationDiagnostic where
  | brokenGrantChain
  | delegationExpanded
  deriving DecidableEq, Repr

inductive DelegationDecision (v : Vocabulary) where
  | accepted (next : ChainState v)
  | denied (reason : DelegationDiagnostic)

def evaluateGrant {v : Vocabulary}
    (parent : ChainState v) (grantId : GrantId v) (grant : Grant v) :
    DelegationDecision v :=
  if linked parent grant then
    if checks : scopeDepthChecks parent grant then
      .accepted (acceptedNextState parent grantId grant checks)
    else
      .denied .delegationExpanded
  else
    .denied .brokenGrantChain

inductive AuthorDiagnostic where
  | profile
  | permissions
  | validity
  | audiences
  | actionConstraint
  | budget
  | delegationDepth
  | status
  | assurance
  | extensions
  deriving DecidableEq, Repr

inductive AuthorDecision where
  | accepted
  | denied (reason : AuthorDiagnostic)
  deriving DecidableEq, Repr

/-- First-failure order used before authoring or custody can be invoked. -/
def evaluateAuthorScope {v : Vocabulary}
    (parent child : AuthorityScope v)
    (parentDepth childDepth : Nat) : AuthorDecision :=
  if ¬ profileLe child.profileScope parent.profileScope then
    .denied .profile
  else if ¬ child.permissions ⊆ parent.permissions then
    .denied .permissions
  else if ¬ windowContained child.validity parent.validity then
    .denied .validity
  else if ¬ child.audiences ⊆ parent.audiences then
    .denied .audiences
  else if ¬ actionConstraintLe child.actionConstraint parent.actionConstraint then
    .denied .actionConstraint
  else if ¬ budgetLe child.budget parent.budget then
    .denied .budget
  else if ¬ (0 < parentDepth ∧ childDepth < parentDepth) then
    .denied .delegationDepth
  else if ¬ statusLe child.status parent.status then
    .denied .status
  else if child.assurance ≠ parent.assurance then
    .denied .assurance
  else if ¬ extensionsLe child.extensions parent.extensions then
    .denied .extensions
  else
    .accepted

inductive CoverageDiagnostic where
  | brokenGrantChain
  | permissionNotGranted
  | actionOutsideValidity
  | audienceMismatch
  | actionConstraintMismatch
  | budgetCeilingExceeded
  deriving DecidableEq, Repr

inductive CoverageDecision where
  | authorized
  | denied (reason : CoverageDiagnostic)
  deriving DecidableEq, Repr

/--
Ordered terminal coverage. First-failure order, as the shipping API.

`expression` is TRUSTED PROFILE-REGISTRY CONTEXT: whether the action's profile
can state a budget at all. It is not read from the action, so an action cannot
declare itself inexpressible to escape a ceiling. It only ever reclassifies an
absent request; see `budgetCoversAction`.
-/
def evaluateCoverage {v : Vocabulary}
    (authority : ChainState v) (action : Action v)
    (expression : BudgetExpression := BudgetExpression.expressible) :
    CoverageDecision :=
  if rooted authority ∧
      action.actor = authority.subject ∧
      action.terminalGrant = authority.lastGrant ∧
      profileAllows authority.scope.profileScope action.profile then
    if action.permission ∉ authority.scope.permissions then
      .denied .permissionNotGranted
    else if ¬ windowContained action.validity authority.scope.validity then
      .denied .actionOutsideValidity
    else if action.audience ∉ authority.scope.audiences then
      .denied .audienceMismatch
    else if ¬ actionConstraintAllows authority.scope.actionConstraint action.bodyDigest then
      .denied .actionConstraintMismatch
    else if ¬ budgetCoversAction authority.scope.budget action.requestedBudget
        expression then
      .denied .budgetCeilingExceeded
    else
      .authorized
  else
    .denied .brokenGrantChain

def terminalCovers {v : Vocabulary}
    (authority : ChainState v) (action : Action v) : Prop :=
  rooted authority ∧
  action.actor = authority.subject ∧
  action.terminalGrant = authority.lastGrant ∧
  actionCovers authority.scope action

/--
A projection carrying a proof that every field IS its semantic decision.

`Auths.Generated.AttenuationProjection` is eleven unconstrained `Bool`s, so
`extensionsAttenuate := true` is expressible. That is not hypothetical: the
eleventh dimension shipped as a literal `true` and the exactness theorems were
what eventually caught it. They catch a bad projection AFTER it exists.

This type makes it unconstructible. Each field below pins one dimension to the
`decide` of its rich relation, so a literal cannot be supplied without a proof
that the literal equals the semantic answer -- and no such proof exists for a
wrong literal. The reviewer's phrasing: a projection that must carry its own
certificate.

Adding a twelfth dimension adds a twelfth obligation here, which no existing
constructor satisfies, so the compiler demands it be addressed.
-/
structure CertifiedProjection {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) where
  value : Auths.Generated.AttenuationProjection
  rootExact : value.rootPreserved = decide (rootPreserved parent grant)
  depthExact :
    value.depthDecreases =
      decide (0 < parent.remainingDepth ∧
        grant.remainingDepth < parent.remainingDepth)
  profileExact :
    value.profileAttenuates =
      decide (profileAllows parent.scope.profileScope grant.profile)
  permissionsExact :
    value.permissionsAttenuate =
      decide (grant.permissions ⊆ parent.scope.permissions)
  validityExact :
    value.validityAttenuates =
      decide (windowContained grant.validity parent.scope.validity)
  audiencesExact :
    value.audiencesAttenuate =
      decide (grant.audiences ⊆ parent.scope.audiences)
  actionConstraintExact :
    value.actionConstraintAttenuates =
      decide (actionConstraintLe grant.actionConstraint
        parent.scope.actionConstraint)
  budgetExact :
    value.budgetAttenuates =
      decide (budgetLe grant.budget parent.scope.budget)
  statusExact :
    value.statusAttenuates =
      decide (statusLe grant.status parent.scope.status)
  assuranceExact :
    value.assuranceAttenuates =
      decide (grant.assurance = parent.scope.assurance)
  extensionsExact :
    value.extensionsAttenuate =
      decide (extensionsLe (some grant.extensions) parent.scope.extensions)

def delegationProjection {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    Auths.Generated.AttenuationProjection where
  rootPreserved := decide (rootPreserved parent grant)
  depthDecreases :=
    decide (0 < parent.remainingDepth ∧
      grant.remainingDepth < parent.remainingDepth)
  profileAttenuates :=
    decide (profileAllows parent.scope.profileScope grant.profile)
  permissionsAttenuate :=
    decide (grant.permissions ⊆ parent.scope.permissions)
  validityAttenuates :=
    decide (windowContained grant.validity parent.scope.validity)
  audiencesAttenuate :=
    decide (grant.audiences ⊆ parent.scope.audiences)
  actionConstraintAttenuates :=
    decide (actionConstraintLe grant.actionConstraint
      parent.scope.actionConstraint)
  budgetAttenuates :=
    decide (budgetLe grant.budget parent.scope.budget)
  statusAttenuates :=
    decide (statusLe grant.status parent.scope.status)
  assuranceAttenuates :=
    decide (grant.assurance = parent.scope.assurance)
  extensionsAttenuate :=
    decide (extensionsLe (some grant.extensions) parent.scope.extensions)

/-- `delegationProjection` is certified: every field is its decision, by rfl. -/
def certifiedDelegationProjection {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    CertifiedProjection parent grant where
  value := delegationProjection parent grant
  rootExact := rfl
  depthExact := rfl
  profileExact := rfl
  permissionsExact := rfl
  validityExact := rfl
  audiencesExact := rfl
  actionConstraintExact := rfl
  budgetExact := rfl
  statusExact := rfl
  assuranceExact := rfl
  extensionsExact := rfl


/--
No certified projection can report a dimension the semantics deny.

This is what the type buys. `extensionsAttenuate := true` beneath a parent that
denies it is not merely detected, it cannot be constructed.
-/
theorem CertifiedProjection.extensions_not_forgeable {v : Vocabulary}
    {parent : ChainState v} {grant : Grant v}
    (certified : CertifiedProjection parent grant)
    (denied : ¬ extensionsLe (some grant.extensions) parent.scope.extensions) :
    certified.value.extensionsAttenuate = false := by
  rw [certified.extensionsExact]
  exact decide_eq_false denied

/-- The same for the trust root, the dimension no other can rescue. -/
theorem CertifiedProjection.root_not_forgeable {v : Vocabulary}
    {parent : ChainState v} {grant : Grant v}
    (certified : CertifiedProjection parent grant)
    (denied : ¬ rootPreserved parent grant) :
    certified.value.rootPreserved = false := by
  rw [certified.rootExact]
  exact decide_eq_false denied

end Auths.Rich

