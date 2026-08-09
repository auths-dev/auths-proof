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

def budgetCovers {v : Vocabulary}
    (ceiling requested : Option (BudgetCeiling v)) : Prop :=
  match requested, ceiling with
  | none, _ => True
  | some _, none => True
  | some requested, some ceiling =>
      requested.algebra = ceiling.algebra ∧
        requested.value ≤ ceiling.value

instance {v : Vocabulary}
    (ceiling requested : Option (BudgetCeiling v)) :
    Decidable (budgetCovers ceiling requested) := by
  cases ceiling <;> cases requested <;>
    simp [budgetCovers] <;> infer_instance

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
  | .allowedBodyDigests child, .allowedBodyDigests parent => child ⊆ parent
  | _, _ => False

instance {v : Vocabulary}
    (child parent : ActionConstraint v) :
    Decidable (actionConstraintLe child parent) := by
  cases child <;> cases parent <;> simp [actionConstraintLe] <;> infer_instance

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
  child.assurance = parent.assurance

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

def linked {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) : Prop :=
  grant.issuer = parent.subject ∧ grant.parent = parent.lastGrant

instance {v : Vocabulary} (parent : ChainState v) (grant : Grant v) :
    Decidable (linked parent grant) := by
  unfold linked
  infer_instance

def grantScopeChecks {v : Vocabulary}
    (parent : AuthorityScope v) (grant : Grant v) : Prop :=
  profileAllows parent.profileScope grant.profile ∧
  grant.permissions ⊆ parent.permissions ∧
  windowContained grant.validity parent.validity ∧
  grant.audiences ⊆ parent.audiences ∧
  actionConstraintLe grant.actionConstraint parent.actionConstraint ∧
  budgetLe grant.budget parent.budget ∧
  statusLe grant.status parent.status ∧
  grant.assurance = parent.assurance

instance {v : Vocabulary} (parent : AuthorityScope v) (grant : Grant v) :
    Decidable (grantScopeChecks parent grant) := by
  unfold grantScopeChecks
  infer_instance

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

/-- First-failure order used by the shipping terminal-coverage API. -/
def evaluateCoverage {v : Vocabulary}
    (authority : ChainState v) (action : Action v) : CoverageDecision :=
  if action.actor = authority.subject ∧
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
    else if ¬ budgetCovers authority.scope.budget action.requestedBudget then
      .denied .budgetCeilingExceeded
    else
      .authorized
  else
    .denied .brokenGrantChain

def terminalCovers {v : Vocabulary}
    (authority : ChainState v) (action : Action v) : Prop :=
  action.actor = authority.subject ∧
  action.terminalGrant = authority.lastGrant ∧
  actionCovers authority.scope action

def delegationProjection {v : Vocabulary}
    (parent : ChainState v) (grant : Grant v) :
    Auths.Generated.AttenuationProjection where
  rootPreserved := true
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
  extensionsAttenuate := true

end Auths.Rich
