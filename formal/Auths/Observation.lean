import Mathlib.Tactic
import Auths.ExtensionLaw

/-!
# Evidence-conditioned authority

An abstract model of observation requirements carried by grants. A
requirement names a trusted observer anchor, a schema, the observed subject,
a maximum age, and a conjunction of closed conditions. The only condition
atoms are exact equality with a literal, exact equality with a profile
action fact, an inclusive unsigned range, and membership in a finite literal
list. There is no disjunction, negation, arithmetic, or user-defined
function.

Observation signatures, the CBOR codec, and the namespace matcher stay in the
existing codec and cryptographic trust boundary. The model therefore works
over the observations that already verified, and over an abstract subject
namespace predicate.
-/

namespace Auths.Observation

inductive FactValue where
  | uint (value : Nat)
  | bytes (value : List UInt8)
  | text (value : String)
  deriving DecidableEq

abbrev Facts := List (String × FactValue)

/-- The value bound to `name`; observation fact names are unique. -/
def lookupFact (facts : Facts) (name : String) : Option FactValue :=
  (facts.find? (fun entry => entry.1 == name)).map Prod.snd

inductive Condition where
  | eqLiteral (name : String) (value : FactValue)
  | eqAction (name : String) (actionFact : String)
  | uintRange (name : String) (lo hi : Nat)
  | member (name : String) (values : List FactValue)

inductive Subject where
  | literal (resource : String)
  | actionFact (name : String)

structure ObservationRecord where
  observer : String
  schema : String
  subject : String
  observedAt : Nat
  facts : Facts

structure Requirement where
  observerAnchor : String
  schema : String
  subject : Subject
  maxAge : Nat
  conditions : List Condition

structure ObserverAnchor where
  principal : String
  schemas : List String
  notBefore : Nat
  expiresAt : Nat

/-- The verifier-side view: evaluation time, trusted observer anchors, the
profile's pure action facts, and the subject namespace matcher. -/
structure Environment where
  evaluationTime : Nat
  anchor : String → Option ObserverAnchor
  actionFact : String → Option FactValue
  subjectAllowed : ObserverAnchor → String → Bool

def conditionName : Condition → String
  | .eqLiteral name _ => name
  | .eqAction name _ => name
  | .uintRange name _ _ => name
  | .member name _ => name

/-- One condition against the looked-up observed value. A missing fact or a
type mismatch makes the condition false. -/
def valueHolds (actionFact : String → Option FactValue)
    (fact : Option FactValue) : Condition → Bool
  | .eqLiteral _ value => decide (fact = some value)
  | .eqAction _ reference =>
      match actionFact reference with
      | some value => decide (fact = some value)
      | none => false
  | .uintRange _ lo hi =>
      match fact with
      | some (.uint value) => decide (lo ≤ value) && decide (value ≤ hi)
      | _ => false
  | .member _ values =>
      match fact with
      | some value => decide (value ∈ values)
      | none => false

def conditionHolds (env : Environment) (observation : ObservationRecord)
    (condition : Condition) : Bool :=
  valueHolds env.actionFact
    (lookupFact observation.facts (conditionName condition)) condition

def conditionsHold (env : Environment) (observation : ObservationRecord)
    (conditions : List Condition) : Bool :=
  conditions.all (conditionHolds env observation)

def resolveSubject (env : Environment) : Subject → Option String
  | .literal resource => some resource
  | .actionFact name =>
      match env.actionFact name with
      | some (.text value) => some value
      | _ => none

/-- Freshness at the verifier's evaluation time, inside the anchor's
validity. A future-dated observation is never fresh. -/
def fresh (now maxAge notBefore expiresAt observedAt : Nat) : Bool :=
  decide (observedAt ≤ now) && decide (now - observedAt ≤ maxAge) &&
    decide (notBefore ≤ observedAt) && decide (observedAt ≤ expiresAt)

/-- An observation is eligible for a requirement when it comes from the
anchored observer, carries the required schema, is about the exact resolved
subject inside the anchor's namespaces, and is fresh. -/
def eligible (env : Environment) (requirement : Requirement)
    (observation : ObservationRecord) : Bool :=
  match env.anchor requirement.observerAnchor with
  | none => false
  | some anchor =>
      decide (observation.observer = anchor.principal) &&
      decide (observation.schema = requirement.schema) &&
      decide (requirement.schema ∈ anchor.schemas) &&
      decide (resolveSubject env requirement.subject = some observation.subject) &&
      env.subjectAllowed anchor observation.subject &&
      fresh env.evaluationTime requirement.maxAge anchor.notBefore
        anchor.expiresAt observation.observedAt

def satisfied (env : Environment) (observations : List ObservationRecord)
    (requirement : Requirement) : Bool :=
  observations.any fun observation =>
    eligible env requirement observation &&
      conditionsHold env observation requirement.conditions

/-- Every requirement of every grant in the chain must be met. -/
def authorized (env : Environment) (observations : List ObservationRecord)
    (requirements : List Requirement) : Bool :=
  requirements.all (satisfied env observations)

/-- The observation stage conjoined with the rest of a chain's authority. -/
def chainAuthorized (base : Environment → Bool)
    (requirements : List Requirement) (env : Environment)
    (observations : List ObservationRecord) : Bool :=
  base env && authorized env observations requirements

def actionFactsAvailable (env : Environment) (requirement : Requirement) : Bool :=
  (match requirement.subject with
    | .literal _ => true
    | .actionFact name => (env.actionFact name).isSome) &&
  requirement.conditions.all fun condition =>
    match condition with
    | .eqAction _ reference => (env.actionFact reference).isSome
    | _ => true

inductive Decision where
  | satisfied
  | denied
  | indeterminate
  deriving DecidableEq

/-- The three-valued per-requirement verdict: satisfied; denied when some
eligible observation exists and every one falsifies a condition; otherwise
indeterminate. An unavailable action fact is indeterminate. -/
def requirementDecision (env : Environment) (observations : List ObservationRecord)
    (requirement : Requirement) : Decision :=
  if !actionFactsAvailable env requirement then .indeterminate
  else if satisfied env observations requirement then .satisfied
  else if observations.any (eligible env requirement) then .denied
  else .indeterminate

theorem requirements_monotone
    {env : Environment} {observations : List ObservationRecord}
    {parent child : List Requirement}
    (superset : ∀ requirement ∈ parent, requirement ∈ child)
    (childAuthorized : authorized env observations child = true) :
    authorized env observations parent = true := by
  simp only [authorized, List.all_eq_true] at *
  exact fun requirement member => childAuthorized requirement (superset requirement member)

theorem conditions_monotone
    {env : Environment} {observations : List ObservationRecord}
    {requirement : Requirement} {conditions : List Condition}
    (superset : ∀ condition ∈ requirement.conditions, condition ∈ conditions)
    (strengthened :
      satisfied env observations { requirement with conditions := conditions } = true) :
    satisfied env observations requirement = true := by
  simp only [satisfied, List.any_eq_true, Bool.and_eq_true, conditionsHold,
    List.all_eq_true] at *
  obtain ⟨observation, member, isEligible, holds⟩ := strengthened
  exact ⟨observation, member, by simpa [eligible] using isEligible,
    fun condition inParent => holds condition (superset condition inParent)⟩

theorem child_requirements_superset_attenuates
    {parentBase childBase : Environment → Bool}
    {parent child : List Requirement}
    (baseAttenuates : ∀ env, childBase env = true → parentBase env = true)
    (superset : ∀ requirement ∈ parent, requirement ∈ child)
    {env : Environment} {observations : List ObservationRecord}
    (childAuthorized : chainAuthorized childBase child env observations = true) :
    chainAuthorized parentBase parent env observations = true := by
  simp only [chainAuthorized, Bool.and_eq_true] at *
  exact ⟨baseAttenuates env childAuthorized.1,
    requirements_monotone superset childAuthorized.2⟩

theorem satisfied_monotone_observations
    {env : Environment} {fewer more : List ObservationRecord}
    {requirement : Requirement}
    (superset : ∀ observation ∈ fewer, observation ∈ more)
    (satisfiedFewer : satisfied env fewer requirement = true) :
    satisfied env more requirement = true := by
  simp only [satisfied, List.any_eq_true] at *
  obtain ⟨observation, member, holds⟩ := satisfiedFewer
  exact ⟨observation, superset observation member, holds⟩

theorem no_observation_satisfies_nothing
    (env : Environment) (requirement : Requirement) :
    satisfied env [] requirement = false := by
  simp [satisfied]

theorem future_observation_never_fresh
    {now maxAge notBefore expiresAt observedAt : Nat}
    (future : now < observedAt) :
    fresh now maxAge notBefore expiresAt observedAt = false := by
  simp only [fresh, Bool.and_eq_false_iff, decide_eq_false_iff_not]
  omega

theorem stale_observation_never_fresh
    {now maxAge notBefore expiresAt observedAt : Nat}
    (stale : maxAge < now - observedAt) :
    fresh now maxAge notBefore expiresAt observedAt = false := by
  simp only [fresh, Bool.and_eq_false_iff, decide_eq_false_iff_not]
  omega

theorem satisfied_requires_action_facts
    {env : Environment} {observations : List ObservationRecord}
    {requirement : Requirement}
    (isSatisfied : satisfied env observations requirement = true) :
    actionFactsAvailable env requirement = true := by
  simp only [satisfied, List.any_eq_true, Bool.and_eq_true, conditionsHold,
    List.all_eq_true] at isSatisfied
  obtain ⟨observation, _, isEligible, holds⟩ := isSatisfied
  simp only [actionFactsAvailable, Bool.and_eq_true, List.all_eq_true]
  constructor
  · cases subject : requirement.subject with
    | literal => rfl
    | actionFact name =>
        unfold eligible at isEligible
        split at isEligible
        · simp at isEligible
        · simp only [Bool.and_eq_true, decide_eq_true_eq] at isEligible
          have resolved := isEligible.1.1.2
          rw [subject] at resolved
          simp only [resolveSubject] at resolved
          cases fact : env.actionFact name with
          | none => simp [fact] at resolved
          | some _ => simp [fact]
  · intro condition member
    have conditionHolds' := holds condition member
    cases condition with
    | eqAction name reference =>
        simp only [conditionHolds, valueHolds] at conditionHolds'
        cases fact : env.actionFact reference with
        | none => simp [fact] at conditionHolds'
        | some _ => simp [fact]
    | eqLiteral => rfl
    | uintRange => rfl
    | member => rfl

theorem decision_satisfied_iff
    (env : Environment) (observations : List ObservationRecord)
    (requirement : Requirement) :
    requirementDecision env observations requirement = .satisfied ↔
      satisfied env observations requirement = true := by
  constructor
  · intro decided
    unfold requirementDecision at decided
    split at decided
    · cases decided
    · split at decided
      · assumption
      · split at decided <;> cases decided
  · intro isSatisfied
    have available := satisfied_requires_action_facts isSatisfied
    simp [requirementDecision, available, isSatisfied]

theorem decision_denied_has_falsifying_observation
    {env : Environment} {observations : List ObservationRecord}
    {requirement : Requirement}
    (decided : requirementDecision env observations requirement = .denied) :
    (∃ observation ∈ observations, eligible env requirement observation = true) ∧
      ∀ observation ∈ observations, eligible env requirement observation = true →
        conditionsHold env observation requirement.conditions = false := by
  unfold requirementDecision at decided
  split at decided
  · cases decided
  · rename_i notSatisfiedBranch
    split at decided
    · cases decided
    · rename_i notSatisfied
      split at decided
      · rename_i someEligible
        refine ⟨by simpa [List.any_eq_true] using someEligible, ?_⟩
        intro observation member isEligible
        simp only [satisfied, List.any_eq_true, Bool.and_eq_true, not_exists,
          not_and, Bool.not_eq_true] at notSatisfied
        have := notSatisfied observation member
        cases holds : conditionsHold env observation requirement.conditions
        · rfl
        · simp [isEligible, holds] at this
      · cases decided

/-!
## The `observation-requirement-v1` attenuation law

A child requirement covers a parent requirement when it is identical or
strictly narrows it: the same observer anchor, schema, and subject; a maximum
age no larger; a superset of the parent's condition atoms; and at least one of
the age or the atom set strictly narrower. A child list attenuates a parent
list when every parent requirement is covered, so the child may add
requirements. The theorems below discharge, for this law, the premise under
which per-identifier attenuation never widens authority.

The requirement carries one observer anchor and an implicit quorum of one,
so "observers a subset" is anchor equality and "quorum no smaller" holds
trivially.
-/

/-- The fields a narrowing must keep. -/
def sameTarget (child parent : Requirement) : Prop :=
  child.observerAnchor = parent.observerAnchor ∧ child.schema = parent.schema ∧
    child.subject = parent.subject

/-- A strict narrowing of one requirement. -/
def narrows (child parent : Requirement) : Prop :=
  sameTarget child parent ∧ child.maxAge ≤ parent.maxAge ∧
    (∀ condition ∈ parent.conditions, condition ∈ child.conditions) ∧
    (child.maxAge < parent.maxAge ∨
      ¬ ∀ condition ∈ child.conditions, condition ∈ parent.conditions)

/-- The child requirement is identical to, or strictly narrows, the parent. -/
def covers (child parent : Requirement) : Prop :=
  child = parent ∨ narrows child parent

/-- Every parent requirement is covered by some child requirement. -/
def requirementsAttenuate (child parent : List Requirement) : Prop :=
  ∀ requirement ∈ parent, ∃ candidate ∈ child, covers candidate requirement

theorem fresh_monotone_max_age
    {now shorter longer notBefore expiresAt observedAt : Nat}
    (order : shorter ≤ longer)
    (isFresh : fresh now shorter notBefore expiresAt observedAt = true) :
    fresh now longer notBefore expiresAt observedAt = true := by
  simp only [fresh, Bool.and_eq_true, decide_eq_true_eq] at isFresh ⊢
  omega

theorem narrows_monotone
    {env : Environment} {observations : List ObservationRecord}
    {child parent : Requirement}
    (narrowed : narrows child parent)
    (childSatisfied : satisfied env observations child = true) :
    satisfied env observations parent = true := by
  obtain ⟨⟨sameAnchor, sameSchema, sameSubject⟩, ageOrder, superset, _⟩ := narrowed
  simp only [satisfied, List.any_eq_true, Bool.and_eq_true, conditionsHold,
    List.all_eq_true] at childSatisfied ⊢
  obtain ⟨observation, member, isEligible, holds⟩ := childSatisfied
  refine ⟨observation, member, ?_, fun condition inParent =>
    holds condition (superset condition inParent)⟩
  unfold eligible at isEligible ⊢
  rw [← sameAnchor]
  split at isEligible
  · simp at isEligible
  · simp only [Bool.and_eq_true, decide_eq_true_eq] at isEligible ⊢
    obtain ⟨⟨⟨⟨⟨observer, schema⟩, schemaAnchored⟩, subject⟩, allowed⟩, isFresh⟩ :=
      isEligible
    refine ⟨⟨⟨⟨⟨observer, sameSchema ▸ schema⟩, sameSchema ▸ schemaAnchored⟩,
      sameSubject ▸ subject⟩, allowed⟩, ?_⟩
    exact fresh_monotone_max_age ageOrder isFresh

theorem covers_monotone
    {env : Environment} {observations : List ObservationRecord}
    {child parent : Requirement}
    (covered : covers child parent)
    (childSatisfied : satisfied env observations child = true) :
    satisfied env observations parent = true := by
  rcases covered with rfl | narrowed
  · exact childSatisfied
  · exact narrows_monotone narrowed childSatisfied

theorem covers_refl (requirement : Requirement) : covers requirement requirement :=
  Or.inl rfl

theorem covers_trans {child middle parent : Requirement}
    (childMiddle : covers child middle) (middleParent : covers middle parent) :
    covers child parent := by
  rcases childMiddle with rfl | childNarrows
  · exact middleParent
  rcases middleParent with rfl | middleNarrows
  · exact Or.inr childNarrows
  right
  obtain ⟨⟨anchorCM, schemaCM, subjectCM⟩, ageCM, supersetCM, strictCM⟩ := childNarrows
  obtain ⟨⟨anchorMP, schemaMP, subjectMP⟩, ageMP, supersetMP, strictMP⟩ := middleNarrows
  refine ⟨⟨anchorCM.trans anchorMP, schemaCM.trans schemaMP,
    subjectCM.trans subjectMP⟩, ageCM.trans ageMP,
    fun condition inParent => supersetCM condition (supersetMP condition inParent), ?_⟩
  by_cases shorter : child.maxAge < parent.maxAge
  · exact Or.inl shorter
  · right
    intro childWithinParent
    have childAge : child.maxAge = middle.maxAge := by omega
    have middleAge : middle.maxAge = parent.maxAge := by omega
    rcases strictCM with ageStrict | notChildWithinMiddle
    · omega
    · exact notChildWithinMiddle fun condition inChild =>
        supersetMP condition (childWithinParent condition inChild)

theorem requirements_attenuate_refl (requirements : List Requirement) :
    requirementsAttenuate requirements requirements :=
  fun requirement member => ⟨requirement, member, covers_refl requirement⟩

theorem requirements_attenuate_trans {child middle parent : List Requirement}
    (childMiddle : requirementsAttenuate child middle)
    (middleParent : requirementsAttenuate middle parent) :
    requirementsAttenuate child parent := by
  intro requirement member
  obtain ⟨middleRequirement, middleMember, middleCovers⟩ :=
    middleParent requirement member
  obtain ⟨childRequirement, childMember, childCovers⟩ :=
    childMiddle middleRequirement middleMember
  exact ⟨childRequirement, childMember, covers_trans childCovers middleCovers⟩

/-- A child list that attenuates its parent's authorizes a subset: every
observation set and environment that meets the child meets the parent. -/
theorem requirements_attenuate_monotone
    {env : Environment} {observations : List ObservationRecord}
    {child parent : List Requirement}
    (attenuates : requirementsAttenuate child parent)
    (childAuthorized : authorized env observations child = true) :
    authorized env observations parent = true := by
  simp only [authorized, List.all_eq_true] at childAuthorized ⊢
  intro requirement member
  obtain ⟨candidate, candidateMember, covered⟩ := attenuates requirement member
  exact covers_monotone covered (childAuthorized candidate candidateMember)

/-- The `observation-requirement-v1` law over decoded requirement lists: the
child attenuates the parent when both carry the extension, adding the
extension is accepted, and a missing child payload is refused. A payload
admits the environments and observation sets that meet all its
requirements. -/
def observationRequirementLaw :
    NarrowingLaw (List Requirement) (Environment × List ObservationRecord) where
  attenuates child parent :=
    match child, parent with
    | some child, some parent => requirementsAttenuate child parent
    | some _, none => True
    | none, _ => False
  admits requirements world := authorized world.1 world.2 requirements = true

/-- The observation-requirement law is a preorder that narrows. -/
theorem observation_requirement_law_lawful : observationRequirementLaw.Lawful where
  refl requirements := requirements_attenuate_refl requirements
  trans child middle parent childMiddle middleParent := by
    cases parent with
    | none => trivial
    | some parent => exact requirements_attenuate_trans childMiddle middleParent
  narrows _ _ attenuates world admitted :=
    requirements_attenuate_monotone attenuates admitted

/-- Adding the extension where the parent has none is accepted. -/
theorem observation_requirement_law_accepts_addition (requirements : List Requirement) :
    observationRequirementLaw.attenuates (some requirements) none :=
  trivial


end Auths.Observation
