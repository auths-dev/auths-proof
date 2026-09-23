import Mathlib.Tactic

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

end Auths.Observation
