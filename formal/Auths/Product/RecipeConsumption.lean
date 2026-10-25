import Auths.Product.NativeCompilerRulesModel
import Mathlib.Data.Finset.Card

/-!
Original-name consumption semantics. Names are complete, losslessly decoded
Strings, with their original schema associations retained in `Rules.Entry`.
The three sets have distinct meanings: any admitted use, body rendering, and
read-back binding. Logical cardinality is not a native allocation bound; the
native representation lemmas must establish that separately.
-/
namespace Auths.Product.RecipeConsumption
open NativeCompiler

structure State where
  all : Finset String
  body : Finset String
  binds : Finset String
  deriving DecidableEq

def empty : State := ⟨∅, ∅, ∅⟩

def bindingField (name : String) : Bool :=
  name == "operator_namespace" || name == "operation_id" || name == "recipe_digest"

def namespaceOrRecipe (name : String) : Bool :=
  name == "operator_namespace" || name == "recipe_digest"

def consume (state : State) (name : String) : State :=
  { state with all := insert name state.all }

def render (state : State) (name : String) : State :=
  { all := insert name state.all, body := insert name state.body, binds := state.binds }

def bind (state : State) (name : String) : State :=
  { all := insert name state.all, body := state.body, binds := insert name state.binds }

def WellFormed (fields : List Rules.Entry) (state : State) : Prop :=
  state.all ⊆ (fields.map Prod.fst).toFinset ∧
    state.body ⊆ state.all ∧ state.binds ⊆ state.all

def schemaFor (name : String) : List Rules.Entry → Option ScalarProjection.Schema
  | [] => none
  | (key, schema) :: rest => if key = name then some schema else schemaFor name rest

def pathSchema : ScalarProjection.Schema → Bool
  | .text _ _ | .enumeration _ => true
  | .integer _ _ | .boolean => false

def formSchema : ScalarProjection.Schema → Bool
  | .boolean => false
  | _ => true

def factSchema : ScalarProjection.Schema → Bool
  | .text _ maximum => decide (maximum ≤ 256)
  | .enumeration _ => true
  | .integer minimum _ => decide (0 ≤ minimum)
  | .boolean => false

def textFactSchema : ScalarProjection.Schema → Bool
  | .text _ maximum => decide (maximum ≤ 256)
  | _ => false

def integerSchema : ScalarProjection.Schema → Bool
  | .integer _ _ => true
  | _ => false

def fieldTest (test : ScalarProjection.Schema → Bool) (fields : List Rules.Entry)
    (name : String) : Bool := (schemaFor name fields).any test

theorem schema_for_present (fields : List Rules.Entry) (name : String) (schema : ScalarProjection.Schema)
    (found : schemaFor name fields = some schema) : name ∈ fields.map Prod.fst := by
  induction fields with
  | nil => simp [schemaFor] at found
  | cons first rest ih =>
      rcases first with ⟨key, value⟩
      by_cases same : key = name
      · simp [same]
      · exact List.mem_cons_of_mem _ (ih (by simpa [schemaFor, same] using found))

theorem field_test_earns_presence (test : ScalarProjection.Schema → Bool)
    (fields : List Rules.Entry) (name : String) (accepted : fieldTest test fields name = true) :
    name ∈ fields.map Prod.fst := by
  cases found : schemaFor name fields with
  | none => simp [fieldTest, found] at accepted
  | some schema => exact schema_for_present fields name schema found

def integerBodyField (fields : List Rules.Entry) (state : State) (name : String) : Bool :=
  fieldTest integerSchema fields name && decide (name ∈ state.body)

inductive Error where
  | preconditionConflict
  | unsafeTemplate
  | invalidAccountScope
  | invalidBounds
  | unboundPartition
  | unsafePath
  | responseLocatorConflict
  | invalidPreEntry
  | invalidRelativeCeiling
  | echoConflict
  | invalidSource
  | preconditionWithoutObservation
  | echoWithoutObservation
  | invalidIdempotency
  | invalidProviderHeader
  | invalidCredentialGuard
  deriving DecidableEq

abbrev Outcome := Except Error Unit × State

/-- Refusal retains the consumed prefix. A duplicate insertion does not erase
the earlier claim. The admissibility argument is the leaf helper's actual
input; `claimVerified` computes it from the complete original schema map. -/
def claimUnused (state : State) (name : String) (admissible : Bool) : Outcome :=
  if admissible && !bindingField name then
    if name ∈ state.all then (.error .preconditionConflict, state)
    else (.ok (), consume state name)
  else (.error .preconditionConflict, state)

def claimVerified (fields : List Rules.Entry) (state : State) : List String → Outcome
  | [] => (.ok (), state)
  | name :: rest =>
      let (verdict, next) := claimUnused state name (fieldTest factSchema fields name)
      match verdict with
      | .error error => (.error error, next)
      | .ok () => claimVerified fields next rest

def ClaimsAdmitted (fields : List Rules.Entry) (state : State) (names : List String) : Prop :=
  names.Nodup ∧ ∀ name ∈ names,
    fieldTest factSchema fields name = true ∧ bindingField name = false ∧ name ∉ state.all

def allFieldsConsumed (fields : List Rules.Entry) (state : State) : Bool :=
  fields.all (fun entry => bindingField entry.1 || decide (entry.1 ∈ state.all))

def partitionBound (state : State) (scopeField : Option String) (name : String) : Bool :=
  decide (name ∈ state.body) || scopeField.any (· == name) || decide (name ∈ state.binds)

theorem empty_well_formed (fields : List Rules.Entry) : WellFormed fields empty := by
  simp [WellFormed, empty]

theorem consume_well_formed (fields : List Rules.Entry) (state : State) (name : String)
    (valid : WellFormed fields state) (present : name ∈ fields.map Prod.fst) :
    WellFormed fields (consume state name) := by
  obtain ⟨known, body, binds⟩ := valid
  refine ⟨?_, ?_, ?_⟩
  · exact Finset.insert_subset_iff.mpr ⟨by simpa using present, known⟩
  · exact body.trans (Finset.subset_insert _ _)
  · exact binds.trans (Finset.subset_insert _ _)

theorem render_well_formed (fields : List Rules.Entry) (state : State) (name : String)
    (valid : WellFormed fields state) (present : name ∈ fields.map Prod.fst) :
    WellFormed fields (render state name) := by
  have added := consume_well_formed fields state name valid present
  exact ⟨added.1, Finset.insert_subset_insert _ valid.2.1,
    valid.2.2.trans (Finset.subset_insert _ _)⟩

theorem bind_well_formed (fields : List Rules.Entry) (state : State) (name : String)
    (valid : WellFormed fields state) (present : name ∈ fields.map Prod.fst) :
    WellFormed fields (bind state name) := by
  have added := consume_well_formed fields state name valid present
  exact ⟨added.1, valid.2.1.trans (Finset.subset_insert _ _),
    Finset.insert_subset_insert _ valid.2.2⟩

theorem consumed_card_bounded (fields : List Rules.Entry) (state : State)
    (valid : WellFormed fields state) :
    state.all.card ≤ fields.length ∧ state.body.card ≤ fields.length ∧ state.binds.card ≤ fields.length := by
  have fieldCount : (fields.map Prod.fst).toFinset.card ≤ fields.length := by
    simpa only [List.length_map] using List.toFinset_card_le (fields.map Prod.fst)
  have allCount := (Finset.card_le_card valid.1).trans fieldCount
  exact ⟨allCount, (Finset.card_le_card valid.2.1).trans allCount,
    (Finset.card_le_card valid.2.2).trans allCount⟩

theorem claim_unused_acceptance (state : State) (name : String) (admissible : Bool) :
    (claimUnused state name admissible).1 = .ok () ↔
      admissible = true ∧ bindingField name = false ∧ name ∉ state.all := by
  unfold claimUnused
  cases admissible <;> cases bindingField name <;> by_cases used : name ∈ state.all <;> simp [used]

theorem claim_unused_refusal_keeps_state (state : State) (name : String) (admissible : Bool)
    (refused : (claimUnused state name admissible).1 = .error .preconditionConflict) :
    (claimUnused state name admissible).2 = state := by
  cases admissible <;> cases bindingField name <;>
    by_cases used : name ∈ state.all <;> simp_all [claimUnused]

theorem claim_verified_frame (fields : List Rules.Entry) (state : State) (names : List String) :
    state.all ⊆ (claimVerified fields state names).2.all ∧
      (claimVerified fields state names).2.body = state.body ∧
      (claimVerified fields state names).2.binds = state.binds := by
  induction names generalizing state with
  | nil => simp [claimVerified]
  | cons name rest ih =>
      unfold claimVerified claimUnused
      split <;> rename_i permitted
      · split <;> rename_i used
        · simp
        · obtain ⟨grows, body, binds⟩ := ih (consume state name)
          exact ⟨(Finset.subset_insert _ _).trans grows, body, binds⟩
      · simp

/-- Every list, including a refused one, leaves only original fields in the
ledger. This follows from the actual schema lookup before each new claim. -/
theorem claim_verified_well_formed (fields : List Rules.Entry) (state : State) (names : List String)
    (valid : WellFormed fields state) : WellFormed fields (claimVerified fields state names).2 := by
  induction names generalizing state with
  | nil => exact valid
  | cons name rest ih =>
      unfold claimVerified claimUnused
      split <;> rename_i permitted
      · split <;> rename_i used
        · exact valid
        · have admissible : fieldTest factSchema fields name = true :=
            (Bool.and_eq_true.mp permitted).1
          exact ih _ (consume_well_formed fields state name valid
            (field_test_earns_presence factSchema fields name admissible))
      · exact valid

/-- Complete independently admitted claim lists succeed, retain every claimed
name, and preserve the separate body/bind meanings. -/
theorem admitted_claims_succeed (fields : List Rules.Entry) (state : State) (names : List String)
    (admitted : ClaimsAdmitted fields state names) :
    claimVerified fields state names = (.ok (),
      { state with all := state.all ∪ names.toFinset }) := by
  induction names generalizing state with
  | nil => simp [claimVerified]
  | cons name rest ih =>
      obtain ⟨unique, claims⟩ := admitted
      obtain ⟨admissible, ordinary, fresh⟩ := claims name (by simp)
      have tailAdmitted : ClaimsAdmitted fields (consume state name) rest := by
        refine ⟨(List.nodup_cons.mp unique).2, ?_⟩
        intro next member
        obtain ⟨fact, binding, unused⟩ := claims next (by simp [member])
        have different : next ≠ name := by
          intro same
          exact (List.nodup_cons.mp unique).1 (same ▸ member)
        exact ⟨fact, binding, by simpa [consume, different] using unused⟩
      simpa [claimVerified, claimUnused, admissible, ordinary, fresh, consume,
        Finset.union_assoc, Finset.union_left_comm, Finset.union_comm] using ih _ tailAdmitted

theorem all_fields_consumed_exact (fields : List Rules.Entry) (state : State) :
    allFieldsConsumed fields state = true ↔
      ∀ entry ∈ fields, bindingField entry.1 = false → entry.1 ∈ state.all := by
  simp only [allFieldsConsumed, List.all_eq_true, Bool.or_eq_true, decide_eq_true_eq]
  constructor
  · intro complete entry member ordinary
    simpa [ordinary] using complete entry member
  · intro complete entry member
    cases binding : bindingField entry.1 with
    | false => exact Or.inr (complete entry member binding)
    | true => exact Or.inl rfl

theorem partition_bound_exact (state : State) (scopeField : Option String) (name : String) :
    partitionBound state scopeField name = true ↔
      name ∈ state.body ∨ scopeField = some name ∨ name ∈ state.binds := by
  cases scopeField <;> simp [partitionBound, or_assoc]

end Auths.Product.RecipeConsumption
