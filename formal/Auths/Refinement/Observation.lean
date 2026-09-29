import Auths.Observation
import Auths.Refinement.Production

/-!
# Translated observation predicates refine the abstract model

Each theorem states that one Aeneas-translated observation predicate from
`auths_model::observation` terminates with `ok` and returns exactly its
counterpart in `Auths.Observation`, under explicit representation-validity
premises. The abstraction maps `U64` to its natural-number value, vectors and
slices to lists, and the translated fact, condition, and verdict carriers to
the model's.

Text comparison in Rust is over UTF-8 bytes; `stringBytes_inj` is the bridge
to `String` equality. The only validity premise needed is that every compared
text fits the `u32` byte bound under which `String::as_bytes` is translated.
-/

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Refinement.Observation

open Auths.Observation

set_option maxHeartbeats 2000000

/-! ## Abstraction -/

def byteValue (byte : Std.U8) : UInt8 :=
  UInt8.ofBitVec byte.bv

def factValue : auths_model.observation.FactValue → FactValue
  | .Uint value => .uint value.val
  | .Bytes value => .bytes (value.val.map byteValue)
  | .Text value => .text value

def factsOf (facts : auths_model.observation.ObservationFacts) : Facts :=
  facts.val.map fun fact => (fact.«name», factValue fact.value)

def conditionOf (factName : String) :
    auths_model.observation.ConditionTest → Condition
  | .EqLiteral value => .eqLiteral factName (factValue value)
  | .EqAction reference => .eqAction factName reference
  | .UintRange range => .uintRange factName range.lo.val range.hi.val
  | .Member values => .member factName (values.val.map factValue)

def condition (value : auths_model.observation.ObservationCondition) : Condition :=
  conditionOf value.«name» value.test

def decisionOf : auths_model.observation.RequirementVerdict → Decision
  | .Satisfied => .satisfied
  | .ConditionFalse => .denied
  | .Missing => .indeterminate

/-! ## Representation validity -/

def FactValueValid : auths_model.observation.FactValue → Prop
  | .Text value => StringBounded value
  | _ => True

def OptionValid (value : Option auths_model.observation.FactValue) : Prop :=
  ∀ inner, value = some inner → FactValueValid inner

def FactsValid (facts : auths_model.observation.ObservationFacts) : Prop :=
  ∀ fact ∈ facts.val, StringBounded fact.«name» ∧ FactValueValid fact.value

def TestValid : auths_model.observation.ConditionTest → Prop
  | .EqLiteral value => FactValueValid value
  | .Member values => ∀ value ∈ values.val, FactValueValid value
  | _ => True

def ConditionValid (value : auths_model.observation.ObservationCondition) : Prop :=
  StringBounded value.«name» ∧ TestValid value.test

/-! ## Carrier lemmas -/

theorem byteValue_injective : Function.Injective byteValue := by
  intro left right equal
  cases left
  cases right
  exact congrArg UScalar.mk (UInt8.ofBitVec.inj equal :)

theorem byteArray_toList_loop (bytes : ByteArray) (index : Nat)
    (accumulated : List UInt8) :
    ByteArray.toList.loop bytes index accumulated =
      accumulated.reverse ++ bytes.data.toList.drop index := by
  induction index, accumulated using ByteArray.toList.loop.induct_unfolding bytes with
  | case1 index accumulated inBounds recursive =>
      rw [recursive]
      have inData : index < bytes.data.toList.length := by
        rw [Array.length_toList]
        exact inBounds
      rw [List.drop_eq_getElem_cons inData]
      simp only [List.reverse_cons, List.append_assoc, List.singleton_append,
        Array.getElem_toList]
      congr 2
      obtain ⟨data⟩ := bytes
      exact getElem!_pos data index inBounds
  | case2 index accumulated outOfBounds =>
      have past : bytes.data.toList.length ≤ index := by
        rw [Array.length_toList]
        exact Nat.le_of_not_lt outOfBounds
      simp [List.drop_eq_nil_of_le past]

theorem byteArray_toList (bytes : ByteArray) :
    bytes.toList = bytes.data.toList := by
  simp [ByteArray.toList, byteArray_toList_loop]

theorem stringBytes_inj {left right : String} :
    stringBytes left = stringBytes right ↔ left = right := by
  constructor
  · intro equal
    have mapInjective : Function.Injective
        (List.map fun byte : UInt8 => (⟨byte.toNat, by
          cases byte
          simp only [UInt8.toNat_ofBitVec, UScalarTy.U8_numBits_eq,
            Nat.reducePow]
          omega⟩ : Std.U8)) := by
      apply List.map_injective_iff.mpr
      intro first second sameValue
      have := congrArg (fun value : Std.U8 => value.val) sameValue
      simp only [UScalar.val] at this
      exact UInt8.toNat_inj.mp (by simpa using this)
    have rawEqual := mapInjective equal
    rw [byteArray_toList, byteArray_toList, Array.toList_inj] at rawEqual
    exact String.toByteArray_inj.mp (ByteArray.ext rawEqual)
  · rintro rfl
    rfl

theorem bool_eq_decide_of_iff {result : Bool} {property : Prop} [Decidable property]
    (equivalent : result = true ↔ property) : result = decide property := by
  cases result <;> by_cases holds : property <;> simp_all

@[step] theorem string_equal_spec
    (left right : String)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    (do
      let leftBytes ← alloc.string.String.as_bytes left
      let rightBytes ← alloc.string.String.as_bytes right
      auths_model.byte_slices_equal leftBytes rightBytes)
      ⦃ result => result = decide (left = right) ⦄ := by
  step with string_as_bytes_spec as ⟨leftSlice, leftBytes⟩
  step with string_as_bytes_spec as ⟨rightSlice, rightBytes⟩
  step with byte_slices_equal_spec as ⟨result, resultIff⟩
  rw [slice_eq_iff_val_eq, leftBytes, rightBytes, stringBytes_inj] at resultIff
  exact bool_eq_decide_of_iff resultIff

theorem result_eq_ok_of_spec {α : Type} {computation : Result α} {value : α}
    (holds : computation ⦃ result => result = value ⦄) :
    computation = ok value := by
  obtain ⟨result, isOk, equal⟩ := spec_imp_exists holds
  rw [isOk, equal]

/-! ## Scalar and text predicates -/

@[step] theorem fact_name_equal_spec
    (left right : String)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    auths_model.observation.fact_name_equal left right
      ⦃ result => result = decide (left = right) ⦄ := by
  unfold auths_model.observation.fact_name_equal
  exact string_equal_spec left right leftBounded rightBounded

/-- Fact names compare as the model's `String` equality. -/
theorem translated_fact_name_equal_refines_model
    (left right : String)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    auths_model.observation.fact_name_equal left right =
      ok (left == right) := by
  rw [beq_eq_decide]
  exact result_eq_ok_of_spec
    (fact_name_equal_spec left right leftBounded rightBounded)

/-- The guarded subtraction cannot underflow, so freshness over `u64` is the
model's freshness over the natural-number values. -/
theorem translated_observation_fresh_refines_model
    (observedAt evaluationTime maxAge notBefore expiresAt : Std.U64) :
    auths_model.observation.observation_fresh observedAt evaluationTime
        maxAge notBefore expiresAt =
      ok (fresh evaluationTime.val maxAge.val notBefore.val expiresAt.val
        observedAt.val) := by
  apply result_eq_ok_of_spec
  unfold auths_model.observation.observation_fresh
  split <;> rename_i future
  · simp only [spec_ok]
    have : evaluationTime.val < observedAt.val := by scalar_tac
    simp [fresh]
    omega
  · step as ⟨age, agePost⟩
    split <;> rename_i stale
    · simp only [spec_ok]
      have : maxAge.val < age.val := by scalar_tac
      simp [fresh]
      omega
    · split <;> rename_i afterNotBefore
      · simp only [spec_ok]
        simp only [fresh]
        have : observedAt.val ≤ evaluationTime.val := by scalar_tac
        have : age.val ≤ maxAge.val := by scalar_tac
        have : notBefore.val ≤ observedAt.val := by scalar_tac
        simp_all
      · simp only [spec_ok]
        have : observedAt.val < notBefore.val := by scalar_tac
        simp [fresh]
        omega

/-- The exact-subject comparison is `String` equality. -/
theorem translated_observation_subject_equal_refines_model
    (expected observed : auths_model.ResourceId)
    (expectedBounded : StringBounded expected)
    (observedBounded : StringBounded observed) :
    auths_model.observation.observation_subject_equal expected observed =
      ok (decide (expected = observed)) := by
  apply result_eq_ok_of_spec
  unfold auths_model.observation.observation_subject_equal
  exact string_equal_spec expected observed expectedBounded observedBounded

@[step] theorem fact_value_equal_spec
    (left right : auths_model.observation.FactValue)
    (leftValid : FactValueValid left) (rightValid : FactValueValid right) :
    auths_model.observation.fact_value_equal left right
      ⦃ result => result = decide (factValue left = factValue right) ⦄ := by
  unfold auths_model.observation.fact_value_equal
  cases left with
  | Uint left =>
      cases right with
      | Uint right =>
          simp only [spec_ok, factValue, FactValue.uint.injEq]
          by_cases equal : left = right
          · subst equal
            simp
          · have : left.val ≠ right.val := fun same =>
              equal (UScalar.eq_of_val_eq same)
            simp [equal, this]
      | Bytes _ => simp [factValue]
      | Text _ => simp [factValue]
  | Bytes left =>
      cases right with
      | Uint _ => simp [factValue]
      | Bytes right =>
          step with byte_slices_equal_spec as ⟨result, resultIff⟩
          rw [slice_eq_iff_val_eq] at resultIff
          simp only [alloc.vec.Vec.deref] at resultIff
          rw [← (List.map_injective_iff.mpr byteValue_injective).eq_iff] at resultIff
          simp only [factValue, FactValue.bytes.injEq]
          exact bool_eq_decide_of_iff resultIff
      | Text _ => simp [factValue]
  | Text left =>
      cases right with
      | Uint _ => simp [factValue]
      | Bytes _ => simp [factValue]
      | Text right =>
          simp only [FactValueValid] at leftValid rightValid
          simp only [factValue, FactValue.text.injEq]
          exact string_equal_spec left right leftValid rightValid

/-- Fact values compare as model values: same constructor and equal payload. -/
theorem translated_fact_value_equal_refines_model
    (left right : auths_model.observation.FactValue)
    (leftValid : FactValueValid left) (rightValid : FactValueValid right) :
    auths_model.observation.fact_value_equal left right =
      ok (decide (factValue left = factValue right)) :=
  result_eq_ok_of_spec (fact_value_equal_spec left right leftValid rightValid)

/-- The inclusive range test is the model's `uintRange` atom on the observed
unsigned value. -/
theorem translated_uint_range_contains_refines_model
    (lo hi value : Std.U64) (factName : String)
    (actionFact : String → Option FactValue) :
    auths_model.observation.uint_range_contains lo hi value =
      ok (valueHolds actionFact (some (.uint value.val))
        (.uintRange factName lo.val hi.val)) := by
  unfold auths_model.observation.uint_range_contains
  split <;> rename_i lower
  · have : lo.val ≤ value.val := by scalar_tac
    simp [valueHolds, this]
  · have : ¬lo.val ≤ value.val := by scalar_tac
    simp [valueHolds, this]

/-! ## Loops -/

@[step] theorem member_values_contain_spec
    (values : auths_model.observation.MemberValues)
    (value : auths_model.observation.FactValue)
    (valuesValid : ∀ member ∈ values.val, FactValueValid member)
    (valueValid : FactValueValid value) :
    auths_model.observation.member_values_contain values value
      ⦃ result => result =
        values.val.any fun member => decide (factValue member = factValue value) ⦄ := by
  unfold auths_model.observation.member_values_contain
    auths_model.observation.member_values_contain_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.1.val.length - state.2.val)
    (inv := fun state =>
      state.1 = values ∧ state.2.val ≤ values.val.length ∧
      (values.val.any fun member => decide (factValue member = factValue value)) =
        ((values.val.drop state.2.val).any fun member =>
          decide (factValue member = factValue value)))
  · rintro ⟨current, index⟩ ⟨rfl, indexBound, anyDrop⟩
    unfold auths_model.observation.member_values_contain_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < current.val.length := by
        simpa using withinBounds
      step as ⟨member, memberEq⟩
      have memberValid : FactValueValid member := by
        rw [memberEq]
        exact valuesValid _ (List.getElem_mem inBounds)
      step with fact_value_equal_spec as ⟨equal, equalEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.any_cons, ← memberEq,
        ← equalEq] at anyDrop
      split <;> rename_i matched
      · simp only [spec_ok]
        simp [anyDrop, matched]
      · step as ⟨nextIndex, nextIndexPost⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [anyDrop, nextIndexPost]
        simp [matched]
    · simp only [spec_ok]
      have atEnd : current.val.length ≤ index.val := by
        simpa using withinBounds
      rw [anyDrop, List.drop_eq_nil_of_le atEnd]
      rfl
  · exact ⟨rfl, by simp, by simp⟩

theorem any_eq_decide_mem (values : List auths_model.observation.FactValue)
    (value : auths_model.observation.FactValue) :
    (values.any fun member => decide (factValue member = factValue value)) =
      decide (factValue value ∈ values.map factValue) := by
  rw [Bool.eq_iff_iff]
  simp only [List.any_eq_true, decide_eq_true_eq, List.mem_map]

/-- Membership in a finite literal list is the model's `member` atom. -/
theorem translated_member_values_contain_refines_model
    (values : auths_model.observation.MemberValues)
    (value : auths_model.observation.FactValue)
    (valuesValid : ∀ member ∈ values.val, FactValueValid member)
    (valueValid : FactValueValid value)
    (factName : String) (actionFact : String → Option FactValue) :
    auths_model.observation.member_values_contain values value =
      ok (valueHolds actionFact (some (factValue value))
        (.member factName (values.val.map factValue))) := by
  apply result_eq_ok_of_spec
  apply WP.spec_mono (member_values_contain_spec values value valuesValid valueValid)
  intro result resultEq
  rw [resultEq]
  simp only [valueHolds]
  exact any_eq_decide_mem values.val value

def factLookup (facts : auths_model.observation.ObservationFacts) (factName : String) :
    Option auths_model.observation.FactValue :=
  (facts.val.find? fun fact => decide (fact.«name» = factName)).map
    auths_model.observation.ObservationFact.value

theorem factLookup_refines (facts : auths_model.observation.ObservationFacts)
    (factName : String) :
    (factLookup facts factName).map factValue = lookupFact (factsOf facts) factName := by
  simp only [factLookup, lookupFact, factsOf, List.find?_map, Option.map_map]
  congr 1

theorem factLookup_valid (facts : auths_model.observation.ObservationFacts)
    (factName : String) (factsValid : FactsValid facts) :
    OptionValid (factLookup facts factName) := by
  intro value found
  simp only [factLookup, Option.map_eq_some_iff] at found
  obtain ⟨fact, foundFact, rfl⟩ := found
  exact (factsValid fact (List.mem_of_find?_eq_some foundFact)).2

@[step] theorem observation_fact_spec
    (facts : auths_model.observation.ObservationFacts) (factName : String)
    (factsValid : FactsValid facts) (nameBounded : StringBounded factName) :
    auths_model.observation.observation_fact facts factName
      ⦃ result => result = factLookup facts factName ⦄ := by
  unfold auths_model.observation.observation_fact
    auths_model.observation.observation_fact_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.1.val.length - state.2.val)
    (inv := fun state =>
      state.1 = facts ∧ state.2.val ≤ facts.val.length ∧
      factLookup facts factName =
        ((facts.val.drop state.2.val).find? fun fact => decide (fact.«name» = factName)).map
          auths_model.observation.ObservationFact.value)
  · rintro ⟨current, index⟩ ⟨rfl, indexBound, lookupDrop⟩
    unfold auths_model.observation.observation_fact_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < current.val.length := by
        simpa using withinBounds
      step as ⟨fact, factEq⟩
      have factBounded : StringBounded fact.«name» := by
        rw [factEq]
        exact (factsValid _ (List.getElem_mem inBounds)).1
      step with fact_name_equal_spec as ⟨equal, equalEq⟩
      rw [List.drop_eq_getElem_cons inBounds, ← factEq] at lookupDrop
      split <;> rename_i matched
      · simp only [spec_ok]
        rw [lookupDrop, List.find?_cons_of_pos (by simpa [equalEq] using matched)]
        rfl
      · step as ⟨nextIndex, nextIndexPost⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [lookupDrop, List.find?_cons_of_neg (by simpa [equalEq] using matched),
          nextIndexPost]
    · simp only [spec_ok]
      have atEnd : current.val.length ≤ index.val := by
        simpa using withinBounds
      rw [lookupDrop, List.drop_eq_nil_of_le atEnd]
      rfl
  · exact ⟨rfl, by simp, by simp [factLookup]⟩

/-- Fact lookup returns the value of the first fact with the requested name,
which the model's `lookupFact` names. -/
theorem translated_observation_fact_refines_model
    (facts : auths_model.observation.ObservationFacts) (factName : String)
    (factsValid : FactsValid facts) (nameBounded : StringBounded factName) :
    ∃ result, auths_model.observation.observation_fact facts factName = ok result ∧
      result.map factValue = lookupFact (factsOf facts) factName := by
  refine ⟨factLookup facts factName, ?_, factLookup_refines facts factName⟩
  exact result_eq_ok_of_spec (observation_fact_spec facts factName factsValid nameBounded)

/-! ## Condition evaluation -/

@[step] theorem condition_value_holds_spec
    (test : auths_model.observation.ConditionTest)
    (observed actionValue : Option auths_model.observation.FactValue)
    (testValid : TestValid test) (observedValid : OptionValid observed)
    (actionValid : OptionValid actionValue) (factName : String) :
    auths_model.observation.condition_value_holds test observed actionValue
      ⦃ result => result =
        valueHolds (fun _ => actionValue.map factValue) (observed.map factValue)
          (conditionOf factName test) ⦄ := by
  unfold auths_model.observation.condition_value_holds
  cases observed with
  | none =>
      simp only [spec_ok]
      cases test <;> simp [conditionOf, valueHolds]
      split <;> simp
  | some observed =>
      have observedValid := observedValid observed rfl
      cases test with
      | EqLiteral literal =>
          apply WP.spec_mono (fact_value_equal_spec observed literal observedValid testValid)
          intro result resultEq
          simp [resultEq, conditionOf, valueHolds]
      | EqAction reference =>
          cases actionValue with
          | none => simp [conditionOf, valueHolds]
          | some actionValue =>
              have actionValid := actionValid actionValue rfl
              apply WP.spec_mono
                (fact_value_equal_spec observed actionValue observedValid actionValid)
              intro result resultEq
              simp [resultEq, conditionOf, valueHolds]
      | UintRange range =>
          cases observed with
          | Uint value =>
              dsimp only
              rw [translated_uint_range_contains_refines_model range.lo range.hi value
                factName (fun _ => actionValue.map factValue)]
              simp [conditionOf, factValue]
          | Bytes _ => simp [conditionOf, valueHolds, factValue]
          | Text _ => simp [conditionOf, valueHolds, factValue]
      | Member values =>
          apply WP.spec_mono
            (member_values_contain_spec values observed testValid observedValid)
          intro result resultEq
          rw [resultEq]
          simp only [conditionOf, valueHolds, factValue]
          exact any_eq_decide_mem values.val observed

/-- One condition atom against an already looked-up observed value is the
model's `valueHolds`, with the explicitly supplied action value standing in
for the profile's action fact. -/
theorem translated_condition_value_holds_refines_model
    (test : auths_model.observation.ConditionTest)
    (observed actionValue : Option auths_model.observation.FactValue)
    (testValid : TestValid test) (observedValid : OptionValid observed)
    (actionValid : OptionValid actionValue) (factName : String) :
    auths_model.observation.condition_value_holds test observed actionValue =
      ok (valueHolds (fun _ => actionValue.map factValue) (observed.map factValue)
        (conditionOf factName test)) :=
  result_eq_ok_of_spec
    (condition_value_holds_spec test observed actionValue testValid observedValid
      actionValid factName)

@[step] theorem observation_condition_holds_spec
    (value : auths_model.observation.ObservationCondition)
    (actionValue : Option auths_model.observation.FactValue)
    (facts : auths_model.observation.ObservationFacts)
    (conditionValid : ConditionValid value) (actionValid : OptionValid actionValue)
    (factsValid : FactsValid facts) :
    auths_model.observation.observation_condition_holds value actionValue facts
      ⦃ result => result =
        valueHolds (fun _ => actionValue.map factValue)
          (lookupFact (factsOf facts) value.«name») (condition value) ⦄ := by
  unfold auths_model.observation.observation_condition_holds
  step with observation_fact_spec as ⟨observed, observedEq⟩
  have observedValid : OptionValid observed := by
    rw [observedEq]
    exact factLookup_valid facts value.«name» factsValid
  cases actionValue with
  | none =>
      apply WP.spec_mono
        (condition_value_holds_spec value.test observed none conditionValid.2
          observedValid (fun _ absent => nomatch absent) value.«name»)
      intro result resultEq
      rw [resultEq, observedEq, factLookup_refines]
      rfl
  | some inner =>
      apply WP.spec_mono
        (condition_value_holds_spec value.test observed (some inner) conditionValid.2
          observedValid actionValid value.«name»)
      intro result resultEq
      rw [resultEq, observedEq, factLookup_refines]
      rfl

/-- One named condition over an observation's facts is the model's
`valueHolds` on the looked-up fact. -/
theorem translated_observation_condition_holds_refines_model
    (value : auths_model.observation.ObservationCondition)
    (actionValue : Option auths_model.observation.FactValue)
    (facts : auths_model.observation.ObservationFacts)
    (conditionValid : ConditionValid value) (actionValid : OptionValid actionValue)
    (factsValid : FactsValid facts) :
    auths_model.observation.observation_condition_holds value actionValue facts =
      ok (valueHolds (fun _ => actionValue.map factValue)
        (lookupFact (factsOf facts) value.«name») (condition value)) :=
  result_eq_ok_of_spec
    (observation_condition_holds_spec value actionValue facts conditionValid
      actionValid factsValid)

def pairHolds (facts : auths_model.observation.ObservationFacts)
    (pair : auths_model.observation.ObservationCondition ×
      Option auths_model.observation.FactValue) : Bool :=
  valueHolds (fun _ => pair.2.map factValue) (lookupFact (factsOf facts) pair.1.«name»)
    (condition pair.1)

@[step] theorem observation_conditions_hold_spec
    (conditions : Slice auths_model.observation.ObservationCondition)
    (actionValues : Slice (Option auths_model.observation.FactValue))
    (facts : auths_model.observation.ObservationFacts)
    (conditionsValid : ∀ value ∈ conditions.val, ConditionValid value)
    (actionValuesValid : ∀ value ∈ actionValues.val, OptionValid value)
    (factsValid : FactsValid facts) :
    auths_model.observation.observation_conditions_hold conditions actionValues facts
      ⦃ result => result =
        (decide (conditions.val.length = actionValues.val.length) &&
          (conditions.val.zip actionValues.val).all (pairHolds facts)) ⦄ := by
  unfold auths_model.observation.observation_conditions_hold
  dsimp only
  split <;> rename_i lengthCondition
  · simp only [spec_ok]
    have : conditions.val.length ≠ actionValues.val.length := by scalar_tac
    simp [this]
  · have lengthEqual : conditions.val.length = actionValues.val.length := by
      scalar_tac
    simp only [lengthEqual, decide_true, Bool.true_and]
    unfold auths_model.observation.observation_conditions_hold_loop
    apply loop.spec_decr_nat
      (measure := fun index => conditions.val.length - index.val)
      (inv := fun index =>
        index.val ≤ conditions.val.length ∧
        (conditions.val.zip actionValues.val).all (pairHolds facts) =
          ((conditions.val.zip actionValues.val).drop index.val).all (pairHolds facts))
    · rintro index ⟨indexBound, allDrop⟩
      unfold auths_model.observation.observation_conditions_hold_loop.body
      dsimp only
      split <;> rename_i withinBounds
      · have inBounds : index.val < conditions.val.length := by
          simpa using withinBounds
        have actionInBounds : index.val < actionValues.val.length := by
          omega
        have zipInBounds :
            index.val < (conditions.val.zip actionValues.val).length := by
          simp [List.length_zip, inBounds, actionInBounds]
        step as ⟨current, currentEq⟩
        step as ⟨actionValue, actionValueEq⟩
        have currentValid : ConditionValid current := by
          rw [currentEq]
          exact conditionsValid _ (List.getElem_mem inBounds)
        have actionValid : OptionValid actionValue := by
          rw [actionValueEq]
          exact actionValuesValid _ (List.getElem_mem actionInBounds)
        step with observation_condition_holds_spec as ⟨holds, holdsEq⟩
        rw [List.drop_eq_getElem_cons zipInBounds, List.all_cons,
          List.getElem_zip] at allDrop
        rw [← currentEq, ← actionValueEq] at allDrop
        have pairEq : pairHolds facts (current, actionValue) = holds := by
          rw [holdsEq]
          rfl
        rw [pairEq] at allDrop
        split <;> rename_i passed
        · step as ⟨nextIndex, nextIndexPost⟩
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          rw [allDrop, nextIndexPost]
          simp [passed]
        · simp only [spec_ok]
          simp [allDrop, passed]
      · simp only [spec_ok]
        have atEnd : (conditions.val.zip actionValues.val).length ≤ index.val := by
          have : conditions.val.length ≤ index.val := by simpa using withinBounds
          simp [List.length_zip]
          omega
        rw [allDrop, List.drop_eq_nil_of_le atEnd]
        rfl
    · exact ⟨by simp, by simp⟩

/-- The conjunction loop is the model's conjunction over the conditions paired
with their supplied action values, and fails closed on a length mismatch. -/
theorem translated_observation_conditions_hold_refines_model
    (conditions : Slice auths_model.observation.ObservationCondition)
    (actionValues : Slice (Option auths_model.observation.FactValue))
    (facts : auths_model.observation.ObservationFacts)
    (conditionsValid : ∀ value ∈ conditions.val, ConditionValid value)
    (actionValuesValid : ∀ value ∈ actionValues.val, OptionValid value)
    (factsValid : FactsValid facts) :
    auths_model.observation.observation_conditions_hold conditions actionValues facts =
      ok (decide (conditions.val.length = actionValues.val.length) &&
        (conditions.val.zip actionValues.val).all fun pair =>
          valueHolds (fun _ => pair.2.map factValue)
            (lookupFact (factsOf facts) pair.1.«name») (condition pair.1)) :=
  result_eq_ok_of_spec
    (observation_conditions_hold_spec conditions actionValues facts conditionsValid
      actionValuesValid factsValid)

/-- A condition list and action-value list of different lengths is rejected
before any condition is evaluated. -/
theorem translated_observation_conditions_length_mismatch_fails_closed
    (conditions : Slice auths_model.observation.ObservationCondition)
    (actionValues : Slice (Option auths_model.observation.FactValue))
    (facts : auths_model.observation.ObservationFacts)
    (mismatch : conditions.val.length ≠ actionValues.val.length) :
    auths_model.observation.observation_conditions_hold conditions actionValues facts =
      ok false := by
  unfold auths_model.observation.observation_conditions_hold
  have : Slice.len conditions ≠ Slice.len actionValues := by
    intro same
    exact mismatch (by simpa using congrArg UScalar.val same)
  simp [this]

/-- The supplied action values are exactly the environment's action facts for
every `eqAction` reference, position by position. -/
def ActionValuesMatch (env : Environment)
    (conditions : List auths_model.observation.ObservationCondition)
    (actionValues : List (Option auths_model.observation.FactValue)) : Prop :=
  ∀ pair ∈ conditions.zip actionValues,
    match pair.1.test with
    | .EqAction reference => pair.2.map factValue = env.actionFact reference
    | _ => True

theorem pairHolds_eq_conditionHolds (env : Environment)
    (observation : ObservationRecord)
    (facts : auths_model.observation.ObservationFacts)
    (factsEq : observation.facts = factsOf facts)
    (pair : auths_model.observation.ObservationCondition ×
      Option auths_model.observation.FactValue)
    (matched : match pair.1.test with
      | .EqAction reference => pair.2.map factValue = env.actionFact reference
      | _ => True) :
    pairHolds facts pair = conditionHolds env observation (condition pair.1) := by
  obtain ⟨⟨factName, test⟩, actionValue⟩ := pair
  simp only [pairHolds, conditionHolds, factsEq, condition]
  cases test with
  | EqAction reference =>
      simp only at matched
      simp only [conditionOf, conditionName, valueHolds]
      rw [matched]
      cases env.actionFact reference <;> rfl
  | EqLiteral _ => simp [conditionOf, conditionName, valueHolds]
  | UintRange _ => simp [conditionOf, conditionName, valueHolds]
  | Member _ => simp [conditionOf, conditionName, valueHolds]

/-- With action values drawn from the environment, the translated conjunction
is the model's `conditionsHold` on the abstracted conditions. -/
theorem translated_observation_conditions_hold_refines_conditions_hold
    (env : Environment) (observation : ObservationRecord)
    (conditions : Slice auths_model.observation.ObservationCondition)
    (actionValues : Slice (Option auths_model.observation.FactValue))
    (facts : auths_model.observation.ObservationFacts)
    (conditionsValid : ∀ value ∈ conditions.val, ConditionValid value)
    (actionValuesValid : ∀ value ∈ actionValues.val, OptionValid value)
    (factsValid : FactsValid facts)
    (factsEq : observation.facts = factsOf facts)
    (lengthEqual : conditions.val.length = actionValues.val.length)
    (matched : ActionValuesMatch env conditions.val actionValues.val) :
    auths_model.observation.observation_conditions_hold conditions actionValues facts =
      ok (conditionsHold env observation (conditions.val.map condition)) := by
  rw [translated_observation_conditions_hold_refines_model conditions actionValues
    facts conditionsValid actionValuesValid factsValid]
  congr 1
  simp only [lengthEqual, decide_true, Bool.true_and, conditionsHold]
  have pointwise : ∀ pair ∈ conditions.val.zip actionValues.val,
      pairHolds facts pair = conditionHolds env observation (condition pair.1) :=
    fun pair member =>
      pairHolds_eq_conditionHolds env observation facts factsEq pair (matched pair member)
  have firsts : (conditions.val.zip actionValues.val).map Prod.fst = conditions.val :=
    List.map_fst_zip (by omega)
  calc (conditions.val.zip actionValues.val).all (fun pair => pairHolds facts pair)
      = (conditions.val.zip actionValues.val).all
          (fun pair => conditionHolds env observation (condition pair.1)) := by
        apply Bool.eq_iff_iff.mpr
        simp only [List.all_eq_true]
        constructor
        · intro holds pair member
          rw [← pointwise pair member]
          exact holds pair member
        · intro holds pair member
          rw [pointwise pair member]
          exact holds pair member
    _ = (conditions.val.map condition).all (conditionHolds env observation) := by
        conv_rhs => rw [← firsts]
        rw [List.map_map, List.all_map]
        rfl

/-! ## Requirement verdict -/

/-- The verdict combinator is the model's three-valued decision order:
satisfied first, then denied when some observation was eligible, otherwise
indeterminate. -/
theorem translated_requirement_verdict_refines_model
    (anyEligible anySatisfying : Bool) :
    ∃ verdict,
      auths_model.observation.requirement_verdict anyEligible anySatisfying = ok verdict ∧
        decisionOf verdict =
          if anySatisfying then .satisfied
          else if anyEligible then .denied
          else .indeterminate := by
  unfold auths_model.observation.requirement_verdict
  cases anySatisfying <;> cases anyEligible <;> simp [decisionOf]

/-- When every action fact the requirement references is available, the
translated verdict over the model's eligibility and satisfaction is exactly
`requirementDecision`. -/
theorem translated_requirement_verdict_refines_requirement_decision
    (env : Environment) (observations : List ObservationRecord)
    (requirement : Requirement)
    (available : actionFactsAvailable env requirement = true) :
    ∃ verdict,
      auths_model.observation.requirement_verdict
          (observations.any (eligible env requirement))
          (satisfied env observations requirement) = ok verdict ∧
        decisionOf verdict = requirementDecision env observations requirement := by
  obtain ⟨verdict, isOk, decided⟩ :=
    translated_requirement_verdict_refines_model
      (observations.any (eligible env requirement))
      (satisfied env observations requirement)
  refine ⟨verdict, isOk, ?_⟩
  rw [decided]
  simp [requirementDecision, available]

/-! ## Requirement attenuation -/

def subjectOf : auths_model.observation.ObservationSubject → Subject
  | .Resource resource => .literal resource
  | .ActionFact factName => .actionFact factName

def requirementOf (value : auths_model.observation.ObservationRequirement) :
    Requirement where
  observerAnchor := value.observer_anchor
  schema := value.schema
  subject := subjectOf value.subject
  maxAge := value.max_age_seconds.val
  conditions := value.conditions.val.map condition

def SubjectValid : auths_model.observation.ObservationSubject → Prop
  | .Resource resource => StringBounded resource
  | .ActionFact factName => StringBounded factName

def TestComparable : auths_model.observation.ConditionTest → Prop
  | .EqLiteral value => FactValueValid value
  | .EqAction reference => StringBounded reference
  | .UintRange _ => True
  | .Member values => ∀ value ∈ values.val, FactValueValid value

def ConditionComparable (value : auths_model.observation.ObservationCondition) : Prop :=
  StringBounded value.«name» ∧ TestComparable value.test

def RequirementValid (value : auths_model.observation.ObservationRequirement) : Prop :=
  StringBounded value.observer_anchor ∧ StringBounded value.schema ∧
    SubjectValid value.subject ∧
    ∀ condition ∈ value.conditions.val, ConditionComparable condition

instance (child parent : Requirement) : Decidable (sameTarget child parent) := by
  unfold sameTarget; infer_instance

instance (child parent : Requirement) : Decidable (narrows child parent) := by
  unfold narrows; infer_instance

instance (child parent : Requirement) : Decidable (covers child parent) := by
  unfold covers; infer_instance

instance (child parent : List Requirement) :
    Decidable (requirementsAttenuate child parent) := by
  unfold requirementsAttenuate; infer_instance

theorem drop_map_eq_iff {α β : Type} (f : α → β) (left right : List α) (index : Nat)
    (inBounds : index < left.length) (sameLength : left.length = right.length) :
    (left.drop index).map f = (right.drop index).map f ↔
      f left[index] = f (right[index]'(sameLength ▸ inBounds)) ∧
        (left.drop (index + 1)).map f = (right.drop (index + 1)).map f := by
  have rightInBounds : index < right.length := sameLength ▸ inBounds
  rw [List.drop_eq_getElem_cons inBounds, List.drop_eq_getElem_cons rightInBounds]
  simp only [List.map_cons, List.cons.injEq]

@[step] theorem observer_anchor_id_equal_spec
    (left right : auths_model.observation.ObserverAnchorId)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    auths_model.observation.observer_anchor_id_equal left right
      ⦃ result => result = decide (left = right) ⦄ := by
  unfold auths_model.observation.observer_anchor_id_equal
  exact string_equal_spec left right leftBounded rightBounded

/-- Observer-anchor identifiers compare as the model's `String` equality. -/
theorem translated_observer_anchor_id_equal_refines_model
    (left right : auths_model.observation.ObserverAnchorId)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    auths_model.observation.observer_anchor_id_equal left right =
      ok (decide (left = right)) :=
  result_eq_ok_of_spec (observer_anchor_id_equal_spec left right leftBounded rightBounded)

@[step] theorem observation_schema_equal_spec
    (left right : auths_model.observation.ObservationSchemaId)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    auths_model.observation.observation_schema_equal left right
      ⦃ result => result = decide (left = right) ⦄ := by
  unfold auths_model.observation.observation_schema_equal
  exact string_equal_spec left right leftBounded rightBounded

/-- Observation-schema identifiers compare as the model's `String` equality. -/
theorem translated_observation_schema_equal_refines_model
    (left right : auths_model.observation.ObservationSchemaId)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    auths_model.observation.observation_schema_equal left right =
      ok (decide (left = right)) :=
  result_eq_ok_of_spec (observation_schema_equal_spec left right leftBounded rightBounded)

@[step] theorem requirement_subject_equal_spec
    (left right : auths_model.observation.ObservationSubject)
    (leftValid : SubjectValid left) (rightValid : SubjectValid right) :
    auths_model.observation.requirement_subject_equal left right
      ⦃ result => result = decide (subjectOf left = subjectOf right) ⦄ := by
  unfold auths_model.observation.requirement_subject_equal
  cases left with
  | Resource left =>
      cases right with
      | Resource right =>
          simp only [SubjectValid] at leftValid rightValid
          dsimp only
          rw [translated_observation_subject_equal_refines_model left right leftValid
            rightValid]
          simp [subjectOf]
      | ActionFact _ => simp [subjectOf]
  | ActionFact left =>
      cases right with
      | Resource _ => simp [subjectOf]
      | ActionFact right =>
          simp only [SubjectValid] at leftValid rightValid
          apply WP.spec_mono (fact_name_equal_spec left right leftValid rightValid)
          intro result resultEq
          simp [resultEq, subjectOf]

/-- Requirement subjects compare as model subjects: the same literal resource
or the same action-fact name. -/
theorem translated_requirement_subject_equal_refines_model
    (left right : auths_model.observation.ObservationSubject)
    (leftValid : SubjectValid left) (rightValid : SubjectValid right) :
    auths_model.observation.requirement_subject_equal left right =
      ok (decide (subjectOf left = subjectOf right)) :=
  result_eq_ok_of_spec (requirement_subject_equal_spec left right leftValid rightValid)

@[step] theorem member_values_equal_spec
    (left right : auths_model.observation.MemberValues)
    (leftValid : ∀ value ∈ left.val, FactValueValid value)
    (rightValid : ∀ value ∈ right.val, FactValueValid value) :
    auths_model.observation.member_values_equal left right
      ⦃ result => result =
        decide (left.val.map factValue = right.val.map factValue) ⦄ := by
  unfold auths_model.observation.member_values_equal
  dsimp only
  split <;> rename_i lengthCondition
  · simp only [spec_ok]
    have : left.val.length ≠ right.val.length := by scalar_tac
    have : left.val.map factValue ≠ right.val.map factValue := fun same =>
      this (by simpa using congrArg List.length same)
    simp [this]
  · have sameLength : left.val.length = right.val.length := by scalar_tac
    unfold auths_model.observation.member_values_equal_loop
    apply loop.spec_decr_nat
      (measure := fun index => left.val.length - index.val)
      (inv := fun index =>
        index.val ≤ left.val.length ∧
        (left.val.map factValue = right.val.map factValue ↔
          (left.val.drop index.val).map factValue =
            (right.val.drop index.val).map factValue))
    · rintro index ⟨indexBound, equalDrop⟩
      unfold auths_model.observation.member_values_equal_loop.body
      dsimp only
      split <;> rename_i withinBounds
      · have inBounds : index.val < left.val.length := by simpa using withinBounds
        have rightInBounds : index.val < right.val.length := by omega
        step as ⟨leftValue, leftEq⟩
        step as ⟨rightValue, rightEq⟩
        have leftValueValid : FactValueValid leftValue := by
          rw [leftEq]; exact leftValid _ (List.getElem_mem inBounds)
        have rightValueValid : FactValueValid rightValue := by
          rw [rightEq]; exact rightValid _ (List.getElem_mem rightInBounds)
        step with fact_value_equal_spec as ⟨equal, equalEq⟩
        rw [drop_map_eq_iff factValue _ _ _ inBounds sameLength, ← leftEq, ← rightEq]
          at equalDrop
        split <;> rename_i matched
        · step as ⟨nextIndex, nextIndexPost⟩
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          rw [equalDrop, nextIndexPost]
          simp_all
        · simp only [spec_ok]
          simp_all
      · simp only [spec_ok]
        have atEnd : left.val.length ≤ index.val := by simpa using withinBounds
        have rightAtEnd : right.val.length ≤ index.val := by omega
        rw [List.drop_eq_nil_of_le atEnd, List.drop_eq_nil_of_le rightAtEnd] at equalDrop
        simp [equalDrop]
    · exact ⟨by simp, by simp⟩


/-- Membership lists compare positionally as lists of model values. -/
theorem translated_member_values_equal_refines_model
    (left right : auths_model.observation.MemberValues)
    (leftValid : ∀ value ∈ left.val, FactValueValid value)
    (rightValid : ∀ value ∈ right.val, FactValueValid value) :
    auths_model.observation.member_values_equal left right =
      ok (decide (left.val.map factValue = right.val.map factValue)) :=
  result_eq_ok_of_spec (member_values_equal_spec left right leftValid rightValid)

@[step] theorem condition_test_equal_spec
    (left right : auths_model.observation.ConditionTest)
    (leftComparable : TestComparable left) (rightComparable : TestComparable right)
    (factName : String) :
    auths_model.observation.condition_test_equal left right
      ⦃ result => result =
        decide (conditionOf factName left = conditionOf factName right) ⦄ := by
  unfold auths_model.observation.condition_test_equal
  cases left with
  | EqLiteral left =>
      cases right with
      | EqLiteral right =>
          apply WP.spec_mono (fact_value_equal_spec left right leftComparable rightComparable)
          intro result resultEq
          simp [resultEq, conditionOf]
      | EqAction _ => simp [conditionOf]
      | UintRange _ => simp [conditionOf]
      | Member _ => simp [conditionOf]
  | EqAction left =>
      cases right with
      | EqLiteral _ => simp [conditionOf]
      | EqAction right =>
          apply WP.spec_mono (fact_name_equal_spec left right leftComparable rightComparable)
          intro result resultEq
          simp [resultEq, conditionOf]
      | UintRange _ => simp [conditionOf]
      | Member _ => simp [conditionOf]
  | UintRange left =>
      cases right with
      | EqLiteral _ => simp [conditionOf]
      | EqAction _ => simp [conditionOf]
      | UintRange right =>
          dsimp only
          simp only [conditionOf, Condition.uintRange.injEq, true_and]
          split <;> rename_i sameLo
          · simp [sameLo, UScalar.val_eq_imp_iff]
          · have : left.lo.val ≠ right.lo.val := fun same =>
              sameLo (UScalar.eq_of_val_eq same)
            simp [this]
      | Member _ => simp [conditionOf]
  | Member left =>
      cases right with
      | EqLiteral _ => simp [conditionOf]
      | EqAction _ => simp [conditionOf]
      | UintRange _ => simp [conditionOf]
      | Member right =>
          apply WP.spec_mono
            (member_values_equal_spec left right leftComparable rightComparable)
          intro result resultEq
          simp [resultEq, conditionOf]

/-- Condition atoms compare as model conditions over the same fact name. -/
theorem translated_condition_test_equal_refines_model
    (left right : auths_model.observation.ConditionTest)
    (leftComparable : TestComparable left) (rightComparable : TestComparable right)
    (factName : String) :
    auths_model.observation.condition_test_equal left right =
      ok (decide (conditionOf factName left = conditionOf factName right)) :=
  result_eq_ok_of_spec
    (condition_test_equal_spec left right leftComparable rightComparable factName)

theorem conditionName_conditionOf (factName : String)
    (test : auths_model.observation.ConditionTest) :
    conditionName (conditionOf factName test) = factName := by
  cases test <;> rfl

theorem condition_eq_iff (left right : auths_model.observation.ObservationCondition) :
    condition left = condition right ↔
      left.«name» = right.«name» ∧
        conditionOf left.«name» left.test = conditionOf left.«name» right.test := by
  constructor
  · intro same
    have sameName : left.«name» = right.«name» := by
      have := congrArg conditionName same
      simpa [condition, conditionName_conditionOf] using this
    refine ⟨sameName, ?_⟩
    simpa [condition, sameName] using same
  · rintro ⟨sameName, sameTest⟩
    simpa [condition, sameName] using sameTest

@[step] theorem observation_condition_equal_spec
    (left right : auths_model.observation.ObservationCondition)
    (leftComparable : ConditionComparable left)
    (rightComparable : ConditionComparable right) :
    auths_model.observation.observation_condition_equal left right
      ⦃ result => result = decide (condition left = condition right) ⦄ := by
  unfold auths_model.observation.observation_condition_equal
  step with fact_name_equal_spec as ⟨sameName, sameNameEq⟩
  split <;> rename_i named
  · have names : left.«name» = right.«name» := by simpa [sameNameEq] using named
    apply WP.spec_mono
      (condition_test_equal_spec left.test right.test leftComparable.2
        rightComparable.2 left.«name»)
    intro result resultEq
    simp [resultEq, condition_eq_iff, names]
  · have names : left.«name» ≠ right.«name» := by simpa [sameNameEq] using named
    simp [condition_eq_iff, names]

/-- One condition compares as the model condition: the same fact name and the
same atom. -/
theorem translated_observation_condition_equal_refines_model
    (left right : auths_model.observation.ObservationCondition)
    (leftComparable : ConditionComparable left)
    (rightComparable : ConditionComparable right) :
    auths_model.observation.observation_condition_equal left right =
      ok (decide (condition left = condition right)) :=
  result_eq_ok_of_spec
    (observation_condition_equal_spec left right leftComparable rightComparable)


@[step] theorem observation_conditions_contain_spec
    (conditions : Slice auths_model.observation.ObservationCondition)
    (value : auths_model.observation.ObservationCondition)
    (conditionsComparable : ∀ member ∈ conditions.val, ConditionComparable member)
    (valueComparable : ConditionComparable value) :
    auths_model.observation.observation_conditions_contain conditions value
      ⦃ result => result = decide (condition value ∈ conditions.val.map condition) ⦄ := by
  unfold auths_model.observation.observation_conditions_contain
    auths_model.observation.observation_conditions_contain_loop
  apply loop.spec_decr_nat
    (measure := fun index => conditions.val.length - index.val)
    (inv := fun index =>
      index.val ≤ conditions.val.length ∧
      (condition value ∈ conditions.val.map condition ↔
        condition value ∈ (conditions.val.drop index.val).map condition))
  · rintro index ⟨indexBound, memberDrop⟩
    unfold auths_model.observation.observation_conditions_contain_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < conditions.val.length := by simpa using withinBounds
      step as ⟨current, currentEq⟩
      have currentComparable : ConditionComparable current := by
        rw [currentEq]; exact conditionsComparable _ (List.getElem_mem inBounds)
      step with observation_condition_equal_spec as ⟨equal, equalEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.mem_cons,
        ← currentEq] at memberDrop
      split <;> rename_i matched
      · simp only [spec_ok]
        have : condition current = condition value := by simpa [equalEq] using matched
        simp [memberDrop, this]
      · step as ⟨nextIndex, nextIndexPost⟩
        have : condition value ≠ condition current := by
          intro same; exact matched (by simp [equalEq, same])
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [memberDrop, nextIndexPost]
        simp [this]
    · simp only [spec_ok]
      have atEnd : conditions.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at memberDrop
      simp [memberDrop]
  · exact ⟨by simp, by simp⟩

/-- Condition-list containment is membership of the model condition. -/
theorem translated_observation_conditions_contain_refines_model
    (conditions : Slice auths_model.observation.ObservationCondition)
    (value : auths_model.observation.ObservationCondition)
    (conditionsComparable : ∀ member ∈ conditions.val, ConditionComparable member)
    (valueComparable : ConditionComparable value) :
    auths_model.observation.observation_conditions_contain conditions value =
      ok (decide (condition value ∈ conditions.val.map condition)) :=
  result_eq_ok_of_spec
    (observation_conditions_contain_spec conditions value conditionsComparable
      valueComparable)

@[step] theorem observation_conditions_include_spec
    (narrower wider : Slice auths_model.observation.ObservationCondition)
    (narrowerComparable : ∀ member ∈ narrower.val, ConditionComparable member)
    (widerComparable : ∀ member ∈ wider.val, ConditionComparable member) :
    auths_model.observation.observation_conditions_include narrower wider
      ⦃ result => result =
        decide (∀ value ∈ wider.val.map condition,
          value ∈ narrower.val.map condition) ⦄ := by
  unfold auths_model.observation.observation_conditions_include
    auths_model.observation.observation_conditions_include_loop
  apply loop.spec_decr_nat
    (measure := fun index => wider.val.length - index.val)
    (inv := fun index =>
      index.val ≤ wider.val.length ∧
      ((∀ value ∈ wider.val.map condition, value ∈ narrower.val.map condition) ↔
        ∀ value ∈ (wider.val.drop index.val).map condition,
          value ∈ narrower.val.map condition))
  · rintro index ⟨indexBound, allDrop⟩
    unfold auths_model.observation.observation_conditions_include_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < wider.val.length := by simpa using withinBounds
      step as ⟨current, currentEq⟩
      have currentComparable : ConditionComparable current := by
        rw [currentEq]; exact widerComparable _ (List.getElem_mem inBounds)
      step with observation_conditions_contain_spec as ⟨contained, containedEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.forall_mem_cons,
        ← currentEq] at allDrop
      split <;> rename_i matched
      · step as ⟨nextIndex, nextIndexPost⟩
        have : condition current ∈ narrower.val.map condition := by
          simpa [containedEq] using matched
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [allDrop, nextIndexPost]
        simp [this]
      · simp only [spec_ok]
        have : condition current ∉ narrower.val.map condition := by
          simpa [containedEq] using matched
        simp only [allDrop, this, false_and, decide_false]
    · simp only [spec_ok]
      have atEnd : wider.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at allDrop
      simp only [allDrop, List.map_nil, List.not_mem_nil, false_implies, implies_true,
        decide_true]
  · exact ⟨by simp, by simp⟩

/-- Condition-list inclusion is the model's atom-set inclusion: every atom of
`wider` occurs in `narrower`. -/
theorem translated_observation_conditions_include_refines_model
    (narrower wider : Slice auths_model.observation.ObservationCondition)
    (narrowerComparable : ∀ member ∈ narrower.val, ConditionComparable member)
    (widerComparable : ∀ member ∈ wider.val, ConditionComparable member) :
    auths_model.observation.observation_conditions_include narrower wider =
      ok (decide (∀ value ∈ wider.val.map condition,
        value ∈ narrower.val.map condition)) :=
  result_eq_ok_of_spec
    (observation_conditions_include_spec narrower wider narrowerComparable
      widerComparable)

@[step] theorem observation_conditions_equal_spec
    (left right : Slice auths_model.observation.ObservationCondition)
    (leftComparable : ∀ member ∈ left.val, ConditionComparable member)
    (rightComparable : ∀ member ∈ right.val, ConditionComparable member) :
    auths_model.observation.observation_conditions_equal left right
      ⦃ result => result =
        decide (left.val.map condition = right.val.map condition) ⦄ := by
  unfold auths_model.observation.observation_conditions_equal
  dsimp only
  split <;> rename_i lengthCondition
  · simp only [spec_ok]
    have : left.val.length ≠ right.val.length := by scalar_tac
    have : left.val.map condition ≠ right.val.map condition := fun same =>
      this (by simpa using congrArg List.length same)
    simp [this]
  · have sameLength : left.val.length = right.val.length := by scalar_tac
    unfold auths_model.observation.observation_conditions_equal_loop
    apply loop.spec_decr_nat
      (measure := fun index => left.val.length - index.val)
      (inv := fun index =>
        index.val ≤ left.val.length ∧
        (left.val.map condition = right.val.map condition ↔
          (left.val.drop index.val).map condition =
            (right.val.drop index.val).map condition))
    · rintro index ⟨indexBound, equalDrop⟩
      unfold auths_model.observation.observation_conditions_equal_loop.body
      dsimp only
      split <;> rename_i withinBounds
      · have inBounds : index.val < left.val.length := by simpa using withinBounds
        have rightInBounds : index.val < right.val.length := by omega
        step as ⟨leftValue, leftEq⟩
        step as ⟨rightValue, rightEq⟩
        have leftValueComparable : ConditionComparable leftValue := by
          rw [leftEq]; exact leftComparable _ (List.getElem_mem inBounds)
        have rightValueComparable : ConditionComparable rightValue := by
          rw [rightEq]; exact rightComparable _ (List.getElem_mem rightInBounds)
        step with observation_condition_equal_spec as ⟨equal, equalEq⟩
        rw [drop_map_eq_iff condition _ _ _ inBounds sameLength, ← leftEq, ← rightEq]
          at equalDrop
        split <;> rename_i matched
        · step as ⟨nextIndex, nextIndexPost⟩
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          rw [equalDrop, nextIndexPost]
          simp_all
        · simp only [spec_ok]
          simp_all
      · simp only [spec_ok]
        have atEnd : left.val.length ≤ index.val := by simpa using withinBounds
        have rightAtEnd : right.val.length ≤ index.val := by omega
        rw [List.drop_eq_nil_of_le atEnd, List.drop_eq_nil_of_le rightAtEnd] at equalDrop
        simp [equalDrop]
    · exact ⟨by simp, by simp⟩

/-- Condition lists compare positionally as lists of model conditions. -/
theorem translated_observation_conditions_equal_refines_model
    (left right : Slice auths_model.observation.ObservationCondition)
    (leftComparable : ∀ member ∈ left.val, ConditionComparable member)
    (rightComparable : ∀ member ∈ right.val, ConditionComparable member) :
    auths_model.observation.observation_conditions_equal left right =
      ok (decide (left.val.map condition = right.val.map condition)) :=
  result_eq_ok_of_spec
    (observation_conditions_equal_spec left right leftComparable rightComparable)


@[step] theorem observation_requirement_same_target_spec
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_same_target child parent
      ⦃ result => result =
        decide (sameTarget (requirementOf child) (requirementOf parent)) ⦄ := by
  obtain ⟨childAnchor, childSchema, childSubject, _⟩ := childValid
  obtain ⟨parentAnchor, parentSchema, parentSubject, _⟩ := parentValid
  unfold auths_model.observation.observation_requirement_same_target
  step with observer_anchor_id_equal_spec as ⟨sameAnchor, sameAnchorEq⟩
  split <;> rename_i anchored
  · have anchors : child.observer_anchor = parent.observer_anchor := by
      simpa [sameAnchorEq] using anchored
    step with observation_schema_equal_spec as ⟨sameSchema, sameSchemaEq⟩
    split <;> rename_i schemed
    · have schemas : child.schema = parent.schema := by
        simpa [sameSchemaEq] using schemed
      apply WP.spec_mono
        (requirement_subject_equal_spec child.subject parent.subject childSubject
          parentSubject)
      intro result resultEq
      simp [resultEq, sameTarget, requirementOf, anchors, schemas]
    · have schemas : child.schema ≠ parent.schema := by
        simpa [sameSchemaEq] using schemed
      simp [sameTarget, requirementOf, schemas]
  · have anchors : child.observer_anchor ≠ parent.observer_anchor := by
      simpa [sameAnchorEq] using anchored
    simp [sameTarget, requirementOf, anchors]

/-- The translated same-target check is the model's `sameTarget`. -/
theorem translated_observation_requirement_same_target_refines_model
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_same_target child parent =
      ok (decide (sameTarget (requirementOf child) (requirementOf parent))) :=
  result_eq_ok_of_spec
    (observation_requirement_same_target_spec child parent childValid parentValid)

theorem requirementOf_eq_iff (child parent : auths_model.observation.ObservationRequirement) :
    requirementOf child = requirementOf parent ↔
      sameTarget (requirementOf child) (requirementOf parent) ∧
        child.max_age_seconds.val = parent.max_age_seconds.val ∧
        child.conditions.val.map condition = parent.conditions.val.map condition := by
  simp only [requirementOf, sameTarget, Requirement.mk.injEq, and_assoc]

@[step] theorem observation_requirement_equal_spec
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_equal child parent
      ⦃ result => result = decide (requirementOf child = requirementOf parent) ⦄ := by
  unfold auths_model.observation.observation_requirement_equal
  step with observation_requirement_same_target_spec as ⟨target, targetEq⟩
  split <;> rename_i targeted
  · have sameTargets : sameTarget (requirementOf child) (requirementOf parent) := by
      simpa [targetEq] using targeted
    split <;> rename_i ageDiffers
    · have : child.max_age_seconds.val ≠ parent.max_age_seconds.val := by
        scalar_tac
      simp [requirementOf_eq_iff, this]
    · have ages : child.max_age_seconds.val = parent.max_age_seconds.val := by
        scalar_tac
      apply WP.spec_mono
        (observation_conditions_equal_spec (alloc.vec.Vec.deref child.conditions)
          (alloc.vec.Vec.deref parent.conditions) childValid.2.2.2 parentValid.2.2.2)
      intro result resultEq
      simp only [alloc.vec.Vec.deref] at resultEq
      simp [resultEq, requirementOf_eq_iff, sameTargets, ages]
  · have : ¬ sameTarget (requirementOf child) (requirementOf parent) := by
      simpa [targetEq] using targeted
    simp [requirementOf_eq_iff, this]

/-- Byte identity of two canonical requirements is equality of the model
requirements. -/
theorem translated_observation_requirement_equal_refines_model
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_equal child parent =
      ok (decide (requirementOf child = requirementOf parent)) :=
  result_eq_ok_of_spec
    (observation_requirement_equal_spec child parent childValid parentValid)


@[step] theorem observation_requirement_narrows_spec
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_narrows child parent
      ⦃ result => result = decide (narrows (requirementOf child) (requirementOf parent)) ⦄ := by
  have childConditions := childValid.2.2.2
  have parentConditions := parentValid.2.2.2
  unfold auths_model.observation.observation_requirement_narrows
  step with observation_requirement_same_target_spec as ⟨target, targetEq⟩
  split <;> rename_i targeted
  · have sameTargets : sameTarget (requirementOf child) (requirementOf parent) := by
      simpa [targetEq] using targeted
    split <;> rename_i older
    · have : ¬ child.max_age_seconds.val ≤ parent.max_age_seconds.val := by
        scalar_tac
      simp [narrows, requirementOf, this]
    · have noOlder : child.max_age_seconds.val ≤ parent.max_age_seconds.val := by
        scalar_tac
      simp only [alloc.vec.Vec.deref]
      step with observation_conditions_include_spec as ⟨superset, supersetEq⟩
      split <;> rename_i isSuperset
      · have superset' : ∀ value ∈ parent.conditions.val.map condition,
            value ∈ child.conditions.val.map condition := by
          simpa [supersetEq] using isSuperset
        split <;> rename_i younger
        · have : child.max_age_seconds.val < parent.max_age_seconds.val := by
            scalar_tac
          simp only [spec_ok]
          exact (decide_eq_true ⟨sameTargets, noOlder, superset', Or.inl this⟩).symm
        · have : ¬ child.max_age_seconds.val < parent.max_age_seconds.val := by
            scalar_tac
          step with observation_conditions_include_spec as ⟨subset, subsetEq⟩
          simp only [subsetEq, decide_eq_true_eq]
          rw [decide_eq_decide]
          constructor
          · intro notSubset
            exact ⟨sameTargets, noOlder, superset', Or.inr notSubset⟩
          · rintro ⟨_, _, _, strict⟩
            exact strict.resolve_left this
      · have : ¬ ∀ value ∈ parent.conditions.val.map condition,
            value ∈ child.conditions.val.map condition := by
          simpa [supersetEq] using isSuperset
        simp only [spec_ok]
        simp only [narrows, requirementOf] at this ⊢
        simp only [this, false_and, and_false, decide_false]
  · have : ¬ sameTarget (requirementOf child) (requirementOf parent) := by
      simpa [targetEq] using targeted
    simp [narrows, this]

/-- The translated strict-narrowing check is the model's `narrows`. -/
theorem translated_observation_requirement_narrows_refines_model
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_narrows child parent =
      ok (decide (narrows (requirementOf child) (requirementOf parent))) :=
  result_eq_ok_of_spec
    (observation_requirement_narrows_spec child parent childValid parentValid)

@[step] theorem observation_requirement_covers_spec
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_covers child parent
      ⦃ result => result = decide (covers (requirementOf child) (requirementOf parent)) ⦄ := by
  unfold auths_model.observation.observation_requirement_covers
  step with observation_requirement_equal_spec as ⟨equal, equalEq⟩
  split <;> rename_i same
  · have : requirementOf child = requirementOf parent := by simpa [equalEq] using same
    simp [covers, this]
  · have : requirementOf child ≠ requirementOf parent := by simpa [equalEq] using same
    apply WP.spec_mono
      (observation_requirement_narrows_spec child parent childValid parentValid)
    intro result resultEq
    simp [resultEq, covers, this]

/-- The translated cover check is the model's `covers`: identical, or a strict
narrowing. -/
theorem translated_observation_requirement_covers_refines_model
    (child parent : auths_model.observation.ObservationRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_covers child parent =
      ok (decide (covers (requirementOf child) (requirementOf parent))) :=
  result_eq_ok_of_spec
    (observation_requirement_covers_spec child parent childValid parentValid)

@[step] theorem observation_requirement_retained_spec
    (child : auths_model.observation.ObservationRequirements)
    (parent : auths_model.observation.ObservationRequirement)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_retained child parent
      ⦃ result => result =
        decide (∃ candidate ∈ child.val.map requirementOf,
          covers candidate (requirementOf parent)) ⦄ := by
  unfold auths_model.observation.observation_requirement_retained
    auths_model.observation.observation_requirement_retained_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.1.val.length - state.2.val)
    (inv := fun state =>
      state.1 = child ∧ state.2.val ≤ child.val.length ∧
      ((∃ candidate ∈ child.val.map requirementOf,
          covers candidate (requirementOf parent)) ↔
        ∃ candidate ∈ (child.val.drop state.2.val).map requirementOf,
          covers candidate (requirementOf parent)))
  · rintro ⟨current, index⟩ ⟨rfl, indexBound, existsDrop⟩
    unfold auths_model.observation.observation_requirement_retained_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < current.val.length := by simpa using withinBounds
      step as ⟨candidate, candidateEq⟩
      have candidateValid : RequirementValid candidate := by
        rw [candidateEq]; exact childValid _ (List.getElem_mem inBounds)
      step with observation_requirement_covers_spec as ⟨covered, coveredEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.exists_mem_cons_iff,
        ← candidateEq] at existsDrop
      split <;> rename_i matched
      · simp only [spec_ok]
        have : covers (requirementOf candidate) (requirementOf parent) := by
          simpa [coveredEq] using matched
        exact (decide_eq_true (existsDrop.mpr (Or.inl this))).symm
      · step as ⟨nextIndex, nextIndexPost⟩
        have : ¬ covers (requirementOf candidate) (requirementOf parent) := by
          simpa [coveredEq] using matched
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [existsDrop, nextIndexPost]
        simp [this]
    · simp only [spec_ok]
      have atEnd : current.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at existsDrop
      simp only [existsDrop, List.map_nil, List.not_mem_nil, false_and, exists_false,
        decide_false]
  · exact ⟨rfl, by simp, by simp⟩

/-- Some child requirement covers the parent requirement, in the model's sense. -/
theorem translated_observation_requirement_retained_refines_model
    (child : auths_model.observation.ObservationRequirements)
    (parent : auths_model.observation.ObservationRequirement)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : RequirementValid parent) :
    auths_model.observation.observation_requirement_retained child parent =
      ok (decide (∃ candidate ∈ child.val.map requirementOf,
        covers candidate (requirementOf parent))) :=
  result_eq_ok_of_spec
    (observation_requirement_retained_spec child parent childValid parentValid)

@[step] theorem observation_requirements_attenuate_spec
    (child parent : auths_model.observation.ObservationRequirements)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : ∀ requirement ∈ parent.val, RequirementValid requirement) :
    auths_model.observation.observation_requirements_attenuate child parent
      ⦃ result => result =
        decide (requirementsAttenuate (child.val.map requirementOf)
          (parent.val.map requirementOf)) ⦄ := by
  unfold auths_model.observation.observation_requirements_attenuate
    auths_model.observation.observation_requirements_attenuate_loop
  unfold requirementsAttenuate
  apply loop.spec_decr_nat
    (measure := fun state => state.1.val.length - state.2.val)
    (inv := fun state =>
      state.1 = parent ∧ state.2.val ≤ parent.val.length ∧
      ((∀ requirement ∈ parent.val.map requirementOf,
          ∃ candidate ∈ child.val.map requirementOf, covers candidate requirement) ↔
        ∀ requirement ∈ (parent.val.drop state.2.val).map requirementOf,
          ∃ candidate ∈ child.val.map requirementOf, covers candidate requirement))
  · rintro ⟨current, index⟩ ⟨rfl, indexBound, allDrop⟩
    unfold auths_model.observation.observation_requirements_attenuate_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < current.val.length := by simpa using withinBounds
      step as ⟨requirement, requirementEq⟩
      have requirementValid : RequirementValid requirement := by
        rw [requirementEq]; exact parentValid _ (List.getElem_mem inBounds)
      step with observation_requirement_retained_spec as ⟨retained, retainedEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.forall_mem_cons,
        ← requirementEq] at allDrop
      split <;> rename_i matched
      · step as ⟨nextIndex, nextIndexPost⟩
        have : ∃ candidate ∈ child.val.map requirementOf,
            covers candidate (requirementOf requirement) := by
          simpa [retainedEq] using matched
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [allDrop, nextIndexPost]
        simp only [this, true_and]
      · simp only [spec_ok]
        have : ¬ ∃ candidate ∈ child.val.map requirementOf,
            covers candidate (requirementOf requirement) := by
          simpa [retainedEq] using matched
        simp only [allDrop, this, false_and, decide_false]
    · simp only [spec_ok]
      have atEnd : current.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at allDrop
      simp only [allDrop, List.map_nil, List.not_mem_nil, false_implies, implies_true,
        decide_true]
  · exact ⟨rfl, by simp, by simp⟩

/-- The translated attenuation check for two requirement lists is the model's
`requirementsAttenuate` on the abstracted lists. -/
theorem translated_observation_requirements_attenuate_refines_model
    (child parent : auths_model.observation.ObservationRequirements)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : ∀ requirement ∈ parent.val, RequirementValid requirement) :
    auths_model.observation.observation_requirements_attenuate child parent =
      ok (decide (requirementsAttenuate (child.val.map requirementOf)
        (parent.val.map requirementOf))) :=
  result_eq_ok_of_spec
    (observation_requirements_attenuate_spec child parent childValid parentValid)

end Auths.Refinement.Observation
