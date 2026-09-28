import Auths.Product.Theorems
import Auths.Product.CeilingCount
import qualification.aeneas.generated.bounded_policy.Funs

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Product.Refinement

def generatedConfigurationMatch :
    Auths.Product.ConfigurationMatch →
      auths_bounded_policy.kernel.ConfigurationMatchCode
  | .matches => .Match
  | .semanticMismatch => .SemanticMismatch
  | .canonicalizationMismatch => .CanonicalizationMismatch
  | .digestMismatch => .DigestMismatch
  | .implementationMismatch => .ImplementationMismatch

theorem translated_configuration_refines_projection
    (semanticEqual canonicalizationEqual digestEqual
      implementationEqualOrUnpinned : Bool) :
    auths_bounded_policy.kernel.configuration_match_code
      semanticEqual canonicalizationEqual digestEqual
      implementationEqualOrUnpinned =
        ok (generatedConfigurationMatch
          (projectedConfigurationMatch
            semanticEqual canonicalizationEqual digestEqual
            implementationEqualOrUnpinned)) := by
  cases semanticEqual <;>
    cases canonicalizationEqual <;>
    cases digestEqual <;>
    cases implementationEqualOrUnpinned <;>
    rfl

theorem translated_checked_add_refines_nat
    (left right : U64) :
    match auths_bounded_policy.kernel.checked_add_u64 left right with
    | ok (some result) =>
        left.val + right.val ≤ U64.max ∧
          result.val = left.val + right.val
    | ok none => U64.max < left.val + right.val
    | fail _ => False
    | div => False := by
  simp only [auths_bounded_policy.kernel.checked_add_u64]
  have specification := U64.checked_add_bv_spec left right
  cases equation : U64.checked_add left right <;>
    simp_all

theorem translated_checked_sub_refines_nat
    (left right : U64) :
    match auths_bounded_policy.kernel.checked_sub_u64 left right with
    | ok (some result) =>
        right.val ≤ left.val ∧ result.val = left.val - right.val
    | ok none => left.val < right.val
    | fail _ => False
    | div => False := by
  simp only [auths_bounded_policy.kernel.checked_sub_u64]
  have specification := U64.checked_sub_bv_spec left right
  cases equation : U64.checked_sub left right <;>
    simp_all

theorem translated_checked_mul_refines_nat
    (left right : U64) :
    match auths_bounded_policy.kernel.checked_mul_u64 left right with
    | ok (some result) =>
        left.val * right.val ≤ U64.max ∧
          result.val = left.val * right.val
    | ok none => U64.max < left.val * right.val
    | fail _ => False
    | div => False := by
  simp only [auths_bounded_policy.kernel.checked_mul_u64]
  have specification := U64.checked_mul_bv_spec left right
  cases equation : U64.checked_mul left right <;>
    simp_all

theorem translated_checked_div_rejects_zero (value : U64) :
    auths_bounded_policy.kernel.checked_div_u64 value (U64.ofNat 0) =
      ok none := by
  simp only [auths_bounded_policy.kernel.checked_div_u64]
  have specification := U64.checked_div_bv_spec value (U64.ofNat 0)
  cases equation : U64.checked_div value (U64.ofNat 0) with
  | none => rfl
  | some result => simp [equation] at specification

def generatedCeilingCountCode :
    Auths.Product.CeilingCount.Code → auths_bounded_policy.kernel.CeilingCountCode
  | .eligible => .Eligible
  | .aboveCeiling => .AboveCeiling
  | .windowExhausted => .WindowExhausted

/-- The translated evaluation leaf computes exactly the model's decision. -/
theorem translated_ceiling_count_refines_model
    (value ceiling count maxCount : U64) :
    auths_bounded_policy.kernel.ceiling_count_code value ceiling count maxCount =
      ok (generatedCeilingCountCode
        (Auths.Product.CeilingCount.codeOf value.val ceiling.val count.val maxCount.val)) := by
  unfold auths_bounded_policy.kernel.ceiling_count_code Auths.Product.CeilingCount.codeOf
  by_cases above : value.val > ceiling.val
  · have above' : value > ceiling := by scalar_tac
    simp [above, above', generatedCeilingCountCode]
  · have notAbove : ¬ value > ceiling := by scalar_tac
    by_cases exhausted : count.val ≥ maxCount.val
    · have exhausted' : count >= maxCount := by scalar_tac
      simp [above, notAbove, exhausted, exhausted', generatedCeilingCountCode]
    · have notExhausted : ¬ count >= maxCount := by scalar_tac
      simp [above, notAbove, exhausted, notExhausted, generatedCeilingCountCode]

/-- The translated tightening leaf computes exactly the model's decider. -/
theorem translated_ceiling_count_tightens_refines_model
    (childCeiling childMax childWindow parentCeiling parentMax parentWindow : U64) :
    auths_bounded_policy.kernel.ceiling_count_tightens
        childCeiling childMax childWindow parentCeiling parentMax parentWindow =
      ok (Auths.Product.CeilingCount.numericTightens
        childCeiling.val childMax.val childWindow.val
        parentCeiling.val parentMax.val parentWindow.val) := by
  unfold auths_bounded_policy.kernel.ceiling_count_tightens
    Auths.Product.CeilingCount.numericTightens
  by_cases windows : childWindow.val = parentWindow.val
  · have windows' : childWindow = parentWindow := by scalar_tac
    by_cases above : childCeiling.val > parentCeiling.val
    · have above' : childCeiling > parentCeiling := by scalar_tac
      simp [windows, windows', above, above']
    · have notAbove : ¬ childCeiling > parentCeiling := by scalar_tac
      simp [windows, windows', above, notAbove]
  · have windows' : childWindow ≠ parentWindow := by
      intro equal
      exact windows (by rw [equal])
    simp [windows, windows']

/-! ## The chain-admission and tightening leaves

`chain_counts_admit`, `chain_sums_admit`, and `argument_policy_tightens`
terminate with `ok` and return exactly their models' results under an
abstraction that maps machine integers to their natural-number values and
vectors and slices to lists. None of the theorems carries a premise: the
loops only read, and the one addition is the checked addition whose overflow
refuses. -/

open Auths.Product.CeilingCount (countsAdmit sumsAdmit)

/-- The natural-number values of a list of machine integers. -/
def natList (values : List U64) : List Nat := values.map (·.val)

/-- The byte values of a list of machine bytes. -/
def byteList (bytes : List U8) : List Nat := bytes.map (·.val)

/-- The bytes of a vector. -/
def vecBytes (vector : alloc.vec.Vec U8) : List Nat := byteList vector.val

@[simp] theorem deref_val {T : Type} (vector : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref vector).val = vector.val := rfl

def valuesOf (list : auths_bounded_policy.kernel.ValueList) :
    Auths.Product.CeilingCount.Values where
  argument := vecBytes list.argument
  values := list.values.val.map vecBytes

def sumBoundOf (bound : auths_bounded_policy.kernel.SumBound) :
    Auths.Product.CeilingCount.SumBound where
  limit := bound.limit.val
  partition := bound.partition.map valuesOf

/-- The model policy of the members the decider reads. -/
def policyOf (members : auths_bounded_policy.kernel.PolicyMembers) :
    Auths.Product.CeilingCount.Policy where
  argument := vecBytes members.argument
  ceiling := members.ceiling.val
  window := members.window.val
  maxCount := members.max_count.val
  sum := members.sum.map sumBoundOf
  scope := members.scope.map valuesOf

theorem zip_all_eq_iff : ∀ (left right : List Nat), left.length = right.length →
    ((left.zip right).all (fun entry => decide (entry.1 = entry.2)) = true ↔ left = right)
  | [], [], _ => by simp
  | [], _ :: _, same => by simp at same
  | _ :: _, [], same => by simp at same
  | head :: tail, head' :: tail', same => by
      simp only [List.length_cons, Nat.add_right_cancel_iff] at same
      simp [zip_all_eq_iff tail tail' same]

/-- The translated count leaf computes exactly the count part of chain
admission. -/
theorem translated_chain_counts_admit_refines_model (counts capacities : Slice U64) :
    auths_bounded_policy.kernel.chain_counts_admit counts capacities ⦃ result =>
      result = countsAdmit (natList counts.val) (natList capacities.val) ⦄ := by
  unfold auths_bounded_policy.kernel.chain_counts_admit
  dsimp only
  split <;> rename_i lengths
  · simp only [spec_ok]
    have differ : counts.val.length ≠ capacities.val.length := by
      simpa [bne_iff_ne, ne_eq, UScalar.eq_equiv] using lengths
    simp [countsAdmit, natList, differ]
  · have same : counts.val.length = capacities.val.length := by
      simpa [bne_iff_ne, ne_eq, UScalar.eq_equiv] using lengths
    unfold auths_bounded_policy.kernel.chain_counts_admit_loop
    apply loop.spec_decr_nat
      (measure := fun index : Usize => counts.val.length - index.val)
      (inv := fun index => countsAdmit (natList counts.val) (natList capacities.val) =
        (((natList counts.val).zip (natList capacities.val)).drop index.val).all
          fun entry => decide (entry.1 < entry.2))
    · intro index invariant
      unfold auths_bounded_policy.kernel.chain_counts_admit_loop.body
      dsimp only
      split <;> rename_i within
      · have inBounds : index.val < counts.val.length := by scalar_tac
        have capacityBounds : index.val < capacities.val.length := by omega
        step as ⟨count, countEq⟩
        step as ⟨capacity, capacityEq⟩
        have zipBounds :
            index.val < ((natList counts.val).zip (natList capacities.val)).length := by
          simp [natList, capacityBounds, inBounds]
        rw [List.drop_eq_getElem_cons zipBounds, List.all_cons] at invariant
        have entryEq : ((natList counts.val).zip (natList capacities.val))[index.val] =
            (count.val, capacity.val) := by
          simp [natList, countEq, capacityEq]
        rw [entryEq] at invariant
        split <;> rename_i exhausted
        · simp only [spec_ok]
          have notBelow : ¬ count.val < capacity.val := by scalar_tac
          simp [invariant, notBelow]
        · step as ⟨next, nextEq⟩
          have below : count.val < capacity.val := by scalar_tac
          refine ⟨?_, by omega⟩
          rw [invariant, nextEq]
          simp [below]
      · simp only [spec_ok]
        have atEnd :
            ((natList counts.val).zip (natList capacities.val)).length ≤ index.val := by
          simp only [natList, List.length_zip, List.length_map]
          scalar_tac
        rw [invariant, List.drop_eq_nil_of_le atEnd]
        rfl
    · simp [countsAdmit, natList, same]

/-- The translated sum leaf computes exactly the sum part of chain
admission; an overflowing addition refuses, as the natural-number model
does, since no capacity exceeds `u64::MAX`. -/
theorem translated_chain_sums_admit_refines_model (sums : Slice U64) (argument : U64)
    (capacities : Slice U64) :
    auths_bounded_policy.kernel.chain_sums_admit sums argument capacities ⦃ result =>
      result = sumsAdmit (natList sums.val) argument.val (natList capacities.val) ⦄ := by
  unfold auths_bounded_policy.kernel.chain_sums_admit
  dsimp only
  split <;> rename_i lengths
  · simp only [spec_ok]
    have differ : sums.val.length ≠ capacities.val.length := by
      simpa [bne_iff_ne, ne_eq, UScalar.eq_equiv] using lengths
    simp [sumsAdmit, natList, differ]
  · have same : sums.val.length = capacities.val.length := by
      simpa [bne_iff_ne, ne_eq, UScalar.eq_equiv] using lengths
    unfold auths_bounded_policy.kernel.chain_sums_admit_loop
    apply loop.spec_decr_nat
      (measure := fun index : Usize => sums.val.length - index.val)
      (inv := fun index => sumsAdmit (natList sums.val) argument.val (natList capacities.val) =
        (((natList sums.val).zip (natList capacities.val)).drop index.val).all
          fun entry => decide (entry.1 + argument.val ≤ entry.2))
    · intro index invariant
      unfold auths_bounded_policy.kernel.chain_sums_admit_loop.body
      dsimp only
      split <;> rename_i within
      · have inBounds : index.val < sums.val.length := by scalar_tac
        have capacityBounds : index.val < capacities.val.length := by omega
        step as ⟨sum, sumEq⟩
        have zipBounds :
            index.val < ((natList sums.val).zip (natList capacities.val)).length := by
          simp [natList, capacityBounds, inBounds]
        rw [List.drop_eq_getElem_cons zipBounds, List.all_cons] at invariant
        have added := U64.checked_add_bv_spec sum argument
        simp only [lift, bind_tc_ok]
        cases equation : U64.checked_add sum argument with
        | none =>
            simp only [spec_ok]
            rw [equation] at added
            have capacityMax : capacities.val[index.val].val ≤ U64.max := by scalar_tac
            have entryEq : ((natList sums.val).zip (natList capacities.val))[index.val] =
                (sum.val, capacities.val[index.val].val) := by
              simp [natList, sumEq]
            rw [entryEq] at invariant
            have exceeds : ¬ sum.val + argument.val ≤ capacities.val[index.val].val := by
              simp only at added
              omega
            simp [invariant, exceeds]
        | some total =>
            rw [equation] at added
            obtain ⟨_, totalEq, _⟩ := added
            step as ⟨capacity, capacityEq⟩
            have entryEq : ((natList sums.val).zip (natList capacities.val))[index.val] =
                (sum.val, capacity.val) := by
              simp [natList, sumEq, capacityEq]
            rw [entryEq] at invariant
            split <;> rename_i above
            · simp only [spec_ok]
              have exceeds : ¬ sum.val + argument.val ≤ capacity.val := by scalar_tac
              simp [invariant, exceeds]
            · step as ⟨next, nextEq⟩
              have within : sum.val + argument.val ≤ capacity.val := by scalar_tac
              refine ⟨?_, by omega⟩
              rw [invariant, nextEq]
              simp [within]
      · simp only [spec_ok]
        have atEnd :
            ((natList sums.val).zip (natList capacities.val)).length ≤ index.val := by
          simp only [natList, List.length_zip, List.length_map]
          scalar_tac
        rw [invariant, List.drop_eq_nil_of_le atEnd]
        rfl
    · simp [sumsAdmit, natList, same]

@[step] theorem bytes_equal_spec (left right : Slice U8) :
    auths_bounded_policy.kernel.bytes_equal left right ⦃ result =>
      result = decide (byteList left.val = byteList right.val) ⦄ := by
  unfold auths_bounded_policy.kernel.bytes_equal
  dsimp only
  split <;> rename_i lengths
  · simp only [spec_ok]
    have differ : left.val.length ≠ right.val.length := by
      simpa [bne_iff_ne, ne_eq, UScalar.eq_equiv] using lengths
    have : byteList left.val ≠ byteList right.val := fun equal => by
      have := congrArg List.length equal
      simp [byteList] at this
      exact differ this
    simp [this]
  · have same : left.val.length = right.val.length := by
      simpa [bne_iff_ne, ne_eq, UScalar.eq_equiv] using lengths
    have modelSame : (byteList left.val).length = (byteList right.val).length := by
      simp [byteList, same]
    unfold auths_bounded_policy.kernel.bytes_equal_loop
    apply loop.spec_decr_nat
      (measure := fun index : Usize => left.val.length - index.val)
      (inv := fun index => decide (byteList left.val = byteList right.val) =
        (((byteList left.val).zip (byteList right.val)).drop index.val).all
          fun entry => decide (entry.1 = entry.2))
    · intro index invariant
      unfold auths_bounded_policy.kernel.bytes_equal_loop.body
      dsimp only
      split <;> rename_i within
      · have inBounds : index.val < left.val.length := by scalar_tac
        have rightBounds : index.val < right.val.length := by omega
        step as ⟨leftByte, leftEq⟩
        step as ⟨rightByte, rightEq⟩
        have zipBounds :
            index.val < ((byteList left.val).zip (byteList right.val)).length := by
          simp [byteList, rightBounds, inBounds]
        rw [List.drop_eq_getElem_cons zipBounds, List.all_cons] at invariant
        have entryEq : ((byteList left.val).zip (byteList right.val))[index.val] =
            (leftByte.val, rightByte.val) := by
          simp [byteList, leftEq, rightEq]
        rw [entryEq] at invariant
        split <;> rename_i differs
        · simp only [spec_ok]
          have notEqual : leftByte.val ≠ rightByte.val := by
            intro equal
            exact (bne_iff_ne.mp differs) (UScalar.eq_equiv _ _ |>.mpr equal)
          simp [invariant, notEqual]
        · step as ⟨next, nextEq⟩
          have equal : leftByte.val = rightByte.val := by
            have := not_ne_iff.mp (fun h => differs (bne_iff_ne.mpr h))
            simp [this]
          refine ⟨?_, by omega⟩
          rw [invariant, nextEq]
          simp [equal]
      · simp only [spec_ok]
        have atEnd : ((byteList left.val).zip (byteList right.val)).length ≤ index.val := by
          simp only [byteList, List.length_zip, List.length_map]
          scalar_tac
        rw [invariant, List.drop_eq_nil_of_le atEnd]
        rfl
    · rw [show ((0#usize : Usize).val) = 0 from by simp, List.drop_zero]
      have := zip_all_eq_iff (byteList left.val) (byteList right.val) modelSame
      by_cases equal : byteList left.val = byteList right.val
      · rw [this.mpr equal]
        simp [equal]
      · have notAll := mt this.mp equal
        simp only [Bool.not_eq_true] at notAll
        simp [equal, notAll]

@[step] theorem values_contain_spec (values : Slice (alloc.vec.Vec U8)) (value : Slice U8) :
    auths_bounded_policy.kernel.values_contain values value ⦃ result =>
      result = decide (byteList value.val ∈ values.val.map vecBytes) ⦄ := by
  unfold auths_bounded_policy.kernel.values_contain auths_bounded_policy.kernel.values_contain_loop
  apply loop.spec_decr_nat
    (measure := fun index : Usize => values.val.length - index.val)
    (inv := fun index => decide (byteList value.val ∈ values.val.map vecBytes) =
      decide (byteList value.val ∈ (values.val.map vecBytes).drop index.val))
  · intro index invariant
    unfold auths_bounded_policy.kernel.values_contain_loop.body
    dsimp only
    split <;> rename_i within
    · have inBounds : index.val < values.val.length := by scalar_tac
      step as ⟨entry, entryEq⟩
      step with bytes_equal_spec as ⟨equal, equalEq⟩
      have mapBounds : index.val < (values.val.map vecBytes).length := by simp [inBounds]
      rw [List.drop_eq_getElem_cons mapBounds] at invariant
      have entryModel : (values.val.map vecBytes)[index.val] = vecBytes entry := by
        simp [entryEq]
      rw [entryModel] at invariant
      simp only [deref_val] at equalEq
      split <;> rename_i found
      · simp only [spec_ok]
        rw [invariant]
        have : vecBytes entry = byteList value.val := by
          simpa [vecBytes, found] using equalEq.symm
        simp [this]
      · step as ⟨next, nextEq⟩
        refine ⟨?_, by omega⟩
        have : vecBytes entry ≠ byteList value.val := by
          intro same
          simp [vecBytes] at same
          simp [same, found] at equalEq
        rw [invariant, nextEq]
        simp [List.mem_cons, Ne.symm this]
    · simp only [spec_ok]
      have atEnd : (values.val.map vecBytes).length ≤ index.val := by
        simp only [List.length_map]
        scalar_tac
      rw [invariant, List.drop_eq_nil_of_le atEnd]
      simp
  · simp

@[step] theorem values_subset_spec (child parent : Slice (alloc.vec.Vec U8)) :
    auths_bounded_policy.kernel.values_subset child parent ⦃ result =>
      result = (child.val.map vecBytes).all fun value =>
        decide (value ∈ parent.val.map vecBytes) ⦄ := by
  unfold auths_bounded_policy.kernel.values_subset auths_bounded_policy.kernel.values_subset_loop
  apply loop.spec_decr_nat
    (measure := fun index : Usize => child.val.length - index.val)
    (inv := fun index => ((child.val.map vecBytes).all fun value =>
        decide (value ∈ parent.val.map vecBytes)) =
      (((child.val.map vecBytes).drop index.val).all fun value =>
        decide (value ∈ parent.val.map vecBytes)))
  · intro index invariant
    unfold auths_bounded_policy.kernel.values_subset_loop.body
    dsimp only
    split <;> rename_i within
    · have inBounds : index.val < child.val.length := by scalar_tac
      step as ⟨entry, entryEq⟩
      step with values_contain_spec as ⟨contained, containedEq⟩
      have mapBounds : index.val < (child.val.map vecBytes).length := by simp [inBounds]
      rw [List.drop_eq_getElem_cons mapBounds, List.all_cons] at invariant
      have entryModel : (child.val.map vecBytes)[index.val] = vecBytes entry := by
        simp [entryEq]
      rw [entryModel] at invariant
      simp only [deref_val] at containedEq
      have modelContained : decide (vecBytes entry ∈ parent.val.map vecBytes) = contained := by
        rw [containedEq]; rfl
      split <;> rename_i found
      · step as ⟨next, nextEq⟩
        refine ⟨?_, by omega⟩
        rw [invariant, nextEq, modelContained, found]
        simp
      · simp only [spec_ok]
        rw [invariant, modelContained]
        simp [found]
    · simp only [spec_ok]
      have atEnd : (child.val.map vecBytes).length ≤ index.val := by
        simp only [List.length_map]
        scalar_tac
      rw [invariant, List.drop_eq_nil_of_le atEnd]
      rfl
  · simp

@[step] theorem values_narrow_spec (child parent : auths_bounded_policy.kernel.ValueList) :
    auths_bounded_policy.kernel.values_narrow child parent ⦃ result =>
      result = Auths.Product.CeilingCount.valuesNarrowB (valuesOf child) (valuesOf parent) ⦄ := by
  unfold auths_bounded_policy.kernel.values_narrow
  step with bytes_equal_spec as ⟨equal, equalEq⟩
  simp only [deref_val] at equalEq
  split <;> rename_i same
  · step with values_subset_spec as ⟨subset, subsetEq⟩
    simp only [deref_val] at subsetEq
    have argumentEq : byteList child.argument.val = byteList parent.argument.val := by
      simpa [same] using equalEq.symm
    rw [subsetEq]
    simp [Auths.Product.CeilingCount.valuesNarrowB, valuesOf, vecBytes, argumentEq]
  · simp only [spec_ok]
    have argumentNe : byteList child.argument.val ≠ byteList parent.argument.val := by
      simpa [same] using equalEq.symm
    simp [Auths.Product.CeilingCount.valuesNarrowB, valuesOf, vecBytes, argumentNe]

@[step] theorem partition_narrows_spec (child parent : Option auths_bounded_policy.kernel.ValueList) :
    auths_bounded_policy.kernel.partition_narrows child parent ⦃ result =>
      result = Auths.Product.CeilingCount.partitionTightens (child.map valuesOf)
        (parent.map valuesOf) ⦄ := by
  unfold auths_bounded_policy.kernel.partition_narrows
  rcases parent with _ | parent <;> rcases child with _ | child
  · simp [Auths.Product.CeilingCount.partitionTightens]
  · simp [Auths.Product.CeilingCount.partitionTightens]
  · simp [Auths.Product.CeilingCount.partitionTightens]
  · simp only [Option.map_some, Auths.Product.CeilingCount.partitionTightens]
    exact values_narrow_spec child parent

@[step] theorem sum_tightens_spec (child parent : Option auths_bounded_policy.kernel.SumBound) :
    auths_bounded_policy.kernel.sum_tightens child parent ⦃ result =>
      result = Auths.Product.CeilingCount.sumTightens (child.map sumBoundOf)
        (parent.map sumBoundOf) ⦄ := by
  unfold auths_bounded_policy.kernel.sum_tightens
  rcases parent with _ | parent <;> rcases child with _ | child
  · simp [Auths.Product.CeilingCount.sumTightens]
  · simp [Auths.Product.CeilingCount.sumTightens]
  · simp [Auths.Product.CeilingCount.sumTightens]
  · simp only [Option.map_some, Auths.Product.CeilingCount.sumTightens, sumBoundOf]
    split <;> rename_i within
    · step with partition_narrows_spec as ⟨narrow, narrowEq⟩
      have : child.limit.val ≤ parent.limit.val := by scalar_tac
      simp [narrowEq, this]
    · simp only [spec_ok]
      have : ¬ child.limit.val ≤ parent.limit.val := by scalar_tac
      simp [this]

@[step] theorem scope_tightens_spec (child parent : Option auths_bounded_policy.kernel.ValueList) :
    auths_bounded_policy.kernel.scope_tightens child parent ⦃ result =>
      result = Auths.Product.CeilingCount.scopeTightens (child.map valuesOf)
        (parent.map valuesOf) ⦄ := by
  unfold auths_bounded_policy.kernel.scope_tightens
  rcases parent with _ | parent <;> rcases child with _ | child
  · simp [Auths.Product.CeilingCount.scopeTightens]
  · simp [Auths.Product.CeilingCount.scopeTightens]
  · simp [Auths.Product.CeilingCount.scopeTightens]
  · simp only [Option.map_some, Auths.Product.CeilingCount.scopeTightens]
    exact values_narrow_spec child parent

/-- The translated tightening decider of policy `/2` computes exactly the
model's decider. -/
theorem translated_argument_policy_tightens_refines_model
    (child parent : auths_bounded_policy.kernel.PolicyMembers) :
    auths_bounded_policy.kernel.argument_policy_tightens child parent ⦃ result =>
      result = Auths.Product.CeilingCount.decider (policyOf child) (policyOf parent) ⦄ := by
  unfold auths_bounded_policy.kernel.argument_policy_tightens
  step with bytes_equal_spec as ⟨equal, equalEq⟩
  simp only [deref_val] at equalEq
  have numeric := translated_ceiling_count_tightens_refines_model child.ceiling child.max_count
    child.window parent.ceiling parent.max_count parent.window
  split <;> rename_i same
  · have argumentEq : byteList child.argument.val = byteList parent.argument.val := by
      simpa [same] using equalEq.symm
    simp only [numeric, bind_tc_ok]
    split <;> rename_i numericHolds
    · step with sum_tightens_spec as ⟨sum, sumEq⟩
      split <;> rename_i sumHolds
      · step with scope_tightens_spec as ⟨scope, scopeEq⟩
        have sumModel : Auths.Product.CeilingCount.sumTightens (child.sum.map sumBoundOf)
            (parent.sum.map sumBoundOf) = true := by rw [← sumEq]; exact sumHolds
        simp [Auths.Product.CeilingCount.decider, policyOf, vecBytes, argumentEq, numericHolds,
          sumModel, scopeEq]
      · simp only [spec_ok]
        have sumModel : Auths.Product.CeilingCount.sumTightens (child.sum.map sumBoundOf)
            (parent.sum.map sumBoundOf) = false := by
          rw [← sumEq]; simpa using sumHolds
        simp [Auths.Product.CeilingCount.decider, policyOf, vecBytes, argumentEq, numericHolds,
          sumModel]
    · simp only [spec_ok]
      have numericModel : Auths.Product.CeilingCount.numericTightens child.ceiling.val
          child.max_count.val child.window.val parent.ceiling.val parent.max_count.val
          parent.window.val = false := by simpa using numericHolds
      simp [Auths.Product.CeilingCount.decider, policyOf, vecBytes, argumentEq, numericModel]
  · simp only [spec_ok]
    have argumentNe : byteList child.argument.val ≠ byteList parent.argument.val := by
      simpa [same] using equalEq.symm
    simp [Auths.Product.CeilingCount.decider, policyOf, vecBytes, argumentNe]

end Auths.Product.Refinement
