import Auths.Product.NativeCompilerConsumption

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def claimFailure : Except RecipeConsumption.Error Unit → Option AuthsNativeRecipe.recipe.GatewayRecipeError
  | .ok () => none
  | .error error => some (consumptionError error)

def ClaimLoopMeaning (fields : NativeRuleMap) (expected : RecipeConsumption.Outcome)
    (actual : NativeRuleMap × AuthsNativeRecipe.recipe.validate.Consumption ×
      Option AuthsNativeRecipe.recipe.GatewayRecipeError) : Prop :=
  actual.1 = fields ∧ consumptionState actual.2.1 = expected.2 ∧
    actual.2.2 = claimFailure expected.1 ∧ ConsumptionOrdered actual.2.1

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

private theorem native_claim_verified_stopped (fields : NativeRuleMap)
    (consumed : AuthsNativeRecipe.recipe.validate.Consumption) (names : Slice String)
    (position : Std.Usize) (failure : AuthsNativeRecipe.recipe.GatewayRecipeError) :
    AuthsNativeRecipe.recipe.validate.Rules.claim_verified_loop fields consumed names position (some failure) =
      ok (fields, consumed, some failure) := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.claim_verified_loop
  split <;> simp [core.option.Option.is_none]

private theorem native_claim_verified_suffix (fields : NativeRuleMap)
    (consumed : AuthsNativeRecipe.recipe.validate.Consumption) (names : Slice String)
    (position : Std.Usize) (positionBound : position.val ≤ names.val.length)
    (nameFits : ∀ name ∈ names.val, TextFits name)
    (fieldFits : ∀ entry ∈ fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered consumed)
    (room : consumed.all.elements.val.length + (names.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.claim_verified_loop fields consumed names position none ⦃ actual =>
      ClaimLoopMeaning fields
        (RecipeConsumption.claimVerified (nativeRuleMapMeaning fields)
          (consumptionState consumed) (names.val.drop position.val)) actual ⦄ := by
  generalize remaining : names.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing consumed position with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.claim_verified_loop
      split <;> rename_i within
      · have inside : position.val < names.val.length := by simpa using within
        simp only [core.option.Option.is_none, Bool.true_eq_true, ↓reduceIte]
        step with Slice.index_usize_spec names position inside as ⟨name, nameAt⟩
        have originalMember : name ∈ names.val := by
          rw [nameAt]
          exact List.getElem_mem inside
        have fits := nameFits name originalMember
        step with native_deref_view_exact name fits as ⟨nameView, sameView⟩
        subst nameView
        step with native_fact_field_exact ⟨fields, consumed⟩ name fits fieldFits
          as ⟨admissible, admissibleMeaning⟩
        have capacity : consumed.all.elements.val.length < Usize.max := by omega
        step with native_claim_unused_exact ⟨fields, consumed⟩ name fits admissible ordered capacity
          as ⟨claimed, claimMeaning, growth⟩
        have originalSuffix : names.val.drop position.val = name :: names.val.drop (position.val + 1) := by
          simpa only [nameAt] using List.drop_eq_getElem_cons inside
        have fullMeaning : ClaimMeaning ⟨fields, consumed⟩
            (RecipeConsumption.claimUnused (consumptionState consumed) name
              (RecipeConsumption.fieldTest RecipeConsumption.factSchema (nativeRuleMapMeaning fields) name)) claimed := by
          simpa only [admissibleMeaning] using claimMeaning
        let expected := RecipeConsumption.claimUnused (consumptionState consumed) name
          (RecipeConsumption.fieldTest RecipeConsumption.factSchema (nativeRuleMapMeaning fields) name)
        have sameFields : claimed.2.fields = fields := fullMeaning.2.2.1
        have sameState : consumptionState claimed.2.consumed = expected.2 := fullMeaning.2.1
        have nextOrdered : ConsumptionOrdered claimed.2.consumed := fullMeaning.2.2.2
        cases verdict : expected.1 with
        | error error =>
            have refused : claimed.1 = .Err (consumptionError error) := by
              simpa only [verdict, consumptionVerdict] using fullMeaning.1
            simp only [refused, bind_tc_ok]
            step as ⟨next, nextValue⟩
            rw [native_claim_verified_stopped]
            simp only [spec_ok, ClaimLoopMeaning]
            refine ⟨sameFields, ?_, rfl, nextOrdered⟩
            simpa [RecipeConsumption.claimVerified, originalSuffix, ← expected,
              verdict, claimFailure] using sameState
        | ok unit =>
            cases unit
            have accepted : claimed.1 = .Ok () := by
              simpa only [verdict, consumptionVerdict] using fullMeaning.1
            simp only [accepted, bind_tc_ok]
            step as ⟨next, nextValue⟩
            have nextBound : next.val ≤ names.val.length := by omega
            have nextRoom : claimed.2.consumed.all.elements.val.length +
                (names.val.length - next.val) ≤ Usize.max := by omega
            have smaller : names.val.length - next.val < count := by omega
            have tail := ih _ smaller claimed.2.consumed next nextBound nextOrdered nextRoom rfl
            apply spec_mono (by simpa only [sameFields] using tail)
            intro actual meaning
            simpa [ClaimLoopMeaning, RecipeConsumption.claimVerified, originalSuffix,
              ← expected, verdict, sameState, nextValue] using meaning
      · have ended : names.val.length ≤ position.val := by simpa using within
        simp [core.option.Option.is_none, ClaimLoopMeaning, List.drop_eq_nil_of_le ended,
          RecipeConsumption.claimVerified, claimFailure, ordered]

/-- All original verified names, including duplicate, already consumed,
binding, unknown and schema-inadmissible names, have the exact outcome and
retained prefix state of the independent model. No fact-classifier callback or
expected validator result is a premise. The room bound covers every possible
new native set element before the source stops at its first refusal. -/
@[step] theorem native_claim_verified_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (names : Slice String) (nameFits : ∀ name ∈ names.val, TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (room : input.consumed.all.elements.val.length + names.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.claim_verified input names ⦃ actual =>
      ClaimMeaning input
        (RecipeConsumption.claimVerified (nativeRuleMapMeaning input.fields)
          (consumptionState input.consumed) names.val) actual ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.claim_verified
  step with native_claim_verified_suffix input.fields input.consumed names 0#usize
    (by simp) nameFits fieldFits ordered (by simpa using room) as ⟨loop, loopMeaning⟩
  have meaning : ClaimLoopMeaning input.fields
      (RecipeConsumption.claimVerified (nativeRuleMapMeaning input.fields)
        (consumptionState input.consumed) names.val) loop := by
    simpa only [List.drop_zero] using loopMeaning
  cases expected : (RecipeConsumption.claimVerified (nativeRuleMapMeaning input.fields)
      (consumptionState input.consumed) names.val).1 <;>
    simp_all [ClaimLoopMeaning, ClaimMeaning, claimFailure, consumptionVerdict]

/-- Useful source acceptance follows from original schemas, distinct names and
disjointness from earlier uses. Successful helper results are earned. -/
theorem native_admitted_claims_succeed (input : AuthsNativeRecipe.recipe.validate.Rules)
    (names : Slice String) (nameFits : ∀ name ∈ names.val, TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (room : input.consumed.all.elements.val.length + names.val.length ≤ Usize.max)
    (admitted : RecipeConsumption.ClaimsAdmitted (nativeRuleMapMeaning input.fields)
      (consumptionState input.consumed) names.val) :
    AuthsNativeRecipe.recipe.validate.Rules.claim_verified input names ⦃ actual =>
      actual.1 = .Ok () ∧ actual.2.fields = input.fields ∧
      consumptionState actual.2.consumed =
        { consumptionState input.consumed with all :=
          (consumptionState input.consumed).all ∪ names.val.toFinset } ∧
      ConsumptionOrdered actual.2.consumed ⦄ := by
  apply spec_mono (native_claim_verified_exact input names nameFits fieldFits ordered room)
  intro actual meaning
  rw [RecipeConsumption.admitted_claims_succeed _ _ _ admitted] at meaning
  exact ⟨meaning.1, meaning.2.2.1, meaning.2.1, meaning.2.2.2⟩

/-- The actual bounded caller domain earns insertion room, and every outcome
retains original-field containment and at most 32 native elements per set.
The bound is on the physical retained vectors, not only their Finset images. -/
theorem native_verified_claims_preserve_field_bound (input : AuthsNativeRecipe.recipe.validate.Rules)
    (names : Slice String) (nameFits : ∀ name ∈ names.val, TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (fieldCount : input.fields.entries.val.length ≤ 32) (nameCount : names.val.length ≤ 8)
    (ordered : ConsumptionOrdered input.consumed)
    (known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields)
      (consumptionState input.consumed)) :
    AuthsNativeRecipe.recipe.validate.Rules.claim_verified input names ⦃ actual =>
      ClaimMeaning input
        (RecipeConsumption.claimVerified (nativeRuleMapMeaning input.fields)
          (consumptionState input.consumed) names.val) actual ∧
      RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields)
        (consumptionState actual.2.consumed) ∧
      actual.2.consumed.all.elements.val.length ≤ 32 ∧
      actual.2.consumed.body.elements.val.length ≤ 32 ∧
      actual.2.consumed.binds.elements.val.length ≤ 32 ⦄ := by
  have originalCount : (nativeRuleMapMeaning input.fields).length ≤ 32 := by
    simpa [nativeRuleMapMeaning] using fieldCount
  have allKnown : nameSet input.consumed.all ⊆
      ((nativeRuleMapMeaning input.fields).map Prod.fst).toFinset := known.1
  have stored := native_name_set_storage_bound input.consumed.all _ ordered.1 allKnown
  have room : input.consumed.all.elements.val.length + names.val.length ≤ Usize.max := by
    have small : input.consumed.all.elements.val.length + names.val.length ≤ 40 := by omega
    scalar_tac
  apply spec_mono (native_claim_verified_exact input names nameFits fieldFits ordered room)
  intro actual meaning
  have nextKnown : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields)
      (consumptionState actual.2.consumed) := by
    rw [meaning.2.1]
    exact RecipeConsumption.claim_verified_well_formed _ _ _ known
  have nativeOrder := meaning.2.2.2
  have allBound := native_name_set_storage_bound actual.2.consumed.all _ nativeOrder.1 nextKnown.1
  have bodyBound := native_name_set_storage_bound actual.2.consumed.body _ nativeOrder.2.1
    (nextKnown.2.1.trans nextKnown.1)
  have bindBound := native_name_set_storage_bound actual.2.consumed.binds _ nativeOrder.2.2
    (nextKnown.2.2.trans nextKnown.1)
  exact ⟨meaning, nextKnown, allBound.trans originalCount,
    bodyBound.trans originalCount, bindBound.trans originalCount⟩

end Auths.Product.NativeCompiler.Refinement
