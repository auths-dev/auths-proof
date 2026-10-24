import Auths.Product.NativeCompilerFieldLookup
import Auths.Product.NativeCompilerOutcome

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def consumptionError : RecipeConsumption.Error → AuthsNativeRecipe.recipe.GatewayRecipeError
  | .preconditionConflict => .PreconditionConflict
  | .unsafeTemplate => .UnsafeTemplate
  | .invalidAccountScope => .InvalidAccountScope
  | .invalidBounds => .InvalidBounds
  | .unboundPartition => .UnboundPartition
  | .unsafePath => .UnsafePath
  | .responseLocatorConflict => .ResponseLocatorConflict
  | .invalidPreEntry => .InvalidPreEntry
  | .invalidRelativeCeiling => .InvalidRelativeCeiling
  | .echoConflict => .EchoConflict
  | .invalidSource => .InvalidSource
  | .preconditionWithoutObservation => .PreconditionWithoutObservation
  | .echoWithoutObservation => .EchoWithoutObservation
  | .invalidIdempotency => .InvalidIdempotency
  | .invalidProviderHeader => .InvalidProviderHeader
  | .invalidCredentialGuard => .InvalidCredentialGuard

def consumptionVerdict : Except RecipeConsumption.Error Unit →
    core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError
  | .ok () => .Ok ()
  | .error error => .Err (consumptionError error)

def ClaimMeaning (before : AuthsNativeRecipe.recipe.validate.Rules)
    (expected : RecipeConsumption.Outcome)
    (actual : core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
      AuthsNativeRecipe.recipe.validate.Rules) : Prop :=
  actual.1 = consumptionVerdict expected.1 ∧
    consumptionState actual.2.consumed = expected.2 ∧
    actual.2.fields = before.fields ∧ ConsumptionOrdered actual.2.consumed

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

@[step] theorem native_binding_field_bytes_exact (name : Str) :
    AuthsNativeRecipe.recipe.validate.is_binding_field name ⦃ actual =>
      actual = decide (schemaSliceBytes name = textBytes "operator_namespace" ∨
        schemaSliceBytes name = textBytes "operation_id" ∨
        schemaSliceBytes name = textBytes "recipe_digest") ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.is_binding_field
  repeat' first | step with native_schema_byte_equality | step | split
  all_goals simp_all [schemaSliceBytes, textBytes]

@[step] theorem native_binding_field_name_exact (name : String) (fits : TextFits name) :
    AuthsNativeRecipe.recipe.validate.is_binding_field (nativeTextView name fits) ⦃ actual =>
      actual = RecipeConsumption.bindingField name ⦄ := by
  apply spec_mono (native_binding_field_bytes_exact (nativeTextView name fits))
  intro actual meaning
  simpa [native_text_view_bytes, text_bytes_injective.eq_iff,
    RecipeConsumption.bindingField, decide_or] using meaning

@[step] theorem native_namespace_recipe_field_exact (name : String) (fits : TextFits name) :
    AuthsNativeRecipe.recipe.validate.is_namespace_or_recipe_field (nativeTextView name fits) ⦃ actual =>
      actual = RecipeConsumption.namespaceOrRecipe name ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.is_namespace_or_recipe_field
  repeat' first | step with native_schema_byte_equality | step | split
  all_goals simp_all [native_text_view_bytes, text_bytes_injective.eq_iff,
    RecipeConsumption.namespaceOrRecipe, schemaSliceBytes, textBytes]

@[step] theorem native_consumption_default :
    AuthsNativeRecipe.recipe.validate.Consumption.Insts.CoreDefaultDefault.default ⦃ actual =>
      consumptionState actual = RecipeConsumption.empty ∧ ConsumptionOrdered actual ⦄ := by
  simp [AuthsNativeRecipe.recipe.validate.Consumption.Insts.CoreDefaultDefault.default,
    AuthsNativeRecipe.alloc.collections.btree.set.BTreeSetTGlobal.Insts.CoreDefaultDefault.default,
    consumptionState, nameSet, RecipeConsumption.empty, ConsumptionOrdered, NameSetOrdered,
    native_empty_contents, spec_ok]

@[step] theorem native_consume_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (name : String) (fits : TextFits name) (ordered : ConsumptionOrdered input.consumed)
    (room : input.consumed.all.elements.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.consume input (nativeTextView name fits) ⦃ actual =>
      consumptionState actual.consumed = RecipeConsumption.consume (consumptionState input.consumed) name ∧
      actual.fields = input.fields ∧ ConsumptionOrdered actual.consumed ∧
      actual.consumed.all.elements.val.length ≤ input.consumed.all.elements.val.length + 1 ∧
      actual.consumed.body = input.consumed.body ∧ actual.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.consume
  step with native_text_view_owned name fits as ⟨owned, same⟩
  subst owned
  step with native_name_set_insert input.consumed.all name ordered.1 room
    as ⟨inserted, flag, members, nextOrder, count, originals⟩
  refine ⟨?_, rfl, ⟨nextOrder, ordered.2⟩, ?_, rfl, rfl⟩
  · simp [consumptionState, RecipeConsumption.consume, members]
  · rw [count]; split <;> omega

/-- Full success/refusal and ledger-state correspondence for the actual
mutating leaf. Admissibility is the leaf's real Boolean input; callers must
earn it from their original field schemas. -/
@[step] theorem native_claim_unused_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (name : String) (fits : TextFits name) (admissible : Bool)
    (ordered : ConsumptionOrdered input.consumed)
    (room : input.consumed.all.elements.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.claim_unused input (nativeTextView name fits) admissible ⦃ actual =>
      ClaimMeaning input (RecipeConsumption.claimUnused (consumptionState input.consumed) name admissible) actual ∧
      actual.2.consumed.all.elements.val.length ≤ input.consumed.all.elements.val.length + 1 ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.claim_unused
  cases admissible with
  | false => simp [ClaimMeaning, RecipeConsumption.claimUnused, consumptionVerdict, consumptionError, ordered]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_binding_field_name_exact name fits as ⟨binding, bindingMeaning⟩
      cases binding with
      | true =>
          simp [ClaimMeaning, RecipeConsumption.claimUnused, consumptionVerdict,
            consumptionError, ← bindingMeaning, ordered]
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          step with native_text_view_owned name fits as ⟨owned, same⟩
          subst owned
          step with native_name_set_insert input.consumed.all name ordered.1 room
            as ⟨inserted, flag, members, nextOrder, count, originals⟩
          have nextOrdered : ConsumptionOrdered { input.consumed with all := inserted.2 } :=
            ⟨nextOrder, ordered.2⟩
          have growth : inserted.2.elements.val.length ≤ input.consumed.all.elements.val.length + 1 := by
            rw [count]; split <;> omega
          by_cases used : name ∈ nameSet input.consumed.all
          · have duplicate : inserted.1 = false := by simpa [used] using flag
            simp [duplicate, ClaimMeaning, RecipeConsumption.claimUnused, RecipeConsumption.consume,
              consumptionVerdict, consumptionError, consumptionState, ← bindingMeaning,
              used, members, nextOrdered, growth, Finset.insert_eq_of_mem used]
          · have fresh : inserted.1 = true := by simpa [used] using flag
            simp [fresh, ClaimMeaning, RecipeConsumption.claimUnused, RecipeConsumption.consume,
              consumptionVerdict, consumptionState, ← bindingMeaning,
              used, members, nextOrdered, growth]

private theorem native_all_fields_suffix
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String NativeScalarSchema)
    (consumed : NativeNameSet) (fits : ∀ entry ∈ iterator.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.all_fields_consumed_loop iterator consumed ⦃ actual =>
      actual = iterator.val.all (fun entry =>
        RecipeConsumption.bindingField entry.1 || decide (entry.1 ∈ nameSet consumed)) ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.all_fields_consumed_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil => simp_all
      | cons first rest =>
          have pairAt : next.1 = some first ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [pairAt.1, bind_tc_ok]
          have nameFits := fits first (by simp [original])
          step with native_deref_view_exact first.1 nameFits as ⟨nameView, sameView⟩
          subst nameView
          step with native_binding_field_name_exact first.1 nameFits as ⟨binding, bindingMeaning⟩
          have recurse : AuthsNativeRecipe.recipe.validate.all_fields_consumed_loop next.2 consumed ⦃ actual =>
              actual = rest.all (fun entry => RecipeConsumption.bindingField entry.1 ||
                decide (entry.1 ∈ nameSet consumed)) ⦄ := by
            apply spec_mono (ih rest.length (by simp [original] at remaining; omega) next.2
              (fun entry member => fits entry (by simp [original, pairAt.2] at member ⊢; exact Or.inr member))
              (by simpa [pairAt.2]))
            intro actual meaning
            simpa [pairAt.2] using meaning
          cases binding with
          | true =>
              simpa [original, ← bindingMeaning] using recurse
          | false =>
              simp only [Bool.false_eq_true, ↓reduceIte]
              step with native_name_set_contains_owned consumed first.1 as ⟨present, membership⟩
              cases present with
              | false => simp [original, ← bindingMeaning, ← membership]
              | true => simpa [original, ← bindingMeaning, ← membership] using recurse

/-- The final consumption check visits every original map pair, exempting only
the three exact binding names. It assumes no expected consumed set or success. -/
@[step] theorem native_all_fields_consumed_exact (fields : NativeRuleMap) (consumed : NativeNameSet)
    (fits : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.all_fields_consumed fields consumed ⦃ actual =>
      actual = RecipeConsumption.allFieldsConsumed (nativeRuleMapMeaning fields)
        ⟨nameSet consumed, ∅, ∅⟩ ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.all_fields_consumed
    AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_all_fields_suffix fields.entries consumed fits)
  intro actual meaning
  simpa [RecipeConsumption.allFieldsConsumed, nativeRuleMapMeaning, List.all_map] using meaning

end Auths.Product.NativeCompiler.Refinement
