import Auths.Product.NativeCompilerResponsePointer
import Auths.Product.NativeCompilerConsumption
import Auths.Product.NativeCompilerRuleSource
import Auths.Product.NativeCompilerPaths

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def rulePathRole : AuthsNativeRecipe.recipe.validate.PathRole → RecipeRuleAdmission.PathRole
  | .Write => .write
  | .Observation => .observation
  | .PreEntry => .preEntry
  | .RelativeCeiling => .relativeCeiling

/-- Validation also borrows response-pointer payloads, unlike lowering's
path-tag projection. This domain includes every original inspected String. -/
def RulePathFits : NativePathSource → Prop
  | .Fixed value | .Field value | .ResponseField value _ => TextFits value
  | .Echo => True

def PathLoopMeaning (fields : NativeRuleMap) (before : AuthsNativeRecipe.recipe.validate.Consumption)
    (remaining : Nat) (expected : RecipeConsumption.Outcome)
    (actual : core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
      NativeRuleMap × AuthsNativeRecipe.recipe.validate.Consumption) : Prop :=
  actual.1 = consumptionVerdict expected.1 ∧ actual.2.1 = fields ∧
    consumptionState actual.2.2 = expected.2 ∧ ConsumptionOrdered actual.2.2 ∧
    actual.2.2.all.elements.val.length ≤ before.all.elements.val.length + remaining ∧
    actual.2.2.body = before.body ∧ actual.2.2.binds = before.binds

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

@[step] theorem native_path_response_limit_exact (role : AuthsNativeRecipe.recipe.validate.PathRole) :
    AuthsNativeRecipe.recipe.validate.PathRole.response_fields role ⦃ actual =>
      actual.val = RecipeRuleAdmission.responseMaximum (rulePathRole role) ⦄ := by
  cases role <;> simp [AuthsNativeRecipe.recipe.validate.PathRole.response_fields,
    AuthsNativeRecipe.recipe.validate.MAX_RESPONSE_FIELDS,
    RecipeRuleAdmission.responseMaximum, rulePathRole, spec_ok]

@[step] theorem native_path_response_error_exact (role : AuthsNativeRecipe.recipe.validate.PathRole) :
    AuthsNativeRecipe.recipe.validate.PathRole.response_error role ⦃ actual =>
      actual = consumptionError (RecipeRuleAdmission.responseError (rulePathRole role)) ⦄ := by
  cases role <;> rfl

@[step] theorem native_recipe_fixed_segment_exact (value : Str) :
    AuthsNativeRecipe.recipe.validate.valid_fixed_segment value ⦃ actual =>
      actual = decide (PathCompiler.FixedValid (schemaSliceBytes value)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.valid_fixed_segment
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  exact native_fixed_segment_exact value

@[step] theorem native_response_field_bound_exact (maximum : Std.U64) :
    (do
      let range ← core.ops.range.RangeInclusive.new 1#u64
        AuthsNativeRecipe.recipe.validate.MAX_RESPONSE_FIELD_BYTES
      AuthsNativeRecipe.core.ops.range.RangeInclusive.contains core.cmp.PartialOrdU64
        core.cmp.PartialOrdU64 core.cmp.PartialOrdU64 range maximum) ⦃ actual =>
      actual = decide (1 ≤ maximum.val ∧ maximum.val ≤ 255) ⦄ := by
  simp [AuthsNativeRecipe.recipe.validate.MAX_RESPONSE_FIELD_BYTES,
    core.ops.range.RangeInclusive.new, AuthsNativeRecipe.core.ops.range.RangeInclusive.contains,
    UScalar.le_equiv, spec_ok]

private theorem native_path_rule_suffix (iterator : core.slice.iter.Iter NativePathSource)
    (fields : NativeRuleMap) (consumed : AuthsNativeRecipe.recipe.validate.Consumption)
    (role : AuthsNativeRecipe.recipe.validate.PathRole) (responses : Std.Usize)
    (fits : ∀ segment ∈ iterator.slice.val, RulePathFits segment)
    (fieldFits : ∀ entry ∈ fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered consumed)
    (room : consumed.all.elements.val.length + (iterator.slice.val.length - iterator.i) ≤ Usize.max)
    (responseRoom : responses.val + (iterator.slice.val.length - iterator.i) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.path_loop iterator fields consumed role responses ⦃ actual =>
      PathLoopMeaning fields consumed (iterator.slice.val.length - iterator.i)
        (RecipeRuleAdmission.pathTail (nativeRuleMapMeaning fields) (rulePathRole role)
          ((iterator.slice.val.drop iterator.i).map ruleSegment) responses.val (consumptionState consumed)) actual ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator consumed responses with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.path_loop
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let segment := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter NativePathSource := { iterator with i := iterator.i + 1 }
        have original : iterator.slice.val.drop iterator.i = segment :: iterator.slice.val.drop next.i := by
          simpa [segment, next] using List.drop_eq_getElem_cons inside
        have smaller : next.slice.val.length - next.i < count := by simp [next] at *; omega
        have nextFits : ∀ segment ∈ next.slice.val, RulePathFits segment := by simpa [next] using fits
        have headFits : RulePathFits segment := fits segment (List.getElem_mem inside)
        have nextRoom : consumed.all.elements.val.length + (next.slice.val.length - next.i) ≤ Usize.max := by
          simp [next] at *; omega
        have nextResponseRoom : responses.val + (next.slice.val.length - next.i) ≤ Usize.max := by
          simp [next] at *; omega
        cases shape : segment with
        | Fixed value =>
            simp only [shape]
            have valueFits : TextFits value := by simpa [RulePathFits, shape] using headFits
            step with native_deref_view_exact value valueFits as ⟨valueView, valueViewMeaning⟩
            subst valueView
            step with native_recipe_fixed_segment_exact (nativeTextView value valueFits) as ⟨valid, validity⟩
            cases valid with
            | false =>
                have invalid : ¬PathCompiler.FixedValid (textBytes value) := by
                  simpa [native_text_view_bytes] using validity.symm
                simp [PathLoopMeaning, original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                  invalid, RecipeRuleAdmission.refused,
                  consumptionVerdict, consumptionError, ordered]
            | true =>
                have admitted : PathCompiler.FixedValid (textBytes value) := by
                  simpa [native_text_view_bytes] using validity.symm
                simp only [Bool.true_eq_true, ↓reduceIte]
                apply spec_mono (ih _ smaller next consumed responses nextFits ordered nextRoom nextResponseRoom rfl)
                rintro actual ⟨verdict, sameFields, sameState, nextOrder, growth, body, binds⟩
                refine ⟨?_, sameFields, ?_, nextOrder, ?_, body, binds⟩
                · simpa [original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                    admitted] using verdict
                · simpa [original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                    admitted] using sameState
                · simp [next] at growth ⊢; omega
        | Field name =>
            simp only [shape]
            have nameFits : TextFits name := by simpa [RulePathFits, shape] using headFits
            step with native_deref_view_exact name nameFits as ⟨nameView, nameViewMeaning⟩
            subst nameView
            step with native_path_field_exact ⟨fields, consumed⟩ name nameFits fieldFits as ⟨scalar, scalarMeaning⟩
            cases scalar with
            | false =>
                simp [PathLoopMeaning, original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                  ← scalarMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
            | true =>
                simp only [Bool.true_eq_true, ↓reduceIte]
                step with native_namespace_recipe_field_exact name nameFits as ⟨reserved, reservedMeaning⟩
                cases reserved with
                | true =>
                    simp [PathLoopMeaning, original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                      ← reservedMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
                | false =>
                    simp only [Bool.false_eq_true, ↓reduceIte]
                    have capacity : consumed.all.elements.val.length < Usize.max := by
                      simp [remaining] at room; omega
                    step with native_consume_exact ⟨fields, consumed⟩ name nameFits ordered capacity
                      as ⟨updated, used, sameFields, nextOrder, growth, sameBody, sameBinds⟩
                    have updatedRoom : updated.consumed.all.elements.val.length +
                        (next.slice.val.length - next.i) ≤ Usize.max := by simp [next] at *; omega
                    have recursive := ih _ smaller next updated.consumed responses nextFits nextOrder
                      updatedRoom nextResponseRoom rfl
                    apply spec_mono (by simpa only [sameFields] using recursive)
                    rintro actual ⟨verdict, finalFields, finalState, finalOrder, finalGrowth, body, binds⟩
                    refine ⟨?_, finalFields, ?_, finalOrder, ?_, body.trans sameBody, binds.trans sameBinds⟩
                    · simpa [original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                        ← scalarMeaning, ← reservedMeaning, used] using verdict
                    · simpa [original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                        ← scalarMeaning, ← reservedMeaning, used] using finalState
                    · simp [next] at finalGrowth ⊢; omega
        | ResponseField pointer maximum =>
            simp only [shape]
            have pointerFits : TextFits pointer := by simpa [RulePathFits, shape] using headFits
            step as ⟨charged, chargedValue⟩
            step with native_path_response_limit_exact role as ⟨limit, limitMeaning⟩
            by_cases excessive : charged.val > RecipeRuleAdmission.responseMaximum (rulePathRole role)
            · have nativeExcessive : charged > limit := by scalar_tac
              simp only [nativeExcessive, ↓reduceIte]
              step with native_path_response_error_exact role as ⟨error, errorMeaning⟩
              simp [PathLoopMeaning, original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                errorMeaning, chargedValue, Nat.not_le.mpr excessive, RecipeRuleAdmission.refused,
                consumptionVerdict, ordered]
            · have within : responses.val + 1 ≤ RecipeRuleAdmission.responseMaximum (rulePathRole role) := by omega
              have nativeWithin : ¬charged > limit := by scalar_tac
              simp only [nativeWithin, ↓reduceIte]
              step with native_deref_view_exact pointer pointerFits as ⟨pointerView, pointerViewMeaning⟩
              subst pointerView
              step with native_response_pointer_exact (nativeTextView pointer pointerFits) as ⟨valid, validity⟩
              cases valid with
              | false =>
                  have invalid : ¬RecipeAdmissionAtoms.ResponsePointer (textBytes pointer) := by
                    simpa [RecipeAdmissionAtoms.responsePointer, native_text_view_bytes] using validity.symm
                  simp only [Bool.false_eq_true, ↓reduceIte]
                  step with native_path_response_error_exact role as ⟨error, errorMeaning⟩
                  simp [PathLoopMeaning, original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                    invalid,
                    errorMeaning, RecipeRuleAdmission.refused, consumptionVerdict, ordered]
              | true =>
                  have pointerValid : RecipeAdmissionAtoms.ResponsePointer (textBytes pointer) := by
                    simpa [RecipeAdmissionAtoms.responsePointer, native_text_view_bytes] using validity.symm
                  simp only [Bool.true_eq_true, ↓reduceIte]
                  step with native_response_field_bound_exact maximum as ⟨bounded, boundMeaning⟩
                  cases bounded with
                  | false =>
                      have invalidBound : ¬(1 ≤ maximum.val ∧ maximum.val ≤ 255) := by
                        simpa using boundMeaning.symm
                      simp only [Bool.false_eq_true, ↓reduceIte]
                      step with native_path_response_error_exact role as ⟨error, errorMeaning⟩
                      simp [PathLoopMeaning, original, shape, ruleSegment, RecipeRuleAdmission.pathTail,
                        invalidBound, errorMeaning, RecipeRuleAdmission.refused, consumptionVerdict, ordered]
                  | true =>
                      have validBound : 1 ≤ maximum.val ∧ maximum.val ≤ 255 := by
                        simpa using boundMeaning.symm
                      simp only [Bool.true_eq_true, ↓reduceIte]
                      have chargedRoom : charged.val + (next.slice.val.length - next.i) ≤ Usize.max := by
                        simp [next] at *; omega
                      apply spec_mono (ih _ smaller next consumed charged nextFits ordered nextRoom chargedRoom rfl)
                      rintro actual ⟨verdict, sameFields, sameState, nextOrder, growth, body, binds⟩
                      refine ⟨?_, sameFields, ?_, nextOrder, ?_, body, binds⟩
                      · simpa [original, shape, ruleSegment, RecipeRuleAdmission.pathTail, within,
                          pointerValid, validBound, chargedValue] using verdict
                      · simpa [original, shape, ruleSegment, RecipeRuleAdmission.pathTail, within,
                          pointerValid, validBound, chargedValue] using sameState
                      · simp [next] at growth ⊢; omega
        | Echo =>
            simp [shape, PathLoopMeaning, original, ruleSegment, RecipeRuleAdmission.pathTail,
              RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        simp [core.slice.iter.IteratorSliceIter.next, dif_neg inside, PathLoopMeaning,
          List.drop_eq_nil_of_le ended, RecipeRuleAdmission.pathTail,
          RecipeRuleAdmission.accepted, consumptionVerdict, ordered]

/-- All represented path shapes retain exact errors and consumed prefixes.
Only field segments consume names. Neither response locators nor fixed text
can become action fields, and the three role-specific response errors remain
distinct. No accepted path or expected plan is an input. -/
@[step] theorem native_path_rules_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (path : Slice NativePathSource) (role : AuthsNativeRecipe.recipe.validate.PathRole)
    (fits : ∀ segment ∈ path.val, RulePathFits segment)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (room : path.val.length ≤ 16 → input.consumed.all.elements.val.length + path.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.path input path role ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.path (nativeRuleMapMeaning input.fields)
        (rulePathRole role) (path.val.map ruleSegment) (consumptionState input.consumed)) actual ∧
      actual.2.consumed.all.elements.val.length ≤ input.consumed.all.elements.val.length + path.val.length ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.path
  by_cases empty : path.val = []
  · simp [core.slice.Slice.is_empty, empty, ClaimMeaning, RecipeRuleAdmission.path,
      RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
  · have nonempty : 0 < path.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases oversized : 16 < path.val.length
    · have nativeLarge : path.len > AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS := by
        simp [AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS,
          AuthsNativeRecipe.auths_gateway_kernel.path_compiler.MAX_PATH_SEGMENTS]
        scalar_tac
      simp [nativeLarge, ClaimMeaning, RecipeRuleAdmission.path, Nat.not_le.mpr oversized,
        RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
    · have nativeWithin : ¬path.len > AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS := by
        simp [AuthsNativeRecipe.recipe.MAX_PATH_SEGMENTS,
          AuthsNativeRecipe.auths_gateway_kernel.path_compiler.MAX_PATH_SEGMENTS]
        scalar_tac
      simp only [nativeWithin, ↓reduceIte,
        SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_tc_ok]
      step with native_path_rule_suffix ⟨path, 0⟩ input.fields input.consumed role 0#usize
        fits fieldFits ordered (by simpa using room (Nat.le_of_not_gt oversized)) (by simpa using path.property)
        as ⟨loop, verdict, sameFields, sameState, nextOrder, growth, sameBody, sameBinds⟩
      refine ⟨⟨?_, ?_, sameFields, nextOrder⟩, ?_, sameBody, sameBinds⟩
      · simpa [RecipeRuleAdmission.path, nonempty, Nat.le_of_not_gt oversized] using verdict
      · simpa [RecipeRuleAdmission.path, nonempty, Nat.le_of_not_gt oversized] using sameState
      · simpa using growth

end Auths.Product.NativeCompiler.Refinement
