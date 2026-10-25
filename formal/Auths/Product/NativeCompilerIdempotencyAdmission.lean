import Auths.Product.NativeCompilerTemplateSelection
import Auths.Product.NativeCompilerPlanInputs
import Auths.Product.NativeCompilerConsumption

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def ruleIdempotencyLocation (source : AuthsNativeRecipe.recipe.source.IdempotencyLocation) :
    RecipePlanModel.IdempotencyLocation :=
  ⟨source.json_pointer.map textBytes, source.form_field.map textBytes, source.pointer.map textBytes⟩

def LocationFits (source : AuthsNativeRecipe.recipe.source.IdempotencyLocation) : Prop :=
  (∀ pointer, source.json_pointer = some pointer → TextFits pointer) ∧
    (∀ name, source.form_field = some name → TextFits name) ∧
    (∀ pointer, source.pointer = some pointer → TextFits pointer)

def IdempotencyFits : AuthsNativeRecipe.recipe.source.IdempotencySource → Prop
  | .DerivedHeader _ => True
  | .OperationIdField location _ => LocationFits location

def idempotencyRetention : RecipePlanModel.Idempotency → Nat
  | .derivedHeader retention | .operationIdField _ retention => retention

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 22000000
set_option maxRecDepth 4096

@[step] theorem native_operation_id_location_exact
    (location : AuthsNativeRecipe.recipe.source.IdempotencyLocation) (fits : LocationFits location)
    (body : SourceBody) (model : TemplateAst.Body) (bounds : BodyBounds body)
    (original : BodySourceMeaning body model) :
    AuthsNativeRecipe.recipe.validate.operation_id_location location body ⦃ actual =>
      actual = RecipeRuleAdmission.operationIdLocation (ruleIdempotencyLocation location) model ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.operation_id_location
  cases original with
  | @json source model meaning =>
      cases bounds with
      | json source bounded =>
          cases fieldAt : location.form_field with
          | some name => simp [fieldAt, core.option.Option.is_some,
              RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation]
          | none =>
              simp only [fieldAt, core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
              cases nestedAt : location.pointer with
              | some pointer => simp [nestedAt, core.option.Option.is_some,
                  RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation, fieldAt]
              | none =>
                  simp only [nestedAt, core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
                  cases pointerAt : location.json_pointer with
                  | none => simp [pointerAt, RecipeRuleAdmission.operationIdLocation,
                      ruleIdempotencyLocation, fieldAt, nestedAt]
                  | some pointer =>
                      have pointerFits := fits.1 pointer pointerAt
                      step with native_deref_view_exact pointer pointerFits as ⟨view, viewMeaning⟩
                      subst view
                      apply spec_mono (native_template_is_operation_id_exact source model bounded meaning pointer pointerFits)
                      intro actual exactLocation
                      simpa [RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation,
                        fieldAt, nestedAt, pointerAt] using exactLocation
  | @form members models meaning =>
      cases bounds with
      | form members names children =>
          cases jsonAt : location.json_pointer with
          | some pointer => simp [jsonAt, core.option.Option.is_some,
              RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation]
          | none =>
              simp only [jsonAt, core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
              cases fieldAt : location.form_field with
              | none => simp [fieldAt, RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation, jsonAt]
              | some name =>
                  step with native_original_map_lookup_owned
                    (fun source model => FormBounds source ∧ FormSourceMeaning source model)
                    members models name (original_form_members_bounded _ _ meaning children)
                    as ⟨selected, selectedMeaning⟩
                  cases selectedMeaning with
                  | none => simp [RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation, jsonAt, fieldAt]
                  | @some source model sourceMeaning =>
                      rcases sourceMeaning with ⟨sourceBounds, sourceOriginal⟩
                      cases sourceOriginal with
                      | text text => simp [RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation, jsonAt, fieldAt]
                      | echo => simp [RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation, jsonAt, fieldAt]
                      | field field =>
                          cases sourceBounds with
                          | field field bounded =>
                              cases nestedAt : location.pointer with
                              | some pointer => simp [nestedAt, core.option.Option.is_none,
                                  RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation, jsonAt, fieldAt]
                              | none =>
                                  simp only [nestedAt, core.option.Option.is_none, Bool.true_eq_true, ↓reduceIte]
                                  change AuthsNativeRecipe.recipe.validate.is_operation_id (.Field field) ⦃ _ ⦄
                                  apply spec_mono (native_is_operation_id_exact (.Field field) (.field (textBytes field))
                                    (.field field bounded) (.field field))
                                  intro actual exactField
                                  simpa [RecipeRuleAdmission.isOperationId, RecipeRuleAdmission.operationIdLocation,
                                    ruleIdempotencyLocation, jsonAt, fieldAt, nestedAt] using exactField
                      | @json value valueModel valueMeaning =>
                          cases sourceBounds with
                          | json value bounded =>
                              cases pointerAt : location.pointer with
                              | none => simp [pointerAt, RecipeRuleAdmission.operationIdLocation,
                                  ruleIdempotencyLocation, jsonAt, fieldAt]
                              | some pointer =>
                                  have pointerFits := fits.2.2 pointer pointerAt
                                  step with native_deref_view_exact pointer pointerFits as ⟨view, viewMeaning⟩
                                  subst view
                                  apply spec_mono (native_template_is_operation_id_exact value valueModel bounded valueMeaning pointer pointerFits)
                                  intro actual exactPointer
                                  simpa [RecipeRuleAdmission.operationIdLocation, ruleIdempotencyLocation,
                                    jsonAt, fieldAt, pointerAt] using exactPointer

@[step] theorem native_idempotency_retention_exact (source : AuthsNativeRecipe.recipe.source.IdempotencySource) :
    AuthsNativeRecipe.recipe.source.IdempotencySource.retention_seconds source ⦃ actual =>
      actual.val = idempotencyRetention (planIdempotency source) ⦄ := by
  cases source <;> rfl

/-- Complete source idempotency admission retains the original location and
body. A derived header needs no operation-ID location; a field placement must
select the original operation_id field, never a literal that resembles it.
Both forms share the actual inclusive retention bounds. -/
@[step] theorem native_idempotency_admission_exact
    (source : AuthsNativeRecipe.recipe.source.IdempotencySource) (fits : IdempotencyFits source)
    (body : SourceBody) (model : TemplateAst.Body) (bounds : BodyBounds body)
    (original : BodySourceMeaning body model) :
    AuthsNativeRecipe.recipe.validate.Rules.idempotency source body ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.idempotency (planIdempotency source) model) ⦄ := by
  cases source with
  | DerivedHeader retention =>
      simp [AuthsNativeRecipe.recipe.validate.Rules.idempotency,
        core.ops.range.RangeInclusive.new, AuthsNativeRecipe.recipe.validate.MAX_RETENTION_SECONDS,
        AuthsNativeRecipe.recipe.source.IdempotencySource.retention_seconds,
        AuthsNativeRecipe.core.ops.range.RangeInclusive.contains,
        UScalar.le_equiv, RecipeRuleAdmission.idempotency, planIdempotency,
        consumptionVerdict, consumptionError, spec_ok]
  | OperationIdField location retention =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.idempotency
      simp only [core.ops.range.RangeInclusive.new, AuthsNativeRecipe.recipe.validate.MAX_RETENTION_SECONDS,
        AuthsNativeRecipe.recipe.source.IdempotencySource.retention_seconds, bind_tc_ok]
      step as ⟨valid, validity⟩
      have exactBound : valid = decide (1 ≤ retention.val ∧ retention.val ≤ 2592000) := by
        simpa [AuthsNativeRecipe.core.ops.range.RangeInclusive.contains, UScalar.le_equiv] using validity
      cases valid with
      | false => simp [RecipeRuleAdmission.idempotency, planIdempotency, ← exactBound,
          consumptionVerdict, consumptionError]
      | true =>
          have within : 1 ≤ retention.val ∧ retention.val ≤ 2592000 := by simpa using exactBound.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_operation_id_location_exact location fits body model bounds original as ⟨located, locationMeaning⟩
          cases located <;> simp [RecipeRuleAdmission.idempotency, planIdempotency,
            ruleIdempotencyLocation, within, ← locationMeaning, consumptionVerdict, consumptionError]

end Auths.Product.NativeCompiler.Refinement
