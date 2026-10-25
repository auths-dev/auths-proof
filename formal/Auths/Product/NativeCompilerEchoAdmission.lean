import Auths.Product.NativeCompilerJsonEchoAdmission
import Auths.Product.NativeCompilerRuleSource

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def ruleEcho (source : AuthsNativeRecipe.recipe.source.EchoSource) : RecipeRuleAdmission.Echo :=
  ⟨textBytes source.observe, planEchoSource source.write⟩

def EchoFits (source : AuthsNativeRecipe.recipe.source.EchoSource) : Prop :=
  TextFits source.observe ∧ NativeEchoFits source.write

def formEchoAt (keys : List (List Nat)) (name : List Nat) : Except RecipeConsumption.Error Unit :=
  if ∀ key ∈ keys, OperationIdentity.validToken key 64 = true then
    match TemplateMembers.canonicalMembers keys (some name) .form with
    | .ok _ => .ok ()
    | .error _ => .error .echoConflict
  else .error .echoConflict

/-- Transparent unchanged form suffix of validate_echo, invoking the actual
name check, full key collector, canonical selector and selected map closures.
It supplies no foreign Auths validator or accepted source/plan flag. -/
def nativeFormEchoStage (fields : SourceMap SourceForm) (name : String) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError) := do
  let empty ← AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.is_empty core.core.clone.CloneGlobal fields
  if empty then ok (.Err .EchoConflict)
  else
    let count ← AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.len core.core.clone.CloneGlobal fields
    if count > AuthsNativeRecipe.recipe.MAX_FORM_FIELDS then ok (.Err .EchoConflict)
    else
      let valid ← AuthsNativeRecipe.recipe.validate.form_member_names_valid fields
      if valid then
        let keys ← AuthsNativeRecipe.recipe.validate.form_member_keys fields
        let bytes ← AuthsNativeRecipe.alloc.string.String.as_bytes name
        let selected ← AuthsNativeRecipe.auths_gateway_kernel.template_members.canonical_members
          (AuthsNativeRecipe.alloc.vec.Vec.deref keys) (some bytes) .Form
        let mapped ← AuthsNativeRecipe.core.result.Result.map
          AuthsNativeRecipe.recipe.validate.validate_echo.closure.Insts.CoreOpsFunctionFnOnceTupleVecMemberChoiceTuple selected ()
        AuthsNativeRecipe.core.result.Result.map_err
          AuthsNativeRecipe.recipe.validate.validate_echo.closure_1.Insts.CoreOpsFunctionFnOnceTupleMemberErrorGatewayRecipeError mapped ()
      else ok (.Err .EchoConflict)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 22000000
set_option maxRecDepth 4096

@[step] theorem native_form_echo_stage_exact (fields : SourceMap SourceForm) (name : String) (nameFits : TextFits name)
    (fits : ∀ member ∈ fields.entries.val, TextFits member.1) :
    nativeFormEchoStage fields name ⦃ actual =>
      actual = consumptionVerdict (formEchoAt (sourceMemberNames fields.entries.val) (textBytes name)) ⦄ := by
  unfold nativeFormEchoStage
  simp only [AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.is_empty, bind_tc_ok]
  by_cases empty : fields.entries.val = []
  · simp [empty, formEchoAt, sourceMemberNames, TemplateMembers.canonicalMembers,
      TemplateMembers.KeyColumn, consumptionVerdict, consumptionError]
  · simp only [List.isEmpty_eq_false.mpr empty, Bool.false_eq_true, ↓reduceIte]
    step as ⟨size, sizeMeaning⟩
    by_cases large : 16 < fields.entries.val.length
    · have nativeLarge : size > AuthsNativeRecipe.recipe.MAX_FORM_FIELDS := by
        simp only [AuthsNativeRecipe.recipe.MAX_FORM_FIELDS]; scalar_tac
      have invalidColumn : ¬TemplateMembers.KeyColumn (sourceMemberNames fields.entries.val) .form := by
        simp only [TemplateMembers.KeyColumn, sourceMemberNames, List.length_map, TemplateMembers.maximum]
        omega
      simp [nativeLarge, formEchoAt, TemplateMembers.canonicalMembers, invalidColumn, consumptionVerdict, consumptionError]
    · have nativeWithin : ¬size > AuthsNativeRecipe.recipe.MAX_FORM_FIELDS := by
        simp only [AuthsNativeRecipe.recipe.MAX_FORM_FIELDS]; scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      step with native_form_member_names_exact fields fits as ⟨valid, validity⟩
      cases valid with
      | false => simp [formEchoAt, ← validity, consumptionVerdict, consumptionError]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_form_member_keys_exact fields fits as ⟨keys, originalKeys, keyCount⟩
          step with borrow_text_exact name nameFits as ⟨nameBytes, nameMeaning⟩
          step with native_canonical_members_exact (AuthsNativeRecipe.alloc.vec.Vec.deref keys) (some nameBytes) .Form
            as ⟨selected, selectedMeaning⟩
          have originalSelection : nativeMemberResult nativeChoices selected =
              TemplateMembers.canonicalMembers (sourceMemberNames fields.entries.val) (some (textBytes name)) .form := by
            simpa [native_key_column_deref, originalKeys, nameMeaning, nativeMemberDomain] using selectedMeaning
          cases selected <;>
            simp [AuthsNativeRecipe.core.result.Result.map, AuthsNativeRecipe.core.result.Result.map_err,
              _root_.core.result.Result.map_err,
              AuthsNativeRecipe.recipe.validate.validate_echo.closure.Insts.CoreOpsFunctionFnOnceTupleVecMemberChoiceTuple,
              AuthsNativeRecipe.recipe.validate.validate_echo.closure.Insts.CoreOpsFunctionFnOnceTupleVecMemberChoiceTuple.call_once,
              AuthsNativeRecipe.recipe.validate.validate_echo.closure_1.Insts.CoreOpsFunctionFnOnceTupleMemberErrorGatewayRecipeError,
              AuthsNativeRecipe.recipe.validate.validate_echo.closure_1.Insts.CoreOpsFunctionFnOnceTupleMemberErrorGatewayRecipeError.call_once,
              formEchoAt, ← validity, ← originalSelection, nativeMemberResult, consumptionVerdict, consumptionError]

/-- The complete actual echo caller earns observation grammar and exact
slash-boundary non-overlap before checking the original write placement. No
prior body/observation admission result is assumed; those are separate caller
obligations. Wrong body kinds and every insertion/collision/count failure
retain the actual EchoConflict/UnsafeTemplate error distinction. -/
@[step] theorem native_echo_admission_exact (source : AuthsNativeRecipe.recipe.source.EchoSource)
    (fits : EchoFits source) (body : SourceBody) (model : TemplateAst.Body)
    (bounds : BodyBounds body) (original : BodySourceMeaning body model)
    (read : AuthsNativeRecipe.recipe.source.ObservationSource) (readFits : TextFits read.json_pointer) :
    AuthsNativeRecipe.recipe.validate.validate_echo source body read ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.echo (ruleEcho source) model (ruleObservation read)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_echo
  step with native_deref_view_exact source.observe fits.1 as ⟨observe, observeMeaning⟩
  subst observe
  step with native_response_pointer_exact (nativeTextView source.observe fits.1) as ⟨valid, validity⟩
  cases valid with
  | false =>
      have invalid : ¬ResponsePointer (textBytes source.observe) := by
        simpa [responsePointer, native_text_view_bytes] using validity.symm
      simp [RecipeRuleAdmission.echo, ruleEcho, invalid, consumptionVerdict, consumptionError]
  | true =>
      have pointerValid : ResponsePointer (textBytes source.observe) := by
        simpa [responsePointer, native_text_view_bytes] using validity.symm
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_deref_view_exact read.json_pointer readFits as ⟨readPointer, readMeaning⟩
      subst readPointer
      step with native_pointers_overlap_exact (nativeTextView source.observe fits.1) (nativeTextView read.json_pointer readFits)
        as ⟨overlap, overlapMeaning⟩
      have originalOverlap : overlap = pointersOverlap (textBytes source.observe) (textBytes read.json_pointer) := by
        simpa [native_text_view_bytes] using overlapMeaning
      cases overlap with
      | true => simp [RecipeRuleAdmission.echo, ruleEcho, ruleObservation, pointerValid,
          ← originalOverlap, consumptionVerdict, consumptionError]
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          cases placement : source.write with
          | JsonPointer pointer =>
              have pointerFits : TextFits pointer := by simpa [EchoFits, placement, NativeEchoFits] using fits.2
              cases original with
              | form meaning => simp [RecipeRuleAdmission.echo, ruleEcho, ruleObservation, pointerValid,
                  ← originalOverlap, placement, planEchoSource, consumptionVerdict, consumptionError]
              | @json value valueModel valueMeaning =>
                  cases bounds with
                  | json value valueBounds =>
                      step with native_deref_view_exact pointer pointerFits as ⟨view, viewMeaning⟩
                      subst view
                      apply spec_mono (native_validate_json_echo_exact (nativeTextView pointer pointerFits) value valueModel valueBounds valueMeaning)
                      intro actual exactPlacement
                      simpa [RecipeRuleAdmission.echo, ruleEcho, ruleObservation, pointerValid,
                        ← originalOverlap, placement, planEchoSource, native_text_view_bytes, jsonEchoAt] using exactPlacement
          | FormField name =>
              have nameFits : TextFits name := by simpa [placement, NativeEchoFits] using fits.2
              cases original with
              | json meaning => simp [RecipeRuleAdmission.echo, ruleEcho, ruleObservation, pointerValid,
                  ← originalOverlap, placement, planEchoSource, consumptionVerdict, consumptionError]
              | @form fields models meaning =>
                  cases bounds with
                  | form fields names children =>
                      change nativeFormEchoStage fields name ⦃ _ ⦄
                      apply spec_mono (native_form_echo_stage_exact fields name nameFits names)
                      intro actual exactPlacement
                      have originalNames := source_form_member_names _ _ meaning
                      simpa [RecipeRuleAdmission.echo, ruleEcho, ruleObservation, pointerValid,
                        ← originalOverlap, placement, planEchoSource, formEchoAt, ← originalNames,
                        List.all_eq_true, List.forall_mem_map] using exactPlacement

theorem native_echo_success_has_separate_observation (source : AuthsNativeRecipe.recipe.source.EchoSource)
    (fits : EchoFits source) (body : SourceBody) (model : TemplateAst.Body)
    (bounds : BodyBounds body) (original : BodySourceMeaning body model)
    (read : AuthsNativeRecipe.recipe.source.ObservationSource) (readFits : TextFits read.json_pointer) :
    AuthsNativeRecipe.recipe.validate.validate_echo source body read ⦃ actual =>
      actual = .Ok () → ResponsePointer (textBytes source.observe) ∧
        pointersOverlap (textBytes source.observe) (textBytes read.json_pointer) = false ⦄ := by
  apply spec_mono (native_echo_admission_exact source fits body model bounds original read readFits)
  intro actual meaning accepted
  have succeeded : RecipeRuleAdmission.echo (ruleEcho source) model (ruleObservation read) = .ok () := by
    cases result : RecipeRuleAdmission.echo (ruleEcho source) model (ruleObservation read) <;>
      simp_all [consumptionVerdict]
  exact RecipeRuleAdmission.echo_success_earns_separate_observation _ _ _ succeeded

end Auths.Product.NativeCompiler.Refinement
