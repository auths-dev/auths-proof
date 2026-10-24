import Auths.Product.NativeCompilerReadPointers
import Auths.Product.NativeCompilerBodyFields
import Auths.Product.NativeCompilerRuleSource
import Auths.Product.RecipeRelativeProperties

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeBind := AuthsNativeRecipe.recipe.source.BindSource

def BindFits (source : NativeBind) : Prop := TextFits source.pointer ∧ TextFits source.field

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms RecipeRuleAdmission
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

private theorem native_bind_seen_prefix (binds : Slice NativeBind) (position : Std.Usize)
    (value : NativeBind) (previous : Std.Usize) (seen : Bool)
    (previousBound : previous.val ≤ position.val) (positionBound : position.val ≤ binds.val.length) :
    AuthsNativeRecipe.recipe.validate.bind_pointer_seen_before_loop binds position value previous seen ⦃ actual =>
      actual = (seen || decide (value.pointer ∈ ((binds.val.map (·.pointer)).take position.val).drop previous.val)) ⦄ := by
  generalize remaining : position.val - previous.val = count
  induction count using Nat.strong_induction_on generalizing previous seen with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.bind_pointer_seen_before_loop
      by_cases inside : previous.val < position.val
      · have nativeInside : previous < position := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases seen with
        | true => simp
        | false =>
            simp only [Bool.false_eq_true, ↓reduceIte]
            have available : previous.val < binds.val.length := by omega
            step with Slice.index_usize_spec binds previous available as ⟨current, currentAt⟩
            step as ⟨equal, equality⟩
            step as ⟨next, nextValue⟩
            have prefixInside : previous.val < ((binds.val.map (·.pointer)).take position.val).length := by
              simp only [List.length_take, List.length_map]; omega
            have prefixValue : ((binds.val.map (·.pointer)).take position.val)[previous.val] = current.pointer := by
              simp [currentAt]
            have suffix : ((binds.val.map (·.pointer)).take position.val).drop previous.val =
                current.pointer :: ((binds.val.map (·.pointer)).take position.val).drop next.val := by
              simpa [prefixValue, nextValue] using List.drop_eq_getElem_cons prefixInside
            apply spec_mono (ih _ (by omega) next equal (by omega) rfl)
            intro actual meaning
            simpa [suffix, List.mem_cons, equality, eq_comm, decide_or] using meaning
      · have nativeEnded : ¬previous < position := by scalar_tac
        have ended : ((binds.val.map (·.pointer)).take position.val).length ≤ previous.val := by
          simp only [List.length_take, List.length_map]; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended]

/-- The direct duplicate helper compares every earlier original pointer,
including its final byte. An out-of-range position conservatively reports a
duplicate; it does not validate pointer grammar or the bind's field. -/
@[step] theorem native_bind_seen_before_exact (binds : Slice NativeBind) (position : Std.Usize) :
    AuthsNativeRecipe.recipe.validate.bind_pointer_seen_before binds position ⦃ actual =>
      actual = seenBefore (binds.val.map (·.pointer)) position.val ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.bind_pointer_seen_before
    core.slice.Slice.get core.slice.index.SliceIndexUsizeSlice
  simp only [core.slice.index.Usize.get, Slice.getElem?_Usize_eq, bind_tc_ok]
  by_cases inside : position.val < binds.val.length
  · simp only [List.getElem?_eq_getElem inside]
    apply spec_mono (native_bind_seen_prefix binds position binds.val[position.val] 0#usize false
      (by simp) (by omega))
    intro actual meaning
    simpa [seenBefore, List.getElem?_eq_getElem (by simpa using inside), List.drop_zero] using meaning
  · have ended : (binds.val.map (·.pointer)).length ≤ position.val := by simp; omega
    simp [seenBefore, List.getElem?_eq_none_iff.mpr (by omega), List.getElem?_eq_none_iff.mpr ended]

private theorem native_bind_pointer_suffix (binds : Slice NativeBind) (position : Std.Usize)
    (valid : Bool) (positionBound : position.val ≤ binds.val.length) :
    AuthsNativeRecipe.recipe.validate.bind_pointers_valid_loop binds position valid ⦃ actual =>
      actual = (valid && decide (BindPointerFresh
        ((binds.val.map (·.pointer)).take position.val) ((binds.val.map (·.pointer)).drop position.val))) ⦄ := by
  generalize remaining : binds.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.bind_pointers_valid_loop
      by_cases inside : position.val < binds.val.length
      · have nativeInside : position < binds.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with native_bind_seen_before_exact binds position as ⟨seen, seenMeaning⟩
            step as ⟨next, nextValue⟩
            have mappedInside : position.val < (binds.val.map (·.pointer)).length := by simpa using inside
            have suffix := List.drop_eq_getElem_cons mappedInside
            have prefix := List.take_succ_eq_append_getElem mappedInside
            apply spec_mono (ih _ (by omega) next (!seen) (by omega) rfl)
            intro actual meaning
            simpa [nextValue, suffix, prefix, bind_pointer_fresh_cons, seenMeaning,
              seenBefore, List.getElem?_eq_getElem mappedInside, decide_and] using meaning
      · have nativeEnded : ¬position < binds.len := by scalar_tac
        have ended : (binds.val.map (·.pointer)).length ≤ position.val := by simp; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended, BindPointerFresh]

@[step] theorem native_bind_pointers_exact (binds : Slice NativeBind) :
    AuthsNativeRecipe.recipe.validate.bind_pointers_valid binds ⦃ actual =>
      actual = decide (binds.val.length ≤ 2 ∧ ((binds.val.map ruleBind).map Bind.pointer).Nodup) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.bind_pointers_valid
  by_cases large : 2 < binds.val.length
  · have nativeLarge : binds.len > AuthsNativeRecipe.recipe.validate.MAX_BINDS := by
      simp only [AuthsNativeRecipe.recipe.validate.MAX_BINDS]; scalar_tac
    simp [nativeLarge, Nat.not_le.mpr large]
  · have within : binds.val.length ≤ 2 := by omega
    have nativeWithin : ¬binds.len > AuthsNativeRecipe.recipe.validate.MAX_BINDS := by
      simp only [AuthsNativeRecipe.recipe.validate.MAX_BINDS]; scalar_tac
    simp only [nativeWithin, ↓reduceIte]
    apply spec_mono (native_bind_pointer_suffix binds 0#usize true (by simp))
    intro actual meaning
    simpa [List.drop_zero, bind_pointer_fresh_empty, within, ruleBind, List.map_map, Function.comp_def] using meaning

@[step] theorem native_bindable_field_exact (fields : NativeRuleMap) (name : String)
    (nameFits : TextFits name) (fieldFits : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.bindable_field fields (nativeTextView name nameFits) ⦃ actual =>
      actual = RecipeConsumption.fieldTest RecipeConsumption.formSchema (nativeRuleMapMeaning fields) name ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.bindable_field
  step with native_rule_map_lookup fields name nameFits fieldFits as ⟨selected, meaning⟩
  cases selected with
  | none => simp [RecipeConsumption.fieldTest, ← meaning]
  | some schema =>
      cases schema <;> simp [RecipeConsumption.fieldTest, ← meaning, nativeScalarMeaning, RecipeConsumption.formSchema]

@[step] theorem native_relative_bind_exact (fields : NativeRuleMap) (source : NativeBind)
    (argument : String) (argumentFits : TextFits argument) (fits : BindFits source)
    (fieldFits : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.relative_bind_valid fields source (nativeTextView argument argumentFits) ⦃ actual =>
      actual = decide (relativeBindAdmitted (nativeRuleMapMeaning fields) argument (ruleBind source)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.relative_bind_valid
  step with native_deref_view_exact source.pointer fits.1 as ⟨pointer, pointerView⟩
  subst pointer
  step with native_response_pointer_exact (nativeTextView source.pointer fits.1) as ⟨valid, validity⟩
  cases valid with
  | false =>
      simp [relativeBindAdmitted, ruleBind, ← validity, responsePointer, native_text_view_bytes]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_deref_view_exact source.field fits.2 as ⟨field, fieldView⟩
      subst field
      step with native_bindable_field_exact fields source.field fits.2 fieldFits as ⟨scalar, scalarMeaning⟩
      cases scalar with
      | false =>
          simp [relativeBindAdmitted, ruleBind, ← scalarMeaning]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with borrow_text_exact source.field fits.2 as ⟨fieldBytes, fieldBytesMeaning⟩
          subst fieldBytes
          simp only [AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
          step with native_schema_byte_equality as ⟨same, equality⟩
          have sameName : same = decide (source.field = argument) := by
            simpa [native_text_view_bytes, text_bytes_injective.eq_iff] using equality
          cases same with
          | true => simp [relativeBindAdmitted, ruleBind, ← scalarMeaning, ← sameName]
          | false =>
              simp only [Bool.false_eq_true, ↓reduceIte]
              step with native_binding_field_name_exact source.field fits.2 as ⟨binding, bindingMeaning⟩
              simp [relativeBindAdmitted, ruleBind, ← validity, responsePointer,
                native_text_view_bytes, ← scalarMeaning, ← sameName, ← bindingMeaning]

private theorem native_relative_bind_suffix (fields : NativeRuleMap) (binds : Slice NativeBind)
    (argument : String) (argumentFits : TextFits argument) (position : Std.Usize) (valid : Bool)
    (positionBound : position.val ≤ binds.val.length) (fits : ∀ source ∈ binds.val, BindFits source)
    (fieldFits : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.relative_binds_valid_loop fields binds (nativeTextView argument argumentFits)
      position valid ⦃ actual => actual = (valid && decide
        (∀ source ∈ binds.val.drop position.val, relativeBindAdmitted (nativeRuleMapMeaning fields) argument (ruleBind source))) ⦄ := by
  generalize remaining : binds.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.relative_binds_valid_loop
      by_cases inside : position.val < binds.val.length
      · have nativeInside : position < binds.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec binds position inside as ⟨source, sourceAt⟩
            have sourceFits := fits source (by rw [sourceAt]; exact List.getElem_mem inside)
            step with native_relative_bind_exact fields source argument argumentFits sourceFits fieldFits
              as ⟨admitted, admission⟩
            step as ⟨next, nextValue⟩
            have suffix : binds.val.drop position.val = source :: binds.val.drop next.val := by
              simpa [sourceAt, nextValue] using List.drop_eq_getElem_cons inside
            apply spec_mono (ih _ (by omega) next admitted (by omega) rfl)
            intro actual meaning
            simpa [suffix, admission, decide_and] using meaning
      · have nativeEnded : ¬position < binds.len := by scalar_tac
        have ended : binds.val.length ≤ position.val := by omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended]

/-- Native relative-bind admission checks the complete original list, every
schema/name, pointer uniqueness and the original ceiling argument. It allows
zero binds and repeated fields at distinct pointers, exactly as Rust does. -/
@[step] theorem native_relative_binds_exact (fields : NativeRuleMap) (binds : Slice NativeBind)
    (argument : String) (argumentFits : TextFits argument) (fits : ∀ source ∈ binds.val, BindFits source)
    (fieldFits : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.relative_binds_valid fields binds (nativeTextView argument argumentFits) ⦃ actual =>
      actual = decide (RelativeBindsAdmitted (nativeRuleMapMeaning fields) argument (binds.val.map ruleBind)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.relative_binds_valid
  step with native_bind_pointers_exact binds as ⟨pointers, pointerMeaning⟩
  cases pointers with
  | false => simp [RelativeBindsAdmitted, ← pointerMeaning]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      apply spec_mono (native_relative_bind_suffix fields binds argument argumentFits 0#usize true
        (by simp) fits fieldFits)
      intro actual meaning
      simpa [RelativeBindsAdmitted, ← pointerMeaning, List.drop_zero,
        List.forall_mem_map, and_assoc] using meaning

end Auths.Product.NativeCompiler.Refinement
