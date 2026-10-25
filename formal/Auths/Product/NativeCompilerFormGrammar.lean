import Auths.Product.NativeCompilerMemberMerge
import Auths.Product.TemplateFormGrammar

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateMembers
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_form_echo_suffix (name : Slice Std.U8) (position : Std.Usize)
    (nonempty : 0 < name.val.length) (bounded : name.val.length ≤ 130)
    (positionBound : position.val ≤ name.val.length)
    (earlier : ∀ byte ∈ (schemaSliceBytes name).take position.val, byte ≠ 91) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.form_echo_name_valid_loop name position
      ⦃ actual => actual = formEchoValid (schemaSliceBytes name) ⦄ := by
  generalize remaining : name.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.form_echo_name_valid_loop
      have nonemptyBool : (schemaSliceBytes name).isEmpty = false := by
        cases original : name.val <;> simp_all [schemaSliceBytes]
      have modelBound : ¬130 < (schemaSliceBytes name).length := by
        simpa [schemaSliceBytes] using Nat.not_lt.mpr bounded
      by_cases inside : position.val < name.val.length
      · have nativeInside : position < name.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec name position inside as ⟨byte, byteAt⟩
        by_cases opening : byte.val = 91
        · have nativeOpening : byte = 91#u8 := by scalar_tac
          have modelInside : position.val < (schemaSliceBytes name).length := by
            simpa [schemaSliceBytes] using inside
          have firstOpen : (schemaSliceBytes name).findIdx (· == 91) = position.val := by
            apply (List.findIdx_eq modelInside).mpr
            constructor
            · simp [schemaSliceBytes, byteAt, opening]
            · intro index before
              have atPrefix : (schemaSliceBytes name)[index] ∈ (schemaSliceBytes name).take position.val := by
                apply List.mem_iff_getElem?.mpr
                refine ⟨index, ?_⟩
                simp [List.getElem?_take, before, List.getElem?_eq_getElem
                  (by omega : index < (schemaSliceBytes name).length)]
              simpa using earlier _ atPrefix
          simp only [nativeOpening, ↓reduceIte]
          by_cases zero : position.val = 0
          · have nativeZero : position = 0#usize := by scalar_tac
            simp [nativeZero, formEchoValid, nonemptyBool, modelBound, firstOpen, zero, modelInside]
          · have nativeNonzero : position ≠ 0#usize := by scalar_tac
            simp only [nativeNonzero, ↓reduceIte]
            step as ⟨lookAhead, lookAheadValue⟩
            by_cases noRoom : name.val.length ≤ position.val + 2
            · have nativeNoRoom : lookAhead >= name.len := by scalar_tac
              simp [nativeNoRoom, formEchoValid, nonemptyBool, modelBound, firstOpen,
                modelInside, schemaSliceBytes, noRoom]
            · have nativeRoom : ¬lookAhead >= name.len := by scalar_tac
              have space : position.val + 2 < (schemaSliceBytes name).length := by
                simp only [schemaSliceBytes, List.length_map]
                omega
              simp only [nativeRoom, ↓reduceIte]
              step as ⟨endIndex, endIndexValue⟩
              have endInside : endIndex.val < name.val.length := by scalar_tac
              step with Slice.index_usize_spec name endIndex endInside as ⟨last, lastAt⟩
              have lastMeaning : (schemaSliceBytes name).getLast? = some last.val := by
                simp [List.getLast?_eq_getElem?, schemaSliceBytes, List.getElem?_map,
                  List.getElem?_eq_getElem endInside, endIndexValue, lastAt]
              by_cases closed : last.val = 93
              · have nativeClosed : last = 93#u8 := by scalar_tac
                have closing : (schemaSliceBytes name).getLast? = some 93 := by
                  simpa [closed] using lastMeaning
                simp only [nativeClosed, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
                step as ⟨base, baseValue⟩
                have baseMeaning : schemaSliceBytes base = (schemaSliceBytes name).take position.val := by
                  simpa [schemaSliceBytes, List.slice_eq_drop_take] using
                    congrArg (List.map (fun byte : Std.U8 => byte.val)) baseValue
                step with native_schema_token_exact base 64#usize as ⟨baseAllowed, baseAllowedMeaning⟩
                cases baseAllowed with
                | false =>
                    have refused : OperationIdentity.validToken ((schemaSliceBytes name).take position.val) 64 = false := by
                      simpa [baseMeaning] using baseAllowedMeaning.symm
                    simp [formEchoValid, nonemptyBool, modelBound, firstOpen, modelInside,
                      zero, Nat.not_le.mpr space, closing, refused]
                | true =>
                    have accepted : OperationIdentity.validToken ((schemaSliceBytes name).take position.val) 64 = true := by
                      simpa [baseMeaning] using baseAllowedMeaning.symm
                    simp only [Bool.true_eq_true, ↓reduceIte]
                    step as ⟨innerStart, innerStartValue⟩
                    step as ⟨innerEnd, innerEndValue⟩
                    step as ⟨inner, innerValue⟩
                    have innerMeaning : schemaSliceBytes inner = ((schemaSliceBytes name).drop (position.val + 1)).take
                        ((schemaSliceBytes name).length - position.val - 2) := by
                      simpa [schemaSliceBytes, List.slice_eq_drop_take, innerStartValue, innerEndValue,
                        show name.val.length - 1 - (position.val + 1) = name.val.length - position.val - 2 by omega]
                        using congrArg (List.map (fun byte : Std.U8 => byte.val)) innerValue
                    step with native_schema_token_exact inner 64#usize as ⟨innerAllowed, innerAllowedMeaning⟩
                    simpa [formEchoValid, nonemptyBool, modelBound, firstOpen, modelInside,
                      zero, Nat.not_le.mpr space, closing, accepted, innerMeaning] using innerAllowedMeaning
              · have nativeNotClosed : last ≠ 93#u8 := by scalar_tac
                have notClosing : (schemaSliceBytes name).getLast? ≠ some 93 := by
                  simpa [lastMeaning] using closed
                simp [nativeNotClosed, formEchoValid, nonemptyBool, modelBound, firstOpen, modelInside, notClosing]
        · have nativeNotOpen : byte ≠ 91#u8 := by scalar_tac
          simp only [nativeNotOpen, ↓reduceIte]
          step as ⟨next, nextValue⟩
          have takeNext : (schemaSliceBytes name).take (position.val + 1) =
              (schemaSliceBytes name).take position.val ++ [byte.val] := by
            simpa [schemaSliceBytes, byteAt] using List.take_succ_eq_append_getElem
              (by simpa [schemaSliceBytes] using inside)
          have nextEarlier : ∀ value ∈ (schemaSliceBytes name).take next.val, value ≠ 91 := by
            rw [nextValue, takeNext]
            intro value member
            rcases List.mem_append.mp member with previous | current
            · exact earlier value previous
            · have same : value = byte.val := by simpa only [List.mem_singleton] using current
              simpa [same] using opening
          exact ih _ (by omega) next (by omega) nextEarlier rfl
      · have ended : position.val = name.val.length := by omega
        have nativeEnded : ¬position < name.len := by scalar_tac
        have noOpen : (schemaSliceBytes name).findIdx (· == 91) = (schemaSliceBytes name).length :=
          List.findIdx_eq_length_of_false (fun byte member => by
            have absent := earlier byte (by simpa [ended, schemaSliceBytes] using member)
            simpa using absent)
        simp only [nativeEnded, ↓reduceIte]
        step with native_schema_token_exact name 64#usize as ⟨allowed, allowedMeaning⟩
        simpa [formEchoValid, nonemptyBool, modelBound, noOpen] using allowedMeaning

@[step] theorem native_form_echo_name_exact (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.form_echo_name_valid name ⦃ actual =>
      actual = formEchoValid (schemaSliceBytes name) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.form_echo_name_valid
  by_cases empty : name.val.length = 0
  · have original : name.val = [] := List.length_eq_zero_iff.mp empty
    simp [core.slice.Slice.is_empty, original, schemaSliceBytes, formEchoValid]
  · simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length,
      empty, decide_false, Bool.false_eq_true, ↓reduceIte]
    by_cases large : 130 < name.val.length
    · have nativeLarge : name.len > 130#usize := by scalar_tac
      simp [nativeLarge, formEchoValid, schemaSliceBytes, large]
    · have nativeBound : ¬name.len > 130#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      exact native_form_echo_suffix name 0#usize (by omega) (by omega) (by simp) (by simp)

theorem native_form_echo_earns_exact_grammar (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.form_echo_name_valid name ⦃ actual =>
      actual = true ↔ FormEchoGrammar (schemaSliceBytes name) ⦄ := by
  apply spec_mono (native_form_echo_name_exact name)
  intro actual meaning
  rw [meaning]
  exact form_echo_valid_iff_grammar _

end Auths.Product.NativeCompiler.Refinement
