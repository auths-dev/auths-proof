import Auths.Product.TemplateFormGrammar
import Auths.Product.TemplateMemberDomainsRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway

namespace Auths.Product.TemplateMembers.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem form_echo_loop_exact (name : Slice Std.U8)
    (nonempty : 0 < name.val.length) (bounded : name.val.length ≤ 130) :
    template_members.form_echo_name_valid_loop name 0#usize ⦃ actual => actual = formEchoValid (sliceBytes name) ⦄ := by
  unfold template_members.form_echo_name_valid_loop
  apply loop.spec_decr_nat
    (measure := fun position => name.val.length - position.val)
    (inv := fun position => position.val ≤ name.val.length ∧
      ∀ byte ∈ (sliceBytes name).take position.val, byte ≠ 91)
  · intro position invariant
    unfold template_members.form_echo_name_valid_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : position.val < name.val.length := by scalar_tac
      step as ⟨byte, byteAt⟩
      split <;> rename_i opening
      · have openByte : byte.val = 91 := by scalar_tac
        have modelInside : position.val < (sliceBytes name).length := by simpa [sliceBytes, byteList] using inside
        have firstOpen : (sliceBytes name).findIdx (· == 91) = position.val := by
          apply (List.findIdx_eq modelInside).mpr
          constructor
          · simp [sliceBytes, byteList, byteAt, openByte]
          · intro index before
            have atPrefix : (sliceBytes name)[index] ∈ (sliceBytes name).take position.val := by
              apply List.mem_iff_getElem?.mpr
              refine ⟨index, ?_⟩
              simp [List.getElem?_take, before, List.getElem?_eq_getElem (by omega : index < (sliceBytes name).length)]
            simpa using invariant.2 _ atPrefix
        have nonemptyBool : (sliceBytes name).isEmpty = false := by
          cases values : name.val <;> simp_all [sliceBytes, byteList]
        have modelBound : ¬130 < (sliceBytes name).length := by simpa [sliceBytes, byteList] using Nat.not_lt.mpr bounded
        by_cases zero : position.val = 0
        · have nativeZero : position = 0#usize := by scalar_tac
          simp [nativeZero, formEchoValid, nonemptyBool, modelBound, firstOpen, zero, modelInside]
        · have nativeNonzero : position ≠ 0#usize := by scalar_tac
          simp only [nativeNonzero, beq_eq_false_iff_ne, Bool.false_or]
          have lookAheadFits : position.val + 2 ≤ 132 := by omega
          step as ⟨lookAhead, lookAheadValue⟩
          by_cases noRoom : name.val.length ≤ position.val + 2
          · have nativeNoRoom : lookAhead ≥ name.len := by scalar_tac
            have modelNoRoom : (sliceBytes name).length ≤ position.val + 2 := by simpa [sliceBytes, byteList] using noRoom
            simp [nativeNoRoom, formEchoValid, nonemptyBool, modelBound, firstOpen, modelInside, modelNoRoom]
          · have nativeRoom : ¬lookAhead ≥ name.len := by scalar_tac
            have space : position.val + 2 < (sliceBytes name).length := by simp only [sliceBytes, byteList, List.length_map]; omega
            simp only [nativeRoom, Bool.false_or, ↓reduceIte]
            step as ⟨endIndex, endIndexValue⟩
            have endInside : endIndex.val < name.val.length := by scalar_tac
            step as ⟨last, lastAt⟩
            have lastMeaning : (sliceBytes name).getLast? = some last.val := by
              simp [List.getLast?_eq_getElem?, sliceBytes, byteList, List.getElem?_map,
                List.getElem?_eq_getElem endInside, endIndexValue, lastAt]
            by_cases closed : last.val = 93
            · have nativeClosed : last = 93#u8 := by scalar_tac
              have closing : (sliceBytes name).getLast? = some 93 := by simpa [closed] using lastMeaning
              simp only [nativeClosed, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
              step as ⟨base, baseValue⟩
              have baseMeaning : sliceBytes base = (sliceBytes name).take position.val := by
                simpa [sliceBytes, byteList, List.slice_eq_drop_take] using congrArg byteList baseValue
              step with OperationIdentity.Refinement.token_exact as ⟨baseAllowed, baseAllowedMeaning⟩
              cases baseAllowed
              · have refused : OperationIdentity.validToken ((sliceBytes name).take position.val) 64 = false := by
                  simpa [baseMeaning] using baseAllowedMeaning.symm
                simp [formEchoValid, nonemptyBool, modelBound, firstOpen, modelInside, zero,
                  Nat.not_le.mpr space, closing, refused]
              · have accepted : OperationIdentity.validToken ((sliceBytes name).take position.val) 64 = true := by
                  simpa [baseMeaning] using baseAllowedMeaning.symm
                simp only [Bool.true_and, ↓reduceIte]
                step as ⟨innerStart, innerStartValue⟩
                step as ⟨innerEnd, innerEndValue⟩
                step as ⟨inner, innerValue⟩
                have innerMeaning : sliceBytes inner = ((sliceBytes name).drop (position.val + 1)).take
                    ((sliceBytes name).length - position.val - 2) := by
                  simpa [sliceBytes, byteList, List.slice_eq_drop_take, innerStartValue, innerEndValue,
                    show name.val.length - 1 - (position.val + 1) = name.val.length - position.val - 2 by omega]
                    using congrArg byteList innerValue
                step with OperationIdentity.Refinement.token_exact as ⟨innerAllowed, innerAllowedMeaning⟩
                simpa [formEchoValid, nonemptyBool, modelBound, firstOpen, modelInside, zero,
                  Nat.not_le.mpr space, closing, accepted, innerMeaning] using innerAllowedMeaning
            · have nativeNotClosed : last ≠ 93#u8 := by scalar_tac
              have notClosing : (sliceBytes name).getLast? ≠ some 93 := by
                simpa [lastMeaning] using closed
              simp [nativeNotClosed, formEchoValid, nonemptyBool, modelBound, firstOpen, modelInside, notClosing]
      · have notOpen : byte.val ≠ 91 := by scalar_tac
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        have takeNext : (sliceBytes name).take (position.val + 1) =
            (sliceBytes name).take position.val ++ [byte.val] := by
          simpa [sliceBytes, byteList, byteAt] using List.take_succ_eq_append_getElem (by simpa [sliceBytes, byteList] using inside)
        rw [nextValue, takeNext]
        intro value member
        rcases List.mem_append.mp member with earlier | current
        · exact invariant.2 value earlier
        · have same : value = byte.val := by simpa only [List.mem_singleton] using current
          simpa [same] using notOpen
    · have endBound : (sliceBytes name).length ≤ position.val := by
        simpa [sliceBytes, byteList] using (show name.val.length ≤ position.val by scalar_tac)
      have noOpen : (sliceBytes name).findIdx (· == 91) = (sliceBytes name).length :=
        List.findIdx_eq_length_of_false (fun byte member => by
          have absent := invariant.2 byte (by simpa [List.take_of_length_le endBound] using member)
          simpa using absent)
      have nonemptyBool : (sliceBytes name).isEmpty = false := by
        cases values : name.val <;> simp_all [sliceBytes, byteList]
      have modelBound : ¬130 < (sliceBytes name).length := by simpa [sliceBytes, byteList] using Nat.not_lt.mpr bounded
      step with OperationIdentity.Refinement.token_exact as ⟨allowed, allowedMeaning⟩
      simpa [formEchoValid, nonemptyBool, modelBound, noOpen] using allowedMeaning
  · exact ⟨by simp, by simp⟩

@[step] theorem form_echo_name_exact (name : Slice Std.U8) :
    template_members.form_echo_name_valid name ⦃ actual => actual = formEchoValid (sliceBytes name) ⦄ := by
  unfold template_members.form_echo_name_valid
  by_cases empty : name.val.length = 0
  · have values : name.val = [] := List.length_eq_zero_iff.mp empty
    simp [values, sliceBytes, byteList, formEchoValid]
  · simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, empty, decide_false, Bool.false_or]
    by_cases large : 130 < name.val.length
    · have nativeLarge : name.len > 130#usize := by scalar_tac
      have modelLarge : 130 < (sliceBytes name).length := by simpa [sliceBytes, byteList] using large
      simp [nativeLarge, formEchoValid, modelLarge]
    · have nativeBound : ¬name.len > 130#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      exact form_echo_loop_exact name (by omega) (by omega)

theorem source_form_echo_grammar_exact (name : Slice Std.U8) :
    template_members.form_echo_name_valid name ⦃ actual => actual = true ↔ FormEchoGrammar (sliceBytes name) ⦄ := by
  apply spec_mono (form_echo_name_exact name)
  intro actual meaning
  rw [meaning]
  exact form_echo_valid_iff_grammar _

end Auths.Product.TemplateMembers.Refinement
