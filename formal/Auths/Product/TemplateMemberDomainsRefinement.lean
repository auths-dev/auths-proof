import Auths.Product.TemplateMemberDomains
import Auths.Product.TemplateMembersRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway

namespace Auths.Product.TemplateMembers.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem keys_loop_exact (keys : Slice template_members.NamedKey) :
    template_members.keys_ordered_loop keys 0#usize ⦃ actual =>
      actual = decide (KeyTail none (keysView keys)) ⦄ := by
  unfold template_members.keys_ordered_loop
  apply loop.spec_decr_nat
    (measure := fun index => keys.val.length - index.val)
    (inv := fun index => index.val ≤ keys.val.length ∧
      (KeyTail none (keysView keys) ↔ KeyTail (previousAt (keysView keys) index.val) ((keysView keys).drop index.val)))
  · intro index invariant
    unfold template_members.keys_ordered_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < keys.val.length := by scalar_tac
      step as ⟨key, keyAt⟩
      have atKey : (keysView keys)[index.val]? = some (sliceBytes key.name) := by
        simp [keysView, List.getElem?_map, List.getElem?_eq_getElem inside, keyAt]
      have suffix : (keysView keys).drop index.val = sliceBytes key.name :: (keysView keys).drop (index.val + 1) := by
        simpa [keysView, List.drop_map, keyAt] using
          congrArg (List.map (fun key => sliceBytes key.name)) (List.drop_eq_getElem_cons inside)
      step with OperationIdentity.Refinement.token_exact as ⟨allowed, allowedMeaning⟩
      cases allowed
      · have invalid : OperationIdentity.validToken (sliceBytes key.name) 64 ≠ true := by simpa using allowedMeaning.symm
        have notAll : ¬KeyTail none (keysView keys) := by
          rw [invariant.2, suffix, KeyTail]
          simp [invalid]
        simp [notAll]
      · have valid : OperationIdentity.validToken (sliceBytes key.name) 64 = true := by simpa using allowedMeaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        by_cases first : index.val = 0
        · have nativeFirst : ¬index > 0#usize := by scalar_tac
          simp only [nativeFirst, Bool.false_and, Bool.false_eq_true, ↓reduceIte]
          step as ⟨next, nextValue⟩
          refine ⟨by omega, ?_, by omega⟩
          simpa [nextValue, previous_at_next, atKey, suffix, KeyTail, previousAt, first, valid] using invariant.2
        · have positive : 0 < index.val := by omega
          have nativePositive : index > 0#usize := by scalar_tac
          simp only [nativePositive, Bool.true_and, ↓reduceIte]
          step as ⟨previousIndex, previousIndexValue⟩
          have previousInside : previousIndex.val < keys.val.length := by scalar_tac
          step as ⟨previous, previousKeyAt⟩
          have previousMeaning : previousAt (keysView keys) index.val = some (sliceBytes previous.name) := by
            simp [previousAt, first, keysView, List.getElem?_map,
              List.getElem?_eq_getElem previousInside, previousKeyAt, previousIndexValue]
          step with byte_less_exact as ⟨ordered, orderedMeaning⟩
          cases ordered
          · have invalid : ¬sliceBytes previous.name < sliceBytes key.name := by simpa using orderedMeaning.symm
            have notAll : ¬KeyTail none (keysView keys) := by
              rw [invariant.2, suffix, KeyTail, previousMeaning]
              simp [invalid]
            simp [notAll]
          · have ordered : sliceBytes previous.name < sliceBytes key.name := by simpa using orderedMeaning.symm
            simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
            step as ⟨next, nextValue⟩
            refine ⟨by omega, ?_, by omega⟩
            simpa [nextValue, previous_at_next, atKey, suffix, KeyTail, previousMeaning, valid, ordered] using invariant.2
    · have finished : keys.val.length ≤ index.val := by scalar_tac
      have finishedModel : (keysView keys).length ≤ index.val := by simpa [keysView] using finished
      have valid : KeyTail none (keysView keys) := by
        rw [invariant.2, List.drop_of_length_le finishedModel]
        trivial
      simp [valid]
  · exact ⟨by simp, by simp [previousAt]⟩

@[step] theorem keys_ordered_exact (keys : Slice template_members.NamedKey) (domain : template_members.MemberDomain) :
    template_members.keys_ordered keys domain ⦃ actual =>
      actual = decide (KeyColumn (keysView keys) (domainOf domain)) ⦄ := by
  cases domain with
  | Json =>
    unfold template_members.keys_ordered
    by_cases empty : keys.val.length = 0
    · have values : keys.val = [] := List.length_eq_zero_iff.mp empty
      simp [values, keysView, KeyColumn]
    · simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, empty, decide_false, Bool.false_or]
      by_cases large : 32 < keys.val.length
      · have nativeLarge : keys.len > 32#usize := by scalar_tac
        have invalid : ¬KeyColumn (keysView keys) .json := by
          intro admitted
          have count := admitted.2.1
          simp only [keysView, List.length_map, maximum] at count
          omega
        simp [nativeLarge, domainOf, invalid]
      · have nativeBound : ¬keys.len > 32#usize := by scalar_tac
        have count : 0 < (keysView keys).length ∧ (keysView keys).length ≤ maximum .json := by
          simp only [keysView, List.length_map, maximum]
          omega
        simp only [nativeBound, ↓reduceIte]
        apply spec_mono (keys_loop_exact keys)
        intro actual meaning
        simpa [key_column_iff, domainOf, count.1, count.2] using meaning
  | Form =>
    unfold template_members.keys_ordered
    by_cases empty : keys.val.length = 0
    · have values : keys.val = [] := List.length_eq_zero_iff.mp empty
      simp [values, keysView, KeyColumn]
    · simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, empty, decide_false, Bool.false_or]
      by_cases large : 16 < keys.val.length
      · have nativeLarge : keys.len > 16#usize := by scalar_tac
        have invalid : ¬KeyColumn (keysView keys) .form := by
          intro admitted
          have count := admitted.2.1
          simp only [keysView, List.length_map, maximum] at count
          omega
        simp [nativeLarge, domainOf, invalid]
      · have nativeBound : ¬keys.len > 16#usize := by scalar_tac
        have count : 0 < (keysView keys).length ∧ (keysView keys).length ≤ maximum .form := by
          simp only [keysView, List.length_map, maximum]
          omega
        simp only [nativeBound, ↓reduceIte]
        apply spec_mono (keys_loop_exact keys)
        intro actual meaning
        simpa [key_column_iff, domainOf, count.1, count.2] using meaning

def tokensView (tokens : Slice (alloc.vec.Vec Std.U8)) : List Bytes := tokens.val.map vecBytes

@[step] theorem pointer_loop_exact (tokens : Slice (alloc.vec.Vec Std.U8)) :
    template_members.pointer_tokens_valid_loop tokens 0#usize 0#usize ⦃ actual =>
      actual = decide (PointerPayload (tokensView tokens) 0) ⦄ := by
  unfold template_members.pointer_tokens_valid_loop
  apply loop.spec_decr_nat
    (measure := fun state => tokens.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ tokens.val.length ∧ state.1.val ≤ 128 ∧
      (PointerPayload (tokensView tokens) 0 ↔ PointerPayload ((tokensView tokens).drop state.2.val) state.1.val))
  · rintro ⟨used, index⟩ invariant
    unfold template_members.pointer_tokens_valid_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < tokens.val.length := by scalar_tac
      step as ⟨token, tokenAt⟩
      have suffix : (tokensView tokens).drop index.val = vecBytes token :: (tokensView tokens).drop (index.val + 1) := by
        simpa [tokensView, List.drop_map, tokenAt] using congrArg (List.map vecBytes) (List.drop_eq_getElem_cons inside)
      step with OperationIdentity.Refinement.token_exact as ⟨allowed, allowedMeaning⟩
      cases allowed
      · have invalid : OperationIdentity.validToken (vecBytes token) 64 ≠ true := by
          simpa [alloc.vec.Vec.deref, sliceBytes] using allowedMeaning.symm
        have notAll : ¬PointerPayload (tokensView tokens) 0 := by
          rw [invariant.2.2, suffix, pointer_payload_cons]
          simp [invalid]
        simp [notAll]
      · have valid : OperationIdentity.validToken (vecBytes token) 64 = true := by
          simpa [alloc.vec.Vec.deref, sliceBytes] using allowedMeaning.symm
        have size : token.val.length ≤ 64 := by
          have length := Auths.Product.FieldProjection.token_length (vecBytes token) valid
          simpa [vecBytes, byteList] using length
        have sumFits : used.val + token.val.length + 1 ≤ 193 := by omega
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨withSeparator, withSeparatorValue⟩
        step as ⟨updated, updatedValue⟩
        have update : updated.val = used.val + (vecBytes token).length + 1 := by
          simp only [vecBytes, byteList, List.length_map]
          scalar_tac
        split <;> rename_i overflow
        · have tooLarge : 128 < used.val + (vecBytes token).length + 1 := by scalar_tac
          have notAll : ¬PointerPayload (tokensView tokens) 0 := by
            rw [invariant.2.2, suffix]
            exact pointer_payload_refuses_overflow _ _ _ tooLarge
          simp [notAll]
        · have updatedBound : updated.val ≤ 128 := by scalar_tac
          step as ⟨next, nextValue⟩
          refine ⟨by omega, updatedBound, ?_, by omega⟩
          simpa [suffix, pointer_payload_cons, valid, nextValue, update] using invariant.2.2
    · have endBound : (tokensView tokens).length ≤ index.val := by
        simpa [tokensView] using (show tokens.val.length ≤ index.val by scalar_tac)
      have valid : PointerPayload (tokensView tokens) 0 := by
        rw [invariant.2.2, List.drop_of_length_le endBound]
        exact ⟨by simp, by simpa [tokenCost] using invariant.2.1⟩
      simp [valid]
  · exact ⟨by simp, by simp, by simp⟩

@[step] theorem pointer_tokens_exact (tokens : Slice (alloc.vec.Vec Std.U8)) :
    template_members.pointer_tokens_valid tokens ⦃ actual => actual = decide (PointerDomain (tokensView tokens)) ⦄ := by
  unfold template_members.pointer_tokens_valid
  by_cases empty : tokens.val.length = 0
  · have values : tokens.val = [] := List.length_eq_zero_iff.mp empty
    simp [values, tokensView, PointerDomain]
  · simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.len_val, Slice.length, empty, decide_false, Bool.false_or]
    by_cases large : 6 < tokens.val.length
    · have nativeLarge : tokens.len > 6#usize := by scalar_tac
      simp [nativeLarge, PointerDomain, tokensView, Nat.not_le.mpr large]
    · have nativeBound : ¬tokens.len > 6#usize := by scalar_tac
      have count : 0 < (tokensView tokens).length ∧ (tokensView tokens).length ≤ 6 := by
        simp only [tokensView, List.length_map]
        omega
      simp only [nativeBound, ↓reduceIte]
      apply spec_mono (pointer_loop_exact tokens)
      intro actual meaning
      simpa [pointer_domain_iff, count.1, count.2] using meaning

end Auths.Product.TemplateMembers.Refinement
