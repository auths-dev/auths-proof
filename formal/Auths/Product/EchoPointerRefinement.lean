import Auths.Product.EchoPointer
import Auths.Product.TemplateTargetRefinement

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.TemplateMembers
open Auths.Product.TemplateMembers.Refinement

namespace Auths.Product.EchoPointer.Refinement
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

/-! Authored source bodies target the new shipping byte decoder. Its actual
loop/tuple/borrow interfaces must be generated, inspected and reconciled before
elaboration/qualification. No fresh generated ABI or passing evidence is
asserted here. -/

def tokenVectors (tokens : alloc.vec.Vec (alloc.vec.Vec Std.U8)) : List Bytes := tokens.val.map vecBytes

@[step] theorem finish_echo_token_exact (prefix : alloc.vec.Vec (alloc.vec.Vec Std.U8)) (token : alloc.vec.Vec Std.U8) :
    template_members.finish_echo_token prefix token ⦃ actual =>
      memberResult tokenVectors actual = finish (tokenVectors prefix) (vecBytes token) ⦄ := by
  unfold template_members.finish_echo_token template_members.MAX_ECHO_POINTER_TOKENS
  by_cases full : 6 ≤ prefix.val.length
  · have nativeFull : prefix.len >= 6#usize := by scalar_tac
    simp [nativeFull, finish, tokenVectors, Nat.not_lt.mpr full, memberResult, memberErrorOf]
  · have room : prefix.val.length < 6 := by omega
    have nativeRoom : ¬prefix.len >= 6#usize := by scalar_tac
    simp only [nativeRoom, Bool.false_or]
    step with OperationIdentity.Refinement.token_exact as ⟨valid, validMeaning⟩
    cases valid
    · have refused : OperationIdentity.validToken (vecBytes token) 64 ≠ true := by
        simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using validMeaning.symm
      simp [refused, finish, tokenVectors, memberResult, memberErrorOf]
    · have admitted : OperationIdentity.validToken (vecBytes token) 64 = true := by
        simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using validMeaning.symm
      have fits : prefix.val.length < Usize.max := lt_usize_max (by omega)
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      step as ⟨output, outputValue⟩
      simp [memberResult, tokenVectors, outputValue, List.map_append, finish, admitted, room]

@[step] theorem echo_pointer_tokens_exact (pointer : Slice Std.U8) :
    template_members.echo_pointer_tokens pointer ⦃ actual =>
      memberResult tokenVectors actual = decode (sliceBytes pointer) ⦄ := by
  unfold template_members.echo_pointer_tokens template_members.MAX_ECHO_POINTER_BYTES
  by_cases empty : pointer.val = []
  · simp [empty, core.slice.Slice.is_empty, decode, sliceBytes, byteList, memberResult, memberErrorOf]
  · by_cases large : 128 < pointer.val.length
    · have nativeLarge : pointer.len > 128#usize := by scalar_tac
      have rejected : decode (sliceBytes pointer) = .error .echoConflict := by
        cases raw : pointer.val with
        | nil => simp [raw, sliceBytes, byteList, decode]
        | cons first rest =>
          by_cases slash : first.val = 47 <;> simp [sliceBytes, byteList, raw, decode, slash, large]
      simp [nativeLarge, empty, core.slice.Slice.is_empty, rejected, memberResult, memberErrorOf]
    · have bounded : pointer.val.length ≤ 128 := by omega
      have nativeBound : ¬pointer.len > 128#usize := by scalar_tac
      have insideHead : 0 < pointer.val.length := List.length_pos.mpr empty
      obtain ⟨firstByte, rest, raw⟩ := List.exists_cons_of_ne_nil empty
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false, nativeBound,
        Bool.false_or, Bool.false_eq_true, ↓reduceIte]
      step as ⟨first, firstAt⟩
      have headSame : first = firstByte := by simpa [raw] using firstAt
      by_cases slash : first = 47#u8
      · have firstValue : firstByte.val = 47 := by simpa [headSame] using congrArg UScalar.val slash
        have leading : sliceBytes pointer = 47 :: byteList rest := by simp [sliceBytes, byteList, raw, firstValue]
        have sourceMeaning : decode (sliceBytes pointer) = scan [] [] (byteList rest) := by
          simp [leading, decode, show (47 :: byteList rest).length ≤ 128 by simpa [leading, sliceBytes, byteList] using bounded]
        simp only [slash, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
        unfold template_members.echo_pointer_tokens_loop
        apply loop.spec_decr_nat
          (measure := fun state => pointer.val.length - state.2.2.val)
          (inv := fun state => 1 ≤ state.2.2.val ∧ state.2.2.val ≤ pointer.val.length ∧
            state.2.1.val.length ≤ 64 ∧ state.1.val.length ≤ 6 ∧
            decode (sliceBytes pointer) = scan (tokenVectors state.1) (vecBytes state.2.1)
              (byteList (pointer.val.drop state.2.2.val)) ∧
            encode (tokenVectors state.1) ++ [47] ++ vecBytes state.2.1 =
              byteList (pointer.val.take state.2.2.val))
        · rintro ⟨prefix, token, position⟩ ⟨positive, positionBound, tokenBound, countBound, semantic, frame⟩
          unfold template_members.echo_pointer_tokens_loop.body
          dsimp only
          split <;> rename_i finished
          · have atEnd : position.val = pointer.val.length := by scalar_tac
            have remaining : byteList (pointer.val.drop position.val) = [] := by simp [atEnd]
            rw [remaining, scan] at semantic
            step with finish_echo_token_exact as ⟨actual, meaning⟩
            simpa [meaning] using semantic.symm
          · have inside : position.val < pointer.val.length := by scalar_tac
            step as ⟨byte, byteAt⟩
            have remaining : byteList (pointer.val.drop position.val) =
                byte.val :: byteList (pointer.val.drop (position.val + 1)) := by
              rw [List.drop_eq_getElem_cons inside]
              simpa [byteList, byteAt]
            have copiedPrefix : byteList (pointer.val.take (position.val + 1)) =
                byteList (pointer.val.take position.val) ++ [byte.val] := by
              rw [List.take_succ_eq_append_getElem inside]
              simp [byteList, List.map_append, byteAt]
            by_cases delimiter : byte = 47#u8
            · have delimiterValue : byte.val = 47 := by simpa using congrArg UScalar.val delimiter
              simp only [delimiter, ↓reduceIte]
              step with finish_echo_token_exact as ⟨committed, committedMeaning⟩
              cases committed with
              | Err error =>
                simpa [memberResult, remaining, scan, delimiterValue, committedMeaning] using semantic.symm
              | Ok committed =>
                have committedRun : finish (tokenVectors prefix) (vecBytes token) = .ok (tokenVectors committed) := by
                  simpa [memberResult] using committedMeaning.symm
                have committedFrame := finish_success _ _ _ committedRun
                have nextCount : committed.val.length ≤ 6 := by
                  have size := congrArg List.length committedFrame.1
                  simp only [tokenVectors, List.length_map, List.length_append, List.length_singleton] at size
                  have before := committedFrame.2.1
                  simp only [tokenVectors, List.length_map] at before
                  omega
                step as ⟨nextPosition, nextPositionValue⟩
                refine ⟨by omega, by omega, by simp, nextCount, ?_, ?_, by omega⟩
                · simpa [remaining, scan, delimiterValue, committedRun, nextPositionValue, vecBytes, byteList] using semantic
                · simpa [committedFrame.1, encode_append, encode, vecBytes, byteList,
                    nextPositionValue, copiedPrefix, delimiterValue, List.append_assoc] using congrArg (· ++ [47]) frame
            · have different : byte.val ≠ 47 := by
                intro same
                apply delimiter
                exact UScalar.eq_of_val_eq same
              simp only [delimiter, Bool.false_eq_true, ↓reduceIte]
              by_cases full : 64 ≤ token.val.length
              · have nativeFull : token.len >= 64#usize := by scalar_tac
                have noRoom : ¬(vecBytes token).length < 64 := by simpa [vecBytes, byteList] using Nat.not_lt.mpr full
                simpa [nativeFull, memberResult, memberErrorOf, remaining, scan, different, noRoom] using semantic.symm
              · have room : token.val.length < 64 := by omega
                have nativeRoom : ¬token.len >= 64#usize := by scalar_tac
                have fits : token.val.length < Usize.max := lt_usize_max (by omega)
                simp only [nativeRoom, Bool.false_eq_true, ↓reduceIte]
                step as ⟨nextToken, nextTokenValue⟩
                step as ⟨nextPosition, nextPositionValue⟩
                refine ⟨by omega, by omega, ?_, countBound, ?_, ?_, by omega⟩
                · simp only [nextTokenValue, List.length_append, List.length_singleton]
                  omega
                · simpa [remaining, scan, different, show (vecBytes token).length < 64 by simpa [vecBytes, byteList] using room,
                    nextTokenValue, nextPositionValue, vecBytes, byteList, List.map_append] using semantic
                · simpa [nextTokenValue, nextPositionValue, copiedPrefix, vecBytes, byteList,
                    List.map_append, List.append_assoc] using congrArg (· ++ [byte.val]) frame
        · refine ⟨by simp, by simpa [raw] using insideHead, by simp, by simp, ?_, ?_⟩
          · simpa [raw, tokenVectors, vecBytes, byteList] using sourceMeaning
          · simp [raw, firstValue, tokenVectors, vecBytes, byteList, encode]
      · have firstDifferent : firstByte.val ≠ 47 := by
          intro same
          apply slash
          exact UScalar.eq_of_val_eq (by simpa [headSame] using same)
        simp [slash, decode, sliceBytes, byteList, raw, firstDifferent, memberResult, memberErrorOf]

theorem source_pointer_retains_exact_original_names (pointer : Slice Std.U8) :
    template_members.echo_pointer_tokens pointer ⦃ actual =>
      match actual with
      | .Err error => error = .EchoConflict ∧ ¬∃ tokens, Meaning (sliceBytes pointer) tokens
      | .Ok tokens => Meaning (sliceBytes pointer) (tokenVectors tokens) ⦄ := by
  apply spec_mono (echo_pointer_tokens_exact pointer)
  intro actual exact
  cases actual with
  | Err error =>
    have rejected : decode (sliceBytes pointer) = .error (memberErrorOf error) := by simpa [memberResult] using exact.symm
    have errorKind := decode_error_class _ _ rejected
    have nativeKind : error = .EchoConflict := by cases error <;> simp_all [memberErrorOf]
    refine ⟨nativeKind, (refusal_exact _).mp ?_⟩
    simpa [nativeKind, memberErrorOf] using rejected
  | Ok tokens =>
    apply (decode_exact _ _).mp
    simpa [memberResult] using exact.symm

theorem source_valid_pointer_has_useful_acceptance (pointer : Slice Std.U8) (tokens : List Bytes)
    (meaning : Meaning (sliceBytes pointer) tokens) :
    template_members.echo_pointer_tokens pointer ⦃ actual => ∃ output,
      actual = .Ok output ∧ tokenVectors output = tokens ∧ PointerDomain (tokenVectors output) ⦄ := by
  apply spec_mono (echo_pointer_tokens_exact pointer)
  intro actual exact
  have accepted := decode_complete _ _ meaning
  rw [accepted] at exact
  cases actual with
  | Err error => simp [memberResult] at exact
  | Ok output =>
    have same : tokenVectors output = tokens := by simpa [memberResult] using exact
    exact ⟨output, rfl, same, by simpa [same] using meaning.2⟩

end Auths.Product.EchoPointer.Refinement
