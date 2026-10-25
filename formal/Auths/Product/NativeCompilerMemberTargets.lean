import Auths.Product.NativeCompilerMemberNames

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeTokens (tokens : Slice (NativeVec Std.U8)) : List (List Nat) := tokens.val.map bytes

def nativeMemberResult {T V : Type} (view : T → V) :
    core.result.Result T NativeMemberError → Except TemplateMembers.Error V
  | .Ok output => .ok (view output)
  | .Err error => .error (nativeMemberErrorMeaning error)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateMembers
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_pointer_payload_suffix (tokens : Slice (NativeVec Std.U8))
    (used position : Std.Usize) (usedBound : used.val ≤ 128)
    (positionBound : position.val ≤ tokens.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.pointer_tokens_valid_loop tokens used position
      ⦃ actual => actual = decide (PointerPayload ((nativeTokens tokens).drop position.val) used.val) ⦄ := by
  generalize remaining : tokens.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing used position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.pointer_tokens_valid_loop
        AuthsNativeRecipe.auths_gateway_kernel.template_members.MAX_ECHO_POINTER_BYTES
      by_cases inside : position.val < tokens.val.length
      · have nativeInside : position < tokens.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec tokens position inside as ⟨token, tokenAt⟩
        have suffix : (nativeTokens tokens).drop position.val = bytes token ::
            (nativeTokens tokens).drop (position.val + 1) := by
          simpa only [nativeTokens, List.drop_map, List.map_cons, tokenAt] using
            congrArg (List.map bytes) (List.drop_eq_getElem_cons inside)
        step with native_schema_token_exact (AuthsNativeRecipe.alloc.vec.Vec.deref token) 64#usize
          as ⟨lexical, lexicalMeaning⟩
        have tokenMeaning : lexical = OperationIdentity.validToken (bytes token) 64 := by
          simpa only [schemaSliceBytes, bytes, native_deref_contents] using lexicalMeaning
        cases lexical with
        | false => simp [suffix, pointer_payload_cons, ← tokenMeaning]
        | true =>
            have lexical : OperationIdentity.validToken (bytes token) 64 = true := tokenMeaning.symm
            have tokenBound : token.val.length ≤ 64 := by
              simpa only [bytes, List.length_map] using (token_shape_bounds _ lexical).2.1
            simp only [Bool.true_eq_true, ↓reduceIte]
            step as ⟨contribution, contributionMeaning⟩
            step as ⟨nextUsed, nextUsedMeaning⟩
            have fullCharge : nextUsed.val = used.val + (bytes token).length + 1 := by
              simp only [bytes, List.length_map]
              omega
            by_cases excess : 128 < nextUsed.val
            · have nativeExcess : nextUsed > 128#usize := by scalar_tac
              have invalid : ¬PointerPayload ((nativeTokens tokens).drop position.val) used.val := by
                rw [suffix]
                apply pointer_payload_refuses_overflow
                omega
              simp [nativeExcess, invalid]
            · have nextBound : nextUsed.val ≤ 128 := by omega
              have nativeFits : ¬nextUsed > 128#usize := by scalar_tac
              simp only [nativeFits, ↓reduceIte]
              step as ⟨nextPosition, nextPositionMeaning⟩
              apply spec_mono (ih _ (by omega) nextUsed nextPosition nextBound (by omega) rfl)
              intro actual exact
              simpa [suffix, pointer_payload_cons, lexical, fullCharge, nextPositionMeaning] using exact
      · have ended : tokens.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < tokens.len := by scalar_tac
        have modelEnded : (nativeTokens tokens).length ≤ position.val := by
          simpa only [nativeTokens, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, PointerPayload, tokenCost, usedBound]

@[step] theorem native_pointer_tokens_valid_exact (tokens : Slice (NativeVec Std.U8)) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.pointer_tokens_valid tokens ⦃ actual =>
      actual = decide (PointerDomain (nativeTokens tokens)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.pointer_tokens_valid
    AuthsNativeRecipe.auths_gateway_kernel.template_members.MAX_ECHO_POINTER_TOKENS
  by_cases empty : tokens.val = []
  · simp [core.slice.Slice.is_empty, empty, PointerDomain, nativeTokens]
  · have positive : 0 < tokens.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 6 < tokens.val.length
    · have nativeLarge : tokens.len > 6#usize := by scalar_tac
      simp [nativeLarge, PointerDomain, nativeTokens, Nat.not_le.mpr large]
    · have bounded : tokens.val.length ≤ 6 := by omega
      have nativeBound : ¬tokens.len > 6#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      apply spec_mono (native_pointer_payload_suffix tokens 0#usize 0#usize (by simp) (by simp))
      intro actual exact
      simpa [pointer_domain_iff, nativeTokens, positive, bounded] using exact

@[step] theorem native_json_echo_target_exact (keys : Slice NativeKey) (tokens : Slice (NativeVec Std.U8)) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.json_echo_target keys tokens ⦃ actual =>
      nativeMemberResult nativeTarget actual = jsonEchoTarget (nativeKeyColumn keys) (nativeTokens tokens) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.json_echo_target
  step with native_keys_ordered_exact keys .Json as ⟨ordered, orderedMeaning⟩
  cases ordered with
  | false => simp [jsonEchoTarget, ← orderedMeaning, nativeMemberDomain,
      nativeMemberResult, nativeMemberErrorMeaning]
  | true =>
      have column : KeyColumn (nativeKeyColumn keys) .json := by
        simpa [nativeMemberDomain] using orderedMeaning.symm
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_pointer_tokens_valid_exact tokens as ⟨valid, validMeaning⟩
      cases valid with
      | false => simp [jsonEchoTarget, column, ← validMeaning, nativeMemberResult, nativeMemberErrorMeaning]
      | true =>
          have pointer : PointerDomain (nativeTokens tokens) := by simpa using validMeaning.symm
          have positive : 0 < tokens.val.length := by
            have count := pointer.1
            simpa only [nativeTokens, List.length_map] using count
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with Slice.index_usize_spec tokens 0#usize positive as ⟨head, headAt⟩
          have originalHead : (nativeTokens tokens).headD [] = bytes head := by
            cases original : tokens.val with
            | nil => simp only [original, List.length_nil] at positive; omega
            | cons first rest =>
                have same : head = first := by simpa only [original] using headAt
                simp [nativeTokens, original, same]
          step with native_key_position_exact keys (AuthsNativeRecipe.alloc.vec.Vec.deref head)
            as ⟨found, foundMeaning⟩
          have lookup : found.map UScalar.val = keyPosition (bytes head) (nativeKeyColumn keys) := by
            simpa only [schemaSliceBytes, bytes, native_deref_contents] using foundMeaning
          by_cases last : tokens.val.length = 1
          · have nativeLast : tokens.len = 1#usize := by scalar_tac
            simp only [nativeLast, ↓reduceIte]
            cases found with
            | some index =>
                simp [core.option.Option.is_some, jsonEchoTarget, column, pointer,
                  nativeTokens, last, originalHead, ← lookup, nativeMemberResult, nativeMemberErrorMeaning]
            | none =>
                simp only [core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
                by_cases full : 32 ≤ keys.val.length
                · have nativeFull : keys.len >= 32#usize := by scalar_tac
                  simp [nativeFull, jsonEchoTarget, column, pointer, nativeTokens,
                    nativeKeyColumn, last, full, originalHead, ← lookup,
                    nativeMemberResult, nativeMemberErrorMeaning]
                · have nativeRoom : ¬keys.len >= 32#usize := by scalar_tac
                  simp [nativeRoom, jsonEchoTarget, column, pointer, nativeTokens,
                    nativeKeyColumn, last, full, originalHead, ← lookup,
                    nativeMemberResult, nativeTarget]
          · have nativeLast : tokens.len ≠ 1#usize := by scalar_tac
            simp only [nativeLast, ↓reduceIte]
            cases found <;>
              simp [jsonEchoTarget, column, pointer, nativeTokens, last, originalHead,
                ← lookup, nativeMemberResult, nativeMemberErrorMeaning, nativeTarget]

theorem native_json_target_retains_original_name (keys : Slice NativeKey) (tokens : Slice (NativeVec Std.U8)) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.json_echo_target keys tokens ⦃ actual =>
      ∀ selected, actual = .Ok (.Descend selected) →
        (nativeKeyColumn keys)[selected.val]? = some ((nativeTokens tokens).headD []) ⦄ := by
  apply spec_mono (native_json_echo_target_exact keys tokens)
  intro actual exact selected accepted
  rw [accepted] at exact
  exact target_descends_to_original_name _ _ _ (by
    simpa only [nativeMemberResult, nativeTarget] using exact.symm)

end Auths.Product.NativeCompiler.Refinement
