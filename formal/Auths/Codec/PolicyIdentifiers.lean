import Auths.Codec.PolicyValidity
import Auths.Codec.ProtocolIdentifiers
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyIdentifiers
open Auths.Codec.Refinement

/- Actual allocation-free indexed source scan. Per-step lookup/increment is
earned from the remaining suffix, including early invalid-byte refusal; the
parser does not assume a successful scan or a caller-provided alphabet flag. -/
@[step] theorem byte_exact (value : Std.U8) :
    auths_model.bounded_policy.policy_identifier_byte_allowed value ⦃ actual =>
      actual = decide (PolicyValidity.allowed value.val) ⦄ := by
  simp [auths_model.bounded_policy.policy_identifier_byte_allowed,
    PolicyValidity.allowed, UScalar.le_equiv, UScalar.lt_equiv, spec_ok,
    Bool.and_eq_true, Bool.or_eq_true]

private theorem scan_suffix (rest : List Std.U8) (bytes : Slice Std.U8) (position : Std.Usize)
    (remaining : bytes.val.drop position.val = rest) :
    auths_model.bounded_policy.policy_identifier_has_invalid_loop bytes position ⦃ actual =>
      actual = PolicyValidity.invalid (byteList rest) ⦄ := by
  induction rest generalizing position with
  | nil =>
    have finished : ¬ position < bytes.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [auths_model.bounded_policy.policy_identifier_has_invalid_loop.eq_def]
    simp [finished, PolicyValidity.invalid, byteList, spec_ok]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head bytes position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next bytes position first tail remaining
    rw [auths_model.bounded_policy.policy_identifier_has_invalid_loop.eq_def]
    simp only [guard, ↓reduceIte, atFirst, bind_tc_ok]
    step with byte_exact first as ⟨accepted, meaning⟩
    by_cases valid : PolicyValidity.allowed first.val
    · simp only [meaning, valid, decide_true, Bool.not_true, Bool.false_eq_true, ↓reduceIte, increment, bind_tc_ok]
      simpa only [byteList, List.map_cons, PolicyValidity.invalid, valid, decide_true,
        Bool.not_true, Bool.false_or] using ih next nextRemaining
    · simp [meaning, valid, PolicyValidity.invalid, byteList, spec_ok]

@[step] theorem scan_exact (bytes : Slice Std.U8) :
    auths_model.bounded_policy.policy_identifier_has_invalid bytes ⦃ actual =>
      actual = PolicyValidity.invalid (byteList bytes.val) ⦄ := by
  unfold auths_model.bounded_policy.policy_identifier_has_invalid
  simpa only [bind_tc_ok] using scan_suffix bytes.val bytes 0#usize (by simp)

@[step] theorem valid_exact (value : Str) (maximum : Std.Usize) :
    auths_model.bounded_policy.policy_identifier_valid value maximum ⦃ actual =>
      actual = (!value.val.isEmpty && decide (value.val.length ≤ maximum.val) &&
        !PolicyValidity.invalid (byteList value.val)) ⦄ := by
  unfold auths_model.bounded_policy.policy_identifier_valid
  simp only [core.str.Str.as_bytes, Slice.is_empty, Slice.len_val, Slice.length,
    UScalar.le_equiv, bind_tc_ok]
  split
  · split
    · step with scan_exact ⟨value.val, by scalar_tac⟩ as ⟨invalid, meaning⟩
      simp_all [spec_ok]
    · simp_all [spec_ok]
  · simp_all [spec_ok]

theorem valid_string (value : String) (maximum : Std.Usize) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_model.bounded_policy.policy_identifier_valid (toStr value bounded) maximum =
      ok (PolicyValidity.accepts value maximum.val) := by
  obtain ⟨result, run, meaning⟩ := spec_imp_exists (valid_exact (toStr value bounded) maximum)
  have representation : byteList (toStr value bounded).val = Auths.Crypto.UnsignedObjects.utf8 value := by
    unfold toStr
    simp only [byteList, List.map_map]
    rfl
  have length : (toStr value bounded).val.length = value.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  have empty : (toStr value bounded).val.isEmpty =
      (Auths.Crypto.UnsignedObjects.utf8 value).isEmpty := by
    rw [← representation]
    simp only [byteList, List.isEmpty_map]
  rw [meaning] at run
  simpa only [representation, length, empty, PolicyValidity.accepts] using run

theorem parse_exact (value : String) (maximum : Std.Usize) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_model.bounded_policy.PolicyIdentifier.parse (toStr value bounded) maximum =
      ok (if PolicyValidity.accepts value maximum.val then .Ok value else .Err .InvalidBoundedPolicy) := by
  unfold auths_model.bounded_policy.PolicyIdentifier.parse
  rw [valid_string value maximum bounded]
  simp only [bind_tc_ok]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem parse_valid (value output : String) (maximum : Std.Usize)
    (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : auths_model.bounded_policy.PolicyIdentifier.parse (toStr value bounded) maximum = ok (.Ok output)) :
    PolicyValidity.Identifier output maximum.val := by
  rw [parse_exact value maximum bounded] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (PolicyValidity.accepts_iff value maximum.val).mp condition
  · simp at accepted

end Auths.Codec.PolicyIdentifiers
