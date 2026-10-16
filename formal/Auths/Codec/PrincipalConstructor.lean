import Auths.Codec.PrincipalScheme
import Auths.Codec.Constructors
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.PrincipalConstructor
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096
open Auths.Refinement.Identifier

/-- The two extraction contexts expose the same transparent byte classifier.
    This is a definitional bridge, not an assumed parser contract. -/
private theorem classifier_same (input : Slice Std.U8) (position : Std.Usize) :
    AuthsScopeCodec.auths_model.identifier.forbidden_identifier_at input position =
      auths_model.identifier.forbidden_identifier_at input position := by
  unfold AuthsScopeCodec.auths_model.identifier.forbidden_identifier_at
    auths_model.identifier.forbidden_identifier_at
    AuthsScopeCodec.auths_model.identifier.forbidden_three_byte_prefix
    auths_model.identifier.forbidden_three_byte_prefix
  rfl

private theorem scan_suffix (remaining : List Std.U8) (input : Slice Std.U8) (position : Std.Usize)
    (suffix : input.val.drop position.val = remaining) :
    AuthsScopeCodec.auths_model.identifier.contains_forbidden_identifier_loop input position ⦃ actual =>
      actual = containsExcluded remaining ⦄ := by
  induction remaining generalizing position with
  | nil =>
    have finished : ¬ position < input.len := by
      have size := congrArg List.length suffix
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [AuthsScopeCodec.auths_model.identifier.contains_forbidden_identifier_loop.eq_def]
    simp [finished, containsExcluded]
  | cons head rest ih =>
    obtain ⟨guard, _⟩ := Auths.StatusSelection.indexed_head input position head rest suffix
    obtain ⟨next, addition, nextValue, nextSuffix⟩ := Auths.StatusSelection.indexed_next input position head rest suffix
    obtain ⟨excluded, checks, meaning⟩ := spec_imp_exists (forbidden_at_exact input position)
    rw [AuthsScopeCodec.auths_model.identifier.contains_forbidden_identifier_loop.eq_def]
    simp only [guard, ↓reduceIte, classifier_same, checks, bind_tc_ok]
    have exactPrefix : excluded = excludedPrefix (head :: rest) := by simpa only [suffix] using meaning
    cases found : excluded
    · simp only [Bool.false_eq_true, ↓reduceIte, addition, bind_tc_ok]
      simpa only [containsExcluded, ← exactPrefix, found, Bool.false_or] using ih next nextSuffix
    · simp [containsExcluded, ← exactPrefix, found]

/-- Complete result of the actual shared identifier scanner in the principal
    extraction context, including empty, oversized and forbidden-byte cases. -/
theorem bounded_identifier_exact (value : Str) (maximum : Std.Usize) :
    AuthsScopeCodec.auths_model.identifier.bounded_identifier_valid value maximum ⦃ actual =>
      actual = (!value.val.isEmpty && decide (value.val.length ≤ maximum.val) &&
        !containsExcluded value.val) ⦄ := by
  unfold AuthsScopeCodec.auths_model.identifier.bounded_identifier_valid
  simp only [AuthsScopeCodec.core.str.Str.is_empty, AuthsScopeCodec.core.str.Str.len,
    AuthsScopeCodec.core.str.Str.as_bytes, _root_.core.str.Str.is_empty,
    _root_.core.str.Str.len, _root_.core.str.Str.as_bytes, bind_tc_ok]
  by_cases empty : value.val.isEmpty = true
  all_goals simp only [empty, Bool.false_eq_true, ↓reduceIte]
  · simp
  · by_cases fits : value.len ≤ maximum
    all_goals simp only [fits, ↓reduceIte]
    · unfold AuthsScopeCodec.auths_model.identifier.contains_forbidden_identifier
      apply spec_bind (scan_suffix value.val value 0#usize (by simp))
      intro result meaning
      simp [meaning, show value.val.length ≤ maximum.val by scalar_tac]
    · simp [show ¬value.val.length ≤ maximum.val by scalar_tac]

/-- The readable constructor policy combines UTF-8 length/scalar restrictions
    with the independent principal-scheme grammar. -/
def valid (value : String) : Bool :=
  Auths.Codec.Constructors.identifierDecision value 512 &&
    Auths.PrincipalScheme.Model.evaluate (value.toByteArray.toList.map UInt8.toNat)

private theorem identifier_string (value : String) (maximum : Std.Usize)
    (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsScopeCodec.auths_model.identifier.bounded_identifier_valid (toStr value bounded) maximum =
      ok (Auths.Codec.Constructors.identifierDecision value maximum.val) := by
  obtain ⟨result, evaluates, meaning⟩ := spec_imp_exists (bounded_identifier_exact (toStr value bounded) maximum)
  have root := Auths.Refinement.Identifier.identifier_exact (toStr value bounded) maximum
  have copied : auths_model.identifier.bounded_identifier_valid (toStr value bounded) maximum =
      ok (Auths.Codec.Constructors.identifierDecision value maximum.val) :=
    Auths.Codec.Constructors.identifier_exact value maximum bounded
  rw [copied, spec_ok] at root
  rw [meaning, ← root] at evaluates
  exact evaluates

/-- Full accepted value and exact typed refusal for the shipping principal
    constructor on every actual Rust string carrier. No success premise. -/
theorem parse_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsScopeCodec.auths_model.PrincipalId.parse (toStr value bounded) =
      ok (if valid value then .Ok value else .Err AuthsScopeCodec.auths_model.ModelError.InvalidPrincipal) := by
  unfold AuthsScopeCodec.auths_model.PrincipalId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  obtain ⟨scheme, schemeEvaluates, schemeMeaning⟩ := spec_imp_exists
    (Auths.PrincipalScheme.scheme_refines (toStr value bounded))
  have representation : (toStr value bounded).val.map (·.val) =
      value.toByteArray.toList.map UInt8.toNat := by
    unfold toStr
    simp only [List.map_map]
    rfl
  rw [representation] at schemeMeaning
  rw [schemeMeaning] at schemeEvaluates
  split <;> simp_all [valid, bind_tc_ok,
    Auths.Codec.StringRefinement.string_copy_exact]
  all_goals split <;> rfl

end Auths.PrincipalConstructor
