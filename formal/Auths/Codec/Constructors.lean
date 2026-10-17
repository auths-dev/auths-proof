import Auths.Codec.Evaluation
import Auths.Codec.String
import Auths.Refinement.Identifier
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
set_option maxHeartbeats 2000000
set_option maxRecDepth 2048
namespace Auths.Codec.Constructors

def identifierDecision (value : String) (maximum : Nat) : Bool :=
  !value.toByteArray.toList.isEmpty && decide (value.toByteArray.size ≤ maximum) &&
    !((value.toList.map Char.toNat).any
      (fun scalar => decide (Auths.Model.Identifier.excluded scalar)))

theorem identifier_exact (value : String) (maximum : Std.Usize)
    (bounded : value.toByteArray.size ≤ U32.max) :
    auths_codec.auths_model.identifier.bounded_identifier_valid (toStr value bounded) maximum =
      ok (identifierDecision value maximum.val) := by
  have contract := Auths.Refinement.Identifier.identifier_string_exact value maximum bounded
  change auths_codec.auths_model.identifier.bounded_identifier_valid (toStr value bounded) maximum
    ⦃ result => result = _ ⦄ at contract
  rw [spec_equiv_exists] at contract
  obtain ⟨result, evaluates, meaning⟩ := contract
  rw [meaning] at evaluates
  convert evaluates using 1
  simp [identifierDecision, toStr, Auths.Model.Identifier.byte_array_list]
  rfl


/-- The independent identifier contract uses UTF-8 byte length and scalar policy. -/
def IdentifierValid (value : String) (maximum : Nat) : Prop :=
  value.toByteArray.size ≠ 0 ∧ value.toByteArray.size ≤ maximum ∧
    ∀ character ∈ value.toList, ¬ Auths.Model.Identifier.excluded character.toNat

theorem identifier_decision_valid (value : String) (maximum : Nat) :
    identifierDecision value maximum = true ↔ IdentifierValid value maximum := by
  have empty : value.toByteArray.toList = [] ↔ value = "" := by
    rw [List.eq_nil_iff_length_eq_zero]
    simp [Auths.Model.Identifier.byte_array_list]
  simp only [identifierDecision, Bool.and_eq_true, Bool.not_eq_true',
    List.isEmpty_eq_false_iff,
    List.any_eq_false, List.mem_map, decide_eq_true_eq]
  simp [IdentifierValid, empty]


-- Exact checked constructors on their intended validated string carrier.
theorem media_type_parse_exact (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    auths_codec.auths_model.MediaType.parse (toStr value bounded) =
      ok (if identifierDecision value 128 then .Ok value
        else .Err auths_codec.auths_model.ModelError.InvalidMediaType) := by
  unfold auths_codec.auths_model.MediaType.parse
  rw [identifier_exact]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]
-- Exact checked constructors on their intended validated string carrier.
theorem profile_id_parse_exact (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    auths_codec.auths_model.ProfileId.parse (toStr value bounded) =
      ok (if identifierDecision value 128 then .Ok value
        else .Err auths_codec.auths_model.ModelError.InvalidProfile) := by
  unfold auths_codec.auths_model.ProfileId.parse
  rw [identifier_exact]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]
-- Exact checked constructors on their intended validated string carrier.
theorem capability_id_parse_exact (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    auths_codec.auths_model.CapabilityId.parse (toStr value bounded) =
      ok (if identifierDecision value 128 then .Ok value
        else .Err auths_codec.auths_model.ModelError.InvalidCapability) := by
  unfold auths_codec.auths_model.CapabilityId.parse
  rw [identifier_exact]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]
-- Exact checked constructors on their intended validated string carrier.
theorem resource_id_parse_exact (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    auths_codec.auths_model.ResourceId.parse (toStr value bounded) =
      ok (if identifierDecision value 1024 then .Ok value
        else .Err auths_codec.auths_model.ModelError.InvalidResource) := by
  unfold auths_codec.auths_model.ResourceId.parse
  rw [identifier_exact]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]
-- Exact checked constructors on their intended validated string carrier.
theorem budget_algebra_id_parse_exact (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    auths_codec.auths_model.BudgetAlgebraId.parse (toStr value bounded) =
      ok (if identifierDecision value 128 then .Ok value
        else .Err auths_codec.auths_model.ModelError.InvalidRegistryId) := by
  unfold auths_codec.auths_model.BudgetAlgebraId.parse
  rw [identifier_exact]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

/-- The constructor checks the nonempty body and the protocol byte ceiling;
other fields are preserved and retain their incoming constructor premises. -/
theorem canonical_action_new_exact
    (profile : auths_codec.auths_model.ProfileRef)
    (mediaType : auths_codec.auths_model.MediaType)
    (body : alloc.vec.Vec Std.U8)
    (permission : auths_codec.auths_model.Permission)
    (budget : Option auths_codec.auths_model.BudgetCeiling) :
    auths_codec.auths_model.CanonicalAction.new profile mediaType body permission budget =
      ok (if 0 < body.val.length ∧ body.val.length ≤ 8388608 then
        .Ok ⟨profile, mediaType, body, permission, budget, alloc.vec.Vec.new _⟩
      else .Err auths_codec.auths_model.ModelError.InvalidCanonicalAction) := by
  unfold auths_codec.auths_model.CanonicalAction.new
  simp only [alloc.vec.Vec.is_empty, bind_tc_ok]
  rw [Evaluation.hard_canonical_body_bytes]
  simp only [bind_tc_ok, UScalar.lt_equiv, alloc.vec.Vec.len_val,
    UScalar.ofNatCore_val_eq]
  by_cases empty : body.val = []
  · simp [empty]
  · have positive : 0 < body.val.length := List.length_pos_iff.mpr empty
    simp [empty, positive]
    split <;> rename_i bound <;> simp_all


end Auths.Codec.Constructors
