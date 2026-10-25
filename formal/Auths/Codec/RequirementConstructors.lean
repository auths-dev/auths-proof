import Auths.Codec.RequirementEquality
import Auths.Codec.ProtocolOrdering

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.RequirementConstructors
set_option maxHeartbeats 2000000

/-- Independent order-preserving constructor semantics. The original count
is checked before duplicate refusal, including when duplicates are separated. -/
def preserved {T Key : Type} [DecidableEq Key] (maximum : Nat)
    (invalid oversized : auths_model.ModelError) (view : T → Key) (input : alloc.vec.Vec T) :
    core.result.Result (alloc.vec.Vec T) auths_model.ModelError :=
  if input.val = [] then .Err invalid
  else if maximum < input.val.length then .Err oversized
  else if (input.val.map view).Nodup then .Ok input else .Err invalid

theorem preserved_success {T Key : Type} [DecidableEq Key] (maximum : Nat)
    (invalid oversized : auths_model.ModelError) (view : T → Key) (input output : alloc.vec.Vec T) :
    preserved maximum invalid oversized view input = .Ok output ↔
      input.val ≠ [] ∧ input.val.length ≤ maximum ∧ (input.val.map view).Nodup ∧ output = input := by
  unfold preserved
  split_ifs <;> simp_all [eq_comm]

private theorem duplicate_branch {T Key : Type} [DecidableEq Key]
    (values : List Key) (value : T) (error : auths_model.ModelError) :
    (if SnapshotUniqueness.hasDuplicate values then .Err error else .Ok value) =
      (if values.Nodup then .Ok value else .Err error : core.result.Result T auths_model.ModelError) := by
  have meaning := SnapshotUniqueness.no_duplicate_iff values
  cases duplicate : SnapshotUniqueness.hasDuplicate values <;> simp_all

theorem members_exact (input : alloc.vec.Vec auths_model.observation.FactValue) :
    auths_model.observation.MemberValues.new input =
      ok (preserved 16 .InvalidObservationRequirement .InvalidObservationRequirement RequirementKeys.fact input) := by
  unfold auths_model.observation.MemberValues.new
  simp only [alloc.vec.Vec.is_empty, bind_tc_ok, AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv,
    core.ops.deref.DerefVec, bind_tc_ok]
  rw [RequirementEquality.literal_scan]
  simp [preserved, duplicate_branch, auths_model.observation.MAX_MEMBER_VALUES,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref]

theorem approvals_exact (input : alloc.vec.Vec auths_model.approval.ApprovalRequirement) :
    auths_model.approval.ApprovalRequirements.new input =
      ok (preserved 4 .InvalidApprovalRequirement .CollectionLimitExceeded RequirementKeys.approval input) := by
  unfold auths_model.approval.ApprovalRequirements.new
  simp only [alloc.vec.Vec.is_empty, bind_tc_ok, AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv,
    core.ops.deref.DerefVec, bind_tc_ok]
  rw [RequirementEquality.approval_scan]
  simp [preserved, duplicate_branch, auths_model.approval.MAX_APPROVAL_REQUIREMENTS_PER_GRANT,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref]

theorem observations_exact (input : alloc.vec.Vec auths_model.observation.ObservationRequirement) :
    auths_model.observation.ObservationRequirements.new input =
      ok (preserved 8 .InvalidObservationRequirement .CollectionLimitExceeded RequirementKeys.observation input) := by
  unfold auths_model.observation.ObservationRequirements.new
  simp only [alloc.vec.Vec.is_empty, bind_tc_ok, AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv,
    core.ops.deref.DerefVec, bind_tc_ok]
  rw [RequirementEquality.observation_scan]
  simp [preserved, duplicate_branch, auths_model.observation.MAX_OBSERVATION_REQUIREMENTS_PER_GRANT,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref]

theorem members_accepts (input output : alloc.vec.Vec auths_model.observation.FactValue) :
    auths_model.observation.MemberValues.new input = ok (.Ok output) ↔
      input.val ≠ [] ∧ input.val.length ≤ 16 ∧ (input.val.map RequirementKeys.fact).Nodup ∧ output = input := by
  rw [members_exact]
  simp only [Result.ok.injEq, preserved_success]

theorem approvals_accepts (input output : alloc.vec.Vec auths_model.approval.ApprovalRequirement) :
    auths_model.approval.ApprovalRequirements.new input = ok (.Ok output) ↔
      input.val ≠ [] ∧ input.val.length ≤ 4 ∧ (input.val.map RequirementKeys.approval).Nodup ∧ output = input := by
  rw [approvals_exact]
  simp only [Result.ok.injEq, preserved_success]

theorem observations_accepts (input output : alloc.vec.Vec auths_model.observation.ObservationRequirement) :
    auths_model.observation.ObservationRequirements.new input = ok (.Ok output) ↔
      input.val ≠ [] ∧ input.val.length ≤ 8 ∧ (input.val.map RequirementKeys.observation).Nodup ∧ output = input := by
  rw [observations_exact]
  simp only [Result.ok.injEq, preserved_success]

theorem members_valid (input : alloc.vec.Vec auths_model.observation.FactValue)
    (output : auths_model.observation.MemberValues)
    (fields : ∀ value ∈ input.val, ProtocolValidity.FactValue value)
    (accepted : auths_model.observation.MemberValues.new input = ok (.Ok output)) :
    ProtocolValidity.MemberValues output := by
  obtain ⟨nonempty, bounded, unique, rfl⟩ := (members_accepts input output).mp accepted
  exact ⟨nonempty, bounded, unique.of_map, fields⟩

theorem approvals_valid (input : alloc.vec.Vec auths_model.approval.ApprovalRequirement)
    (output : auths_model.approval.ApprovalRequirements)
    (fields : ∀ value ∈ input.val, ProtocolValidity.ApprovalRequirement value)
    (accepted : auths_model.approval.ApprovalRequirements.new input = ok (.Ok output)) :
    ProtocolValidity.ApprovalRequirements output := by
  obtain ⟨nonempty, bounded, unique, rfl⟩ := (approvals_accepts input output).mp accepted
  exact ⟨nonempty, bounded, unique.of_map, fields⟩

theorem observations_valid (input : alloc.vec.Vec auths_model.observation.ObservationRequirement)
    (output : auths_model.observation.ObservationRequirements)
    (fields : ∀ value ∈ input.val, ProtocolValidity.ObservationRequirement value)
    (accepted : auths_model.observation.ObservationRequirements.new input = ok (.Ok output)) :
    ProtocolValidity.ObservationRequirements output := by
  obtain ⟨nonempty, bounded, unique, rfl⟩ := (observations_accepts input output).mp accepted
  exact ⟨nonempty, bounded, unique.of_map, fields⟩

theorem range_exact (lo hi : Std.U64) :
    auths_model.observation.UintRange.new lo hi =
      ok (if lo.val ≤ hi.val then .Ok ⟨lo, hi⟩ else .Err .InvalidObservationRequirement) := by
  unfold auths_model.observation.UintRange.new
  by_cases ordered : lo.val ≤ hi.val
  · have comparison : ¬ hi < lo := by scalar_tac
    simp [comparison, ordered]
  · have comparison : hi < lo := by scalar_tac
    simp [comparison, ordered]

theorem condition_exact (value : auths_model.observation.ObservationCondition) :
    auths_model.observation.ObservationCondition.new value.name value.test = ok value := by
  cases value
  rfl

theorem observation_exact (value : auths_model.observation.ObservationRequirement) :
    auths_model.observation.ObservationRequirement.new value.observer_anchor value.schema value.subject
      value.max_age_seconds value.conditions =
      ok (if 0 < value.max_age_seconds.val ∧ value.max_age_seconds.val ≤ 86400 ∧
          value.conditions.val ≠ [] ∧ value.conditions.val.length ≤ 16
        then .Ok value else .Err .InvalidObservationRequirement) := by
  unfold auths_model.observation.ObservationRequirement.new
  simp only [alloc.vec.Vec.is_empty, AuthsProtocolCodec.alloc.vec.len_value, bind_tc_ok, UScalar.lt_equiv, UScalar.eq_equiv]
  simp [auths_model.observation.MAX_OBSERVATION_AGE_SECONDS,
    auths_model.observation.MAX_OBSERVATION_CONDITIONS]
  split_ifs <;> simp_all <;> omega

theorem observation_valid (value output : auths_model.observation.ObservationRequirement)
    (fields : ProtocolValidity.ObservationRequirementFields value)
    (accepted : auths_model.observation.ObservationRequirement.new value.observer_anchor value.schema value.subject
      value.max_age_seconds value.conditions = ok (.Ok output)) : ProtocolValidity.ObservationRequirement output := by
  rw [observation_exact] at accepted
  split at accepted
  · rename_i dimensions
    have same : value = output := by simpa using accepted
    subst output
    exact ⟨fields, dimensions⟩
  · simp at accepted

def approvalExpected (input : alloc.vec.Vec auths_model.PrincipalId) (threshold : Std.U16) :
    core.result.Result auths_model.approval.ApprovalRequirement auths_model.ModelError :=
  if input.val = [] ∨ 16 < input.val.length ∨ threshold.val = 0 ∨ input.val.length < threshold.val then
    .Err .InvalidApprovalRequirement
  else if CollectionInvariants.adjacent (ProtocolSort.sortedVector (fun left right => compare left right) input).val
    then .Err .InvalidApprovalRequirement
  else .Ok ⟨ProtocolSort.sortedVector (fun left right => compare left right) input, threshold⟩

theorem approval_exact (input : alloc.vec.Vec auths_model.PrincipalId) (threshold : Std.U16) :
    auths_model.approval.ApprovalRequirement.new input threshold = ok (approvalExpected input threshold) := by
  unfold auths_model.approval.ApprovalRequirement.new
  simp only [alloc.vec.Vec.is_empty, AuthsProtocolCodec.alloc.vec.len_value, bind_tc_ok, UScalar.lt_equiv,
    UScalar.eq_equiv, core.convert.num.FromUsizeU16.from_val_eq]
  by_cases invalid : input.val = [] ∨ 16 < input.val.length ∨ threshold.val = 0 ∨ input.val.length < threshold.val
  · simp_all [approvalExpected, auths_model.approval.MAX_APPROVERS_PER_REQUIREMENT]
  · push_neg at invalid
    rcases invalid with ⟨nonempty, bounded, nonzero, floor⟩
    simp only [auths_model.approval.MAX_APPROVERS_PER_REQUIREMENT]
    simp only [nonempty, List.isEmpty_eq_false_iff.mpr nonempty,
      not_lt_of_ge bounded, nonzero, not_lt_of_ge floor, ↓reduceIte]
    simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
      Aeneas.Std.alloc.vec.Vec.deref_mut, bind_tc_ok]
    rw [ProtocolSort.slice_sort_exact auths_model.PrincipalId.Insts.CoreCmpOrd
      (fun left right => compare left right) ProtocolOrdering.principal_compare]
    simp only [bind_tc_ok]
    rw [ProtocolEquality.principals_scan_exact]
    simp [approvalExpected, nonempty, bounded, nonzero, floor, ProtocolSort.sortedVector,
      alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.deref,
      auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
      auths_composition.alloc.vec.Vec.deref, auths_model.approval.MAX_APPROVERS_PER_REQUIREMENT]

theorem approval_accepts (input : alloc.vec.Vec auths_model.PrincipalId) (threshold : Std.U16)
    (output : auths_model.approval.ApprovalRequirement) :
    auths_model.approval.ApprovalRequirement.new input threshold = ok (.Ok output) ↔
      input.val ≠ [] ∧ input.val.length ≤ 16 ∧ 0 < threshold.val ∧ threshold.val ≤ input.val.length ∧
      CollectionInvariants.adjacent (ProtocolSort.sortedVector (fun left right => compare left right) input).val = false ∧
      output = ⟨ProtocolSort.sortedVector (fun left right => compare left right) input, threshold⟩ := by
  rw [approval_exact]
  unfold approvalExpected
  split_ifs <;> simp_all [eq_comm] <;> omega

theorem approval_valid (input : alloc.vec.Vec auths_model.PrincipalId) (threshold : Std.U16)
    (output : auths_model.approval.ApprovalRequirement)
    (fields : ∀ principal ∈ input.val, ProtocolValidity.Principal principal)
    (accepted : auths_model.approval.ApprovalRequirement.new input threshold = ok (.Ok output)) :
    ProtocolValidity.ApprovalRequirement output := by
  obtain ⟨nonempty, bounded, positive, floor, clean, rfl⟩ := (approval_accepts input threshold output).mp accepted
  have same := ProtocolSort.sorted_vector_permutation (fun left right => compare left right) input
  have unique := KeyOrder.sorted_clean_unique id input (by simpa using clean)
  have ordered := KeyOrder.sorted_clean_strict id input (by simpa using clean)
  refine ⟨?_, ?_, positive, ?_, ?_, ?_, ?_⟩
  · intro empty
    have lengths := same.length_eq
    rw [empty, List.length_nil] at lengths
    exact nonempty (List.length_eq_zero_iff.mp lengths.symm)
  · simpa [same.length_eq] using bounded
  · simpa [same.length_eq] using floor
  · intro principal member
    exact fields principal (same.mem_iff.mp member)
  · have strict := List.pairwise_map.mp ordered
    exact strict.imp (fun left right less => (ProtocolOrdering.text_lt_iff left right).mp less)
  · simpa using unique

end Auths.Codec.RequirementConstructors
