import Auths.Codec.RequirementKeys
import Auths.Codec.ProtocolEquality
import Auths.Codec.ProtocolVectorEquality

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.RequirementEquality
set_option maxHeartbeats 2000000

/- All concrete Auths-derived comparison bodies remain transparent. No
successful list scan, hash equality or semantic-policy equivalence is an
element-comparison premise. Standard Vec equality delegates to the pinned
library model through the already proved positive carrier isomorphism. -/

theorem fact_bytes (left right : auths_model.observation.FactBytes) :
    auths_model.observation.FactBytes.Insts.CoreCmpPartialEqFactBytes.eq left right =
      ok (decide (left.val.map UScalar.val = right.val.map UScalar.val)) := by
  simpa [auths_model.observation.FactBytes.Insts.CoreCmpPartialEqFactBytes.eq,
    core.cmp.PartialEqVec] using ProtocolVectorEquality.bytes_exact left right

theorem fact_text (left right : auths_model.observation.FactText) :
    auths_model.observation.FactText.Insts.CoreCmpPartialEqFactText.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.observation.FactText.Insts.CoreCmpPartialEqFactText.eq,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq]

theorem fact (left right : auths_model.observation.FactValue) :
    auths_model.observation.FactValue.Insts.CoreCmpPartialEqFactValue.eq left right =
      ok (decide (RequirementKeys.fact left = RequirementKeys.fact right)) := by
  cases left <;> cases right <;>
    simp [auths_model.observation.FactValue.Insts.CoreCmpPartialEqFactValue.eq,
      RequirementKeys.fact, fact_bytes, fact_text, UScalar.eq_equiv]

theorem member_values (left right : auths_model.observation.MemberValues) :
    auths_model.observation.MemberValues.Insts.CoreCmpPartialEqMemberValues.eq left right =
      ok (decide (left.val.map RequirementKeys.fact = right.val.map RequirementKeys.fact)) := by
  simpa [auths_model.observation.MemberValues.Insts.CoreCmpPartialEqMemberValues.eq,
    core.cmp.PartialEqVec] using ProtocolVectorEquality.source_exact
      auths_model.observation.FactValue.Insts.CoreCmpPartialEqFactValue RequirementKeys.fact
      (by intro first second; exact fact first second) left right

theorem range (left right : auths_model.observation.UintRange) :
    auths_model.observation.UintRange.Insts.CoreCmpPartialEqUintRange.eq left right =
      ok (decide ((left.lo.val, left.hi.val) = (right.lo.val, right.hi.val))) := by
  simp [auths_model.observation.UintRange.Insts.CoreCmpPartialEqUintRange.eq, UScalar.eq_equiv]

theorem test (left right : auths_model.observation.ConditionTest) :
    auths_model.observation.ConditionTest.Insts.CoreCmpPartialEqConditionTest.eq left right =
      ok (decide (RequirementKeys.test left = RequirementKeys.test right)) := by
  cases left <;> cases right <;>
    simp [auths_model.observation.ConditionTest.Insts.CoreCmpPartialEqConditionTest.eq,
      RequirementKeys.test, fact, ProtocolEquality.fact_name_exact, range, member_values]

theorem condition (left right : auths_model.observation.ObservationCondition) :
    auths_model.observation.ObservationCondition.Insts.CoreCmpPartialEqObservationCondition.eq left right =
      ok (decide (RequirementKeys.condition left = RequirementKeys.condition right)) := by
  simp [auths_model.observation.ObservationCondition.Insts.CoreCmpPartialEqObservationCondition.eq,
    RequirementKeys.condition, ProtocolEquality.fact_name_exact, test]

theorem subject (left right : auths_model.observation.ObservationSubject) :
    auths_model.observation.ObservationSubject.Insts.CoreCmpPartialEqObservationSubject.eq left right =
      ok (decide (RequirementKeys.subject left = RequirementKeys.subject right)) := by
  cases left <;> cases right <;>
    simp [auths_model.observation.ObservationSubject.Insts.CoreCmpPartialEqObservationSubject.eq,
      RequirementKeys.subject, auths_model.ResourceId.Insts.CoreCmpPartialEqResourceId.eq,
      AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
      _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq, ProtocolEquality.fact_name_exact]

theorem observation (left right : auths_model.observation.ObservationRequirement) :
    auths_model.observation.ObservationRequirement.Insts.CoreCmpPartialEqObservationRequirement.eq left right =
      ok (decide (RequirementKeys.observation left = RequirementKeys.observation right)) := by
  have conditions := ProtocolVectorEquality.source_exact
    auths_model.observation.ObservationCondition.Insts.CoreCmpPartialEqObservationCondition RequirementKeys.condition
    (by intro first second; exact condition first second) left.conditions right.conditions
  simp [auths_model.observation.ObservationRequirement.Insts.CoreCmpPartialEqObservationRequirement.eq,
    auths_model.observation.ObserverAnchorId.Insts.CoreCmpPartialEqObserverAnchorId.eq,
    auths_model.observation.ObservationSchemaId.Insts.CoreCmpPartialEqObservationSchemaId.eq,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    RequirementKeys.observation, core.cmp.PartialEqVec, conditions, subject, UScalar.eq_equiv]

theorem approval (left right : auths_model.approval.ApprovalRequirement) :
    auths_model.approval.ApprovalRequirement.Insts.CoreCmpPartialEqApprovalRequirement.eq left right =
      ok (decide (RequirementKeys.approval left = RequirementKeys.approval right)) := by
  have approvers := ProtocolVectorEquality.source_exact
    auths_model.PrincipalId.Insts.CoreCmpPartialEqPrincipalId id
    (by intro first second; exact ProtocolEquality.principal_exact first second) left.approvers right.approvers
  simp [auths_model.approval.ApprovalRequirement.Insts.CoreCmpPartialEqApprovalRequirement.eq,
    RequirementKeys.approval, core.cmp.PartialEqVec, approvers, UScalar.eq_equiv]

theorem literal_scan (values : Slice auths_model.observation.FactValue) :
    @auths_model.collection_scan.has_duplicates auths_model.observation.FactValue
      auths_model.observation.FactValue.Insts.CoreCmpPartialEqFactValue values =
      ok (SnapshotUniqueness.hasDuplicate (values.val.map RequirementKeys.fact)) :=
  ProtocolCollectionScans.duplicates_exact
    auths_model.observation.FactValue.Insts.CoreCmpPartialEqFactValue RequirementKeys.fact
    (by intro left right; exact fact left right) values

theorem observation_scan (values : Slice auths_model.observation.ObservationRequirement) :
    @auths_model.collection_scan.has_duplicates auths_model.observation.ObservationRequirement
      auths_model.observation.ObservationRequirement.Insts.CoreCmpPartialEqObservationRequirement values =
      ok (SnapshotUniqueness.hasDuplicate (values.val.map RequirementKeys.observation)) :=
  ProtocolCollectionScans.duplicates_exact
    auths_model.observation.ObservationRequirement.Insts.CoreCmpPartialEqObservationRequirement RequirementKeys.observation
    (by intro left right; exact observation left right) values

theorem approval_scan (values : Slice auths_model.approval.ApprovalRequirement) :
    @auths_model.collection_scan.has_duplicates auths_model.approval.ApprovalRequirement
      auths_model.approval.ApprovalRequirement.Insts.CoreCmpPartialEqApprovalRequirement values =
      ok (SnapshotUniqueness.hasDuplicate (values.val.map RequirementKeys.approval)) :=
  ProtocolCollectionScans.duplicates_exact
    auths_model.approval.ApprovalRequirement.Insts.CoreCmpPartialEqApprovalRequirement RequirementKeys.approval
    (by intro left right; exact approval left right) values

end Auths.Codec.RequirementEquality
