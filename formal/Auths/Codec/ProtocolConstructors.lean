import qualification.aeneas.generated.protocol_codec.Funs
import Auths.Codec.ProtocolValidity

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolConstructors
open ProtocolValidity

set_option maxHeartbeats 2000000

theorem protocol_version_exact (value : Std.U16) :
    auths_model.ProtocolVersion.new value =
      ok (if value.val = 1 then .Ok value else .Err .UnsupportedProtocol) := by
  simp [auths_model.ProtocolVersion.new, auths_model.PROTOCOL_V1]

theorem freshness_exact (value : Std.U64) :
    auths_model.FreshnessLimit.new value =
      ok (if value.val = 0 then .Err .InvalidStatus else .Ok value) := by
  simp [auths_model.FreshnessLimit.new]

theorem window_exact (first last : auths_model.Timestamp) :
    auths_model.ValidityWindow.new first last =
      ok (if first.val ≤ last.val then .Ok ⟨first, last⟩ else .Err .InvalidValidity) := by
  unfold auths_model.ValidityWindow.new
  by_cases ordered : first.val ≤ last.val
  · have comparison : ¬ last < first := by scalar_tac
    simp [comparison, ordered]
  · have comparison : last < first := by scalar_tac
    simp [comparison, ordered]

theorem profile_exact (identifier : auths_model.ProfileId) (version : Std.U16) :
    auths_model.ProfileRef.new identifier version =
      ok (if version.val = 0 then .Err .InvalidProfile else .Ok ⟨identifier, version⟩) := by
  simp [auths_model.ProfileRef.new]

theorem signature_bytes_exact (bytes : alloc.vec.Vec Std.U8) :
    auths_model.SignatureBytes.new bytes =
      ok (if bytes.val = [] ∨ 4096 < bytes.val.length then .Err .InvalidSignature else .Ok bytes) := by
  unfold auths_model.SignatureBytes.new
  simp [alloc.vec.Vec.is_empty, alloc.vec.Vec.len, auths_model.HARD_MAX_SIGNATURE_BYTES,
    alloc.vec.Vec.toBase, auths_composition.alloc.vec.Vec.toBase,
    alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.val,
    UScalar.lt_equiv, List.isEmpty_iff]

theorem fact_bytes_exact (bytes : alloc.vec.Vec Std.U8) :
    auths_model.observation.FactBytes.new bytes =
      ok (if bytes.val.length ≤ 64 then .Ok bytes else .Err .InvalidObservation) := by
  unfold auths_model.observation.FactBytes.new
  simp only [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv]
  by_cases bounded : bytes.val.length ≤ 64 <;>
    simp [auths_model.observation.MAX_FACT_VALUE_BYTES, bounded]

theorem critical_extension_exact (identifier : auths_model.ExtensionId)
    (bytes : alloc.vec.Vec Std.U8) :
    auths_model.CriticalExtension.new identifier bytes =
      ok (if bytes.val.length ≤ 65536 then .Ok ⟨identifier, bytes⟩ else .Err .InvalidExtension) := by
  unfold auths_model.CriticalExtension.new
  simp only [AuthsProtocolCodec.alloc.vec.len_value, UScalar.lt_equiv]
  by_cases bounded : bytes.val.length ≤ 65536 <;>
    simp [auths_model.HARD_MAX_EXTENSION_BYTES, bounded]

theorem timestamp_gt_exact (left right : auths_model.Timestamp) :
    core.cmp.PartialOrd.gt.default auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp left right =
      ok (decide (right.val < left.val)) := by
  simp [AuthsProtocolCodec.core.cmp.PartialOrd.gt.default,
    Aeneas.Std.core.cmp.PartialOrd.gt.default, Aeneas.Std.core.cmp.PartialOrd.gt_body,
    auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp.partial_cmp,
    auths_model.Timestamp.Insts.CoreCmpOrd.cmp, core.cmp.impls.OrdU64.cmp, Nat.compare_eq_gt]

theorem principal_status_exact (value : auths_model.PrincipalStatusStatement) :
    auths_model.PrincipalStatusStatement.new value.method value.principal value.state value.sequence
      value.observed_at value.valid_until value.issuer value.extensions =
      ok (if value.observed_at.val ≤ value.valid_until.val then
        .Ok {value with version := 1#u16} else .Err .InvalidStatus) := by
  simp only [auths_model.PrincipalStatusStatement.new, timestamp_gt_exact, bind_tc_ok]
  by_cases ordered : value.observed_at.val ≤ value.valid_until.val <;> simp_all

theorem grant_status_exact (value : auths_model.GrantStatusStatement) :
    auths_model.GrantStatusStatement.new value.method value.grant_id value.state value.sequence
      value.observed_at value.valid_until value.issuer value.extensions =
      ok (if value.observed_at.val ≤ value.valid_until.val then
        .Ok {value with version := 1#u16} else .Err .InvalidStatus) := by
  simp only [auths_model.GrantStatusStatement.new, timestamp_gt_exact, bind_tc_ok]
  by_cases ordered : value.observed_at.val ≤ value.valid_until.val <;> simp_all

/- These equations name actual translated Rust constructors. A prototype is
only convenient notation for their input fields: it supplies no assumed result,
validity flag or successful decoder execution. All fields are preserved except
the protocol version, which the actual constructors set to V1.

The validity consequences below require the component invariants established by
field parsing/constructors. A public-decoder proof must earn those premises.
These lemmas alone do not establish that public-decoder closure. -/

theorem signature_descriptor_exact (value : auths_model.SignatureDescriptor) :
    auths_model.SignatureDescriptor.new value.principal_method value.verification_method value.suite =
      ok value := by
  cases value
  rfl

theorem signature_envelope_exact (value : auths_model.SignatureEnvelope) :
    auths_model.SignatureEnvelope.new value.descriptor value.signature = ok value := by
  cases value
  rfl

theorem grant_exact (value : auths_model.GrantStatement) :
    auths_model.GrantStatement.new value.issuer value.subject value.profile value.permissions
      value.validity value.audiences value.action_constraint value.budget_ceiling
      value.remaining_depth value.parent value.status_policy value.assurance_floor value.extensions =
      ok {value with version := 1#u16} := by
  cases value
  rfl

theorem action_exact (value : auths_model.ActionEnvelope) :
    auths_model.ActionEnvelope.new value.profile value.body_media_type value.canonical_body_digest
      value.permission value.requested_budget value.audience value.challenge value.validity
      value.actor value.terminal_grant value.authorization_plan value.channel_binding value.proof_ref
      value.attachments value.extensions = ok {value with version := 1#u16} := by
  cases value
  rfl

theorem approval_exact (value : auths_model.approval.ApprovalStatement) :
    auths_model.approval.ApprovalStatement.new value.approver value.requirement value.media_type
      value.body_digest value.permission value.requested_budget value.attributes value.audience
      value.challenge value.validity = ok {value with version := 1#u16} := by
  cases value
  rfl

theorem observation_exact (value : auths_model.observation.ObservationStatement) :
    auths_model.observation.ObservationStatement.new value.observer value.schema value.subject
      value.observed_at value.facts = ok {value with version := 1#u16} := by
  cases value
  rfl

theorem signed_grant_exact (value : auths_model.SignedGrant) :
    auths_model.SignedGrant.new value.statement value.signature = ok value := by
  cases value
  rfl

theorem signed_action_exact (value : auths_model.SignedAction) :
    auths_model.SignedAction.new value.envelope value.signature = ok value := by
  cases value
  rfl

theorem signed_principal_status_exact (value : auths_model.SignedPrincipalStatus) :
    auths_model.SignedPrincipalStatus.new value.statement value.signature = ok value := by
  cases value
  rfl

theorem signed_grant_status_exact (value : auths_model.SignedGrantStatus) :
    auths_model.SignedGrantStatus.new value.statement value.signature = ok value := by
  cases value
  rfl

theorem attachment_descriptor_exact (value : auths_model.AttachmentDescriptor) :
    auths_model.AttachmentDescriptor.new value.digest value.media_type value.byte_length
      value.disposition value.confidentiality value.presence value.opacity = ok value := by
  cases value
  rfl

theorem permission_exact (value : auths_model.Permission) :
    auths_model.Permission.new value.capability value.resource = ok value := by
  cases value
  rfl

theorem budget_exact (value : auths_model.BudgetCeiling) :
    auths_model.BudgetCeiling.new value.algebra value.value = ok value := by
  cases value
  rfl

theorem observation_fact_exact (value : auths_model.observation.ObservationFact) :
    auths_model.observation.ObservationFact.new value.name value.value = ok value := by
  cases value
  rfl

theorem window_accepts_iff (first last : auths_model.Timestamp)
    (output : auths_model.ValidityWindow) :
    auths_model.ValidityWindow.new first last = ok (.Ok output) ↔
      output = ⟨first, last⟩ ∧ first.val ≤ last.val := by
  rw [window_exact]
  by_cases ordered : first.val ≤ last.val <;> simp [ordered, eq_comm]

theorem signature_bytes_accepts_iff (bytes output : alloc.vec.Vec Std.U8) :
    auths_model.SignatureBytes.new bytes = ok (.Ok output) ↔
      output = bytes ∧ bytes.val ≠ [] ∧ bytes.val.length ≤ 4096 := by
  rw [signature_bytes_exact]
  by_cases invalid : bytes.val = [] ∨ 4096 < bytes.val.length
  · simp only [invalid, ↓reduceIte, reduceCtorEq, Result.ok.injEq]
    rcases invalid with empty | oversized <;> simp_all
  · simp only [invalid, ↓reduceIte, Result.ok.injEq, core.result.Result.Ok.injEq]
    push_neg at invalid
    simp [eq_comm, invalid]

theorem principal_status_accepts_iff (value output : auths_model.PrincipalStatusStatement) :
    auths_model.PrincipalStatusStatement.new value.method value.principal value.state value.sequence
      value.observed_at value.valid_until value.issuer value.extensions = ok (.Ok output) ↔
      output = {value with version := 1#u16} ∧ value.observed_at.val ≤ value.valid_until.val := by
  rw [principal_status_exact]
  by_cases ordered : value.observed_at.val ≤ value.valid_until.val <;> simp [ordered, eq_comm]

theorem grant_status_accepts_iff (value output : auths_model.GrantStatusStatement) :
    auths_model.GrantStatusStatement.new value.method value.grant_id value.state value.sequence
      value.observed_at value.valid_until value.issuer value.extensions = ok (.Ok output) ↔
      output = {value with version := 1#u16} ∧ value.observed_at.val ≤ value.valid_until.val := by
  rw [grant_status_exact]
  by_cases ordered : value.observed_at.val ≤ value.valid_until.val <;> simp [ordered, eq_comm]

theorem principal_status_output_valid (value output : auths_model.PrincipalStatusStatement)
    (fields : PrincipalStatusFields value)
    (accepted : auths_model.PrincipalStatusStatement.new value.method value.principal value.state
      value.sequence value.observed_at value.valid_until value.issuer value.extensions = ok (.Ok output)) :
    PrincipalStatus output := by
  obtain ⟨rfl, ordered⟩ := (principal_status_accepts_iff value output).mp accepted
  exact ⟨by simp, fields, ordered⟩

theorem grant_status_output_valid (value output : auths_model.GrantStatusStatement)
    (fields : GrantStatusFields value)
    (accepted : auths_model.GrantStatusStatement.new value.method value.grant_id value.state
      value.sequence value.observed_at value.valid_until value.issuer value.extensions = ok (.Ok output)) :
    GrantStatus output := by
  obtain ⟨rfl, ordered⟩ := (grant_status_accepts_iff value output).mp accepted
  exact ⟨by simp, fields, ordered⟩

theorem signature_constructs_valid (descriptor : auths_model.SignatureDescriptor)
    (bytes : alloc.vec.Vec Std.U8) (fields : ProtocolValidity.SignatureDescriptor descriptor)
    (nonempty : bytes.val ≠ []) (bounded : bytes.val.length ≤ 4096) :
    ∃ signature, auths_model.SignatureBytes.new bytes = ok (.Ok bytes) ∧
      auths_model.SignatureEnvelope.new descriptor bytes = ok signature ∧ Signature signature := by
  refine ⟨⟨descriptor, bytes⟩, ?_, signature_envelope_exact ⟨descriptor, bytes⟩, fields, nonempty, bounded⟩
  exact (signature_bytes_accepts_iff bytes bytes).mpr ⟨rfl, nonempty, bounded⟩

theorem critical_extension_output_valid (identifier : auths_model.ExtensionId)
    (bytes : alloc.vec.Vec Std.U8) (output : auths_model.CriticalExtension)
    (field : Identifier identifier 128)
    (accepted : auths_model.CriticalExtension.new identifier bytes = ok (.Ok output)) :
    Extension output := by
  rw [critical_extension_exact] at accepted
  split at accepted
  · rename_i bounded
    have same : (⟨identifier, bytes⟩ : auths_model.CriticalExtension) = output := by simpa using accepted
    subst output
    exact ⟨field, bounded⟩
  · simp at accepted

theorem principal_status_valid (value : auths_model.PrincipalStatusStatement)
    (fields : PrincipalStatusFields value) (ordered : value.observed_at.val ≤ value.valid_until.val) :
    ∃ output, auths_model.PrincipalStatusStatement.new value.method value.principal value.state
      value.sequence value.observed_at value.valid_until value.issuer value.extensions =
        ok (.Ok output) ∧ PrincipalStatus output := by
  refine ⟨{value with version := 1#u16}, ?_, ?_⟩
  · rw [principal_status_exact, if_pos ordered]
  · exact ⟨by simp, fields, ordered⟩

theorem grant_status_valid (value : auths_model.GrantStatusStatement)
    (fields : GrantStatusFields value) (ordered : value.observed_at.val ≤ value.valid_until.val) :
    ∃ output, auths_model.GrantStatusStatement.new value.method value.grant_id value.state
      value.sequence value.observed_at value.valid_until value.issuer value.extensions =
        ok (.Ok output) ∧ GrantStatus output := by
  refine ⟨{value with version := 1#u16}, ?_, ?_⟩
  · rw [grant_status_exact, if_pos ordered]
  · exact ⟨by simp, fields, ordered⟩

/-- Actual grant construction earns V1 and preserves component validity;
neither graph authority nor signature validity is a component premise. -/
theorem grant_valid (value : auths_model.GrantStatement) (fields : GrantFields value) :
    ∃ output,
      auths_model.GrantStatement.new value.issuer value.subject value.profile value.permissions
        value.validity value.audiences value.action_constraint value.budget_ceiling
        value.remaining_depth value.parent value.status_policy value.assurance_floor value.extensions =
        ok output ∧ Grant output := by
  refine ⟨{value with version := 1#u16}, grant_exact value, ?_⟩
  exact ⟨by simp, fields⟩

theorem action_valid (value : auths_model.ActionEnvelope) (fields : ActionFields value) :
    ∃ output,
      auths_model.ActionEnvelope.new value.profile value.body_media_type value.canonical_body_digest
        value.permission value.requested_budget value.audience value.challenge value.validity
        value.actor value.terminal_grant value.authorization_plan value.channel_binding value.proof_ref
        value.attachments value.extensions = ok output ∧ Action output := by
  refine ⟨{value with version := 1#u16}, action_exact value, ?_⟩
  exact ⟨by simp, fields⟩

theorem approval_valid (value : auths_model.approval.ApprovalStatement)
    (fields : ApprovalFields value) :
    ∃ output,
      auths_model.approval.ApprovalStatement.new value.approver value.requirement value.media_type
        value.body_digest value.permission value.requested_budget value.attributes value.audience
        value.challenge value.validity = ok output ∧ Approval output := by
  refine ⟨{value with version := 1#u16}, approval_exact value, ?_⟩
  exact ⟨by simp, fields⟩

theorem observation_valid (value : auths_model.observation.ObservationStatement)
    (fields : ObservationFields value) :
    ∃ output,
      auths_model.observation.ObservationStatement.new value.observer value.schema value.subject
        value.observed_at value.facts = ok output ∧ Observation output := by
  refine ⟨{value with version := 1#u16}, observation_exact value, ?_⟩
  exact ⟨by simp, fields⟩

theorem signed_grant_valid (statement : auths_model.GrantStatement)
    (signature : auths_model.SignatureEnvelope) (fields : Grant statement) (sig : Signature signature) :
    ∃ output, auths_model.SignedGrant.new statement signature = ok output ∧ SignedGrant output := by
  exact ⟨⟨statement, signature⟩, signed_grant_exact ⟨statement, signature⟩, fields, sig⟩

theorem signed_action_valid (envelope : auths_model.ActionEnvelope)
    (signature : auths_model.SignatureEnvelope) (fields : Action envelope) (sig : Signature signature) :
    ∃ output, auths_model.SignedAction.new envelope signature = ok output ∧ SignedAction output := by
  exact ⟨⟨envelope, signature⟩, signed_action_exact ⟨envelope, signature⟩, fields, sig⟩

theorem signed_principal_status_valid (statement : auths_model.PrincipalStatusStatement)
    (signature : auths_model.SignatureEnvelope) (fields : PrincipalStatus statement)
    (sig : Signature signature) :
    ∃ output, auths_model.SignedPrincipalStatus.new statement signature = ok output ∧
      SignedPrincipalStatus output := by
  exact ⟨⟨statement, signature⟩, signed_principal_status_exact ⟨statement, signature⟩, fields, sig⟩

theorem signed_grant_status_valid (statement : auths_model.GrantStatusStatement)
    (signature : auths_model.SignatureEnvelope) (fields : GrantStatus statement)
    (sig : Signature signature) :
    ∃ output, auths_model.SignedGrantStatus.new statement signature = ok output ∧
      SignedGrantStatus output := by
  exact ⟨⟨statement, signature⟩, signed_grant_status_exact ⟨statement, signature⟩, fields, sig⟩

end Auths.Codec.ProtocolConstructors
