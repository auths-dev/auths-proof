import Auths.Codec.Evaluation
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.Limits

/-- A readable record of protocol hard ceilings. Validity checks the entire
record, even when a caller happens to use only action-related fields. -/
def hard : auths_codec.auths_model.VerifierLimits := {
  bundle_bytes := 8388608#usize
  action_bytes := 16777216#usize
  context_bytes := 16777216#usize
  grants := auths_model.HARD_MAX_GRANTS
  actions := auths_model.HARD_MAX_ACTIONS
  plan_leaves := auths_model.HARD_MAX_PLAN_LEAVES
  plan_depth := auths_model.HARD_MAX_PLAN_DEPTH
  plan_branching := auths_model.HARD_MAX_PLAN_BRANCHING
  evidence := auths_model.HARD_MAX_EVIDENCE
  evidence_bytes := 2097152#usize
  bindings := auths_model.HARD_MAX_BINDINGS
  principal_status := auths_model.HARD_MAX_PRINCIPAL_STATUS
  grant_status := auths_model.HARD_MAX_GRANT_STATUS
  attachments := auths_model.HARD_MAX_ATTACHMENTS
  attachment_bytes := 8388608#usize
  signatures := auths_model.HARD_MAX_SIGNATURES
  signature_bytes := auths_model.HARD_MAX_SIGNATURE_BYTES
  permissions := auths_model.HARD_MAX_PERMISSIONS
  audiences := auths_model.HARD_MAX_AUDIENCES
  extensions := auths_model.HARD_MAX_EXTENSIONS
  extension_bytes := auths_model.HARD_MAX_EXTENSION_BYTES
  body_digests := auths_model.HARD_MAX_BODY_DIGESTS
  binding_evidence := auths_model.HARD_MAX_BINDING_EVIDENCE
  canonical_body_bytes := 8388608#usize
  registry_entries := auths_model.HARD_MAX_REGISTRY_ENTRIES
  trust_anchors := auths_model.HARD_MAX_TRUST_ANCHORS
  work_units := auths_model.HARD_MAX_WORK_UNITS
  approvals := auths_model.HARD_MAX_APPROVALS
  approver_anchors := auths_model.HARD_MAX_APPROVER_ANCHORS
  approval_requirements := auths_model.HARD_MAX_CONTEXT_APPROVAL_REQUIREMENTS
}

def Valid (value : auths_codec.auths_model.VerifierLimits) : Prop :=
  value.bundle_bytes.val ≤ hard.bundle_bytes.val ∧
  value.action_bytes.val ≤ hard.action_bytes.val ∧
  value.context_bytes.val ≤ hard.context_bytes.val ∧
  value.grants.val ≤ hard.grants.val ∧
  value.actions.val ≤ hard.actions.val ∧
  value.plan_leaves.val ≤ hard.plan_leaves.val ∧
  value.plan_depth.val ≤ hard.plan_depth.val ∧
  value.plan_branching.val ≤ hard.plan_branching.val ∧
  value.evidence.val ≤ hard.evidence.val ∧
  value.evidence_bytes.val ≤ hard.evidence_bytes.val ∧
  value.bindings.val ≤ hard.bindings.val ∧
  value.principal_status.val ≤ hard.principal_status.val ∧
  value.grant_status.val ≤ hard.grant_status.val ∧
  value.attachments.val ≤ hard.attachments.val ∧
  value.attachment_bytes.val ≤ hard.attachment_bytes.val ∧
  value.signatures.val ≤ hard.signatures.val ∧
  value.signature_bytes.val ≤ hard.signature_bytes.val ∧
  value.permissions.val ≤ hard.permissions.val ∧
  value.audiences.val ≤ hard.audiences.val ∧
  value.extensions.val ≤ hard.extensions.val ∧
  value.extension_bytes.val ≤ hard.extension_bytes.val ∧
  value.body_digests.val ≤ hard.body_digests.val ∧
  value.binding_evidence.val ≤ hard.binding_evidence.val ∧
  value.canonical_body_bytes.val ≤ hard.canonical_body_bytes.val ∧
  value.registry_entries.val ≤ hard.registry_entries.val ∧
  value.trust_anchors.val ≤ hard.trust_anchors.val ∧
  value.approvals.val ≤ hard.approvals.val ∧
  value.approver_anchors.val ≤ hard.approver_anchors.val ∧
  value.approval_requirements.val ≤ hard.approval_requirements.val ∧
  value.work_units.val ≤ hard.work_units.val

@[step] theorem hard_exact : auths_model.VerifierLimits.hard ⦃ actual => actual = hard ⦄ := by
  unfold auths_model.VerifierLimits.hard
  rw [Evaluation.hard_bundle_bytes, Evaluation.hard_action_bytes, Evaluation.hard_context_bytes,
    Evaluation.hard_evidence_bytes, Evaluation.hard_attachment_bytes, Evaluation.hard_canonical_body_bytes]
  rfl

@[step] theorem validate_exact (value : auths_codec.auths_model.VerifierLimits) :
    auths_model.VerifierLimits.validate value ⦃ actual =>
      actual = if Valid value then .Ok () else .Err .CollectionLimitExceeded ⦄ := by
  unfold auths_model.VerifierLimits.validate
  step with hard_exact as ⟨ceilings, exactCeilings⟩
  simp only [exactCeilings]
  repeat' split
  all_goals simp_all only [spec_ok, Valid, UScalar.lt_equiv, not_lt, ↓reduceIte]

theorem accepted_action_limits (value : auths_codec.auths_model.VerifierLimits)
    (accepted : auths_model.VerifierLimits.validate value = ok (.Ok ())) :
    value.action_bytes.val ≤ 16777216 ∧ value.attachments.val ≤ 512 ∧
    value.attachment_bytes.val ≤ 8388608 ∧ value.canonical_body_bytes.val ≤ 8388608 := by
  have contract := validate_exact value
  rw [accepted] at contract
  simp only [spec_ok] at contract
  have valid : Valid value := by
    by_contra refused
    simp [refused] at contract
  simp only [Valid, hard, auths_model.HARD_MAX_ATTACHMENTS, UScalar.ofNatCore_val_eq] at valid
  rcases valid with ⟨bundle, action, context, grants, actions, leaves, depth, branching,
    evidence, evidenceBytes, bindings, principalStatus, grantStatus, attachments,
    attachmentBytes, signatures, signatureBytes, permissions, audiences, extensions,
    extensionBytes, bodyDigests, bindingEvidence, body, registry, trust, approvals,
    approvers, approvalRequirements, work⟩
  exact ⟨action, attachments, attachmentBytes, body⟩

end Auths.Codec.Limits
