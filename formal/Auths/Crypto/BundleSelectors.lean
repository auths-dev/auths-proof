import Auths.Crypto.BundleObjects

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Crypto.BundleSelectors

/- Exact concrete source key selection. These small equations expose every
record/identifier association; they do not assume a sorting outcome. Sorting,
derived-ID meaning and normalization/work must still be composed at callers. -/
theorem grant_key (entry : auths_model.GrantId × auths_model.SignedGrant) :
    encode.grant_ref_sort_key entry = ok entry.1 := by rfl

theorem principal_status_key
    (entry : auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus) :
    encode.principal_status_ref_sort_key entry = ok entry.1 := by rfl

theorem grant_status_key (entry : auths_model.GrantStatusId × auths_model.SignedGrantStatus) :
    encode.grant_status_ref_sort_key entry = ok entry.1 := by rfl

theorem action_key (value : auths_model.SignedAction) :
    encode.action_ref_sort_key value = ok value.envelope.proof_ref := by
  simp only [encode.action_ref_sort_key, auths_model.SignedAction.impl.envelope,
    auths_model.ActionEnvelope.impl.proof_ref, bind_tc_ok]

theorem evidence_key (value : auths_model.EvidenceObject) :
    encode.evidence_ref_sort_key value = ok value.id := by
  simp only [encode.evidence_ref_sort_key, auths_model.EvidenceObject.impl.id, bind_tc_ok]

theorem binding_key (value : auths_model.ControlBinding) :
    encode.binding_ref_sort_key value = ok value.statement := by
  simp only [encode.binding_ref_sort_key, auths_model.ControlBinding.impl.statement, bind_tc_ok]

theorem attachment_key (value : auths_model.AttachmentDescriptor) :
    encode.attachment_ref_sort_key value = ok value.digest := by
  simp only [encode.attachment_ref_sort_key, auths_model.AttachmentDescriptor.impl.digest, bind_tc_ok]

end Auths.Crypto.BundleSelectors
