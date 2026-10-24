import Auths.Crypto.SigningPreimages
import Auths.Crypto.FramedHash

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SigningPreimageResults
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Crypto.StatementWriters Auths.Crypto.SigningObjectWriters

/- Full typed results of the real public signing-preimage callers. These
statements obtain successful encodings from independent input validity and
writer-space conditions. Framing acceptance/refusal is then classified by
independent byte-length/native-capacity predicates. No successful preimage,
expected encoder output, trusted descriptor or cryptographic premise is used. -/

@[step] theorem grant_total (value : auths_model.GrantStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Grant value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grantSigningCost value descriptor ≤ Usize.max) :
    hash.grant_signing_preimage value descriptor ⦃ result =>
      FramedHash.PreimageResult (FramedHash.SigningAdmissible (SigningPreimages.grantFrame value descriptor))
        (Framing.encode (SigningPreimages.grantFrame value descriptor)) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.grant_signing_valid value descriptor valid descriptorValid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := (ValidatedWriters.grant_strings value valid).profile
  have borrowed : auths_model.ProfileId.as_str value.profile.id = ok (toStr value.profile.id profileBound) := by
    simpa only [auths_model.ProfileId.as_str] using
      StringRefinement.string_borrow_exact value.profile.id profileBound
  have profileBytes := ProtocolWriter.borrowed_bytes value.profile.id profileBound
  unfold hash.grant_signing_preimage
  simp only [auths_model.GrantStatement.impl.profile, auths_model.ProfileRef.impl.id,
    auths_model.ProfileRef.impl.version, borrowed, encoded,
    core.result.Result.Insts.CoreOpsTry.branch, core.ops.deref.DerefVec, bind_tc_ok]
  simpa only [SigningPreimages.grantFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.deref_exact, profileBytes, payloadBytes] using
    FramedHash.signing_preimage_total .Grant (toStr value.profile.id profileBound)
      value.profile.version (alloc.vec.Vec.deref payload)

theorem grant_accepts (value : auths_model.GrantStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Grant value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grantSigningCost value descriptor ≤ Usize.max)
    (fits : FramedHash.SigningAdmissible (SigningPreimages.grantFrame value descriptor)) :
    ∃ output, hash.grant_signing_preimage value descriptor = ok (.Ok output) ∧
      byteList output.val = Framing.encode (SigningPreimages.grantFrame value descriptor) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (grant_total value descriptor valid descriptorValid space)
  obtain ⟨output, same, meaning⟩ := FramedHash.preimage_accepted classified fits
  exact ⟨output, by simpa only [same] using runs, meaning⟩

theorem grant_refuses (value : auths_model.GrantStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Grant value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grantSigningCost value descriptor ≤ Usize.max)
    (outside : ¬ FramedHash.SigningAdmissible (SigningPreimages.grantFrame value descriptor)) :
    hash.grant_signing_preimage value descriptor = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (grant_total value descriptor valid descriptorValid space)
  simpa only [FramedHash.preimage_refused classified outside] using runs

@[step] theorem action_total (value : auths_model.ActionEnvelope)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Action value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : actionSigningCost value descriptor ≤ Usize.max) :
    hash.action_signing_preimage value descriptor ⦃ result =>
      FramedHash.PreimageResult (FramedHash.SigningAdmissible (SigningPreimages.actionFrame value descriptor))
        (Framing.encode (SigningPreimages.actionFrame value descriptor)) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.action_signing_valid value descriptor valid descriptorValid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := (ValidatedWriters.action_strings value valid).profile
  have borrowed : auths_model.ProfileId.as_str value.profile.id = ok (toStr value.profile.id profileBound) := by
    simpa only [auths_model.ProfileId.as_str] using
      StringRefinement.string_borrow_exact value.profile.id profileBound
  have profileBytes := ProtocolWriter.borrowed_bytes value.profile.id profileBound
  unfold hash.action_signing_preimage
  simp only [auths_model.ActionEnvelope.impl.profile, auths_model.ProfileRef.impl.id,
    auths_model.ProfileRef.impl.version, borrowed, encoded,
    core.result.Result.Insts.CoreOpsTry.branch, core.ops.deref.DerefVec, bind_tc_ok]
  simpa only [SigningPreimages.actionFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.deref_exact, profileBytes, payloadBytes] using
    FramedHash.signing_preimage_total .Action (toStr value.profile.id profileBound)
      value.profile.version (alloc.vec.Vec.deref payload)

theorem action_accepts (value : auths_model.ActionEnvelope)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Action value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : actionSigningCost value descriptor ≤ Usize.max)
    (fits : FramedHash.SigningAdmissible (SigningPreimages.actionFrame value descriptor)) :
    ∃ output, hash.action_signing_preimage value descriptor = ok (.Ok output) ∧
      byteList output.val = Framing.encode (SigningPreimages.actionFrame value descriptor) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (action_total value descriptor valid descriptorValid space)
  obtain ⟨output, same, meaning⟩ := FramedHash.preimage_accepted classified fits
  exact ⟨output, by simpa only [same] using runs, meaning⟩

theorem action_refuses (value : auths_model.ActionEnvelope)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Action value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : actionSigningCost value descriptor ≤ Usize.max)
    (outside : ¬ FramedHash.SigningAdmissible (SigningPreimages.actionFrame value descriptor)) :
    hash.action_signing_preimage value descriptor = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (action_total value descriptor valid descriptorValid space)
  simpa only [FramedHash.preimage_refused classified outside] using runs

@[step] theorem principal_status_total (value : auths_model.PrincipalStatusStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.PrincipalStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : principal_statusSigningCost value descriptor ≤ Usize.max) :
    hash.principal_status_signing_preimage value descriptor ⦃ result =>
      FramedHash.PreimageResult (FramedHash.SigningAdmissible (SigningPreimages.principal_statusFrame value descriptor))
        (Framing.encode (SigningPreimages.principal_statusFrame value descriptor)) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.principal_status_signing_valid value descriptor valid descriptorValid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.principal_status_signing_preimage
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  simpa only [SigningPreimages.principal_statusFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.deref_exact, payloadBytes, List.map_nil, UScalar.ofNat_val_eq] using
    FramedHash.signing_preimage_total .PrincipalStatus ⟨[], by scalar_tac⟩ 0#u16 (alloc.vec.Vec.deref payload)

theorem principal_status_accepts (value : auths_model.PrincipalStatusStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.PrincipalStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : principal_statusSigningCost value descriptor ≤ Usize.max)
    (fits : FramedHash.SigningAdmissible (SigningPreimages.principal_statusFrame value descriptor)) :
    ∃ output, hash.principal_status_signing_preimage value descriptor = ok (.Ok output) ∧
      byteList output.val = Framing.encode (SigningPreimages.principal_statusFrame value descriptor) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (principal_status_total value descriptor valid descriptorValid space)
  obtain ⟨output, same, meaning⟩ := FramedHash.preimage_accepted classified fits
  exact ⟨output, by simpa only [same] using runs, meaning⟩

theorem principal_status_refuses (value : auths_model.PrincipalStatusStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.PrincipalStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : principal_statusSigningCost value descriptor ≤ Usize.max)
    (outside : ¬ FramedHash.SigningAdmissible (SigningPreimages.principal_statusFrame value descriptor)) :
    hash.principal_status_signing_preimage value descriptor = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (principal_status_total value descriptor valid descriptorValid space)
  simpa only [FramedHash.preimage_refused classified outside] using runs

@[step] theorem grant_status_total (value : auths_model.GrantStatusStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.GrantStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grant_statusSigningCost value descriptor ≤ Usize.max) :
    hash.grant_status_signing_preimage value descriptor ⦃ result =>
      FramedHash.PreimageResult (FramedHash.SigningAdmissible (SigningPreimages.grant_statusFrame value descriptor))
        (Framing.encode (SigningPreimages.grant_statusFrame value descriptor)) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.grant_status_signing_valid value descriptor valid descriptorValid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.grant_status_signing_preimage
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  simpa only [SigningPreimages.grant_statusFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.deref_exact, payloadBytes, List.map_nil, UScalar.ofNat_val_eq] using
    FramedHash.signing_preimage_total .GrantStatus ⟨[], by scalar_tac⟩ 0#u16 (alloc.vec.Vec.deref payload)

theorem grant_status_accepts (value : auths_model.GrantStatusStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.GrantStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grant_statusSigningCost value descriptor ≤ Usize.max)
    (fits : FramedHash.SigningAdmissible (SigningPreimages.grant_statusFrame value descriptor)) :
    ∃ output, hash.grant_status_signing_preimage value descriptor = ok (.Ok output) ∧
      byteList output.val = Framing.encode (SigningPreimages.grant_statusFrame value descriptor) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (grant_status_total value descriptor valid descriptorValid space)
  obtain ⟨output, same, meaning⟩ := FramedHash.preimage_accepted classified fits
  exact ⟨output, by simpa only [same] using runs, meaning⟩

theorem grant_status_refuses (value : auths_model.GrantStatusStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.GrantStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grant_statusSigningCost value descriptor ≤ Usize.max)
    (outside : ¬ FramedHash.SigningAdmissible (SigningPreimages.grant_statusFrame value descriptor)) :
    hash.grant_status_signing_preimage value descriptor = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (grant_status_total value descriptor valid descriptorValid space)
  simpa only [FramedHash.preimage_refused classified outside] using runs

@[step] theorem approval_total (value : auths_model.approval.ApprovalStatement)
    (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef)
    (valid : ProtocolValidity.Approval value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (profileValid : ProtocolValidity.Profile profileValue)
    (space : approvalSigningCost value descriptor ≤ Usize.max) :
    hash.approval_signing_preimage value descriptor profileValue ⦃ result =>
      FramedHash.PreimageResult (FramedHash.SigningAdmissible (SigningPreimages.approvalFrame value descriptor profileValue))
        (Framing.encode (SigningPreimages.approvalFrame value descriptor profileValue)) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.approval_signing_valid value descriptor valid descriptorValid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := ValidatedWriters.identifier_bound _ 128 profileValid.1 (by scalar_tac)
  have borrowed : auths_model.ProfileId.as_str profileValue.id = ok (toStr profileValue.id profileBound) := by
    simpa only [auths_model.ProfileId.as_str] using
      StringRefinement.string_borrow_exact profileValue.id profileBound
  have profileBytes := ProtocolWriter.borrowed_bytes profileValue.id profileBound
  unfold hash.approval_signing_preimage
  simp only [auths_model.ProfileRef.impl.id,
    auths_model.ProfileRef.impl.version, borrowed, encoded,
    core.result.Result.Insts.CoreOpsTry.branch, core.ops.deref.DerefVec, bind_tc_ok]
  simpa only [SigningPreimages.approvalFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.deref_exact, profileBytes, payloadBytes] using
    FramedHash.signing_preimage_total .Approval (toStr profileValue.id profileBound)
      profileValue.version (alloc.vec.Vec.deref payload)

theorem approval_accepts (value : auths_model.approval.ApprovalStatement)
    (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef)
    (valid : ProtocolValidity.Approval value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (profileValid : ProtocolValidity.Profile profileValue)
    (space : approvalSigningCost value descriptor ≤ Usize.max)
    (fits : FramedHash.SigningAdmissible (SigningPreimages.approvalFrame value descriptor profileValue)) :
    ∃ output, hash.approval_signing_preimage value descriptor profileValue = ok (.Ok output) ∧
      byteList output.val = Framing.encode (SigningPreimages.approvalFrame value descriptor profileValue) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (approval_total value descriptor profileValue valid descriptorValid profileValid space)
  obtain ⟨output, same, meaning⟩ := FramedHash.preimage_accepted classified fits
  exact ⟨output, by simpa only [same] using runs, meaning⟩

theorem approval_refuses (value : auths_model.approval.ApprovalStatement)
    (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef)
    (valid : ProtocolValidity.Approval value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (profileValid : ProtocolValidity.Profile profileValue)
    (space : approvalSigningCost value descriptor ≤ Usize.max)
    (outside : ¬ FramedHash.SigningAdmissible (SigningPreimages.approvalFrame value descriptor profileValue)) :
    hash.approval_signing_preimage value descriptor profileValue = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (approval_total value descriptor profileValue valid descriptorValid profileValid space)
  simpa only [FramedHash.preimage_refused classified outside] using runs

@[step] theorem observation_total (value : auths_model.observation.ObservationStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Observation value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : observationSigningCost value descriptor ≤ Usize.max) :
    hash.observation_signing_preimage value descriptor ⦃ result =>
      FramedHash.PreimageResult (FramedHash.SigningAdmissible (SigningPreimages.observationFrame value descriptor))
        (Framing.encode (SigningPreimages.observationFrame value descriptor)) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.observation_signing_valid value descriptor valid descriptorValid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.observation_signing_preimage
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  simpa only [SigningPreimages.observationFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.deref_exact, payloadBytes, List.map_nil, UScalar.ofNat_val_eq] using
    FramedHash.signing_preimage_total .Observation ⟨[], by scalar_tac⟩ 0#u16 (alloc.vec.Vec.deref payload)

theorem observation_accepts (value : auths_model.observation.ObservationStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Observation value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : observationSigningCost value descriptor ≤ Usize.max)
    (fits : FramedHash.SigningAdmissible (SigningPreimages.observationFrame value descriptor)) :
    ∃ output, hash.observation_signing_preimage value descriptor = ok (.Ok output) ∧
      byteList output.val = Framing.encode (SigningPreimages.observationFrame value descriptor) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (observation_total value descriptor valid descriptorValid space)
  obtain ⟨output, same, meaning⟩ := FramedHash.preimage_accepted classified fits
  exact ⟨output, by simpa only [same] using runs, meaning⟩

theorem observation_refuses (value : auths_model.observation.ObservationStatement)
    (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Observation value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : observationSigningCost value descriptor ≤ Usize.max)
    (outside : ¬ FramedHash.SigningAdmissible (SigningPreimages.observationFrame value descriptor)) :
    hash.observation_signing_preimage value descriptor = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (observation_total value descriptor valid descriptorValid space)
  simpa only [FramedHash.preimage_refused classified outside] using runs

end Auths.Crypto.SigningPreimageResults
