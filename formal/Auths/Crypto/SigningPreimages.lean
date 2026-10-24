import Auths.Crypto.ValidatedWriters
import Auths.Crypto.SigningCallers

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SigningPreimages
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Crypto.StatementWriters Auths.Crypto.SigningObjectWriters

/- Complete source-caller-to-independent-preimage consequences. The model
validity and capacity conditions are input predicates. Actual caller success
is explicit; neither an expected signing-object encoding nor a desired
intermediate preimage is supplied. SHA/signature security is not used. -/

theorem encoded_payload {model : List Nat}
    {effect : Result (core.result.Result (alloc.vec.Vec Std.U8) error.CodecError)}
    (specified : effect ⦃ result => Encodes model result ⦄)
    (payload : alloc.vec.Vec Std.U8) (accepted : effect = ok (.Ok payload)) :
    byteList payload.val = model := by
  obtain ⟨actual, runs, meaning⟩ := spec_imp_exists specified
  have same : actual = .Ok payload := Result.ok.inj (runs.symm.trans accepted)
  simpa only [same, Encodes] using meaning

theorem profile_borrow_bytes (value : auths_model.ProfileId) (borrowed : Str)
    (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : auths_model.ProfileId.as_str value = ok borrowed) :
    borrowed.val.map UScalar.val = UnsignedObjects.utf8 value := by
  have expected : auths_model.ProfileId.as_str value = ok (toStr value bounded) := by
    simpa only [auths_model.ProfileId.as_str] using StringRefinement.string_borrow_exact value bounded
  have same : borrowed = toStr value bounded := Result.ok.inj (accepted.symm.trans expected)
  rw [same]
  exact ProtocolWriter.borrowed_bytes value bounded

def grantFrame (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor) : Framing.Frame :=
  ⟨1, UnsignedObjects.utf8 value.profile.id, value.profile.version.val, UnsignedObjects.grantSigningObject value descriptor⟩

theorem grant_exact (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Grant value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grantSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.grant_signing_preimage value descriptor = ok (.Ok output)) :
    byteList output.val = Framing.encode (grantFrame value descriptor) := by
  obtain ⟨profile, payload, borrowed, encoded, framed, exactFrame⟩ :=
    SigningCallers.grant_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.grant_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := (ValidatedWriters.grant_strings value valid).profile
  have profileBytes := profile_borrow_bytes value.profile.id profile profileBound borrowed
  simpa only [grantFrame, byteList, profileBytes, payloadBytes] using exactFrame

theorem grant_frame_valid (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Grant value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grantSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.grant_signing_preimage value descriptor = ok (.Ok output)) :
    (grantFrame value descriptor).Valid := by
  obtain ⟨profile, payload, borrowed, encoded, framed, _⟩ :=
    SigningCallers.grant_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.grant_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := (ValidatedWriters.grant_strings value valid).profile
  have profileBytes := profile_borrow_bytes value.profile.id profile profileBound borrowed
  have frameValid := ProtocolFraming.accepted_frame_valid _ _ _ _ output framed
  simpa only [grantFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, profileBytes, payloadBytes] using frameValid

def actionFrame (value : auths_model.ActionEnvelope) (descriptor : auths_model.SignatureDescriptor) : Framing.Frame :=
  ⟨2, UnsignedObjects.utf8 value.profile.id, value.profile.version.val, UnsignedObjects.actionSigningObject value descriptor⟩

theorem action_exact (value : auths_model.ActionEnvelope) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Action value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : actionSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.action_signing_preimage value descriptor = ok (.Ok output)) :
    byteList output.val = Framing.encode (actionFrame value descriptor) := by
  obtain ⟨profile, payload, borrowed, encoded, framed, exactFrame⟩ :=
    SigningCallers.action_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.action_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := (ValidatedWriters.action_strings value valid).profile
  have profileBytes := profile_borrow_bytes value.profile.id profile profileBound borrowed
  simpa only [actionFrame, byteList, profileBytes, payloadBytes] using exactFrame

theorem action_frame_valid (value : auths_model.ActionEnvelope) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Action value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : actionSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.action_signing_preimage value descriptor = ok (.Ok output)) :
    (actionFrame value descriptor).Valid := by
  obtain ⟨profile, payload, borrowed, encoded, framed, _⟩ :=
    SigningCallers.action_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.action_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := (ValidatedWriters.action_strings value valid).profile
  have profileBytes := profile_borrow_bytes value.profile.id profile profileBound borrowed
  have frameValid := ProtocolFraming.accepted_frame_valid _ _ _ _ output framed
  simpa only [actionFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, profileBytes, payloadBytes] using frameValid

def principal_statusFrame (value : auths_model.PrincipalStatusStatement) (descriptor : auths_model.SignatureDescriptor) : Framing.Frame :=
  ⟨3, [], 0, UnsignedObjects.principalStatusSigningObject value descriptor⟩

theorem principal_status_exact (value : auths_model.PrincipalStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.PrincipalStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : principal_statusSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.principal_status_signing_preimage value descriptor = ok (.Ok output)) :
    byteList output.val = Framing.encode (principal_statusFrame value descriptor) := by
  obtain ⟨payload, encoded, framed, exactFrame⟩ :=
    SigningCallers.principal_status_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.principal_status_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  simpa only [principal_statusFrame, byteList, payloadBytes] using exactFrame

theorem principal_status_frame_valid (value : auths_model.PrincipalStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.PrincipalStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : principal_statusSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.principal_status_signing_preimage value descriptor = ok (.Ok output)) :
    (principal_statusFrame value descriptor).Valid := by
  obtain ⟨payload, encoded, framed, _⟩ := SigningCallers.principal_status_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.principal_status_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have frameValid := ProtocolFraming.accepted_frame_valid _ _ _ _ output framed
  simpa only [principal_statusFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, payloadBytes,
    List.map_nil, UScalar.ofNat_val_eq] using frameValid

def grant_statusFrame (value : auths_model.GrantStatusStatement) (descriptor : auths_model.SignatureDescriptor) : Framing.Frame :=
  ⟨4, [], 0, UnsignedObjects.grantStatusSigningObject value descriptor⟩

theorem grant_status_exact (value : auths_model.GrantStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.GrantStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grant_statusSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.grant_status_signing_preimage value descriptor = ok (.Ok output)) :
    byteList output.val = Framing.encode (grant_statusFrame value descriptor) := by
  obtain ⟨payload, encoded, framed, exactFrame⟩ :=
    SigningCallers.grant_status_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.grant_status_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  simpa only [grant_statusFrame, byteList, payloadBytes] using exactFrame

theorem grant_status_frame_valid (value : auths_model.GrantStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.GrantStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grant_statusSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.grant_status_signing_preimage value descriptor = ok (.Ok output)) :
    (grant_statusFrame value descriptor).Valid := by
  obtain ⟨payload, encoded, framed, _⟩ := SigningCallers.grant_status_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.grant_status_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have frameValid := ProtocolFraming.accepted_frame_valid _ _ _ _ output framed
  simpa only [grant_statusFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, payloadBytes,
    List.map_nil, UScalar.ofNat_val_eq] using frameValid

def approvalFrame (value : auths_model.approval.ApprovalStatement) (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef) : Framing.Frame :=
  ⟨10, UnsignedObjects.utf8 profileValue.id, profileValue.version.val, UnsignedObjects.approvalSigningObject value descriptor⟩

theorem approval_exact (value : auths_model.approval.ApprovalStatement) (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef)
    (valid : ProtocolValidity.Approval value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (profileValid : ProtocolValidity.Profile profileValue)
    (space : approvalSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.approval_signing_preimage value descriptor profileValue = ok (.Ok output)) :
    byteList output.val = Framing.encode (approvalFrame value descriptor profileValue) := by
  obtain ⟨profile, payload, borrowed, encoded, framed, exactFrame⟩ :=
    SigningCallers.approval_trace value descriptor profileValue output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.approval_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := ValidatedWriters.identifier_bound _ 128 profileValid.1 (by scalar_tac)
  have profileBytes := profile_borrow_bytes profileValue.id profile profileBound borrowed
  simpa only [approvalFrame, byteList, profileBytes, payloadBytes] using exactFrame

theorem approval_frame_valid (value : auths_model.approval.ApprovalStatement) (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef)
    (valid : ProtocolValidity.Approval value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (profileValid : ProtocolValidity.Profile profileValue)
    (space : approvalSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.approval_signing_preimage value descriptor profileValue = ok (.Ok output)) :
    (approvalFrame value descriptor profileValue).Valid := by
  obtain ⟨profile, payload, borrowed, encoded, framed, _⟩ :=
    SigningCallers.approval_trace value descriptor profileValue output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.approval_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have profileBound := ValidatedWriters.identifier_bound _ 128 profileValid.1 (by scalar_tac)
  have profileBytes := profile_borrow_bytes profileValue.id profile profileBound borrowed
  have frameValid := ProtocolFraming.accepted_frame_valid _ _ _ _ output framed
  simpa only [approvalFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, profileBytes, payloadBytes] using frameValid

def observationFrame (value : auths_model.observation.ObservationStatement) (descriptor : auths_model.SignatureDescriptor) : Framing.Frame :=
  ⟨9, [], 0, UnsignedObjects.observationSigningObject value descriptor⟩

theorem observation_exact (value : auths_model.observation.ObservationStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Observation value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : observationSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.observation_signing_preimage value descriptor = ok (.Ok output)) :
    byteList output.val = Framing.encode (observationFrame value descriptor) := by
  obtain ⟨payload, encoded, framed, exactFrame⟩ :=
    SigningCallers.observation_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.observation_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  simpa only [observationFrame, byteList, payloadBytes] using exactFrame

theorem observation_frame_valid (value : auths_model.observation.ObservationStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Observation value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : observationSigningCost value descriptor ≤ Usize.max) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.observation_signing_preimage value descriptor = ok (.Ok output)) :
    (observationFrame value descriptor).Valid := by
  obtain ⟨payload, encoded, framed, _⟩ := SigningCallers.observation_trace value descriptor output accepted
  have payloadBytes := encoded_payload
    (ValidatedWriters.observation_signing_valid value descriptor valid descriptorValid space) payload encoded
  change payload.val.map UScalar.val = _ at payloadBytes
  have frameValid := ProtocolFraming.accepted_frame_valid _ _ _ _ output framed
  simpa only [observationFrame, ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, payloadBytes,
    List.map_nil, UScalar.ofNat_val_eq] using frameValid

end Auths.Crypto.SigningPreimages
