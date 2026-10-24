import Auths.Crypto.EvidenceArrays
import Auths.Codec.CanonicalValues

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SignedObjectWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters
open Auths.Crypto.UnsignedLeaves Auths.Crypto.SigningObjectWriters

/- Exact complete signed-record bytes. A signature is encoded data here;
these results neither verify it nor infer authority from evidence presence.
Independent validity earns field bounds, while the computed envelope accounts
for every intermediate append. Source encodings/results are not premises. -/

structure SignatureStrings (value : auths_model.SignatureEnvelope) : Prop where
  principal : value.descriptor.principal_method.toByteArray.size ≤ U32.max
  verification : value.descriptor.verification_method.toByteArray.size ≤ U32.max
  suite : value.descriptor.suite.toByteArray.size ≤ U32.max

theorem signature_strings_valid (value : auths_model.SignatureEnvelope)
    (valid : ProtocolValidity.Signature value) : SignatureStrings value := by
  obtain ⟨principal, verification, suite⟩ := ValidatedWriters.descriptor_bounds value.descriptor valid.1
  exact ⟨principal, verification, suite⟩

structure GrantStrings (value : auths_model.SignedGrant) : Prop where
  statement : StatementWriters.GrantStrings value.statement
  signature : SignatureStrings value.signature

def grantCost (value : auths_model.SignedGrant) : Nat :=
  27 + StatementWriters.grantCost value.statement + signatureCost value.signature

theorem grant_strings_valid (value : auths_model.SignedGrant) (valid : ProtocolValidity.SignedGrant value) :
    GrantStrings value := {
  statement := ValidatedWriters.grant_strings value.statement valid.1
  signature := signature_strings_valid value.signature valid.2
}

theorem grant_length (value : auths_model.SignedGrant) :
    (UnsignedObjects.signedGrant value).length ≤ grantCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.grant value.statement), (1, UnsignedObjects.signature value.signature)]
  have statement := StatementWriters.grant_length value.statement
  have signature := signature_length_bound value.signature
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [grantCost]
  omega

@[step] theorem grant_exact (self : cbor.Encoder) (value : auths_model.SignedGrant)
    (strings : GrantStrings value) (space : self.output.val.length + grantCost value ≤ Usize.max) :
    encode.encode_signed_grant_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.signedGrant value ⦄ := by
  unfold encode.encode_signed_grant_to
  simp only [grantCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedGrant.impl.statement, bind_tc_ok]
  step with StatementWriters.grant_exact e1 value.statement strings.statement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.grant_length value.statement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedGrant.impl.signature, bind_tc_ok]
  step with UnsignedLeaves.signature_exact e3 value.signature strings.signature.principal strings.signature.verification strings.signature.suite (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := signature_length_bound value.signature
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.signedGrant,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem grant_encoder (value : auths_model.SignedGrant)
    (strings : GrantStrings value) (space : grantCost value ≤ Usize.max) :
    encode.encode_signed_grant value ⦃ result => Encodes (UnsignedObjects.signedGrant value) result ⦄ := by
  unfold encode.encode_signed_grant
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with grant_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem grant_encoder_valid (value : auths_model.SignedGrant)
    (valid : ProtocolValidity.SignedGrant value) (space : grantCost value ≤ Usize.max) :
    encode.encode_signed_grant value ⦃ result => Encodes (UnsignedObjects.signedGrant value) result ⦄ :=
  grant_encoder value (grant_strings_valid value valid) space

structure ActionStrings (value : auths_model.SignedAction) : Prop where
  statement : StatementWriters.ActionStrings value.envelope
  signature : SignatureStrings value.signature

def actionCost (value : auths_model.SignedAction) : Nat :=
  27 + StatementWriters.actionCost value.envelope + signatureCost value.signature

theorem action_strings_valid (value : auths_model.SignedAction) (valid : ProtocolValidity.SignedAction value) :
    ActionStrings value := {
  statement := ValidatedWriters.action_strings value.envelope valid.1
  signature := signature_strings_valid value.signature valid.2
}

theorem action_length (value : auths_model.SignedAction) :
    (UnsignedObjects.signedAction value).length ≤ actionCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.action value.envelope), (1, UnsignedObjects.signature value.signature)]
  have statement := StatementWriters.action_length value.envelope
  have signature := signature_length_bound value.signature
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [actionCost]
  omega

@[step] theorem action_exact (self : cbor.Encoder) (value : auths_model.SignedAction)
    (strings : ActionStrings value) (space : self.output.val.length + actionCost value ≤ Usize.max) :
    encode.encode_signed_action_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.signedAction value ⦄ := by
  unfold encode.encode_signed_action_to
  simp only [actionCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedAction.impl.envelope, bind_tc_ok]
  step with StatementWriters.action_exact e1 value.envelope strings.statement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.action_length value.envelope
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedAction.impl.signature, bind_tc_ok]
  step with UnsignedLeaves.signature_exact e3 value.signature strings.signature.principal strings.signature.verification strings.signature.suite (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := signature_length_bound value.signature
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.signedAction,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem action_encoder (value : auths_model.SignedAction)
    (strings : ActionStrings value) (space : actionCost value ≤ Usize.max) :
    encode.encode_signed_action value ⦃ result => Encodes (UnsignedObjects.signedAction value) result ⦄ := by
  unfold encode.encode_signed_action
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with action_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem action_encoder_valid (value : auths_model.SignedAction)
    (valid : ProtocolValidity.SignedAction value) (space : actionCost value ≤ Usize.max) :
    encode.encode_signed_action value ⦃ result => Encodes (UnsignedObjects.signedAction value) result ⦄ :=
  action_encoder value (action_strings_valid value valid) space

structure PrincipalStatusStrings (value : auths_model.SignedPrincipalStatus) : Prop where
  statement : StatementWriters.PrincipalStatusStrings value.statement
  signature : SignatureStrings value.signature

def principal_statusCost (value : auths_model.SignedPrincipalStatus) : Nat :=
  27 + StatementWriters.principal_statusCost value.statement + signatureCost value.signature

theorem principal_status_strings_valid (value : auths_model.SignedPrincipalStatus) (valid : ProtocolValidity.SignedPrincipalStatus value) :
    PrincipalStatusStrings value := {
  statement := ValidatedWriters.principal_status_strings value.statement valid.1
  signature := signature_strings_valid value.signature valid.2
}

theorem principal_status_length (value : auths_model.SignedPrincipalStatus) :
    (UnsignedObjects.signedPrincipalStatus value).length ≤ principal_statusCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.principalStatus value.statement), (1, UnsignedObjects.signature value.signature)]
  have statement := StatementWriters.principal_status_length value.statement
  have signature := signature_length_bound value.signature
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [principal_statusCost]
  omega

@[step] theorem principal_status_exact (self : cbor.Encoder) (value : auths_model.SignedPrincipalStatus)
    (strings : PrincipalStatusStrings value) (space : self.output.val.length + principal_statusCost value ≤ Usize.max) :
    encode.encode_signed_principal_status_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.signedPrincipalStatus value ⦄ := by
  unfold encode.encode_signed_principal_status_to
  simp only [principal_statusCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedPrincipalStatus.impl.statement, bind_tc_ok]
  step with StatementWriters.principal_status_exact e1 value.statement strings.statement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.principal_status_length value.statement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedPrincipalStatus.impl.signature, bind_tc_ok]
  step with UnsignedLeaves.signature_exact e3 value.signature strings.signature.principal strings.signature.verification strings.signature.suite (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := signature_length_bound value.signature
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.signedPrincipalStatus,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem principal_status_encoder (value : auths_model.SignedPrincipalStatus)
    (strings : PrincipalStatusStrings value) (space : principal_statusCost value ≤ Usize.max) :
    encode.encode_signed_principal_status value ⦃ result => Encodes (UnsignedObjects.signedPrincipalStatus value) result ⦄ := by
  unfold encode.encode_signed_principal_status
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with principal_status_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem principal_status_encoder_valid (value : auths_model.SignedPrincipalStatus)
    (valid : ProtocolValidity.SignedPrincipalStatus value) (space : principal_statusCost value ≤ Usize.max) :
    encode.encode_signed_principal_status value ⦃ result => Encodes (UnsignedObjects.signedPrincipalStatus value) result ⦄ :=
  principal_status_encoder value (principal_status_strings_valid value valid) space

structure GrantStatusStrings (value : auths_model.SignedGrantStatus) : Prop where
  statement : StatementWriters.GrantStatusStrings value.statement
  signature : SignatureStrings value.signature

def grant_statusCost (value : auths_model.SignedGrantStatus) : Nat :=
  27 + StatementWriters.grant_statusCost value.statement + signatureCost value.signature

theorem grant_status_strings_valid (value : auths_model.SignedGrantStatus) (valid : ProtocolValidity.SignedGrantStatus value) :
    GrantStatusStrings value := {
  statement := ValidatedWriters.grant_status_strings value.statement valid.1
  signature := signature_strings_valid value.signature valid.2
}

theorem grant_status_length (value : auths_model.SignedGrantStatus) :
    (UnsignedObjects.signedGrantStatus value).length ≤ grant_statusCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.grantStatus value.statement), (1, UnsignedObjects.signature value.signature)]
  have statement := StatementWriters.grant_status_length value.statement
  have signature := signature_length_bound value.signature
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [grant_statusCost]
  omega

@[step] theorem grant_status_exact (self : cbor.Encoder) (value : auths_model.SignedGrantStatus)
    (strings : GrantStatusStrings value) (space : self.output.val.length + grant_statusCost value ≤ Usize.max) :
    encode.encode_signed_grant_status_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.signedGrantStatus value ⦄ := by
  unfold encode.encode_signed_grant_status_to
  simp only [grant_statusCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedGrantStatus.impl.statement, bind_tc_ok]
  step with StatementWriters.grant_status_exact e1 value.statement strings.statement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.grant_status_length value.statement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignedGrantStatus.impl.signature, bind_tc_ok]
  step with UnsignedLeaves.signature_exact e3 value.signature strings.signature.principal strings.signature.verification strings.signature.suite (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := signature_length_bound value.signature
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.signedGrantStatus,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem grant_status_encoder (value : auths_model.SignedGrantStatus)
    (strings : GrantStatusStrings value) (space : grant_statusCost value ≤ Usize.max) :
    encode.encode_signed_grant_status value ⦃ result => Encodes (UnsignedObjects.signedGrantStatus value) result ⦄ := by
  unfold encode.encode_signed_grant_status
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with grant_status_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem grant_status_encoder_valid (value : auths_model.SignedGrantStatus)
    (valid : ProtocolValidity.SignedGrantStatus value) (space : grant_statusCost value ≤ Usize.max) :
    encode.encode_signed_grant_status value ⦃ result => Encodes (UnsignedObjects.signedGrantStatus value) result ⦄ :=
  grant_status_encoder value (grant_status_strings_valid value valid) space

structure ApprovalStrings (value : auths_model.approval.SignedApproval) : Prop where
  statement : StatementWriters.ApprovalStrings value.statement
  signature : SignatureStrings value.signature
  evidence : ∀ object ∈ value.evidence.val, EvidenceWriters.Strings object

def approvalCost (value : auths_model.approval.SignedApproval) : Nat :=
  36 + StatementWriters.approvalCost value.statement + signatureCost value.signature + EvidenceArrays.cost value.evidence.val

theorem approval_strings_valid (value : auths_model.approval.SignedApproval) (valid : ProtocolValidity.SignedApproval value) :
    ApprovalStrings value := {
  statement := ValidatedWriters.approval_strings value.statement valid.1
  signature := signature_strings_valid value.signature valid.2.1
  evidence := fun object member => EvidenceWriters.strings_valid object (valid.2.2.2.1 object member)
}

theorem approval_length (value : auths_model.approval.SignedApproval) :
    (UnsignedObjects.signedApproval value).length ≤ approvalCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.approval value.statement), (1, UnsignedObjects.signature value.signature), (2, UnsignedWire.array (value.evidence.val.map UnsignedObjects.evidence))]
  have statement := StatementWriters.approval_length value.statement
  have signature := signature_length_bound value.signature
  have evidence := EvidenceArrays.length_bound value.evidence.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [approvalCost]
  omega

@[step] theorem approval_exact (self : cbor.Encoder) (value : auths_model.approval.SignedApproval)
    (strings : ApprovalStrings value) (space : self.output.val.length + approvalCost value ≤ Usize.max) :
    approval.encode_signed_approval_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.signedApproval value ⦄ := by
  unfold approval.encode_signed_approval_to
  simp only [approvalCost, EvidenceArrays.cost] at space
  step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.SignedApproval.impl.statement, bind_tc_ok]
  step with StatementWriters.approval_exact e1 value.statement strings.statement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.approval_length value.statement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.SignedApproval.impl.signature, bind_tc_ok]
  step with UnsignedLeaves.signature_exact e3 value.signature strings.signature.principal strings.signature.verification strings.signature.suite (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := signature_length_bound value.signature
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.SignedApproval.impl.evidence, core.ops.deref.DerefVec, bind_tc_ok]
  step with EvidenceArrays.evidence_exact e5 (alloc.vec.Vec.deref value.evidence) strings.evidence (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation EvidenceWriters.recordCost value.evidence.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := EvidenceArrays.length_bound value.evidence.val
  simp [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.signedApproval,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem approval_encoder (value : auths_model.approval.SignedApproval)
    (strings : ApprovalStrings value) (space : approvalCost value ≤ Usize.max) :
    approval.encode_signed_approval_value value ⦃ result => Encodes (UnsignedObjects.signedApproval value) result ⦄ := by
  unfold approval.encode_signed_approval_value
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with approval_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem approval_encoder_valid (value : auths_model.approval.SignedApproval)
    (valid : ProtocolValidity.SignedApproval value) (space : approvalCost value ≤ Usize.max) :
    approval.encode_signed_approval_value value ⦃ result => Encodes (UnsignedObjects.signedApproval value) result ⦄ :=
  approval_encoder value (approval_strings_valid value valid) space

@[step] theorem approval_canonical_encoder (carrier : canonical_value.Canonical auths_model.approval.SignedApproval)
    (value : auths_model.approval.SignedApproval) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (valid : ProtocolValidity.SignedApproval value) (space : approvalCost value ≤ Usize.max) :
    approval.encode_signed_approval carrier ⦃ result => Encodes (UnsignedObjects.signedApproval value) result ⦄ := by
  unfold approval.encode_signed_approval
  rw [projection]
  simpa only [bind_tc_ok] using approval_encoder_valid value valid space

theorem approval_canonical_projection (carrier : canonical_value.Canonical auths_model.approval.SignedApproval) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (valid : ProtocolValidity.SignedApproval value) (space : approvalCost value ≤ Usize.max),
        approval.encode_signed_approval carrier ⦃ result => Encodes (UnsignedObjects.signedApproval value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun valid space => approval_canonical_encoder carrier value projection valid space⟩

structure ObservationStrings (value : auths_model.observation.SignedObservation) : Prop where
  statement : StatementWriters.ObservationStrings value.statement
  signature : SignatureStrings value.signature
  evidence : ∀ object ∈ value.evidence.val, EvidenceWriters.Strings object

def observationCost (value : auths_model.observation.SignedObservation) : Nat :=
  36 + StatementWriters.observationCost value.statement + signatureCost value.signature + EvidenceArrays.cost value.evidence.val

theorem observation_strings_valid (value : auths_model.observation.SignedObservation) (valid : ProtocolValidity.SignedObservation value) :
    ObservationStrings value := {
  statement := ValidatedWriters.observation_strings value.statement valid.1
  signature := signature_strings_valid value.signature valid.2.1
  evidence := fun object member => EvidenceWriters.strings_valid object (valid.2.2.2.1 object member)
}

theorem observation_length (value : auths_model.observation.SignedObservation) :
    (UnsignedObjects.signedObservation value).length ≤ observationCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.observation value.statement), (1, UnsignedObjects.signature value.signature), (2, UnsignedWire.array (value.evidence.val.map UnsignedObjects.evidence))]
  have statement := StatementWriters.observation_length value.statement
  have signature := signature_length_bound value.signature
  have evidence := EvidenceArrays.length_bound value.evidence.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [observationCost]
  omega

@[step] theorem observation_exact (self : cbor.Encoder) (value : auths_model.observation.SignedObservation)
    (strings : ObservationStrings value) (space : self.output.val.length + observationCost value ≤ Usize.max) :
    observation.encode_signed_observation_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.signedObservation value ⦄ := by
  unfold observation.encode_signed_observation_to
  simp only [observationCost, EvidenceArrays.cost] at space
  step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.SignedObservation.impl.statement, bind_tc_ok]
  step with StatementWriters.observation_exact e1 value.statement strings.statement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.observation_length value.statement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.SignedObservation.impl.signature, bind_tc_ok]
  step with UnsignedLeaves.signature_exact e3 value.signature strings.signature.principal strings.signature.verification strings.signature.suite (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := signature_length_bound value.signature
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.SignedObservation.impl.evidence, core.ops.deref.DerefVec, bind_tc_ok]
  step with EvidenceArrays.evidence_exact e5 (alloc.vec.Vec.deref value.evidence) strings.evidence (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation EvidenceWriters.recordCost value.evidence.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := EvidenceArrays.length_bound value.evidence.val
  simp [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.signedObservation,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem observation_encoder (value : auths_model.observation.SignedObservation)
    (strings : ObservationStrings value) (space : observationCost value ≤ Usize.max) :
    observation.encode_signed_observation_value value ⦃ result => Encodes (UnsignedObjects.signedObservation value) result ⦄ := by
  unfold observation.encode_signed_observation_value
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with observation_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem observation_encoder_valid (value : auths_model.observation.SignedObservation)
    (valid : ProtocolValidity.SignedObservation value) (space : observationCost value ≤ Usize.max) :
    observation.encode_signed_observation_value value ⦃ result => Encodes (UnsignedObjects.signedObservation value) result ⦄ :=
  observation_encoder value (observation_strings_valid value valid) space

@[step] theorem observation_canonical_encoder (carrier : canonical_value.Canonical auths_model.observation.SignedObservation)
    (value : auths_model.observation.SignedObservation) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (valid : ProtocolValidity.SignedObservation value) (space : observationCost value ≤ Usize.max) :
    observation.encode_signed_observation carrier ⦃ result => Encodes (UnsignedObjects.signedObservation value) result ⦄ := by
  unfold observation.encode_signed_observation
  rw [projection]
  simpa only [bind_tc_ok] using observation_encoder_valid value valid space

theorem observation_canonical_projection (carrier : canonical_value.Canonical auths_model.observation.SignedObservation) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (valid : ProtocolValidity.SignedObservation value) (space : observationCost value ≤ Usize.max),
        observation.encode_signed_observation carrier ⦃ result => Encodes (UnsignedObjects.signedObservation value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun valid space => observation_canonical_encoder carrier value projection valid space⟩

end Auths.Crypto.SignedObjectWriters
