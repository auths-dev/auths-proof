import Auths.Crypto.StatementWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SigningObjectWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Crypto.StatementWriters

/- These public source wrappers start from the actual empty encoder and
compose the complete unsigned-statement and descriptor writers. The post-
condition is the independent schema, with no successful encoder, desired
intermediate bytes, trusted descriptor or signature premise supplied. -/

def Encodes (bytes : List Nat)
    (result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError) : Prop :=
  match result with | .Err _ => False | .Ok output => byteList output.val = bytes

theorem encoder_success {bytes : List Nat}
    {effect : Result (core.result.Result (alloc.vec.Vec Std.U8) error.CodecError)}
    (specified : effect ⦃ result => Encodes bytes result ⦄) :
    ∃ output, effect = ok (.Ok output) ∧ byteList output.val = bytes := by
  obtain ⟨result, runs, meaning⟩ := spec_imp_exists specified
  cases result with
  | Err reason => exact False.elim meaning
  | Ok output => exact ⟨output, runs, meaning⟩

@[step] theorem grant_statement_exact (value : auths_model.GrantStatement)
    (strings : GrantStrings value) (space : grantCost value ≤ Usize.max) :
    encode.encode_grant_statement value ⦃ result => Encodes (UnsignedObjects.grant value) result ⦄ := by
  unfold encode.encode_grant_statement
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with StatementWriters.grant_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

def grantSigningCost (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor) : Nat :=
  27 + grantCost value + DescriptorWriter.cost descriptor

@[step] theorem grant_signing_exact (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor)
    (strings : GrantStrings value)
    (principalBound : descriptor.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : descriptor.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : descriptor.suite.toByteArray.size ≤ U32.max)
    (space : grantSigningCost value descriptor ≤ Usize.max) :
    encode.encode_grant_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.grantSigningObject value descriptor) result ⦄ := by
  unfold encode.encode_grant_signing_input
  simp only [grantSigningCost] at space
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with ProtocolWriter.map_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) 2#u64
    (by simp only [alloc.vec.new_contents, List.length_nil]; omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [alloc.vec.new_contents, List.length_nil] at len0
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with StatementWriters.grant_exact e1 value strings (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.grant_length value
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with DescriptorWriter.descriptor_exact e3 descriptor principalBound verificationBound suiteBound (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer, Encodes,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.grantSigningObject,
    UnsignedObjects.signatureDescriptor, UnsignedWire.signingObject,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, byteList,
    alloc.vec.new_contents, List.append_assoc]

@[step] theorem action_statement_exact (value : auths_model.ActionEnvelope)
    (strings : ActionStrings value) (space : actionCost value ≤ Usize.max) :
    encode.encode_action_envelope value ⦃ result => Encodes (UnsignedObjects.action value) result ⦄ := by
  unfold encode.encode_action_envelope
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with StatementWriters.action_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

def actionSigningCost (value : auths_model.ActionEnvelope) (descriptor : auths_model.SignatureDescriptor) : Nat :=
  27 + actionCost value + DescriptorWriter.cost descriptor

@[step] theorem action_signing_exact (value : auths_model.ActionEnvelope) (descriptor : auths_model.SignatureDescriptor)
    (strings : ActionStrings value)
    (principalBound : descriptor.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : descriptor.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : descriptor.suite.toByteArray.size ≤ U32.max)
    (space : actionSigningCost value descriptor ≤ Usize.max) :
    encode.encode_action_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.actionSigningObject value descriptor) result ⦄ := by
  unfold encode.encode_action_signing_input
  simp only [actionSigningCost] at space
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with ProtocolWriter.map_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) 2#u64
    (by simp only [alloc.vec.new_contents, List.length_nil]; omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [alloc.vec.new_contents, List.length_nil] at len0
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with StatementWriters.action_exact e1 value strings (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.action_length value
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with DescriptorWriter.descriptor_exact e3 descriptor principalBound verificationBound suiteBound (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer, Encodes,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.actionSigningObject,
    UnsignedObjects.signatureDescriptor, UnsignedWire.signingObject,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, byteList,
    alloc.vec.new_contents, List.append_assoc]

@[step] theorem principal_status_statement_exact (value : auths_model.PrincipalStatusStatement)
    (strings : PrincipalStatusStrings value) (space : principal_statusCost value ≤ Usize.max) :
    encode.encode_principal_status_statement value ⦃ result => Encodes (UnsignedObjects.principalStatus value) result ⦄ := by
  unfold encode.encode_principal_status_statement
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with StatementWriters.principal_status_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

def principal_statusSigningCost (value : auths_model.PrincipalStatusStatement) (descriptor : auths_model.SignatureDescriptor) : Nat :=
  27 + principal_statusCost value + DescriptorWriter.cost descriptor

@[step] theorem principal_status_signing_exact (value : auths_model.PrincipalStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (strings : PrincipalStatusStrings value)
    (principalBound : descriptor.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : descriptor.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : descriptor.suite.toByteArray.size ≤ U32.max)
    (space : principal_statusSigningCost value descriptor ≤ Usize.max) :
    encode.encode_principal_status_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.principalStatusSigningObject value descriptor) result ⦄ := by
  unfold encode.encode_principal_status_signing_input
  simp only [principal_statusSigningCost] at space
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with ProtocolWriter.map_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) 2#u64
    (by simp only [alloc.vec.new_contents, List.length_nil]; omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [alloc.vec.new_contents, List.length_nil] at len0
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with StatementWriters.principal_status_exact e1 value strings (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.principal_status_length value
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with DescriptorWriter.descriptor_exact e3 descriptor principalBound verificationBound suiteBound (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer, Encodes,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.principalStatusSigningObject,
    UnsignedObjects.signatureDescriptor, UnsignedWire.signingObject,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, byteList,
    alloc.vec.new_contents, List.append_assoc]

@[step] theorem grant_status_statement_exact (value : auths_model.GrantStatusStatement)
    (strings : GrantStatusStrings value) (space : grant_statusCost value ≤ Usize.max) :
    encode.encode_grant_status_statement value ⦃ result => Encodes (UnsignedObjects.grantStatus value) result ⦄ := by
  unfold encode.encode_grant_status_statement
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with StatementWriters.grant_status_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

def grant_statusSigningCost (value : auths_model.GrantStatusStatement) (descriptor : auths_model.SignatureDescriptor) : Nat :=
  27 + grant_statusCost value + DescriptorWriter.cost descriptor

@[step] theorem grant_status_signing_exact (value : auths_model.GrantStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (strings : GrantStatusStrings value)
    (principalBound : descriptor.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : descriptor.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : descriptor.suite.toByteArray.size ≤ U32.max)
    (space : grant_statusSigningCost value descriptor ≤ Usize.max) :
    encode.encode_grant_status_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.grantStatusSigningObject value descriptor) result ⦄ := by
  unfold encode.encode_grant_status_signing_input
  simp only [grant_statusSigningCost] at space
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with ProtocolWriter.map_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) 2#u64
    (by simp only [alloc.vec.new_contents, List.length_nil]; omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [alloc.vec.new_contents, List.length_nil] at len0
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with StatementWriters.grant_status_exact e1 value strings (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.grant_status_length value
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with DescriptorWriter.descriptor_exact e3 descriptor principalBound verificationBound suiteBound (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer, Encodes,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.grantStatusSigningObject,
    UnsignedObjects.signatureDescriptor, UnsignedWire.signingObject,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, byteList,
    alloc.vec.new_contents, List.append_assoc]

@[step] theorem approval_statement_exact (value : auths_model.approval.ApprovalStatement)
    (strings : ApprovalStrings value) (space : approvalCost value ≤ Usize.max) :
    approval.encode_approval_statement value ⦃ result => Encodes (UnsignedObjects.approval value) result ⦄ := by
  unfold approval.encode_approval_statement
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with StatementWriters.approval_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

def approvalSigningCost (value : auths_model.approval.ApprovalStatement) (descriptor : auths_model.SignatureDescriptor) : Nat :=
  27 + approvalCost value + DescriptorWriter.cost descriptor

@[step] theorem approval_signing_exact (value : auths_model.approval.ApprovalStatement) (descriptor : auths_model.SignatureDescriptor)
    (strings : ApprovalStrings value)
    (principalBound : descriptor.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : descriptor.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : descriptor.suite.toByteArray.size ≤ U32.max)
    (space : approvalSigningCost value descriptor ≤ Usize.max) :
    approval.encode_approval_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.approvalSigningObject value descriptor) result ⦄ := by
  unfold approval.encode_approval_signing_input
  simp only [approvalSigningCost] at space
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with ProtocolWriter.map_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) 2#u64
    (by simp only [alloc.vec.new_contents, List.length_nil]; omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [alloc.vec.new_contents, List.length_nil] at len0
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with StatementWriters.approval_exact e1 value strings (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.approval_length value
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with DescriptorWriter.descriptor_exact e3 descriptor principalBound verificationBound suiteBound (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer, Encodes,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.approvalSigningObject,
    UnsignedObjects.signatureDescriptor, UnsignedWire.signingObject,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, byteList,
    alloc.vec.new_contents, List.append_assoc]

@[step] theorem observation_statement_exact (value : auths_model.observation.ObservationStatement)
    (strings : ObservationStrings value) (space : observationCost value ≤ Usize.max) :
    observation.encode_observation_statement value ⦃ result => Encodes (UnsignedObjects.observation value) result ⦄ := by
  unfold observation.encode_observation_statement
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with StatementWriters.observation_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

def observationSigningCost (value : auths_model.observation.ObservationStatement) (descriptor : auths_model.SignatureDescriptor) : Nat :=
  27 + observationCost value + DescriptorWriter.cost descriptor

@[step] theorem observation_signing_exact (value : auths_model.observation.ObservationStatement) (descriptor : auths_model.SignatureDescriptor)
    (strings : ObservationStrings value)
    (principalBound : descriptor.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : descriptor.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : descriptor.suite.toByteArray.size ≤ U32.max)
    (space : observationSigningCost value descriptor ≤ Usize.max) :
    observation.encode_observation_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.observationSigningObject value descriptor) result ⦄ := by
  unfold observation.encode_observation_signing_input
  simp only [observationSigningCost] at space
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with ProtocolWriter.map_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) 2#u64
    (by simp only [alloc.vec.new_contents, List.length_nil]; omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [alloc.vec.new_contents, List.length_nil] at len0
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with StatementWriters.observation_exact e1 value strings (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := StatementWriters.observation_length value
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with DescriptorWriter.descriptor_exact e3 descriptor principalBound verificationBound suiteBound (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer, Encodes,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationSigningObject,
    UnsignedObjects.signatureDescriptor, UnsignedWire.signingObject,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, byteList,
    alloc.vec.new_contents, List.append_assoc]

end Auths.Crypto.SigningObjectWriters
