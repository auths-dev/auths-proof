import Auths.Crypto.ValidatedWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.EvidenceWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Crypto.SigningObjectWriters

structure Strings (value : auths_model.EvidenceObject) : Prop where
  evidenceType : value.evidence_type.toByteArray.size ≤ U32.max
  mediaType : value.media_type.toByteArray.size ≤ U32.max

def contentCost (value : auths_model.EvidenceObject) : Nat :=
  63 + value.evidence_type.toByteArray.size + value.media_type.toByteArray.size + value.bytes.val.length

def recordCost (value : auths_model.EvidenceObject) : Nat :=
  113 + value.evidence_type.toByteArray.size + value.media_type.toByteArray.size + value.bytes.val.length

theorem strings_valid (value : auths_model.EvidenceObject) (valid : ProtocolValidity.Evidence value) :
    Strings value :=
  ⟨ValidatedWriters.identifier_bound _ 128 valid.1 (by scalar_tac),
    ValidatedWriters.identifier_bound _ 128 valid.2.1 (by scalar_tac)⟩

theorem content_length (value : auths_model.EvidenceObject) :
    (UnsignedObjects.evidenceContent value).length ≤ contentCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.evidence_type), (1, UnsignedObjects.identifier value.media_type), (2, UnsignedWire.bytes (value.bytes.val.map UScalar.val))]
  have bound0 := UnsignedWire.text_length (UnsignedObjects.utf8 value.evidence_type)
  have bound1 := UnsignedWire.text_length (UnsignedObjects.utf8 value.media_type)
  have bound2 := UnsignedWire.bytes_length (value.bytes.val.map UScalar.val)
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  simp only [UnsignedObjects.identifier, UnsignedObjects.utf8, List.length_map,
    ByteArray.length_toList] at *
  change (UnsignedWire.map _).length ≤ _
  simp only [contentCost]
  omega

@[step] theorem content_exact (self : cbor.Encoder) (value : auths_model.EvidenceObject)
    (strings : Strings value) (space : self.output.val.length + contentCost value ≤ Usize.max) :
    encode.encode_evidence_content_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.evidenceContent value ⦄ := by
  unfold encode.encode_evidence_content_to
  simp only [contentCost] at space
  step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.EvidenceObject.impl.evidence_type, auths_model.EvidenceTypeId.as_str]
  rw [StringRefinement.string_borrow_exact value.evidence_type strings.evidenceType]
  simp only [bind_tc_ok]
  have stringLength0 : (toStr value.evidence_type strings.evidenceType).val.length =
      value.evidence_type.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.evidence_type strings.evidenceType) (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.evidence_type)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.EvidenceObject.impl.media_type, auths_model.MediaType.as_str]
  rw [StringRefinement.string_borrow_exact value.media_type strings.mediaType]
  simp only [bind_tc_ok]
  have stringLength1 : (toStr value.media_type strings.mediaType).val.length =
      value.media_type.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.media_type strings.mediaType) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.media_type)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.EvidenceObject.impl.bytes, core.ops.deref.DerefVec]
  step with ProtocolWriter.bytes_exact e5 (alloc.vec.Vec.deref value.bytes) (by
    simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + (9 + value.bytes.val.length) ≤ Usize.max by omega))
    as ⟨r6, e6, ok6, bytes6⟩
  simp [ok6, core.result.Result.Insts.CoreOpsTry.branch,
    bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.evidenceContent, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, UnsignedWire.bytes, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, List.append_assoc]

theorem record_length (value : auths_model.EvidenceObject) :
    (UnsignedObjects.evidence value).length ≤ recordCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.digest value.id), (1, UnsignedObjects.identifier value.evidence_type), (2, UnsignedObjects.identifier value.media_type), (3, UnsignedWire.bytes (value.bytes.val.map UScalar.val))]
  have bound0 := UnsignedLeaves.digest_length value.id
  have bound1 := UnsignedWire.text_length (UnsignedObjects.utf8 value.evidence_type)
  have bound2 := UnsignedWire.text_length (UnsignedObjects.utf8 value.media_type)
  have bound3 := UnsignedWire.bytes_length (value.bytes.val.map UScalar.val)
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  simp only [UnsignedObjects.identifier, UnsignedObjects.utf8, List.length_map,
    ByteArray.length_toList] at *
  change (UnsignedWire.map _).length ≤ _
  simp only [recordCost]
  omega

@[step] theorem record_exact (self : cbor.Encoder) (value : auths_model.EvidenceObject)
    (strings : Strings value) (space : self.output.val.length + recordCost value ≤ Usize.max) :
    encode.encode_evidence self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.evidence value ⦄ := by
  unfold encode.encode_evidence
  simp only [recordCost] at space
  step with ProtocolWriter.map_exact self 4#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 4⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.EvidenceObject.impl.id, auths_model.EvidenceId.as_bytes]
  step with UnsignedLeaves.digest_exact e1 value.id (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := UnsignedLeaves.digest_length value.id
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.EvidenceObject.impl.evidence_type, auths_model.EvidenceTypeId.as_str]
  rw [StringRefinement.string_borrow_exact value.evidence_type strings.evidenceType]
  simp only [bind_tc_ok]
  have stringLength1 : (toStr value.evidence_type strings.evidenceType).val.length =
      value.evidence_type.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.evidence_type strings.evidenceType) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.evidence_type)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.EvidenceObject.impl.media_type, auths_model.MediaType.as_str]
  rw [StringRefinement.string_borrow_exact value.media_type strings.mediaType]
  simp only [bind_tc_ok]
  have stringLength2 : (toStr value.media_type strings.mediaType).val.length =
      value.media_type.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e5 (toStr value.media_type strings.mediaType) (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  rw [borrowed_bytes] at bytes6
  have len6 := output_length bytes6
  have bound6 := payload_length_bound 3 (stringBytes value.media_type)
  rw [stringBytes_length] at bound6
  simp only [ok6, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.EvidenceObject.impl.bytes, core.ops.deref.DerefVec]
  step with ProtocolWriter.bytes_exact e7 (alloc.vec.Vec.deref value.bytes) (by
    simpa only [alloc.vec.deref_exact] using (show e7.output.val.length + (9 + value.bytes.val.length) ≤ Usize.max by omega))
    as ⟨r8, e8, ok8, bytes8⟩
  simp [ok8, core.result.Result.Insts.CoreOpsTry.branch,
    bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.evidence, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, UnsignedWire.bytes, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, List.append_assoc]

@[step] theorem content_encoder (value : auths_model.EvidenceObject)
    (strings : Strings value) (space : contentCost value ≤ Usize.max) :
    encode.encode_evidence_content value ⦃ result => Encodes (UnsignedObjects.evidenceContent value) result ⦄ := by
  unfold encode.encode_evidence_content
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with content_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem content_encoder_valid (value : auths_model.EvidenceObject)
    (valid : ProtocolValidity.Evidence value) (space : contentCost value ≤ Usize.max) :
    encode.encode_evidence_content value ⦃ result => Encodes (UnsignedObjects.evidenceContent value) result ⦄ :=
  content_encoder value (strings_valid value valid) space

-- Content identifiers deliberately exclude the declared identifier field.
-- The complete record writer above includes it and preserves it exactly.
theorem content_ignores_declared_id (value : auths_model.EvidenceObject) (identifier : auths_model.EvidenceId) :
    UnsignedObjects.evidenceContent { value with id := identifier } = UnsignedObjects.evidenceContent value := rfl

end Auths.Crypto.EvidenceWriters
