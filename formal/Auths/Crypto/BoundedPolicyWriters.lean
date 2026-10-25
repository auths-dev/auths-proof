import Auths.Crypto.BoundedPolicyObjects
import Auths.Crypto.SigningObjectWriters
import Auths.Codec.CanonicalValues

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BoundedPolicyWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Crypto.SigningObjectWriters

structure Fields (value : auths_model.bounded_policy.PolicyCommitment) : Prop where
  policy_type : value.policy_type.toByteArray.size ≤ U32.max
  canonicalization : value.canonicalization_id.toByteArray.size ≤ U32.max
  evaluator : value.evaluator_semantic_id.toByteArray.size ≤ U32.max

theorem commitment_length (value : auths_model.bounded_policy.PolicyCommitment) :
    (BoundedPolicyObjects.commitment value).length ≤ BoundedPolicyObjects.commitmentCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.policy_type),
    (1, UnsignedWire.uint value.policy_version.val), (2, UnsignedObjects.identifier value.canonicalization_id),
    (3, UnsignedObjects.digest value.policy_digest), (4, UnsignedObjects.identifier value.evaluator_semantic_id)]
  have policy_type := UnsignedLeaves.identifier_length value.policy_type
  have version := UnsignedWire.uint_length value.policy_version.val
  have canonicalization := UnsignedLeaves.identifier_length value.canonicalization_id
  have digest := UnsignedLeaves.digest_length value.policy_digest
  have evaluator := UnsignedLeaves.identifier_length value.evaluator_semantic_id
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [BoundedPolicyObjects.commitmentCost]
  omega

theorem body_length (value : auths_model.bounded_policy.BoundedPolicyCommitment) :
    (BoundedPolicyObjects.body value).length ≤ BoundedPolicyObjects.bodyCost value := by
  have outer := UnsignedWire.map_length [(0, BoundedPolicyObjects.commitment value.commitment),
    (1, UnsignedWire.bytes (byteList value.policy.val)), (2, UnsignedObjects.optionalDigest value.parent)]
  have commitment := commitment_length value.commitment
  have policy := UnsignedWire.bytes_length (byteList value.policy.val)
  have parent := UnsignedLeaves.optional_digest_length value.parent
  simp only [byteList, List.length_map] at policy
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [BoundedPolicyObjects.bodyCost]
  omega

@[step] theorem commitment_exact (self : cbor.Encoder) (value : auths_model.bounded_policy.PolicyCommitment)
    (fields : Fields value)
    (space : self.output.val.length + BoundedPolicyObjects.commitmentCost value ≤ Usize.max)
    (native : (2 * (self.output.val.length + BoundedPolicyObjects.commitmentCost value) : Int) ≤ Isize.max) :
    bounded_policy.encode_commitment self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ BoundedPolicyObjects.commitment value ⦄ := by
  unfold bounded_policy.encode_commitment
  simp only [BoundedPolicyObjects.commitmentCost] at space
  step with ProtocolWriter.map_exact self 5#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 5⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.PolicyCommitment.impl.policy_type, auths_model.bounded_policy.PolicyIdentifier.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.policy_type fields.policy_type]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.policy_type fields.policy_type).val.length = value.policy_type.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.policy_type fields.policy_type) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.policy_type)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.PolicyCommitment.impl.policy_version, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e3 value.policy_version (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, (value.policy_version).val⟩
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.PolicyCommitment.impl.canonicalization_id, auths_model.bounded_policy.PolicyIdentifier.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.canonicalization_id fields.canonicalization]
  simp only [bind_tc_ok]
  have borrowLength6 : (toStr value.canonicalization_id fields.canonicalization).val.length = value.canonicalization_id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e5 (toStr value.canonicalization_id fields.canonicalization) (by omega) as ⟨r6, e6, ok6, bytes6⟩
  rw [borrowed_bytes] at bytes6
  have len6 := output_length bytes6
  have bound6 := payload_length_bound 3 (stringBytes value.canonicalization_id)
  rw [stringBytes_length] at bound6
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.PolicyCommitment.impl.policy_digest, auths_model.Digest.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e7 value.policy_digest (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := UnsignedLeaves.digest_length value.policy_digest
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.PolicyCommitment.impl.evaluator_semantic_id, auths_model.bounded_policy.PolicyIdentifier.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.evaluator_semantic_id fields.evaluator]
  simp only [bind_tc_ok]
  have borrowLength10 : (toStr value.evaluator_semantic_id fields.evaluator).val.length = value.evaluator_semantic_id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e9 (toStr value.evaluator_semantic_id fields.evaluator) (by omega) as ⟨r10, e10, ok10, bytes10⟩
  rw [borrowed_bytes] at bytes10
  have len10 := output_length bytes10
  have bound10 := payload_length_bound 3 (stringBytes value.evaluator_semantic_id)
  rw [stringBytes_length] at bound10
  simp [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, BoundedPolicyObjects.commitment,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem body_exact (self : cbor.Encoder) (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (fields : Fields value.commitment)
    (space : self.output.val.length + BoundedPolicyObjects.bodyCost value ≤ Usize.max)
    (native : (2 * (self.output.val.length + BoundedPolicyObjects.bodyCost value) : Int) ≤ Isize.max) :
    bounded_policy.encode_bounded_policy_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ BoundedPolicyObjects.body value ⦄ := by
  unfold bounded_policy.encode_bounded_policy_to
  simp only [BoundedPolicyObjects.bodyCost] at space native
  step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.BoundedPolicyCommitment.impl.commitment, bind_tc_ok]
  step with commitment_exact e1 value.commitment fields (by omega) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := commitment_length value.commitment
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.BoundedPolicyCommitment.impl.policy, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolWriter.bytes_exact e3 (alloc.vec.Vec.deref value.policy) (by simpa only [alloc.vec.deref_exact] using (show e3.output.val.length + 9 + value.policy.val.length ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := UnsignedWire.bytes_length (byteList value.policy.val)
  simp only [byteList, List.length_map] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.bounded_policy.BoundedPolicyCommitment.impl.parent, core.option.Option.as_ref, bind_tc_ok]
  step with UnsignedLeaves.optional_digest_exact e5 value.parent (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := UnsignedLeaves.optional_digest_length value.parent
  simp [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, BoundedPolicyObjects.body,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem body_encoder (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (fields : Fields value.commitment) (space : BoundedPolicyObjects.bodyCost value ≤ Usize.max)
    (native : (2 * BoundedPolicyObjects.bodyCost value : Int) ≤ Isize.max) :
    bounded_policy.encode_bounded_policy_commitment_value value ⦃ result => Encodes (BoundedPolicyObjects.body value) result ⦄ := by
  unfold bounded_policy.encode_bounded_policy_commitment_value
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with body_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value fields
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using native)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem canonical_encoder
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (projection : canonical_value.Canonical.as_value carrier = ok value)
    (fields : Fields value.commitment) (space : BoundedPolicyObjects.bodyCost value ≤ Usize.max)
    (native : (2 * BoundedPolicyObjects.bodyCost value : Int) ≤ Isize.max) :
    bounded_policy.encode_bounded_policy_commitment carrier ⦃ result => Encodes (BoundedPolicyObjects.body value) result ⦄ := by
  unfold bounded_policy.encode_bounded_policy_commitment
  rw [projection]
  simpa only [bind_tc_ok] using body_encoder value fields space native

theorem canonical_projection
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (fields : Fields value.commitment) (space : BoundedPolicyObjects.bodyCost value ≤ Usize.max)
        (native : (2 * BoundedPolicyObjects.bodyCost value : Int) ≤ Isize.max),
        bounded_policy.encode_bounded_policy_commitment carrier ⦃ result => Encodes (BoundedPolicyObjects.body value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun fields space native => canonical_encoder carrier value projection fields space native⟩

end Auths.Crypto.BoundedPolicyWriters
