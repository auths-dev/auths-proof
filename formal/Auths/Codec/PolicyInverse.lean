import Auths.Codec.PolicyCanonical
import Auths.Codec.ProtocolPieces
import Auths.Codec.ProtocolCanonical

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyInverse
open Auths.Codec.Refinement Auths.Codec.ProtocolEncoderState Auths.Codec.ProtocolWriter
open Auths.Crypto

/- Independent complete policy schema pieces. Actual primitive reads, parser
and model construction must each earn their state transition. No successful
decoder/constructor, expected cursor or caller-supplied parse flag is assumed. -/
def commitmentParts (value : auths_model.bounded_policy.PolicyCommitment) : List (List Nat) :=
  [encodeHead ⟨5, 5⟩, encodeHead ⟨0, 0⟩, UnsignedObjects.identifier value.policy_type,
    encodeHead ⟨0, 1⟩, UnsignedWire.uint value.policy_version.val,
    encodeHead ⟨0, 2⟩, UnsignedObjects.identifier value.canonicalization_id,
    encodeHead ⟨0, 3⟩, UnsignedObjects.digest value.policy_digest,
    encodeHead ⟨0, 4⟩, UnsignedObjects.identifier value.evaluator_semantic_id]

theorem commitment_parts (value : auths_model.bounded_policy.PolicyCommitment) :
    (commitmentParts value).flatten = BoundedPolicyObjects.commitment value := by
  simp [commitmentParts, BoundedPolicyObjects.commitment, UnsignedWire.map,
    UnsignedWire.entries, UnsignedWire.uint, List.append_assoc]

theorem identifier_wire (value : String) :
    UnsignedObjects.identifier value = payloadEncoding 3 (stringBytes value) := by rfl

theorem digest_wire (value : auths_model.Digest) :
    UnsignedObjects.digest value = payloadEncoding 2 (byteList value.val) := by rfl

@[step] theorem parent_inverse (self : cbor.Decoder) (value : Option auths_model.Digest)
    (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ UnsignedObjects.optionalDigest value ++ trailing)
    (start : self.position.val = leading.length) :
    bounded_policy.parent_digest self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (UnsignedObjects.optionalDigest value).length ∧
      actual.2.input = self.input ⦄ := by
  unfold bounded_policy.parent_digest
  cases value with
  | none =>
    have wire : byteList self.input.val = leading ++ [246] ++ trailing := by
      simpa only [UnsignedObjects.optionalDigest, UnsignedWire.null] using input
    step with ProtocolPrimitiveInverse.null_probe self leading trailing wire start as ⟨probe, probeMeaning⟩
    simp only [probeMeaning, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok, ↓reduceIte]
    step with ProtocolPrimitiveInverse.null_inverse self leading trailing wire start
      as ⟨verdict, next, success, position, sameInput⟩
    simp [success, position, sameInput, core.result.Result.Insts.CoreOpsTry.branch,
      UnsignedObjects.optionalDigest, UnsignedWire.null]
  | some value =>
    have wire : byteList self.input.val = leading ++ payloadEncoding 2 (byteList value.val) ++ trailing := by
      simpa only [UnsignedObjects.optionalDigest, digest_wire] using input
    step with ProtocolPrimitiveInverse.digest_probe self value leading trailing wire start as ⟨probe, probeMeaning⟩
    simp only [probeMeaning, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok, ↓reduceIte]
    step with ProtocolPrimitiveInverse.digest_inverse self value leading trailing wire start
      as ⟨verdict, next, success, position, sameInput⟩
    simp [success, position, sameInput, auths_model.Digest.new,
      core.result.Result.Insts.CoreOpsTry.branch, UnsignedObjects.optionalDigest, digest_wire]

@[step] theorem commitment_inverse (self : cbor.Decoder) (value : auths_model.bounded_policy.PolicyCommitment)
    (valid : PolicyValidity.Commitment value) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ BoundedPolicyObjects.commitment value ++ trailing)
    (start : self.position.val = leading.length) :
    bounded_policy.commitment self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (BoundedPolicyObjects.commitment value).length ∧
      actual.2.input = self.input ⦄ := by
  have fields := PolicyConstructors.fields_valid value valid
  have typeAccept : PolicyValidity.accepts value.policy_type 128 = true :=
    (PolicyValidity.accepts_iff value.policy_type 128).mpr ⟨valid.1.1, valid.2.2.1⟩
  have canonicalizationAccept : PolicyValidity.accepts value.canonicalization_id 64 = true :=
    (PolicyValidity.accepts_iff value.canonicalization_id 64).mpr ⟨valid.1.2.1, valid.2.2.2.1⟩
  have evaluatorAccept : PolicyValidity.accepts value.evaluator_semantic_id 128 = true :=
    (PolicyValidity.accepts_iff value.evaluator_semantic_id 128).mpr ⟨valid.1.2.2, valid.2.2.2.2⟩
  have typeParse : auths_model.bounded_policy.PolicyIdentifier.parse (toStr value.policy_type fields.policy_type) 128#usize = ok (.Ok value.policy_type) := by
    rw [PolicyIdentifiers.parse_exact]
    simp only [typeAccept, Bool.true_eq, ↓reduceIte]
  have canonicalizationParse : auths_model.bounded_policy.PolicyIdentifier.parse
      (toStr value.canonicalization_id fields.canonicalization) 64#usize = ok (.Ok value.canonicalization_id) := by
    rw [PolicyIdentifiers.parse_exact]
    simp only [canonicalizationAccept, Bool.true_eq, ↓reduceIte]
  have evaluatorParse : auths_model.bounded_policy.PolicyIdentifier.parse
      (toStr value.evaluator_semantic_id fields.evaluator) 128#usize = ok (.Ok value.evaluator_semantic_id) := by
    rw [PolicyIdentifiers.parse_exact]
    simp only [evaluatorAccept, Bool.true_eq, ↓reduceIte]
  let pieces := commitmentParts value
  have whole : byteList self.input.val = leading ++ pieces.flatten ++ trailing := by
    simpa only [pieces, commitment_parts] using input
  have at0 : ProtocolPieces.At self.input leading pieces self 0 := ⟨rfl, by simpa [ProtocolPieces.before] using start⟩
  unfold bounded_policy.commitment
  simp only [auths_model.bounded_policy.MAX_POLICY_IDENTIFIER_BYTES,
    auths_model.bounded_policy.MAX_POLICY_CANONICALIZATION_BYTES, bind_tc_ok]
  have piece0 : pieces[0]? = some (encodeHead ⟨5, 5⟩) := rfl
  have input0 := ProtocolPieces.input_piece self.input leading trailing pieces self 0 (encodeHead ⟨5, 5⟩) whole at0 piece0
  step with ProtocolPrimitiveInverse.map_inverse self 5#u64 (leading ++ ProtocolPieces.before pieces 0) (ProtocolPieces.after pieces 0 ++ trailing) input0 (by simpa only [List.length_append] using at0.2) as ⟨r0, d0, ok0, position0, same0⟩
  have at1 : ProtocolPieces.At self.input leading pieces d0 1 :=
    ProtocolPieces.advance self.input leading pieces self d0 0 (encodeHead ⟨5, 5⟩) at0 piece0 position0 same0
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece1 : pieces[1]? = some (encodeHead ⟨0, 0⟩) := rfl
  have input1 := ProtocolPieces.input_piece self.input leading trailing pieces d0 1 (encodeHead ⟨0, 0⟩) whole at1 piece1
  step with ProtocolPrimitiveInverse.key_inverse d0 0#u8 (leading ++ ProtocolPieces.before pieces 1) (ProtocolPieces.after pieces 1 ++ trailing) input1 (by simpa only [List.length_append] using at1.2) as ⟨r1, d1, ok1, position1, same1⟩
  have at2 : ProtocolPieces.At self.input leading pieces d1 2 :=
    ProtocolPieces.advance self.input leading pieces d0 d1 1 (encodeHead ⟨0, 0⟩) at1 piece1 position1 same1
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece2 : pieces[2]? = some (UnsignedObjects.identifier value.policy_type) := rfl
  have input2 := ProtocolPieces.input_piece self.input leading trailing pieces d1 2 (UnsignedObjects.identifier value.policy_type) whole at2 piece2
  rw [identifier_wire value.policy_type] at input2
  step with ProtocolPrimitiveInverse.text_inverse d1 value.policy_type fields.policy_type (leading ++ ProtocolPieces.before pieces 2) (ProtocolPieces.after pieces 2 ++ trailing) input2 (by simpa only [List.length_append] using at2.2) as ⟨r2, d2, ok2, position2, same2⟩
  rw [← identifier_wire value.policy_type] at position2
  have at3 : ProtocolPieces.At self.input leading pieces d2 3 :=
    ProtocolPieces.advance self.input leading pieces d1 d2 2 (UnsignedObjects.identifier value.policy_type) at2 piece2 position2 same2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  simp only [typeParse, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece3 : pieces[3]? = some (encodeHead ⟨0, 1⟩) := rfl
  have input3 := ProtocolPieces.input_piece self.input leading trailing pieces d2 3 (encodeHead ⟨0, 1⟩) whole at3 piece3
  step with ProtocolPrimitiveInverse.key_inverse d2 1#u8 (leading ++ ProtocolPieces.before pieces 3) (ProtocolPieces.after pieces 3 ++ trailing) input3 (by simpa only [List.length_append] using at3.2) as ⟨r3, d3, ok3, position3, same3⟩
  have at4 : ProtocolPieces.At self.input leading pieces d3 4 :=
    ProtocolPieces.advance self.input leading pieces d2 d3 3 (encodeHead ⟨0, 1⟩) at3 piece3 position3 same3
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece4 : pieces[4]? = some (UnsignedWire.uint value.policy_version.val) := rfl
  have input4 := ProtocolPieces.input_piece self.input leading trailing pieces d3 4 (UnsignedWire.uint value.policy_version.val) whole at4 piece4
  step with ProtocolPrimitiveInverse.u16_inverse d3 value.policy_version (leading ++ ProtocolPieces.before pieces 4) (ProtocolPieces.after pieces 4 ++ trailing) input4 (by simpa only [List.length_append] using at4.2) as ⟨r4, d4, ok4, position4, same4⟩
  have at5 : ProtocolPieces.At self.input leading pieces d4 5 :=
    ProtocolPieces.advance self.input leading pieces d3 d4 4 (UnsignedWire.uint value.policy_version.val) at4 piece4 position4 same4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece5 : pieces[5]? = some (encodeHead ⟨0, 2⟩) := rfl
  have input5 := ProtocolPieces.input_piece self.input leading trailing pieces d4 5 (encodeHead ⟨0, 2⟩) whole at5 piece5
  step with ProtocolPrimitiveInverse.key_inverse d4 2#u8 (leading ++ ProtocolPieces.before pieces 5) (ProtocolPieces.after pieces 5 ++ trailing) input5 (by simpa only [List.length_append] using at5.2) as ⟨r5, d5, ok5, position5, same5⟩
  have at6 : ProtocolPieces.At self.input leading pieces d5 6 :=
    ProtocolPieces.advance self.input leading pieces d4 d5 5 (encodeHead ⟨0, 2⟩) at5 piece5 position5 same5
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece6 : pieces[6]? = some (UnsignedObjects.identifier value.canonicalization_id) := rfl
  have input6 := ProtocolPieces.input_piece self.input leading trailing pieces d5 6 (UnsignedObjects.identifier value.canonicalization_id) whole at6 piece6
  rw [identifier_wire value.canonicalization_id] at input6
  step with ProtocolPrimitiveInverse.text_inverse d5 value.canonicalization_id fields.canonicalization (leading ++ ProtocolPieces.before pieces 6) (ProtocolPieces.after pieces 6 ++ trailing) input6 (by simpa only [List.length_append] using at6.2) as ⟨r6, d6, ok6, position6, same6⟩
  rw [← identifier_wire value.canonicalization_id] at position6
  have at7 : ProtocolPieces.At self.input leading pieces d6 7 :=
    ProtocolPieces.advance self.input leading pieces d5 d6 6 (UnsignedObjects.identifier value.canonicalization_id) at6 piece6 position6 same6
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  simp only [canonicalizationParse, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have piece7 : pieces[7]? = some (encodeHead ⟨0, 3⟩) := rfl
  have input7 := ProtocolPieces.input_piece self.input leading trailing pieces d6 7 (encodeHead ⟨0, 3⟩) whole at7 piece7
  step with ProtocolPrimitiveInverse.key_inverse d6 3#u8 (leading ++ ProtocolPieces.before pieces 7) (ProtocolPieces.after pieces 7 ++ trailing) input7 (by simpa only [List.length_append] using at7.2) as ⟨r7, d7, ok7, position7, same7⟩
  have at8 : ProtocolPieces.At self.input leading pieces d7 8 :=
    ProtocolPieces.advance self.input leading pieces d6 d7 7 (encodeHead ⟨0, 3⟩) at7 piece7 position7 same7
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece8 : pieces[8]? = some (UnsignedObjects.digest value.policy_digest) := rfl
  have input8 := ProtocolPieces.input_piece self.input leading trailing pieces d7 8 (UnsignedObjects.digest value.policy_digest) whole at8 piece8
  rw [digest_wire value.policy_digest] at input8
  step with ProtocolPrimitiveInverse.digest_inverse d7 value.policy_digest (leading ++ ProtocolPieces.before pieces 8) (ProtocolPieces.after pieces 8 ++ trailing) input8 (by simpa only [List.length_append] using at8.2) as ⟨r8, d8, ok8, position8, same8⟩
  rw [← digest_wire value.policy_digest] at position8
  have at9 : ProtocolPieces.At self.input leading pieces d8 9 :=
    ProtocolPieces.advance self.input leading pieces d7 d8 8 (UnsignedObjects.digest value.policy_digest) at8 piece8 position8 same8
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  simp only [auths_model.Digest.new, bind_tc_ok]
  have piece9 : pieces[9]? = some (encodeHead ⟨0, 4⟩) := rfl
  have input9 := ProtocolPieces.input_piece self.input leading trailing pieces d8 9 (encodeHead ⟨0, 4⟩) whole at9 piece9
  step with ProtocolPrimitiveInverse.key_inverse d8 4#u8 (leading ++ ProtocolPieces.before pieces 9) (ProtocolPieces.after pieces 9 ++ trailing) input9 (by simpa only [List.length_append] using at9.2) as ⟨r9, d9, ok9, position9, same9⟩
  have at10 : ProtocolPieces.At self.input leading pieces d9 10 :=
    ProtocolPieces.advance self.input leading pieces d8 d9 9 (encodeHead ⟨0, 4⟩) at9 piece9 position9 same9
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece10 : pieces[10]? = some (UnsignedObjects.identifier value.evaluator_semantic_id) := rfl
  have input10 := ProtocolPieces.input_piece self.input leading trailing pieces d9 10 (UnsignedObjects.identifier value.evaluator_semantic_id) whole at10 piece10
  rw [identifier_wire value.evaluator_semantic_id] at input10
  step with ProtocolPrimitiveInverse.text_inverse d9 value.evaluator_semantic_id fields.evaluator (leading ++ ProtocolPieces.before pieces 10) (ProtocolPieces.after pieces 10 ++ trailing) input10 (by simpa only [List.length_append] using at10.2) as ⟨r10, d10, ok10, position10, same10⟩
  rw [← identifier_wire value.evaluator_semantic_id] at position10
  have at11 : ProtocolPieces.At self.input leading pieces d10 11 :=
    ProtocolPieces.advance self.input leading pieces d9 d10 10 (UnsignedObjects.identifier value.evaluator_semantic_id) at10 piece10 position10 same10
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  simp only [evaluatorParse, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    PolicyConstructors.commitment_valid_exact value valid, core.result.Result.map_err, BuiltinFnOnce]
  have complete := ProtocolPieces.final_position self.input leading pieces d10 (by simpa [pieces, commitmentParts] using at11)
  simp only [pieces, commitment_parts] at complete
  exact ⟨rfl, complete, at11.1⟩


def bodyParts (value : auths_model.bounded_policy.BoundedPolicyCommitment) : List (List Nat) :=
  [encodeHead ⟨5, 3⟩, encodeHead ⟨0, 0⟩, BoundedPolicyObjects.commitment value.commitment,
    encodeHead ⟨0, 1⟩, UnsignedWire.bytes (byteList value.policy.val),
    encodeHead ⟨0, 2⟩, UnsignedObjects.optionalDigest value.parent]

theorem body_parts (value : auths_model.bounded_policy.BoundedPolicyCommitment) :
    (bodyParts value).flatten = BoundedPolicyObjects.body value := by
  simp [bodyParts, BoundedPolicyObjects.body, UnsignedWire.map,
    UnsignedWire.entries, UnsignedWire.uint, List.append_assoc]

theorem extension_limit : auths_model.HARD_MAX_EXTENSION_BYTES = ok (65536#usize) := by rfl

@[step] theorem decode_encoding [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256)
    (input : Slice Std.U8) (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body value) (wire : byteList input.val = BoundedPolicyObjects.body value) :
    bounded_policy.decode_bounded_policy_commitment input ⦃ result =>
      result = if PolicyValidity.Opening sha256 value then .Ok ⟨value⟩ else .Err .DigestMismatch ⦄ := by
  have inputLength : input.val.length = (BoundedPolicyObjects.body value).length := by
    simpa only [byteList, List.length_map] using congrArg List.length wire
  have resources := PolicyConstructors.body_resources value valid
  have within : ¬ 65536#usize < input.len := by
    simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
    omega
  obtain ⟨encoded, encoderRun, encodedBytes⟩ := SigningObjectWriters.encoder_success
    (PolicyConstructors.body_encoder_valid value valid)
  have sameBytes : encoded.val = input.val := ProtocolPrimitiveInverse.bytes_injective (encodedBytes.trans wire.symm)
  unfold bounded_policy.decode_bounded_policy_commitment
  simp only [extension_limit, bind_tc_ok, within, ↓reduceIte]
  step with ProtocolCursor.new_exact input as ⟨decoder, decoderInput, decoderPosition⟩
  let self := decoder
  let leading : List Nat := []
  let trailing : List Nat := []
  let pieces := bodyParts value
  have whole : byteList self.input.val = leading ++ pieces.flatten ++ trailing := by
    simpa only [self, leading, trailing, List.nil_append, List.append_nil, decoderInput, pieces, body_parts] using wire
  have at0 : ProtocolPieces.At self.input leading pieces self 0 :=
    ⟨rfl, by simpa [self, leading, ProtocolPieces.before] using decoderPosition⟩
  simp only [auths_model.bounded_policy.MAX_BOUNDED_POLICY_BYTES, bind_tc_ok]
  have piece0 : pieces[0]? = some (encodeHead ⟨5, 3⟩) := rfl
  have input0 := ProtocolPieces.input_piece self.input leading trailing pieces self 0 (encodeHead ⟨5, 3⟩) whole at0 piece0
  step with ProtocolPrimitiveInverse.map_inverse self 3#u64 (leading ++ ProtocolPieces.before pieces 0) (ProtocolPieces.after pieces 0 ++ trailing) input0 (by simpa only [List.length_append] using at0.2) as ⟨r0, d0, ok0, position0, same0⟩
  have at1 : ProtocolPieces.At self.input leading pieces d0 1 :=
    ProtocolPieces.advance self.input leading pieces self d0 0 (encodeHead ⟨5, 3⟩) at0 piece0 position0 same0
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece1 : pieces[1]? = some (encodeHead ⟨0, 0⟩) := rfl
  have input1 := ProtocolPieces.input_piece self.input leading trailing pieces d0 1 (encodeHead ⟨0, 0⟩) whole at1 piece1
  step with ProtocolPrimitiveInverse.key_inverse d0 0#u8 (leading ++ ProtocolPieces.before pieces 1) (ProtocolPieces.after pieces 1 ++ trailing) input1 (by simpa only [List.length_append] using at1.2) as ⟨r1, d1, ok1, position1, same1⟩
  have at2 : ProtocolPieces.At self.input leading pieces d1 2 :=
    ProtocolPieces.advance self.input leading pieces d0 d1 1 (encodeHead ⟨0, 0⟩) at1 piece1 position1 same1
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece2 : pieces[2]? = some (BoundedPolicyObjects.commitment value.commitment) := rfl
  have input2 := ProtocolPieces.input_piece self.input leading trailing pieces d1 2 (BoundedPolicyObjects.commitment value.commitment) whole at2 piece2
  step with commitment_inverse d1 value.commitment valid.1 (leading ++ ProtocolPieces.before pieces 2) (ProtocolPieces.after pieces 2 ++ trailing) input2 (by simpa only [List.length_append] using at2.2) as ⟨r2, d2, ok2, position2, same2⟩
  have at3 : ProtocolPieces.At self.input leading pieces d2 3 :=
    ProtocolPieces.advance self.input leading pieces d1 d2 2 (BoundedPolicyObjects.commitment value.commitment) at2 piece2 position2 same2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece3 : pieces[3]? = some (encodeHead ⟨0, 1⟩) := rfl
  have input3 := ProtocolPieces.input_piece self.input leading trailing pieces d2 3 (encodeHead ⟨0, 1⟩) whole at3 piece3
  step with ProtocolPrimitiveInverse.key_inverse d2 1#u8 (leading ++ ProtocolPieces.before pieces 3) (ProtocolPieces.after pieces 3 ++ trailing) input3 (by simpa only [List.length_append] using at3.2) as ⟨r3, d3, ok3, position3, same3⟩
  have at4 : ProtocolPieces.At self.input leading pieces d3 4 :=
    ProtocolPieces.advance self.input leading pieces d2 d3 3 (encodeHead ⟨0, 1⟩) at3 piece3 position3 same3
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece4 : pieces[4]? = some (UnsignedWire.bytes (byteList value.policy.val)) := rfl
  have input4 := ProtocolPieces.input_piece self.input leading trailing pieces d3 4 (UnsignedWire.bytes (byteList value.policy.val)) whole at4 piece4
  step with ProtocolPrimitiveInverse.bytes_inverse d3 4096#usize false value.policy (leading ++ ProtocolPieces.before pieces 4) (ProtocolPieces.after pieces 4 ++ trailing) input4 (by simpa only [List.length_append] using at4.2) (by simp) valid.2.2 (by have bound := valid.2.2; scalar_tac) as ⟨r4, d4, ok4, position4, same4⟩
  have at5 : ProtocolPieces.At self.input leading pieces d4 5 :=
    ProtocolPieces.advance self.input leading pieces d3 d4 4 (UnsignedWire.bytes (byteList value.policy.val)) at4 piece4 position4 same4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece5 : pieces[5]? = some (encodeHead ⟨0, 2⟩) := rfl
  have input5 := ProtocolPieces.input_piece self.input leading trailing pieces d4 5 (encodeHead ⟨0, 2⟩) whole at5 piece5
  step with ProtocolPrimitiveInverse.key_inverse d4 2#u8 (leading ++ ProtocolPieces.before pieces 5) (ProtocolPieces.after pieces 5 ++ trailing) input5 (by simpa only [List.length_append] using at5.2) as ⟨r5, d5, ok5, position5, same5⟩
  have at6 : ProtocolPieces.At self.input leading pieces d5 6 :=
    ProtocolPieces.advance self.input leading pieces d4 d5 5 (encodeHead ⟨0, 2⟩) at5 piece5 position5 same5
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have piece6 : pieces[6]? = some (UnsignedObjects.optionalDigest value.parent) := rfl
  have input6 := ProtocolPieces.input_piece self.input leading trailing pieces d5 6 (UnsignedObjects.optionalDigest value.parent) whole at6 piece6
  step with parent_inverse d5 value.parent (leading ++ ProtocolPieces.before pieces 6) (ProtocolPieces.after pieces 6 ++ trailing) input6 (by simpa only [List.length_append] using at6.2) as ⟨r6, d6, ok6, position6, same6⟩
  have at7 : ProtocolPieces.At self.input leading pieces d6 7 :=
    ProtocolPieces.advance self.input leading pieces d5 d6 6 (UnsignedObjects.optionalDigest value.parent) at6 piece6 position6 same6
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    BuiltinFnOnce, bind_tc_ok]
  have complete := ProtocolPieces.final_position self.input leading pieces d6
    (by simpa [pieces, bodyParts] using at7)
  have finished : d6.position.val = input.val.length := by
    simp only [leading, List.length_nil, Nat.zero_add, pieces, body_parts] at complete
    omega
  step with ProtocolCursor.ensure_complete_exact d6 input as ⟨verdict, completeMeaning⟩
  rw [if_pos finished] at completeMeaning
  simp only [completeMeaning, PolicyConstructors.body_valid_exact value valid,
    core.result.Result.map_err, BuiltinFnOnce, core.result.Result.Insts.CoreOpsTry.branch,
    encoderRun, bind_tc_ok]
  step with ProtocolCanonical.accept_exact input encoded value as ⟨accepted, acceptedMeaning⟩
  rw [if_pos sameBytes] at acceptedMeaning
  simp only [acceptedMeaning, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  rw [PolicyCanonical.checked_exact sha256 contract value valid]
  simp only [spec_ok]

@[step] theorem public_roundtrip [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256)
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : PolicyValidity.Body carrier.value) (opened : PolicyValidity.Opening sha256 carrier.value) :
    bounded_policy.encode_bounded_policy_commitment carrier ⦃ encoded =>
      match encoded with
      | .Err _ => False
      | .Ok bytes => bounded_policy.decode_bounded_policy_commitment (alloc.vec.Vec.deref bytes)
          ⦃ decoded => decoded = .Ok carrier ⦄ ⦄ := by
  obtain ⟨space, native, length⟩ := PolicyConstructors.body_resources carrier.value valid
  apply spec_mono (BoundedPolicyWriters.canonical_encoder carrier carrier.value rfl
    (PolicyConstructors.fields_valid carrier.value.commitment valid.1) space native)
  intro encoded bytesMeaning
  cases encoded with
  | Err reason => exact False.elim bytesMeaning
  | Ok bytes =>
    apply spec_mono (decode_encoding sha256 contract (alloc.vec.Vec.deref bytes) carrier.value valid
      (by simpa only [alloc.vec.deref_exact] using bytesMeaning))
    intro decoded meaning
    simpa only [if_pos opened] using meaning

end Auths.Codec.PolicyInverse
