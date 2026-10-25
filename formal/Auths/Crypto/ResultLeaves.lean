import Auths.Crypto.ResultObjects
import Auths.Crypto.ContextLimits
import Auths.Crypto.ContextAssurance
import Auths.Crypto.BundleLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ResultLeaves
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

/- Actual closed tags, stable code labels, resource words and byte leaves.
These writer equations do not imply that a reported outcome came from the
verifier, that its code agrees with its decision, or that its digest opens. -/

@[step] theorem decision_tag_exact (value : auths_model.VerificationDecision) :
    encode.verification_decision_tag value ⦃ actual => actual.val = ResultObjects.decision value ⦄ := by
  cases value <;> simp [encode.verification_decision_tag, ResultObjects.decision, spec_ok]

@[step] theorem stage_tag_exact (value : auths_model.VerificationStage) :
    encode.verification_stage_tag value ⦃ actual => actual.val = ResultObjects.stage value ⦄ := by
  cases value <;> simp [encode.verification_stage_tag, ResultObjects.stage, spec_ok]

@[step] theorem code_class_tag_exact (value : auths_model.VerificationCode) :
    encode.verification_code_class value ⦃ actual => actual.val = ResultObjects.codeClass value ⦄ := by
  cases value <;> simp [encode.verification_code_class, ResultObjects.codeClass, spec_ok]

@[step] theorem code_label_exact (value : auths_model.VerificationCode) :
    auths_model.VerificationCode.code value ⦃ actual =>
      byteList actual.val = UnsignedObjects.utf8 (ResultObjects.codeLabel value) ⦄ := by
  cases value with
  | Authorized =>
    simp [auths_model.VerificationCode.code, ResultObjects.codeLabel,
      UnsignedObjects.utf8, byteList, spec_ok]
  | Denied reason =>
    cases reason <;>
      simp [auths_model.VerificationCode.code, auths_model.DenialReason.code,
        ResultObjects.codeLabel, ResultObjects.denialLabel, UnsignedObjects.utf8, byteList, spec_ok]
  | Indeterminate requirement =>
    cases requirement <;>
      simp [auths_model.VerificationCode.code, auths_model.Requirement.code,
        ResultObjects.codeLabel, ResultObjects.requirementLabel, UnsignedObjects.utf8, byteList, spec_ok]

theorem code_length (value : auths_model.VerificationCode) :
    (ResultObjects.code value).length ≤ ResultObjects.codeCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedWire.uint (ResultObjects.codeClass value)),
    (1, UnsignedObjects.identifier (ResultObjects.codeLabel value))]
  have class := UnsignedWire.uint_length (ResultObjects.codeClass value)
  have label := UnsignedLeaves.identifier_length (ResultObjects.codeLabel value)
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ResultObjects.codeCost]
  omega

@[step] theorem code_exact (self : cbor.Encoder) (value : auths_model.VerificationCode)
    (space : self.output.val.length + ResultObjects.codeCost value ≤ Usize.max) :
    encode.encode_verification_code self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.code value ⦄ := by
  unfold encode.encode_verification_code
  simp only [ResultObjects.codeCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with code_class_tag_exact value as ⟨class, classMeaning⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e1 class (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (class).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with code_label_exact value as ⟨label, labelMeaning⟩
  have labelLength : label.val.length = (ResultObjects.codeLabel value).toByteArray.size := by
    have length := congrArg List.length labelMeaning
    simpa only [byteList, List.length_map, UnsignedLeaves.utf8_length] using length
  step with ProtocolWriter.text_exact e3 label (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := UnsignedWire.text_length (UnsignedObjects.utf8 (ResultObjects.codeLabel value))
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.code, classMeaning, labelMeaning,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem timestamp_length (value : Option auths_model.Timestamp) : (ResultObjects.optionalTime value).length ≤ 9 := by
  cases value with
  | none => simp [ResultObjects.optionalTime, UnsignedWire.null]
  | some value => exact UnsignedWire.uint_length value.val

@[step] theorem timestamp_exact (self : cbor.Encoder) (value : Option auths_model.Timestamp)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    encode.encode_optional_timestamp self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.optionalTime value ⦄ := by
  unfold encode.encode_optional_timestamp
  cases value with
  | none =>
    step with ProtocolEncoderState.null_exact self (by omega) as ⟨after, written⟩
    simpa [ResultObjects.optionalTime, UnsignedWire.null] using written
  | some value =>
    simp only [auths_model.Timestamp.get, bind_tc_ok]
    step with ProtocolEncoderState.u64_exact self value space as ⟨verdict, after, success, written⟩
    simp [success, written, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      ResultObjects.optionalTime, UnsignedWire.uint]

@[step] theorem role_exact (self : cbor.Encoder) (value : auths_model.ParticipantRole)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    encode.encode_role self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedWire.uint (ContextObjects.role value) ⦄ := by
  unfold encode.encode_role
  step with ContextAssurance.role_tag_exact value as ⟨tag, tagMeaning⟩
  step with ProtocolEncoderState.u8_exact self tag space as ⟨verdict, after, success, written⟩
  simp [success, written, tagMeaning, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, UnsignedWire.uint]

theorem self_digest_length (include : Bool) (value : auths_model.VerificationResultDigest) :
    (ResultObjects.selfDigest include value).length ≤ 41 := by
  cases include with
  | false =>
    have bytes := UnsignedWire.bytes_length (List.replicate 32 0)
    simpa only [ResultObjects.selfDigest, Bool.false_eq_true, ↓reduceIte, List.length_replicate] using bytes
  | true => exact UnsignedLeaves.digest_length value

@[step] theorem self_digest_exact (self : cbor.Encoder) (value : auths_model.VerificationResultDigest)
    (include : Bool) (space : self.output.val.length + 41 ≤ Usize.max) :
    encode.encode_result_digest self value include ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.selfDigest include value ⦄ := by
  unfold encode.encode_result_digest
  cases include with
  | false =>
    change (do
      let result ← encode.bytes self ⟨List.replicate 32 0#u8, by scalar_tac⟩
      match result.1 with
      | .Err reason => ok (.Err reason, result.2)
      | .Ok () => ok (.Ok (), result.2)) ⦃ actual => _ ⦄
    step with ProtocolWriter.bytes_exact self ⟨List.replicate 32 0#u8, by scalar_tac⟩
      (by simpa only [List.length_replicate] using space)
      as ⟨verdict, after, success, written⟩
    simp [success, written, ResultObjects.selfDigest, byteList, List.map_replicate,
      payloadEncoding, UnsignedWire.bytes]
  | true =>
    simp only [auths_model.VerificationResultDigest.as_bytes, lift, bind_tc_ok]
    apply spec_mono (UnsignedLeaves.digest_exact self value space)
    rintro actual ⟨success, written⟩
    simp [success, written, ResultObjects.selfDigest, core.result.Result.Insts.CoreOpsTry.branch]

theorem optional_configuration_borrow (value : Option auths_model.VerifierConfigurationId) :
    (match value with
      | none => ok none
      | some identifier => do
          let bytes ← auths_model.VerifierConfigurationId.as_bytes identifier
          ok (some bytes)) = ok value := by cases value <;> rfl

@[step] theorem resource_entry_exact (self : cbor.Encoder) (index : Std.U8) (value : Std.U64)
    (space : self.output.val.length + 18 ≤ Usize.max) :
    encode.encode_unsigned_entry self index value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextLimits.entry index.val value.val ⦄ := by
  unfold encode.encode_unsigned_entry
  step with ProtocolWriter.key_exact self index (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨0, index.val⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e0 value (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, (value).val⟩
  simp [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes1, bytes0, ContextLimits.entry,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem resources_length (value : auths_model.VerificationResources) : (ResultObjects.resources value).length ≤ 135 := by
  have outer := UnsignedWire.map_length (ContextObjects.numbered 0 (ResultObjects.resourceValues value))
  have fields := ContextLimits.numbered_budget 0 (ResultObjects.resourceValues value)
  simp only [ResultObjects.resourceValues, List.length_cons, List.length_nil] at fields
  change (UnsignedWire.map _).length ≤ _
  omega

@[step] theorem resources_exact (self : cbor.Encoder) (value : auths_model.VerificationResources)
    (space : self.output.val.length + 135 ≤ Usize.max) :
    encode.encode_verification_resources self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.resources value ⦄ := by
  unfold encode.encode_verification_resources
  step with ProtocolWriter.map_exact self 7#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 7⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerificationResources.impl.proof_bytes, bind_tc_ok]
  step with resource_entry_exact e0 0#u8 value.proof_bytes (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := ContextLimits.entry_length 0 value.proof_bytes.val
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerificationResources.impl.action_bytes, bind_tc_ok]
  step with resource_entry_exact e1 1#u8 value.action_bytes (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := ContextLimits.entry_length 1 value.action_bytes.val
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerificationResources.impl.context_bytes, bind_tc_ok]
  step with resource_entry_exact e2 2#u8 value.context_bytes (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := ContextLimits.entry_length 2 value.context_bytes.val
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerificationResources.impl.object_count, bind_tc_ok]
  step with resource_entry_exact e3 3#u8 value.object_count (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := ContextLimits.entry_length 3 value.object_count.val
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerificationResources.impl.plan_leaves, bind_tc_ok]
  step with resource_entry_exact e4 4#u8 value.plan_leaves (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := ContextLimits.entry_length 4 value.plan_leaves.val
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerificationResources.impl.plan_depth, bind_tc_ok]
  step with resource_entry_exact e5 5#u8 value.plan_depth (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := ContextLimits.entry_length 5 value.plan_depth.val
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerificationResources.impl.work_units, bind_tc_ok]
  step with resource_entry_exact e6 6#u8 value.work_units (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := ContextLimits.entry_length 6 value.work_units.val
  simp [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.resources, ResultObjects.resourceValues, ContextObjects.numbered, ContextLimits.entry,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

private theorem proof_refs_stopped (self : cbor.Encoder) (values : Slice auths_model.ProofRef)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_proof_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_proof_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem proof_refs_suffix (values : Slice auths_model.ProofRef) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.ProofRef)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, (fun _ => True) value)
    (space : self.output.val.length + allocation (fun _ => 41) rest ≤ Usize.max) :
    encode.encode_proof_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.digest rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_proof_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, (fun _ => True) value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + (fun _ => 41) first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_proof_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    simp only [auths_model.ProofRef.as_bytes, lift, Array.to_slice, bind_tc_ok]
    step with UnsignedLeaves.digest_exact self first firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := digest_length first
    have tailSpace : after.output.val.length + allocation (fun _ => 41) tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem proof_refs_exact (self : cbor.Encoder) (values : Slice auths_model.ProofRef)
    (space : self.output.val.length + 9 + allocation (fun _ => 41) values.val ≤ Usize.max) :
    encode.encode_proof_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.digest) ⦄ := by
  unfold encode.encode_proof_refs
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation (fun _ => 41) values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with proof_refs_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) (by simp) loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

end Auths.Crypto.ResultLeaves
