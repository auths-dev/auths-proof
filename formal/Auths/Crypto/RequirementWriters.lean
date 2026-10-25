import Auths.Crypto.RequirementLeaves
import Auths.Codec.ProtocolTextWriters
import Auths.Crypto.SigningObjectWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.RequirementWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Codec.ProtocolTextWriters
open Auths.Crypto.UnsignedLeaves Auths.Crypto.RequirementLeaves
open Auths.Crypto.SigningObjectWriters

def ApprovalStrings (value : auths_model.approval.ApprovalRequirement) : Prop :=
  ∀ principal ∈ value.approvers.val, principal.toByteArray.size ≤ U32.max

structure ObservationStrings (value : auths_model.observation.ObservationRequirement) : Prop where
  observer : value.observer_anchor.toByteArray.size ≤ U32.max
  schema : value.schema.toByteArray.size ≤ U32.max
  subject : SubjectStrings value.subject
  conditions : ∀ condition ∈ value.conditions.val, ConditionStrings condition

def approvalCost (value : auths_model.approval.ApprovalRequirement) : Nat :=
  45 + allocation textCost value.approvers.val

def observationCost (value : auths_model.observation.ObservationRequirement) : Nat :=
  90 + value.observer_anchor.toByteArray.size + value.schema.toByteArray.size +
    subjectCost value.subject + allocation conditionCost value.conditions.val

theorem approval_strings_valid (value : auths_model.approval.ApprovalRequirement)
    (valid : ProtocolValidity.ApprovalRequirement value) : ApprovalStrings value := by
  intro principal member
  exact ValidatedWriters.principal_bound principal (valid.2.2.2.2.1 principal member)

theorem observation_strings_valid (value : auths_model.observation.ObservationRequirement)
    (valid : ProtocolValidity.ObservationRequirement value) : ObservationStrings value := by
  rcases valid.1 with ⟨observer, schema, subject, conditions⟩
  exact {
    observer := ValidatedWriters.identifier_bound _ 128 observer (by scalar_tac)
    schema := ValidatedWriters.identifier_bound _ 128 schema (by scalar_tac)
    subject := subject_strings_valid value.subject subject
    conditions := fun condition member => condition_strings_valid condition (conditions condition member)
  }

theorem approval_length (value : auths_model.approval.ApprovalRequirement) :
    (UnsignedObjects.approvalRequirement value).length ≤ approvalCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedWire.array (value.approvers.val.map UnsignedObjects.identifier)),
    (1, UnsignedWire.uint value.threshold.val)]
  have members := array_model_length UnsignedObjects.identifier textCost identifier_length value.approvers.val
  have threshold := UnsignedWire.uint_length value.threshold.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [approvalCost]
  omega

theorem observation_length (value : auths_model.observation.ObservationRequirement) :
    (UnsignedObjects.observationRequirement value).length ≤ observationCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.observer_anchor),
    (1, UnsignedObjects.identifier value.schema), (2, UnsignedObjects.observationSubject value.subject),
    (3, UnsignedWire.uint value.max_age_seconds.val),
    (4, UnsignedWire.array (value.conditions.val.map UnsignedObjects.observationCondition))]
  have observer := identifier_length value.observer_anchor
  have schema := identifier_length value.schema
  have subject := subject_length value.subject
  have age := UnsignedWire.uint_length value.max_age_seconds.val
  have conditions := array_model_length UnsignedObjects.observationCondition conditionCost condition_length value.conditions.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [observationCost]
  omega

theorem approval_cost_valid (value : auths_model.approval.ApprovalRequirement)
    (valid : ProtocolValidity.ApprovalRequirement value) : approvalCost value ≤ 8381 := by
  have members := allocation_bound textCost value.approvers.val 521 (by
    intro principal member
    have principalValid := valid.2.2.2.2.1 principal member
    have bound : principal.toByteArray.size ≤ 512 := principalValid.1.2.1
    simp only [textCost]
    omega)
  have count : value.approvers.val.length ≤ 16 := valid.2.1
  simp only [approvalCost]
  omega

theorem observation_cost_valid (value : auths_model.observation.ObservationRequirement)
    (valid : ProtocolValidity.ObservationRequirement value) : observationCost value ≤ 72311 := by
  rcases valid.1 with ⟨observer, schema, subject, conditions⟩
  have observerBound : value.observer_anchor.toByteArray.size ≤ 128 := observer.2.1
  have schemaBound : value.schema.toByteArray.size ≤ 128 := schema.2.1
  have subjectBound := subject_cost_valid value.subject subject
  have members := allocation_bound conditionCost value.conditions.val 4431
    (fun condition member => condition_cost_valid condition (conditions condition member))
  have count : value.conditions.val.length ≤ 16 := valid.2.2.2.2
  simp only [observationCost]
  omega

private theorem conditions_stopped (self : cbor.Encoder) (values : Slice auths_model.observation.ObservationCondition)
    (position : Std.Usize) (failure : error.CodecError) :
    observation.encode_conditions_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [observation.encode_conditions_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem conditions_suffix (values : Slice auths_model.observation.ObservationCondition) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.observation.ObservationCondition)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ConditionStrings value)
    (space : self.output.val.length + allocation conditionCost rest ≤ Usize.max) :
    observation.encode_conditions_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.observationCondition rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [observation.encode_conditions_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ConditionStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + conditionCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [observation.encode_conditions_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with RequirementLeaves.condition_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := condition_length first
    have tailSpace : after.output.val.length + allocation conditionCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem conditions_exact (self : cbor.Encoder) (values : Slice auths_model.observation.ObservationCondition)
    (fields : ∀ value ∈ values.val, ConditionStrings value)
    (space : self.output.val.length + 9 + allocation conditionCost values.val ≤ Usize.max) :
    observation.encode_conditions self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.observationCondition) ⦄ := by
  unfold observation.encode_conditions
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation conditionCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with conditions_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

@[step] theorem approval_exact (self : cbor.Encoder) (value : auths_model.approval.ApprovalRequirement)
    (strings : ApprovalStrings value) (space : self.output.val.length + approvalCost value ≤ Usize.max) :
    approval.encode_approval_requirement_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.approvalRequirement value ⦄ := by
  unfold approval.encode_approval_requirement_to
  simp only [approvalCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalRequirement.impl.approvers, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.principal_ids_exact e1 (alloc.vec.Vec.deref value.approvers) strings (by simpa only [alloc.vec.deref_exact] using (show e1.output.val.length + 9 + allocation textCost value.approvers.val ≤ Usize.max by omega)) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := array_model_length UnsignedObjects.identifier textCost identifier_length value.approvers.val
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalRequirement.impl.threshold, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e3 value.threshold (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, value.threshold.val⟩
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.approvalRequirement,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem observation_exact (self : cbor.Encoder) (value : auths_model.observation.ObservationRequirement)
    (strings : ObservationStrings value) (space : self.output.val.length + observationCost value ≤ Usize.max) :
    observation.encode_requirement_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.observationRequirement value ⦄ := by
  unfold observation.encode_requirement_to
  simp only [observationCost] at space
  step with ProtocolWriter.map_exact self 5#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 5⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationRequirement.impl.observer_anchor, auths_model.observation.ObserverAnchorId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.observer_anchor strings.observer]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.observer_anchor strings.observer).val.length = value.observer_anchor.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.observer_anchor strings.observer) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.observer_anchor)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationRequirement.impl.schema, auths_model.observation.ObservationSchemaId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.schema strings.schema]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.schema strings.schema).val.length = value.schema.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.schema strings.schema) (by omega) as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.schema)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationRequirement.impl.subject, bind_tc_ok]
  step with RequirementLeaves.subject_exact e5 value.subject strings.subject (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := subject_length value.subject
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationRequirement.impl.max_age_seconds, bind_tc_ok]
  step with ProtocolEncoderState.u32_exact e7 value.max_age_seconds (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := encodeHead_length_le_nine ⟨0, value.max_age_seconds.val⟩
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationRequirement.impl.conditions, core.ops.deref.DerefVec, bind_tc_ok]
  step with conditions_exact e9 (alloc.vec.Vec.deref value.conditions) strings.conditions (by simpa only [alloc.vec.deref_exact] using (show e9.output.val.length + 9 + allocation conditionCost value.conditions.val ≤ Usize.max by omega)) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := array_model_length UnsignedObjects.observationCondition conditionCost condition_length value.conditions.val
  simp [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationRequirement,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem approval_encoder (value : auths_model.approval.ApprovalRequirement)
    (strings : ApprovalStrings value) (space : approvalCost value ≤ Usize.max) :
    approval.encode_approval_requirement value ⦃ result => Encodes (UnsignedObjects.approvalRequirement value) result ⦄ := by
  unfold approval.encode_approval_requirement
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with approval_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem approval_encoder_valid (value : auths_model.approval.ApprovalRequirement)
    (valid : ProtocolValidity.ApprovalRequirement value) (space : approvalCost value ≤ Usize.max) :
    approval.encode_approval_requirement value ⦃ result => Encodes (UnsignedObjects.approvalRequirement value) result ⦄ :=
  approval_encoder value (approval_strings_valid value valid) space

@[step] theorem observation_encoder (value : auths_model.observation.ObservationRequirement)
    (strings : ObservationStrings value) (space : observationCost value ≤ Usize.max) :
    observation.encode_observation_requirement value ⦃ result => Encodes (UnsignedObjects.observationRequirement value) result ⦄ := by
  unfold observation.encode_observation_requirement
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with observation_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value strings
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem observation_encoder_valid (value : auths_model.observation.ObservationRequirement)
    (valid : ProtocolValidity.ObservationRequirement value) (space : observationCost value ≤ Usize.max) :
    observation.encode_observation_requirement value ⦃ result => Encodes (UnsignedObjects.observationRequirement value) result ⦄ :=
  observation_encoder value (observation_strings_valid value valid) space

end Auths.Crypto.RequirementWriters
