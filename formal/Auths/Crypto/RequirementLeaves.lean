import Auths.Codec.ProtocolArrayWriters
import Auths.Crypto.ValidatedWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.RequirementLeaves
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Crypto.UnsignedLeaves

def SubjectStrings : auths_model.observation.ObservationSubject → Prop
  | .Resource value => value.toByteArray.size ≤ U32.max
  | .ActionFact name => name.toByteArray.size ≤ U32.max

def subjectCost : auths_model.observation.ObservationSubject → Nat
  | .Resource value => 45 + value.toByteArray.size
  | .ActionFact name => 45 + name.toByteArray.size

def TestStrings : auths_model.observation.ConditionTest → Prop
  | .EqLiteral value => FactValueStrings value
  | .EqAction name => name.toByteArray.size ≤ U32.max
  | .UintRange _ => True
  | .Member values => ∀ value ∈ values.val, FactValueStrings value

def ConditionStrings (value : auths_model.observation.ObservationCondition) : Prop :=
  value.name.toByteArray.size ≤ U32.max ∧ TestStrings value.test

def tailCost : auths_model.observation.ConditionTest → Nat
  | .EqLiteral value => factValueCost value
  | .EqAction name => 9 + name.toByteArray.size
  | .UintRange _ => 27
  | .Member values => 9 + allocation factValueCost values.val

def conditionCost (value : auths_model.observation.ObservationCondition) : Nat :=
  54 + value.name.toByteArray.size + tailCost value.test

theorem subject_strings_valid (value : auths_model.observation.ObservationSubject)
    (valid : ProtocolValidity.ObservationSubject value) : SubjectStrings value := by
  cases value with
  | Resource value => exact ValidatedWriters.identifier_bound _ 1024 valid (by scalar_tac)
  | ActionFact name => exact ValidatedWriters.identifier_bound _ 128 valid (by scalar_tac)

theorem test_strings_valid (value : auths_model.observation.ConditionTest)
    (valid : ProtocolValidity.ConditionTest value) : TestStrings value := by
  cases value with
  | EqLiteral value => exact ValidatedWriters.fact_value_strings value valid
  | EqAction name => exact ValidatedWriters.identifier_bound _ 128 valid (by scalar_tac)
  | UintRange range => trivial
  | Member values =>
    exact fun value member => ValidatedWriters.fact_value_strings value (valid.2.2.2 value member)

theorem condition_strings_valid (value : auths_model.observation.ObservationCondition)
    (valid : ProtocolValidity.Condition value) : ConditionStrings value :=
  ⟨ValidatedWriters.identifier_bound _ 128 valid.1 (by scalar_tac), test_strings_valid value.test valid.2⟩

theorem subject_length (value : auths_model.observation.ObservationSubject) :
    (UnsignedObjects.observationSubject value).length ≤ subjectCost value := by
  cases value with
  | Resource value =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 0), (1, UnsignedObjects.identifier value)]
    have tag := UnsignedWire.uint_length 0
    have text := identifier_length value
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ _
    simp only [subjectCost]
    omega
  | ActionFact name =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 1), (1, UnsignedObjects.identifier name)]
    have tag := UnsignedWire.uint_length 1
    have text := identifier_length name
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ _
    simp only [subjectCost]
    omega

theorem condition_length (value : auths_model.observation.ObservationCondition) :
    (UnsignedObjects.observationCondition value).length ≤ conditionCost value := by
  cases branch : value.test with
  | EqLiteral literal =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 0),
      (1, UnsignedObjects.identifier value.name), (2, UnsignedObjects.factValue literal)]
    have tag := UnsignedWire.uint_length 0
    have name := identifier_length value.name
    have item := fact_value_length_bound literal
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    simp only [UnsignedObjects.observationCondition, branch, conditionCost, tailCost]
    omega
  | EqAction name =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 1),
      (1, UnsignedObjects.identifier value.name), (2, UnsignedObjects.identifier name)]
    have tag := UnsignedWire.uint_length 1
    have field := identifier_length value.name
    have item := identifier_length name
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    simp only [UnsignedObjects.observationCondition, branch, conditionCost, tailCost]
    omega
  | UintRange range =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 2),
      (1, UnsignedObjects.identifier value.name), (2, UnsignedWire.uint range.lo.val),
      (3, UnsignedWire.uint range.hi.val)]
    have tag := UnsignedWire.uint_length 2
    have name := identifier_length value.name
    have lo := UnsignedWire.uint_length range.lo.val
    have hi := UnsignedWire.uint_length range.hi.val
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    simp only [UnsignedObjects.observationCondition, branch, conditionCost, tailCost]
    omega
  | Member values =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 3),
      (1, UnsignedObjects.identifier value.name),
      (2, UnsignedWire.array (values.val.map UnsignedObjects.factValue))]
    have tag := UnsignedWire.uint_length 3
    have name := identifier_length value.name
    have items := array_model_length UnsignedObjects.factValue factValueCost fact_value_length_bound values.val
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    simp only [UnsignedObjects.observationCondition, branch, conditionCost, tailCost]
    omega

theorem fact_cost_valid (value : auths_model.observation.FactValue)
    (valid : ProtocolValidity.FactValue value) : factValueCost value ≤ 265 := by
  cases value with
  | Uint value => simp [factValueCost]
  | Bytes bytes =>
    change 9 + bytes.val.length ≤ 265
    have bound : bytes.val.length ≤ 64 := valid
    omega
  | Text text =>
    change 9 + text.toByteArray.size ≤ 265
    have bound : text.toByteArray.size ≤ 256 := valid
    omega

theorem tail_cost_valid (value : auths_model.observation.ConditionTest)
    (valid : ProtocolValidity.ConditionTest value) : tailCost value ≤ 4249 := by
  cases value with
  | EqLiteral literal =>
    have bound := fact_cost_valid literal valid
    simpa only [tailCost] using (show factValueCost literal ≤ 4249 by omega)
  | EqAction name =>
    have bound : name.toByteArray.size ≤ 128 := valid.2.1
    simp only [tailCost]
    omega
  | UintRange range => simp [tailCost]
  | Member values =>
    have bound := allocation_bound factValueCost values.val 265
      (fun value member => fact_cost_valid value (valid.2.2.2 value member))
    have count : values.val.length ≤ 16 := valid.2.1
    simp only [tailCost]
    omega

theorem condition_cost_valid (value : auths_model.observation.ObservationCondition)
    (valid : ProtocolValidity.Condition value) : conditionCost value ≤ 4431 := by
  have name : value.name.toByteArray.size ≤ 128 := valid.1.2.1
  have tail := tail_cost_valid value.test valid.2
  simp only [conditionCost]
  omega

theorem subject_cost_valid (value : auths_model.observation.ObservationSubject)
    (valid : ProtocolValidity.ObservationSubject value) : subjectCost value ≤ 1069 := by
  cases value with
  | Resource value =>
    have bound : value.toByteArray.size ≤ 1024 := valid.2.1
    simp only [subjectCost]
    omega
  | ActionFact name =>
    have bound : name.toByteArray.size ≤ 128 := valid.2.1
    simp only [subjectCost]
    omega

private theorem member_values_stopped (self : cbor.Encoder) (values : Slice auths_model.observation.FactValue)
    (position : Std.Usize) (failure : error.CodecError) :
    observation.encode_member_values_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [observation.encode_member_values_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem member_values_suffix (values : Slice auths_model.observation.FactValue) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.observation.FactValue)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, FactValueStrings value)
    (space : self.output.val.length + allocation factValueCost rest ≤ Usize.max) :
    observation.encode_member_values_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.factValue rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [observation.encode_member_values_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, FactValueStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + factValueCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [observation.encode_member_values_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with UnsignedLeaves.fact_value_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := fact_value_length_bound first
    have tailSpace : after.output.val.length + allocation factValueCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem member_values_exact (self : cbor.Encoder) (values : Slice auths_model.observation.FactValue)
    (fields : ∀ value ∈ values.val, FactValueStrings value)
    (space : self.output.val.length + 9 + allocation factValueCost values.val ≤ Usize.max) :
    observation.encode_member_values self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.factValue) ⦄ := by
  unfold observation.encode_member_values
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation factValueCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with member_values_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

@[step] theorem subject_exact (self : cbor.Encoder) (value : auths_model.observation.ObservationSubject)
    (strings : SubjectStrings value) (space : self.output.val.length + subjectCost value ≤ Usize.max) :
    observation.encode_observation_subject self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.observationSubject value ⦄ := by
  cases value with
  | Resource text =>
    unfold observation.encode_observation_subject
    simp only [subjectCost] at space
    step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e1 0#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.ResourceId.as_str]
    rw [StringRefinement.string_borrow_exact text strings]
    simp only [bind_tc_ok]
    have borrowLength4 : (toStr text strings).val.length = text.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e3 (toStr text strings) (by omega) as ⟨r4, e4, ok4, bytes4⟩
    rw [borrowed_bytes] at bytes4
    have len4 := output_length bytes4
    have bound4 := payload_length_bound 3 (stringBytes text)
    rw [stringBytes_length] at bound4
    simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationSubject,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | ActionFact text =>
    unfold observation.encode_observation_subject
    simp only [subjectCost] at space
    step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e1 1#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.FactName.as_str]
    rw [StringRefinement.string_borrow_exact text strings]
    simp only [bind_tc_ok]
    have borrowLength4 : (toStr text strings).val.length = text.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e3 (toStr text strings) (by omega) as ⟨r4, e4, ok4, bytes4⟩
    rw [borrowed_bytes] at bytes4
    have len4 := output_length bytes4
    have bound4 := payload_length_bound 3 (stringBytes text)
    rw [stringBytes_length] at bound4
    simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationSubject,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem condition_exact (self : cbor.Encoder) (value : auths_model.observation.ObservationCondition)
    (strings : ConditionStrings value) (space : self.output.val.length + conditionCost value ≤ Usize.max) :
    observation.encode_condition self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.observationCondition value ⦄ := by
  cases branch : value.test with
  | EqLiteral literal =>
    unfold observation.encode_condition
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, bind_tc_ok]
    simp only [conditionCost, branch, tailCost] at space
    have branchStrings : FactValueStrings literal := by simpa only [TestStrings, branch] using strings.2
    step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e1 0#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.name, auths_model.observation.FactName.as_str, bind_tc_ok]
    rw [StringRefinement.string_borrow_exact value.name strings.1]
    simp only [bind_tc_ok]
    have borrowLength4 : (toStr value.name strings.1).val.length = value.name.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e3 (toStr value.name strings.1) (by omega) as ⟨r4, e4, ok4, bytes4⟩
    rw [borrowed_bytes] at bytes4
    have len4 := output_length bytes4
    have bound4 := payload_length_bound 3 (stringBytes value.name)
    rw [stringBytes_length] at bound4
    simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
    have len5 := output_length bytes5
    have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
    simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, bind_tc_ok]
    step with UnsignedLeaves.fact_value_exact e5 literal branchStrings (by omega) as ⟨r6, e6, ok6, bytes6⟩
    have len6 := output_length bytes6
    have bound6 := fact_value_length_bound literal
    simp [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationCondition, branch,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | EqAction name =>
    unfold observation.encode_condition
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, bind_tc_ok]
    simp only [conditionCost, branch, tailCost] at space
    have branchStrings : name.toByteArray.size ≤ U32.max := by simpa only [TestStrings, branch] using strings.2
    step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e1 1#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.name, auths_model.observation.FactName.as_str, bind_tc_ok]
    rw [StringRefinement.string_borrow_exact value.name strings.1]
    simp only [bind_tc_ok]
    have borrowLength4 : (toStr value.name strings.1).val.length = value.name.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e3 (toStr value.name strings.1) (by omega) as ⟨r4, e4, ok4, bytes4⟩
    rw [borrowed_bytes] at bytes4
    have len4 := output_length bytes4
    have bound4 := payload_length_bound 3 (stringBytes value.name)
    rw [stringBytes_length] at bound4
    simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
    have len5 := output_length bytes5
    have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
    simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, auths_model.observation.FactName.as_str, bind_tc_ok]
    rw [StringRefinement.string_borrow_exact name branchStrings]
    simp only [bind_tc_ok]
    have borrowLength6 : (toStr name branchStrings).val.length = name.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e5 (toStr name branchStrings) (by omega) as ⟨r6, e6, ok6, bytes6⟩
    rw [borrowed_bytes] at bytes6
    have len6 := output_length bytes6
    have bound6 := payload_length_bound 3 (stringBytes name)
    rw [stringBytes_length] at bound6
    simp [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationCondition, branch,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | UintRange range =>
    unfold observation.encode_condition
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, bind_tc_ok]
    simp only [conditionCost, branch, tailCost] at space
    have branchStrings : True := by simpa only [TestStrings, branch] using strings.2
    step with ProtocolWriter.map_exact self 4#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 4⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e1 2#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 2⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.name, auths_model.observation.FactName.as_str, bind_tc_ok]
    rw [StringRefinement.string_borrow_exact value.name strings.1]
    simp only [bind_tc_ok]
    have borrowLength4 : (toStr value.name strings.1).val.length = value.name.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e3 (toStr value.name strings.1) (by omega) as ⟨r4, e4, ok4, bytes4⟩
    rw [borrowed_bytes] at bytes4
    have len4 := output_length bytes4
    have bound4 := payload_length_bound 3 (stringBytes value.name)
    rw [stringBytes_length] at bound4
    simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
    have len5 := output_length bytes5
    have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
    simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, auths_model.observation.UintRange.impl.lo, bind_tc_ok]
    step with ProtocolEncoderState.u64_exact e5 range.lo (by omega) as ⟨r6, e6, ok6, bytes6⟩
    have len6 := output_length bytes6
    have bound6 := encodeHead_length_le_nine ⟨0, range.lo.val⟩
    simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
    have len7 := output_length bytes7
    have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
    simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.UintRange.impl.hi, bind_tc_ok]
    step with ProtocolEncoderState.u64_exact e7 range.hi (by omega) as ⟨r8, e8, ok8, bytes8⟩
    have len8 := output_length bytes8
    have bound8 := encodeHead_length_le_nine ⟨0, range.hi.val⟩
    simp [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationCondition, branch,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | Member values =>
    unfold observation.encode_condition
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, bind_tc_ok]
    simp only [conditionCost, branch, tailCost] at space
    have branchStrings : ∀ value ∈ values.val, FactValueStrings value := by simpa only [TestStrings, branch] using strings.2
    step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e1 3#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 3⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.name, auths_model.observation.FactName.as_str, bind_tc_ok]
    rw [StringRefinement.string_borrow_exact value.name strings.1]
    simp only [bind_tc_ok]
    have borrowLength4 : (toStr value.name strings.1).val.length = value.name.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e3 (toStr value.name strings.1) (by omega) as ⟨r4, e4, ok4, bytes4⟩
    rw [borrowed_bytes] at bytes4
    have len4 := output_length bytes4
    have bound4 := payload_length_bound 3 (stringBytes value.name)
    rw [stringBytes_length] at bound4
    simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
    have len5 := output_length bytes5
    have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
    simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.observation.ObservationCondition.impl.test, branch, auths_model.observation.MemberValues.impl.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
    step with member_values_exact e5 (alloc.vec.Vec.deref values) branchStrings (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation factValueCost values.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
    have len6 := output_length bytes6
    have bound6 := array_model_length UnsignedObjects.factValue factValueCost fact_value_length_bound values.val
    simp [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observationCondition, branch,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]

end Auths.Crypto.RequirementLeaves
