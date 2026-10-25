import Auths.Crypto.ContextProfiles

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextAssurance
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

/- Complete assurance-policy data. Exact encoding is separate from claim
authentication, adapter dispatch, implication closure or policy satisfaction.
Every option branch is retained, including present zero versions/ages. -/
def OptionalStrings : Option String → Prop
  | none => True
  | some value => value.toByteArray.size ≤ U32.max

def ParameterStrings (value : auths_model.ClaimParameterId × auths_model.ClaimParameterId) : Prop :=
  value.1.toByteArray.size ≤ U32.max ∧ value.2.toByteArray.size ≤ U32.max

structure RequirementStrings (value : auths_model.AssuranceRequirement) : Prop where
  claim : value.claim_kind.toByteArray.size ≤ U32.max
  parameters : ∀ parameter ∈ value.parameters.val, ParameterStrings parameter
  source : OptionalStrings value.source
  adapter : OptionalStrings value.adapter

structure PolicyStrings (value : auths_model.AssurancePolicy) : Prop where
  identifier : value.id.toByteArray.size ≤ U32.max
  requirements : ∀ requirement ∈ value.requirements.val, RequirementStrings requirement

theorem optional_text_length (value : Option String) :
    (ContextObjects.optionalText value).length ≤ ContextObjects.optionalTextCost value := by
  cases value with
  | none => simp [ContextObjects.optionalText, ContextObjects.optionalTextCost, UnsignedWire.null]
  | some value => exact UnsignedLeaves.identifier_length value

theorem optional_version_length (value : Option Std.U16) :
    (ContextObjects.optionalU16 value).length ≤ 9 := by
  cases value with
  | none => simp [ContextObjects.optionalU16, UnsignedWire.null]
  | some value => exact UnsignedWire.uint_length value.val

theorem optional_age_length (value : Option auths_model.FreshnessLimit) :
    (ContextObjects.optionalAge value).length ≤ 9 := by
  cases value with
  | none => simp [ContextObjects.optionalAge, UnsignedWire.null]
  | some value => exact UnsignedWire.uint_length value.val

theorem parameter_length (value : auths_model.ClaimParameterId × auths_model.ClaimParameterId) :
    (ContextObjects.parameter value).length ≤ ContextObjects.parameterCost value := by
  have outer := UnsignedWire.array_length [UnsignedObjects.identifier value.1, UnsignedObjects.identifier value.2]
  have name := UnsignedLeaves.identifier_length value.1
  have parameter := UnsignedLeaves.identifier_length value.2
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.array _).length ≤ _
  simp only [ContextObjects.parameterCost]
  omega

@[step] theorem role_tag_exact (value : auths_model.ParticipantRole) :
    encode.assurance_role_tag value ⦃ actual => actual.val = ContextObjects.role value ⦄ := by
  cases value <;> simp [encode.assurance_role_tag, ContextObjects.role, spec_ok]

@[step] theorem quantifier_tag_exact (value : auths_model.AssuranceQuantifier) :
    encode.assurance_quantifier_tag value ⦃ actual => actual.val = ContextObjects.quantifier value ⦄ := by
  cases value <;> simp [encode.assurance_quantifier_tag, ContextObjects.quantifier, spec_ok]

@[step] theorem source_exact (self : cbor.Encoder) (value : Option auths_model.EvidenceSourceId)
    (fields : OptionalStrings value)
    (space : self.output.val.length + ContextObjects.optionalTextCost value ≤ Usize.max) :
    encode.encode_assurance_source self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.optionalText value ⦄ := by
  unfold encode.encode_assurance_source
  cases value with
  | none =>
    step with ProtocolEncoderState.null_exact self (by simpa [ContextObjects.optionalTextCost] using space)
      as ⟨after, written⟩
    simpa [ContextObjects.optionalText, UnsignedWire.null] using written
  | some value =>
    simp only [auths_model.EvidenceSourceId.as_str]
    rw [StringRefinement.string_borrow_exact value fields]
    simp only [bind_tc_ok]
    have length : (toStr value fields).val.length = value.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr value fields) (by
      simpa only [ContextObjects.optionalTextCost, length] using space)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    simp [success, written, core.result.Result.Insts.CoreOpsTry.branch,
      ContextObjects.optionalText, UnsignedObjects.identifier, UnsignedObjects.utf8,
      UnsignedWire.text, payloadEncoding, stringBytes, List.append_assoc]

@[step] theorem adapter_exact (self : cbor.Encoder) (value : Option auths_model.AdapterId)
    (fields : OptionalStrings value)
    (space : self.output.val.length + ContextObjects.optionalTextCost value ≤ Usize.max) :
    encode.encode_assurance_adapter self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.optionalText value ⦄ := by
  unfold encode.encode_assurance_adapter
  cases value with
  | none =>
    step with ProtocolEncoderState.null_exact self (by simpa [ContextObjects.optionalTextCost] using space)
      as ⟨after, written⟩
    simpa [ContextObjects.optionalText, UnsignedWire.null] using written
  | some value =>
    simp only [auths_model.AdapterId.as_str]
    rw [StringRefinement.string_borrow_exact value fields]
    simp only [bind_tc_ok]
    have length : (toStr value fields).val.length = value.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr value fields) (by
      simpa only [ContextObjects.optionalTextCost, length] using space)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    simp [success, written, core.result.Result.Insts.CoreOpsTry.branch,
      ContextObjects.optionalText, UnsignedObjects.identifier, UnsignedObjects.utf8,
      UnsignedWire.text, payloadEncoding, stringBytes, List.append_assoc]

@[step] theorem version_exact (self : cbor.Encoder) (value : Option Std.U16)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    encode.encode_assurance_version self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.optionalU16 value ⦄ := by
  unfold encode.encode_assurance_version
  cases value with
  | none =>
    step with ProtocolEncoderState.null_exact self (by omega) as ⟨after, written⟩
    simpa [ContextObjects.optionalU16, UnsignedWire.null] using written
  | some value =>
    step with ProtocolEncoderState.u16_exact self value space as ⟨verdict, after, success, written⟩
    simp [success, written, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      ContextObjects.optionalU16, UnsignedWire.uint]

@[step] theorem maximum_age_exact (self : cbor.Encoder) (value : Option auths_model.FreshnessLimit)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    encode.encode_assurance_maximum_age self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.optionalAge value ⦄ := by
  unfold encode.encode_assurance_maximum_age
  cases value with
  | none =>
    step with ProtocolEncoderState.null_exact self (by omega) as ⟨after, written⟩
    simpa [ContextObjects.optionalAge, UnsignedWire.null] using written
  | some value =>
    simp only [auths_model.FreshnessLimit.get, bind_tc_ok]
    step with ProtocolEncoderState.u64_exact self value space as ⟨verdict, after, success, written⟩
    simp [success, written, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      ContextObjects.optionalAge, UnsignedWire.uint]

@[step] theorem parameter_exact (self : cbor.Encoder)
    (value : auths_model.ClaimParameterId × auths_model.ClaimParameterId)
    (fields : ParameterStrings value)
    (space : self.output.val.length + ContextObjects.parameterCost value ≤ Usize.max) :
    encode.encode_claim_parameter self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.parameter value ⦄ := by
  unfold encode.encode_claim_parameter
  simp only [ContextObjects.parameterCost] at space
  step with ProtocolWriter.array_exact self 2#usize (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨4, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ClaimParameterId.as_str]
  rw [StringRefinement.string_borrow_exact value.1 fields.1]
  simp only [bind_tc_ok]
  have borrowLength1 : (toStr value.1 fields.1).val.length = value.1.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e0 (toStr value.1 fields.1) (by omega) as ⟨r1, e1, ok1, bytes1⟩
  rw [borrowed_bytes] at bytes1
  have len1 := output_length bytes1
  have bound1 := payload_length_bound 3 (stringBytes value.1)
  rw [stringBytes_length] at bound1
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ClaimParameterId.as_str]
  rw [StringRefinement.string_borrow_exact value.2 fields.2]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.2 fields.2).val.length = value.2.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.2 fields.2) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.2)
  rw [stringBytes_length] at bound2
  simp [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes2, bytes1, bytes0, ContextObjects.parameter,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

private theorem parameters_stopped (self : cbor.Encoder) (values : Slice (auths_model.ClaimParameterId × auths_model.ClaimParameterId))
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_assurance_parameters_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_assurance_parameters_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem parameters_suffix (values : Slice (auths_model.ClaimParameterId × auths_model.ClaimParameterId)) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List (auths_model.ClaimParameterId × auths_model.ClaimParameterId))
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ParameterStrings value)
    (space : self.output.val.length + allocation ContextObjects.parameterCost rest ≤ Usize.max) :
    encode.encode_assurance_parameters_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ContextObjects.parameter rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_assurance_parameters_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ParameterStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ContextObjects.parameterCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_assurance_parameters_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with parameter_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := parameter_length first
    have tailSpace : after.output.val.length + allocation ContextObjects.parameterCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem parameters_exact (self : cbor.Encoder) (values : Slice (auths_model.ClaimParameterId × auths_model.ClaimParameterId))
    (fields : ∀ value ∈ values.val, ParameterStrings value)
    (space : self.output.val.length + 9 + allocation ContextObjects.parameterCost values.val ≤ Usize.max) :
    encode.encode_assurance_parameters self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ContextObjects.parameter) ⦄ := by
  unfold encode.encode_assurance_parameters
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ContextObjects.parameterCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with parameters_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


theorem requirement_length (value : auths_model.AssuranceRequirement) :
    (ContextObjects.assuranceRequirement value).length ≤ ContextObjects.assuranceRequirementCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedWire.uint (ContextObjects.role value.role)),
    (1, UnsignedObjects.identifier value.claim_kind),
    (2, UnsignedWire.array (value.parameters.val.map ContextObjects.parameter)),
    (3, ContextObjects.optionalText value.source), (4, ContextObjects.optionalText value.adapter),
    (5, ContextObjects.optionalU16 value.adapter_version), (6, ContextObjects.optionalAge value.maximum_age),
    (7, UnsignedWire.uint (ContextObjects.quantifier value.quantifier))]
  have role := UnsignedWire.uint_length (ContextObjects.role value.role)
  have claim := UnsignedLeaves.identifier_length value.claim_kind
  have parameters := array_model_length ContextObjects.parameter ContextObjects.parameterCost parameter_length value.parameters.val
  have source := optional_text_length value.source
  have adapter := optional_text_length value.adapter
  have version := optional_version_length value.adapter_version
  have age := optional_age_length value.maximum_age
  have quantifier := UnsignedWire.uint_length (ContextObjects.quantifier value.quantifier)
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.assuranceRequirementCost]
  omega

@[step] theorem requirement_exact (self : cbor.Encoder) (value : auths_model.AssuranceRequirement)
    (fields : RequirementStrings value)
    (space : self.output.val.length + ContextObjects.assuranceRequirementCost value ≤ Usize.max) :
    encode.encode_assurance_requirement self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.assuranceRequirement value ⦄ := by
  unfold encode.encode_assurance_requirement
  simp only [ContextObjects.assuranceRequirementCost] at space
  step with ProtocolWriter.map_exact self 8#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 8⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.role, bind_tc_ok]
  step with role_tag_exact value.role as ⟨role, roleMeaning⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e1 role (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (role).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.claim_kind, auths_model.AssuranceClaimId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.claim_kind fields.claim]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.claim_kind fields.claim).val.length = value.claim_kind.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.claim_kind fields.claim) (by omega) as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.claim_kind)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.parameters, core.ops.deref.DerefVec, bind_tc_ok]
  step with parameters_exact e5 (alloc.vec.Vec.deref value.parameters) fields.parameters (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation ContextObjects.parameterCost value.parameters.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := array_model_length ContextObjects.parameter ContextObjects.parameterCost parameter_length value.parameters.val
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.source, core.option.Option.as_ref, bind_tc_ok]
  step with source_exact e7 value.source fields.source (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := optional_text_length value.source
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.adapter, core.option.Option.as_ref, bind_tc_ok]
  step with adapter_exact e9 value.adapter fields.adapter (by omega) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := optional_text_length value.adapter
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.adapter_version, bind_tc_ok]
  step with version_exact e11 value.adapter_version (by omega) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := optional_version_length value.adapter_version
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.maximum_age, bind_tc_ok]
  step with maximum_age_exact e13 value.maximum_age (by omega) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := optional_age_length value.maximum_age
  simp only [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega) as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceRequirement.impl.quantifier, bind_tc_ok]
  step with quantifier_tag_exact value.quantifier as ⟨quantifier, quantifierMeaning⟩
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e15 quantifier (by omega) as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := encodeHead_length_le_nine ⟨0, (quantifier).val⟩
  simp [ok16, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.assuranceRequirement, roleMeaning, quantifierMeaning,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

private theorem requirements_stopped (self : cbor.Encoder) (values : Slice auths_model.AssuranceRequirement)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_assurance_requirements_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_assurance_requirements_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem requirements_suffix (values : Slice auths_model.AssuranceRequirement) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.AssuranceRequirement)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, RequirementStrings value)
    (space : self.output.val.length + allocation ContextObjects.assuranceRequirementCost rest ≤ Usize.max) :
    encode.encode_assurance_requirements_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ContextObjects.assuranceRequirement rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_assurance_requirements_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, RequirementStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ContextObjects.assuranceRequirementCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_assurance_requirements_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with requirement_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := requirement_length first
    have tailSpace : after.output.val.length + allocation ContextObjects.assuranceRequirementCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem requirements_exact (self : cbor.Encoder) (values : Slice auths_model.AssuranceRequirement)
    (fields : ∀ value ∈ values.val, RequirementStrings value)
    (space : self.output.val.length + 9 + allocation ContextObjects.assuranceRequirementCost values.val ≤ Usize.max) :
    encode.encode_assurance_requirements self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ContextObjects.assuranceRequirement) ⦄ := by
  unfold encode.encode_assurance_requirements
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ContextObjects.assuranceRequirementCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with requirements_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


theorem policy_length (value : auths_model.AssurancePolicy) :
    (ContextObjects.assurancePolicy value).length ≤ ContextObjects.assurancePolicyCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.id),
    (1, UnsignedWire.array (value.requirements.val.map ContextObjects.assuranceRequirement))]
  have identifier := UnsignedLeaves.identifier_length value.id
  have requirements := array_model_length ContextObjects.assuranceRequirement
    ContextObjects.assuranceRequirementCost requirement_length value.requirements.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.assurancePolicyCost]
  omega

@[step] theorem policy_exact (self : cbor.Encoder) (value : auths_model.AssurancePolicy)
    (fields : PolicyStrings value)
    (space : self.output.val.length + ContextObjects.assurancePolicyCost value ≤ Usize.max) :
    encode.encode_assurance_policy self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.assurancePolicy value ⦄ := by
  unfold encode.encode_assurance_policy
  simp only [ContextObjects.assurancePolicyCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssurancePolicy.impl.id, auths_model.AssurancePolicyId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.id fields.identifier]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.id fields.identifier).val.length = value.id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.id fields.identifier) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.id)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssurancePolicy.impl.requirements, core.ops.deref.DerefVec, bind_tc_ok]
  step with requirements_exact e3 (alloc.vec.Vec.deref value.requirements) fields.requirements (by simpa only [alloc.vec.deref_exact] using (show e3.output.val.length + 9 + allocation ContextObjects.assuranceRequirementCost value.requirements.val ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := array_model_length ContextObjects.assuranceRequirement ContextObjects.assuranceRequirementCost requirement_length value.requirements.val
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.assurancePolicy,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

end Auths.Crypto.ContextAssurance
