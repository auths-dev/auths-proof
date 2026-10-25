import Auths.Crypto.ResultLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ResultAssurance
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

/- Complete reported assurance records, including claims, evidence and adapter
identity. Encoding these reports is separate from authenticating any claim or
proving that the source verifier actually produced/satisfied the reports. -/
structure ClaimFields (value : auths_model.AssuranceClaim) : Prop where
  kind : value.kind.toByteArray.size ≤ U32.max
  parameters : ∀ parameter ∈ value.parameters.val, ContextAssurance.ParameterStrings parameter
  source : value.source.toByteArray.size ≤ U32.max

structure ReportFields (value : auths_model.ParticipantAssurance) : Prop where
  principal : value.principal.toByteArray.size ≤ U32.max
  claims : ∀ claim ∈ value.claims.val, ClaimFields claim
  adapter : value.adapter.toByteArray.size ≤ U32.max

structure SatisfactionFields (value : auths_model.AssuranceSatisfaction) : Prop where
  principal : value.principal.toByteArray.size ≤ U32.max
  claim : ClaimFields value.claim

theorem claim_length (value : auths_model.AssuranceClaim) :
    (ResultObjects.claim value).length ≤ ResultObjects.claimCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.kind),
    (1, UnsignedWire.array (value.parameters.val.map ContextObjects.parameter)),
    (2, ResultObjects.optionalTime value.observed_at), (3, UnsignedObjects.identifier value.source)]
  have kind := UnsignedLeaves.identifier_length value.kind
  have parameters := array_model_length ContextObjects.parameter ContextObjects.parameterCost ContextAssurance.parameter_length value.parameters.val
  have time := ResultLeaves.timestamp_length value.observed_at
  have source := UnsignedLeaves.identifier_length value.source
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ResultObjects.claimCost]
  omega

@[step] theorem claim_exact (self : cbor.Encoder) (value : auths_model.AssuranceClaim)
    (fields : ClaimFields value)
    (space : self.output.val.length + ResultObjects.claimCost value ≤ Usize.max) :
    encode.encode_assurance_claim self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.claim value ⦄ := by
  unfold encode.encode_assurance_claim
  simp only [ResultObjects.claimCost] at space
  step with ProtocolWriter.map_exact self 4#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 4⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceClaim.impl.kind, auths_model.AssuranceClaimId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.kind fields.kind]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.kind fields.kind).val.length = value.kind.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.kind fields.kind) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.kind)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceClaim.impl.parameters, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextAssurance.parameters_exact e3 (alloc.vec.Vec.deref value.parameters) fields.parameters (by simpa only [alloc.vec.deref_exact] using (show e3.output.val.length + 9 + allocation ContextObjects.parameterCost value.parameters.val ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := array_model_length ContextObjects.parameter ContextObjects.parameterCost ContextAssurance.parameter_length value.parameters.val
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceClaim.impl.observed_at, bind_tc_ok]
  step with ResultLeaves.timestamp_exact e5 value.observed_at (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := ResultLeaves.timestamp_length value.observed_at
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceClaim.impl.source, auths_model.EvidenceSourceId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.source fields.source]
  simp only [bind_tc_ok]
  have borrowLength8 : (toStr value.source fields.source).val.length = value.source.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e7 (toStr value.source fields.source) (by omega) as ⟨r8, e8, ok8, bytes8⟩
  rw [borrowed_bytes] at bytes8
  have len8 := output_length bytes8
  have bound8 := payload_length_bound 3 (stringBytes value.source)
  rw [stringBytes_length] at bound8
  simp [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.claim,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

private theorem claims_stopped (self : cbor.Encoder) (values : Slice auths_model.AssuranceClaim)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_assurance_claims_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_assurance_claims_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem claims_suffix (values : Slice auths_model.AssuranceClaim) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.AssuranceClaim)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ClaimFields value)
    (space : self.output.val.length + allocation ResultObjects.claimCost rest ≤ Usize.max) :
    encode.encode_assurance_claims_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ResultObjects.claim rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_assurance_claims_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ClaimFields value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ResultObjects.claimCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_assurance_claims_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with claim_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := claim_length first
    have tailSpace : after.output.val.length + allocation ResultObjects.claimCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem claims_exact (self : cbor.Encoder) (values : Slice auths_model.AssuranceClaim)
    (fields : ∀ value ∈ values.val, ClaimFields value)
    (space : self.output.val.length + 9 + allocation ResultObjects.claimCost values.val ≤ Usize.max) :
    encode.encode_assurance_claims self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ResultObjects.claim) ⦄ := by
  unfold encode.encode_assurance_claims
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ResultObjects.claimCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with claims_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


theorem report_length (value : auths_model.ParticipantAssurance) :
    (ResultObjects.report value).length ≤ ResultObjects.reportCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.principal),
    (1, UnsignedWire.uint (ContextObjects.role value.role)),
    (2, UnsignedWire.array (value.claims.val.map ResultObjects.claim)),
    (3, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest)),
    (4, UnsignedObjects.identifier value.adapter), (5, UnsignedWire.uint value.adapter_version.val)]
  have principal := UnsignedLeaves.identifier_length value.principal
  have role := UnsignedWire.uint_length (ContextObjects.role value.role)
  have claims := array_model_length ResultObjects.claim ResultObjects.claimCost claim_length value.claims.val
  have evidence := BundleLeaves.evidence_ids_length value.evidence.val
  have adapter := UnsignedLeaves.identifier_length value.adapter
  have version := UnsignedWire.uint_length value.adapter_version.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ResultObjects.reportCost]
  omega

@[step] theorem report_exact (self : cbor.Encoder) (value : auths_model.ParticipantAssurance)
    (fields : ReportFields value)
    (space : self.output.val.length + ResultObjects.reportCost value ≤ Usize.max) :
    encode.encode_assurance_report self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.report value ⦄ := by
  unfold encode.encode_assurance_report
  simp only [ResultObjects.reportCost] at space
  step with ProtocolWriter.map_exact self 6#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 6⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ParticipantAssurance.impl.principal, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.principal fields.principal]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.principal fields.principal).val.length = value.principal.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.principal fields.principal) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.principal)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ParticipantAssurance.impl.role, bind_tc_ok]
  step with ResultLeaves.role_exact e3 value.role (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := UnsignedWire.uint_length (ContextObjects.role value.role)
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ParticipantAssurance.impl.claims, core.ops.deref.DerefVec, bind_tc_ok]
  step with claims_exact e5 (alloc.vec.Vec.deref value.claims) fields.claims (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation ResultObjects.claimCost value.claims.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := array_model_length ResultObjects.claim ResultObjects.claimCost claim_length value.claims.val
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ParticipantAssurance.impl.evidence, core.ops.deref.DerefVec, bind_tc_ok]
  step with BundleLeaves.evidence_ids_exact e7 (alloc.vec.Vec.deref value.evidence) (by simpa only [alloc.vec.deref_exact, BundleLeaves.id_allocation] using (show e7.output.val.length + 9 + 41 * value.evidence.val.length ≤ Usize.max by omega)) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := BundleLeaves.evidence_ids_length value.evidence.val
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ParticipantAssurance.impl.adapter, auths_model.AdapterId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.adapter fields.adapter]
  simp only [bind_tc_ok]
  have borrowLength10 : (toStr value.adapter fields.adapter).val.length = value.adapter.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e9 (toStr value.adapter fields.adapter) (by omega) as ⟨r10, e10, ok10, bytes10⟩
  rw [borrowed_bytes] at bytes10
  have len10 := output_length bytes10
  have bound10 := payload_length_bound 3 (stringBytes value.adapter)
  rw [stringBytes_length] at bound10
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ParticipantAssurance.impl.adapter_version, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e11 value.adapter_version (by omega) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := encodeHead_length_le_nine ⟨0, (value.adapter_version).val⟩
  simp [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.report,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

private theorem reports_stopped (self : cbor.Encoder) (values : Slice auths_model.ParticipantAssurance)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_assurance_reports_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_assurance_reports_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem reports_suffix (values : Slice auths_model.ParticipantAssurance) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.ParticipantAssurance)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ReportFields value)
    (space : self.output.val.length + allocation ResultObjects.reportCost rest ≤ Usize.max) :
    encode.encode_assurance_reports_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ResultObjects.report rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_assurance_reports_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ReportFields value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ResultObjects.reportCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_assurance_reports_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with report_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := report_length first
    have tailSpace : after.output.val.length + allocation ResultObjects.reportCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem reports_exact (self : cbor.Encoder) (values : Slice auths_model.ParticipantAssurance)
    (fields : ∀ value ∈ values.val, ReportFields value)
    (space : self.output.val.length + 9 + allocation ResultObjects.reportCost values.val ≤ Usize.max) :
    encode.encode_assurance_reports self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ResultObjects.report) ⦄ := by
  unfold encode.encode_assurance_reports
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ResultObjects.reportCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with reports_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


theorem satisfaction_length (value : auths_model.AssuranceSatisfaction) :
    (ResultObjects.assuranceSatisfaction value).length ≤ ResultObjects.assuranceSatisfactionCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedWire.uint value.requirement_index.val),
    (1, UnsignedObjects.identifier value.principal), (2, ResultObjects.claim value.claim),
    (3, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest))]
  have index := UnsignedWire.uint_length value.requirement_index.val
  have principal := UnsignedLeaves.identifier_length value.principal
  have claim := claim_length value.claim
  have evidence := BundleLeaves.evidence_ids_length value.evidence.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ResultObjects.assuranceSatisfactionCost]
  omega

@[step] theorem satisfaction_exact (self : cbor.Encoder) (value : auths_model.AssuranceSatisfaction)
    (fields : SatisfactionFields value)
    (space : self.output.val.length + ResultObjects.assuranceSatisfactionCost value ≤ Usize.max) :
    encode.encode_assurance_satisfaction self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.assuranceSatisfaction value ⦄ := by
  unfold encode.encode_assurance_satisfaction
  simp only [ResultObjects.assuranceSatisfactionCost] at space
  step with ProtocolWriter.map_exact self 4#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 4⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceSatisfaction.impl.requirement_index, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.requirement_index (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (value.requirement_index).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceSatisfaction.impl.principal, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.principal fields.principal]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.principal fields.principal).val.length = value.principal.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.principal fields.principal) (by omega) as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.principal)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceSatisfaction.impl.claim, bind_tc_ok]
  step with claim_exact e5 value.claim fields.claim (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := claim_length value.claim
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AssuranceSatisfaction.impl.evidence, core.ops.deref.DerefVec, bind_tc_ok]
  step with BundleLeaves.evidence_ids_exact e7 (alloc.vec.Vec.deref value.evidence) (by simpa only [alloc.vec.deref_exact, BundleLeaves.id_allocation] using (show e7.output.val.length + 9 + 41 * value.evidence.val.length ≤ Usize.max by omega)) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := BundleLeaves.evidence_ids_length value.evidence.val
  simp [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.assuranceSatisfaction,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

private theorem satisfactions_stopped (self : cbor.Encoder) (values : Slice auths_model.AssuranceSatisfaction)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_assurance_satisfactions_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_assurance_satisfactions_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem satisfactions_suffix (values : Slice auths_model.AssuranceSatisfaction) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.AssuranceSatisfaction)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, SatisfactionFields value)
    (space : self.output.val.length + allocation ResultObjects.assuranceSatisfactionCost rest ≤ Usize.max) :
    encode.encode_assurance_satisfactions_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents ResultObjects.assuranceSatisfaction rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_assurance_satisfactions_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, SatisfactionFields value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ResultObjects.assuranceSatisfactionCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_assurance_satisfactions_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with satisfaction_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := satisfaction_length first
    have tailSpace : after.output.val.length + allocation ResultObjects.assuranceSatisfactionCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem satisfactions_exact (self : cbor.Encoder) (values : Slice auths_model.AssuranceSatisfaction)
    (fields : ∀ value ∈ values.val, SatisfactionFields value)
    (space : self.output.val.length + 9 + allocation ResultObjects.assuranceSatisfactionCost values.val ≤ Usize.max) :
    encode.encode_assurance_satisfactions self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map ResultObjects.assuranceSatisfaction) ⦄ := by
  unfold encode.encode_assurance_satisfactions
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ResultObjects.assuranceSatisfactionCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with satisfactions_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]


end Auths.Crypto.ResultAssurance
