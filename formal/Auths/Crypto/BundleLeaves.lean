import Auths.Crypto.BundleObjects
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BundleLeaves
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters
open Auths.Crypto.UnsignedLeaves

theorem header_length (value : auths_model.BundleHeader) : (BundleObjects.header value).length ≤ 45 := by
  have outer := UnsignedWire.map_length [(0, UnsignedWire.uint value.version.val), (1, UnsignedWire.uint value.flags.val)]
  have version := UnsignedWire.uint_length value.version.val
  have flags := UnsignedWire.uint_length value.flags.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  omega

theorem reference_length (value : auths_model.StatementRef) : (BundleObjects.statementRef value).length ≤ 77 := by
  have outer := UnsignedWire.map_length [(0, UnsignedWire.uint (BundleObjects.statementParts value).1),
    (1, UnsignedObjects.digest (BundleObjects.statementParts value).2)]
  have tag := UnsignedWire.uint_length (BundleObjects.statementParts value).1
  have identifier := digest_length (BundleObjects.statementParts value).2
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  omega

theorem id_allocation (values : List auths_model.EvidenceId) :
    allocation (fun _ => 41) values = 41 * values.length := by
  induction values with
  | nil => simp [allocation]
  | cons first rest ih =>
    change 41 + allocation (fun _ => 41) rest = 41 * (rest.length + 1)
    rw [ih]
    omega

theorem evidence_ids_length (values : List auths_model.EvidenceId) :
    (UnsignedWire.array (values.map UnsignedObjects.digest)).length ≤ 9 + 41 * values.length := by
  have bound := array_model_length UnsignedObjects.digest (fun _ => 41) digest_length values
  simpa only [id_allocation] using bound

theorem binding_length (value : auths_model.ControlBinding) :
    (BundleObjects.binding value).length ≤ BundleObjects.bindingCost value := by
  have outer := UnsignedWire.map_length [(0, BundleObjects.statementRef value.statement),
    (1, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest))]
  have reference := reference_length value.statement
  have evidence := evidence_ids_length value.evidence.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [BundleObjects.bindingCost]
  omega

theorem optional_bytes_length (value : Option (alloc.vec.Vec Std.U8)) :
    (BundleObjects.optionalBytes value).length ≤ BundleObjects.optionalBytesCost value := by
  cases value with
  | none => simp [BundleObjects.optionalBytes, BundleObjects.optionalBytesCost, UnsignedWire.null]
  | some value =>
    simpa only [BundleObjects.optionalBytes, BundleObjects.optionalBytesCost, byteList, List.length_map]
      using UnsignedWire.bytes_length (byteList value.val)

private theorem evidence_ids_stopped (self : cbor.Encoder) (values : Slice auths_model.EvidenceId)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_evidence_ids_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_evidence_ids_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem evidence_ids_suffix (values : Slice auths_model.EvidenceId) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.EvidenceId)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, (fun _ => True) value)
    (space : self.output.val.length + allocation (fun _ => 41) rest ≤ Usize.max) :
    encode.encode_evidence_ids_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.digest rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_evidence_ids_loop.eq_def]
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
    rw [encode.encode_evidence_ids_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    simp only [auths_model.EvidenceId.as_bytes, lift, Array.to_slice, bind_tc_ok]
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

@[step] theorem evidence_ids_exact (self : cbor.Encoder) (values : Slice auths_model.EvidenceId)
    (space : self.output.val.length + 9 + allocation (fun _ => 41) values.val ≤ Usize.max) :
    encode.encode_evidence_ids self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.digest) ⦄ := by
  unfold encode.encode_evidence_ids
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation (fun _ => 41) values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with evidence_ids_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) (by simp) loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

@[step] theorem header_exact (self : cbor.Encoder) (value : auths_model.BundleHeader)
    (space : self.output.val.length + 45 ≤ Usize.max) :
    encode.encode_bundle_header self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ BundleObjects.header value ⦄ := by
  unfold encode.encode_bundle_header
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.BundleHeader.impl.version, auths_model.ProtocolVersion.get, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.version (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (value.version).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.BundleHeader.impl.flags, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e3 value.flags (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, (value.flags).val⟩
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, BundleObjects.header,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem reference_exact (self : cbor.Encoder) (value : auths_model.StatementRef)
    (space : self.output.val.length + 77 ≤ Usize.max) :
    encode.encode_statement_ref self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ BundleObjects.statementRef value ⦄ := by
  cases value with
  | Grant identifier =>
    unfold encode.encode_statement_ref
    step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 0#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, (0#u8).val⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.GrantId.as_bytes, lift, bind_tc_ok]
    step with UnsignedLeaves.digest_exact e3 identifier (by omega) as ⟨r4, e4, ok4, bytes4⟩
    have len4 := output_length bytes4
    have bound4 := digest_length identifier
    simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes4, bytes3, bytes2, bytes1, bytes0, BundleObjects.statementRef, BundleObjects.statementParts,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | Action identifier =>
    unfold encode.encode_statement_ref
    step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 1#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, (1#u8).val⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.ActionId.as_bytes, lift, bind_tc_ok]
    step with UnsignedLeaves.digest_exact e3 identifier (by omega) as ⟨r4, e4, ok4, bytes4⟩
    have len4 := output_length bytes4
    have bound4 := digest_length identifier
    simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes4, bytes3, bytes2, bytes1, bytes0, BundleObjects.statementRef, BundleObjects.statementParts,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | PrincipalStatus identifier =>
    unfold encode.encode_statement_ref
    step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 2#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, (2#u8).val⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.PrincipalStatusId.as_bytes, lift, bind_tc_ok]
    step with UnsignedLeaves.digest_exact e3 identifier (by omega) as ⟨r4, e4, ok4, bytes4⟩
    have len4 := output_length bytes4
    have bound4 := digest_length identifier
    simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes4, bytes3, bytes2, bytes1, bytes0, BundleObjects.statementRef, BundleObjects.statementParts,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | GrantStatus identifier =>
    unfold encode.encode_statement_ref
    step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 3#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, (3#u8).val⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.GrantStatusId.as_bytes, lift, bind_tc_ok]
    step with UnsignedLeaves.digest_exact e3 identifier (by omega) as ⟨r4, e4, ok4, bytes4⟩
    have len4 := output_length bytes4
    have bound4 := digest_length identifier
    simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes4, bytes3, bytes2, bytes1, bytes0, BundleObjects.statementRef, BundleObjects.statementParts,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem binding_exact (self : cbor.Encoder) (value : auths_model.ControlBinding)
    (space : self.output.val.length + BundleObjects.bindingCost value ≤ Usize.max) :
    encode.encode_binding self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ BundleObjects.binding value ⦄ := by
  unfold encode.encode_binding
  simp only [BundleObjects.bindingCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ControlBinding.impl.statement, bind_tc_ok]
  step with reference_exact e1 value.statement (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := reference_length value.statement
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ControlBinding.impl.evidence, core.ops.deref.DerefVec, bind_tc_ok]
  step with evidence_ids_exact e3 (alloc.vec.Vec.deref value.evidence) (by simpa only [alloc.vec.deref_exact, id_allocation] using (show e3.output.val.length + 9 + 41 * value.evidence.val.length ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := evidence_ids_length value.evidence.val
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, BundleObjects.binding,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem body_projection (value : auths_model.ProofBundle) :
    auths_model.ProofBundle.impl.canonical_body value = ok (BundleObjects.bodySlices value.canonical_body) := by
  unfold auths_model.ProofBundle.impl.canonical_body
  cases body : value.canonical_body <;>
    simp [body, core.option.Option.as_ref, alloc.vec.Vec.as_slice, BundleObjects.bodySlices, bind_tc_ok]

@[step] theorem optional_body_exact (self : cbor.Encoder) (value : Option (Slice Std.U8))
    (space : self.output.val.length + BundleObjects.optionalSliceCost value ≤ Usize.max) :
    encode.encode_optional_body self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ BundleObjects.optionalSliceBytes value ⦄ := by
  cases value with
  | none =>
    unfold encode.encode_optional_body
    step with ProtocolEncoderState.null_exact self (by simpa only [BundleObjects.optionalSliceCost] using space)
      as ⟨output, written⟩
    simp [spec_ok, written, BundleObjects.optionalSliceBytes, UnsignedWire.null]
  | some body =>
    unfold encode.encode_optional_body
    step with ProtocolWriter.bytes_exact self body (by simpa only [BundleObjects.optionalSliceCost] using space)
      as ⟨verdict, output, success, written⟩
    simp [success, core.result.Result.Insts.CoreOpsTry.branch, written,
      BundleObjects.optionalSliceBytes, UnsignedWire.bytes, ProtocolEncoderState.payloadEncoding]

theorem bundle_length (sha256 : List Nat → auths_model.Digest) (value : auths_model.ProofBundle) :
    (BundleObjects.bundle sha256 value).length ≤ BundleObjects.cost value := by
  have outer := UnsignedWire.map_length [
    (0, BundleObjects.header value.header),
    (1, UnsignedWire.array ((BundleObjects.grants sha256 value).map UnsignedObjects.signedGrant)),
    (2, UnsignedWire.array ((BundleObjects.actions value).map UnsignedObjects.signedAction)),
    (3, PlanWire.encode (PlanWriters.viewPlan value.plan)),
    (4, UnsignedWire.array ((BundleObjects.evidence value).map UnsignedObjects.evidence)),
    (5, UnsignedWire.array ((BundleObjects.bindings value).map BundleObjects.binding)),
    (6, UnsignedWire.array ((BundleObjects.principalStatus sha256 value).map UnsignedObjects.signedPrincipalStatus)),
    (7, UnsignedWire.array ((BundleObjects.grantStatus sha256 value).map UnsignedObjects.signedGrantStatus)),
    (8, UnsignedWire.array ((BundleObjects.attachments value).map UnsignedObjects.attachment)),
    (9, BundleObjects.optionalBytes value.canonical_body),
    (10, UnsignedWire.array (value.approvals.val.map UnsignedObjects.signedApproval))]
  have header := header_length value.header
  have grants := array_model_length UnsignedObjects.signedGrant SignedObjectWriters.grantCost
    SignedObjectWriters.grant_length (BundleObjects.grants sha256 value)
  have actions := array_model_length UnsignedObjects.signedAction SignedObjectWriters.actionCost
    SignedObjectWriters.action_length (BundleObjects.actions value)
  have plan := PlanWire.encode_length (PlanWriters.viewPlan value.plan)
  have evidence := array_model_length UnsignedObjects.evidence EvidenceWriters.recordCost
    EvidenceWriters.record_length (BundleObjects.evidence value)
  have bindings := array_model_length BundleObjects.binding BundleObjects.bindingCost
    binding_length (BundleObjects.bindings value)
  have principal := array_model_length UnsignedObjects.signedPrincipalStatus SignedObjectWriters.principal_statusCost
    SignedObjectWriters.principal_status_length (BundleObjects.principalStatus sha256 value)
  have grant := array_model_length UnsignedObjects.signedGrantStatus SignedObjectWriters.grant_statusCost
    SignedObjectWriters.grant_status_length (BundleObjects.grantStatus sha256 value)
  have attachments := array_model_length UnsignedObjects.attachment UnsignedLeaves.attachmentCost
    attachment_length_bound (BundleObjects.attachments value)
  have body := optional_bytes_length value.canonical_body
  have approvals := array_model_length UnsignedObjects.signedApproval SignedObjectWriters.approvalCost
    SignedObjectWriters.approval_length value.approvals.val
  simp only [BundleObjects.grants, BundleObjects.actions, BundleObjects.evidence, BundleObjects.bindings,
    BundleObjects.principalStatus, BundleObjects.grantStatus, BundleObjects.attachments,
    BundleObjects.allocation_normalized] at grants actions evidence bindings principal grant attachments
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [BundleObjects.cost, PlanWriters.cost, List.sum_cons, List.sum_nil]
  omega

end Auths.Crypto.BundleLeaves
