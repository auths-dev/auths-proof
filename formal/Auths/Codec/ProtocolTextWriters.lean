import Auths.Codec.ProtocolArrayWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolTextWriters
open Auths.Codec.Refinement Auths.Codec.ProtocolWriter Auths.Codec.ProtocolArrayWriters
open Auths.Crypto

def textCost (value : String) : Nat := 9 + value.toByteArray.size

theorem text_length_bound (value : String) :
    (UnsignedObjects.identifier value).length ≤ textCost value := by
  simpa [UnsignedObjects.identifier, textCost, UnsignedLeaves.utf8_length] using
    UnsignedWire.text_length (UnsignedObjects.utf8 value)

/- These concrete source families share no user-supplied parser, projector or
writer callback. Each proof unfolds its actual recursive source loop and
actual typed as_str operation. The logical aliases expose String carriers;
constructor validity and downstream authority remain separate obligations. -/

private theorem principal_ids_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_principal_ids_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_principal_ids_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem principal_ids_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_principal_ids_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_principal_ids_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_principal_ids_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.PrincipalId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem principal_ids_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_principal_ids self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_principal_ids
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with principal_ids_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem principal_methods_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_principal_methods_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_principal_methods_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem principal_methods_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_principal_methods_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_principal_methods_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_principal_methods_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.PrincipalMethodId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem principal_methods_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_principal_methods self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_principal_methods
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with principal_methods_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem resource_ids_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_resource_ids_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_resource_ids_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem resource_ids_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_resource_ids_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_resource_ids_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_resource_ids_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.ResourceId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem resource_ids_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_resource_ids self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_resource_ids
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with resource_ids_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem signature_suites_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_signature_suites_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_signature_suites_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem signature_suites_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_signature_suites_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_signature_suites_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_signature_suites_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.SignatureSuiteId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem signature_suites_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_signature_suites self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_signature_suites
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with signature_suites_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem evidence_types_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_evidence_types_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_evidence_types_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem evidence_types_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_evidence_types_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_evidence_types_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_evidence_types_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.EvidenceTypeId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem evidence_types_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_evidence_types self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_evidence_types
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with evidence_types_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem status_methods_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_status_methods_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_status_methods_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem status_methods_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_status_methods_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_status_methods_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_status_methods_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.StatusMethodId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem status_methods_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_status_methods self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_status_methods
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with status_methods_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem assurance_claims_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_assurance_claims_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_assurance_claims_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem assurance_claims_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_assurance_claims_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_assurance_claims_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_assurance_claims_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.AssuranceClaimId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem assurance_claims_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_assurance_claims self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_assurance_claims
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with assurance_claims_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem assurance_implications_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_assurance_implications_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_assurance_implications_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem assurance_implications_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_assurance_implications_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_assurance_implications_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_assurance_implications_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.AssuranceImplicationId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem assurance_implications_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_assurance_implications self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_assurance_implications
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with assurance_implications_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem resource_matchers_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_resource_matchers_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_resource_matchers_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem resource_matchers_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_resource_matchers_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_resource_matchers_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_resource_matchers_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.ResourceMatcherId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem resource_matchers_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_resource_matchers self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_resource_matchers
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with resource_matchers_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem budget_algebras_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_budget_algebras_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_budget_algebras_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem budget_algebras_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_budget_algebras_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_budget_algebras_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_budget_algebras_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.BudgetAlgebraId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem budget_algebras_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_budget_algebras self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_budget_algebras
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with budget_algebras_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem extension_ids_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_extension_ids_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_extension_ids_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem extension_ids_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_extension_ids_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_extension_ids_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_extension_ids_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.ExtensionId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem extension_ids_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_extension_ids self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_extension_ids
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with extension_ids_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem profile_policies_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_profile_policies_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_profile_policies_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem profile_policies_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_profile_policies_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_profile_policies_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_profile_policies_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.ProfilePolicyId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem profile_policies_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_profile_policies self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_profile_policies
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with profile_policies_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem observation_schemas_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_observation_schemas_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_observation_schemas_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem observation_schemas_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_observation_schemas_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_observation_schemas_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_observation_schemas_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.observation.ObservationSchemaId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem observation_schemas_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_observation_schemas self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_observation_schemas
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with observation_schemas_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem audiences_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_audiences_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_audiences_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem audiences_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_audiences_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_audiences_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_audiences_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.Audience.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem audiences_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_audiences self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_audiences
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with audiences_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

private theorem trust_anchor_ids_stopped (self : cbor.Encoder) (values : Slice String)
    (position : Std.Usize) (failure : error.CodecError) :
    text_list.encode_trust_anchor_ids_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [text_list.encode_trust_anchor_ids_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem trust_anchor_ids_suffix (values : Slice String) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List String)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + allocation textCost rest ≤ Usize.max) :
    text_list.encode_trust_anchor_ids_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.identifier rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [text_list.encode_trust_anchor_ids_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, value.toByteArray.size ≤ U32.max :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + textCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [text_list.encode_trust_anchor_ids_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok,
      auths_model.TrustAnchorId.as_str]
    rw [StringRefinement.string_borrow_exact first firstValid]
    simp only [bind_tc_ok]
    have firstLength : (toStr first firstValid).val.length = first.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact self (toStr first firstValid) (by
      simpa [textCost, firstLength] using firstSpace)
      as ⟨verdict, after, success, written⟩
    rw [borrowed_bytes] at written
    have exactBytes : byteList after.output.val =
        byteList self.output.val ++ UnsignedObjects.identifier first := by
      simpa [UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.text,
        ProtocolEncoderState.payloadEncoding, stringBytes] using written
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length exactBytes
    have itemBound := text_length_bound first
    have tailSpace : after.output.val.length + allocation textCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, exactBytes]
    simp [contents, List.append_assoc]

@[step] theorem trust_anchor_ids_exact (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + allocation textCost values.val ≤ Usize.max) :
    text_list.encode_trust_anchor_ids self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.identifier) ⦄ := by
  unfold text_list.encode_trust_anchor_ids
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation textCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with trust_anchor_ids_suffix values 0#usize afterHeader values.val
    (by simp) fields loopSpace as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, List.append_assoc]

end Auths.Codec.ProtocolTextWriters
