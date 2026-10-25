import Auths.Crypto.BundleLeaves
import Auths.Crypto.SignedObjectWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BundleArrays
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

/- Every concrete source array loop composes a proved complete record writer.
Order, multiplicity and full payloads are explicit; no arbitrary callback,
successful source writer or desired output vector is supplied. The seven
borrowed reference vectors are consumed by their real Rust helpers. -/

private theorem grant_stopped (self : cbor.Encoder) (values : Slice auths_model.SignedGrant)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_grant_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_grant_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem grant_suffix (values : Slice auths_model.SignedGrant) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.SignedGrant)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, SignedObjectWriters.GrantStrings value)
    (space : self.output.val.length + allocation SignedObjectWriters.grantCost rest ≤ Usize.max) :
    encode.encode_grant_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.signedGrant rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_grant_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, SignedObjectWriters.GrantStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + SignedObjectWriters.grantCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_grant_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with SignedObjectWriters.grant_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := SignedObjectWriters.grant_length first
    have tailSpace : after.output.val.length + allocation SignedObjectWriters.grantCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem grant_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.SignedGrant)
    (fields : ∀ value ∈ values.val, SignedObjectWriters.GrantStrings value)
    (space : self.output.val.length + 9 + allocation SignedObjectWriters.grantCost values.val ≤ Usize.max) :
    encode.encode_grant_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.signedGrant) ⦄ := by
  unfold encode.encode_grant_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation SignedObjectWriters.grantCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with grant_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem action_stopped (self : cbor.Encoder) (values : Slice auths_model.SignedAction)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_action_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_action_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem action_suffix (values : Slice auths_model.SignedAction) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.SignedAction)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, SignedObjectWriters.ActionStrings value)
    (space : self.output.val.length + allocation SignedObjectWriters.actionCost rest ≤ Usize.max) :
    encode.encode_action_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.signedAction rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_action_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, SignedObjectWriters.ActionStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + SignedObjectWriters.actionCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_action_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with SignedObjectWriters.action_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := SignedObjectWriters.action_length first
    have tailSpace : after.output.val.length + allocation SignedObjectWriters.actionCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem action_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.SignedAction)
    (fields : ∀ value ∈ values.val, SignedObjectWriters.ActionStrings value)
    (space : self.output.val.length + 9 + allocation SignedObjectWriters.actionCost values.val ≤ Usize.max) :
    encode.encode_action_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.signedAction) ⦄ := by
  unfold encode.encode_action_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation SignedObjectWriters.actionCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with action_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem evidence_stopped (self : cbor.Encoder) (values : Slice auths_model.EvidenceObject)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_evidence_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_evidence_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem evidence_suffix (values : Slice auths_model.EvidenceObject) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.EvidenceObject)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, EvidenceWriters.Strings value)
    (space : self.output.val.length + allocation EvidenceWriters.recordCost rest ≤ Usize.max) :
    encode.encode_evidence_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.evidence rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_evidence_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, EvidenceWriters.Strings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + EvidenceWriters.recordCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_evidence_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with EvidenceWriters.record_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := EvidenceWriters.record_length first
    have tailSpace : after.output.val.length + allocation EvidenceWriters.recordCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem evidence_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.EvidenceObject)
    (fields : ∀ value ∈ values.val, EvidenceWriters.Strings value)
    (space : self.output.val.length + 9 + allocation EvidenceWriters.recordCost values.val ≤ Usize.max) :
    encode.encode_evidence_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.evidence) ⦄ := by
  unfold encode.encode_evidence_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation EvidenceWriters.recordCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with evidence_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem binding_stopped (self : cbor.Encoder) (values : Slice auths_model.ControlBinding)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_binding_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_binding_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem binding_suffix (values : Slice auths_model.ControlBinding) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.ControlBinding)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, (fun _ => True) value)
    (space : self.output.val.length + allocation BundleObjects.bindingCost rest ≤ Usize.max) :
    encode.encode_binding_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents BundleObjects.binding rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_binding_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, (fun _ => True) value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + BundleObjects.bindingCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_binding_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with BundleLeaves.binding_exact self first firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := BundleLeaves.binding_length first
    have tailSpace : after.output.val.length + allocation BundleObjects.bindingCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem binding_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.ControlBinding)
    (fields : ∀ value ∈ values.val, (fun _ => True) value)
    (space : self.output.val.length + 9 + allocation BundleObjects.bindingCost values.val ≤ Usize.max) :
    encode.encode_binding_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map BundleObjects.binding) ⦄ := by
  unfold encode.encode_binding_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation BundleObjects.bindingCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with binding_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem principal_status_stopped (self : cbor.Encoder) (values : Slice auths_model.SignedPrincipalStatus)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_principal_status_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_principal_status_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem principal_status_suffix (values : Slice auths_model.SignedPrincipalStatus) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.SignedPrincipalStatus)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, SignedObjectWriters.PrincipalStatusStrings value)
    (space : self.output.val.length + allocation SignedObjectWriters.principal_statusCost rest ≤ Usize.max) :
    encode.encode_principal_status_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.signedPrincipalStatus rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_principal_status_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, SignedObjectWriters.PrincipalStatusStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + SignedObjectWriters.principal_statusCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_principal_status_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with SignedObjectWriters.principal_status_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := SignedObjectWriters.principal_status_length first
    have tailSpace : after.output.val.length + allocation SignedObjectWriters.principal_statusCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem principal_status_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (fields : ∀ value ∈ values.val, SignedObjectWriters.PrincipalStatusStrings value)
    (space : self.output.val.length + 9 + allocation SignedObjectWriters.principal_statusCost values.val ≤ Usize.max) :
    encode.encode_principal_status_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.signedPrincipalStatus) ⦄ := by
  unfold encode.encode_principal_status_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation SignedObjectWriters.principal_statusCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with principal_status_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem grant_status_stopped (self : cbor.Encoder) (values : Slice auths_model.SignedGrantStatus)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_grant_status_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_grant_status_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem grant_status_suffix (values : Slice auths_model.SignedGrantStatus) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.SignedGrantStatus)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, SignedObjectWriters.GrantStatusStrings value)
    (space : self.output.val.length + allocation SignedObjectWriters.grant_statusCost rest ≤ Usize.max) :
    encode.encode_grant_status_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.signedGrantStatus rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_grant_status_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, SignedObjectWriters.GrantStatusStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + SignedObjectWriters.grant_statusCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_grant_status_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with SignedObjectWriters.grant_status_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := SignedObjectWriters.grant_status_length first
    have tailSpace : after.output.val.length + allocation SignedObjectWriters.grant_statusCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem grant_status_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.SignedGrantStatus)
    (fields : ∀ value ∈ values.val, SignedObjectWriters.GrantStatusStrings value)
    (space : self.output.val.length + 9 + allocation SignedObjectWriters.grant_statusCost values.val ≤ Usize.max) :
    encode.encode_grant_status_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.signedGrantStatus) ⦄ := by
  unfold encode.encode_grant_status_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation SignedObjectWriters.grant_statusCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with grant_status_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem attachment_stopped (self : cbor.Encoder) (values : Slice auths_model.AttachmentDescriptor)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_attachment_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_attachment_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem attachment_suffix (values : Slice auths_model.AttachmentDescriptor) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.AttachmentDescriptor)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ProtocolArrayWriters.AttachmentStrings value)
    (space : self.output.val.length + allocation UnsignedLeaves.attachmentCost rest ≤ Usize.max) :
    encode.encode_attachment_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.attachment rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_attachment_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ProtocolArrayWriters.AttachmentStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + UnsignedLeaves.attachmentCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_attachment_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with UnsignedLeaves.attachment_exact self first firstValid.1 firstValid.2 firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := UnsignedLeaves.attachment_length_bound first
    have tailSpace : after.output.val.length + allocation UnsignedLeaves.attachmentCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem attachment_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.AttachmentDescriptor)
    (fields : ∀ value ∈ values.val, ProtocolArrayWriters.AttachmentStrings value)
    (space : self.output.val.length + 9 + allocation UnsignedLeaves.attachmentCost values.val ≤ Usize.max) :
    encode.encode_attachment_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.attachment) ⦄ := by
  unfold encode.encode_attachment_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation UnsignedLeaves.attachmentCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with attachment_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem approval_stopped (self : cbor.Encoder) (values : Slice auths_model.approval.SignedApproval)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_signed_approvals_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_signed_approvals_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem approval_suffix (values : Slice auths_model.approval.SignedApproval) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.approval.SignedApproval)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, SignedObjectWriters.ApprovalStrings value)
    (space : self.output.val.length + allocation SignedObjectWriters.approvalCost rest ≤ Usize.max) :
    encode.encode_signed_approvals_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.signedApproval rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_signed_approvals_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, SignedObjectWriters.ApprovalStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + SignedObjectWriters.approvalCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_signed_approvals_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with SignedObjectWriters.approval_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := SignedObjectWriters.approval_length first
    have tailSpace : after.output.val.length + allocation SignedObjectWriters.approvalCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem approval_exact (self : cbor.Encoder) (values : Slice auths_model.approval.SignedApproval)
    (fields : ∀ value ∈ values.val, SignedObjectWriters.ApprovalStrings value)
    (space : self.output.val.length + 9 + allocation SignedObjectWriters.approvalCost values.val ≤ Usize.max) :
    encode.encode_signed_approvals self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.signedApproval) ⦄ := by
  unfold encode.encode_signed_approvals
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation SignedObjectWriters.approvalCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with approval_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

end Auths.Crypto.BundleArrays
