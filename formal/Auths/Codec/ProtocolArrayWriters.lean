import Auths.Crypto.UnsignedLeaves
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolArrayWriters
open Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Crypto Auths.Crypto.UnsignedLeaves

/- Every concrete loop below unfolds its real generated recursive equation.
The independent list specification retains order and multiplicity. Source
item writers are proved concrete leaves, not caller-supplied callbacks or
opaque Auths algorithms. Actual loop/backward-borrow ABI review remains part
of the deferred extraction and elaboration pass. -/

def contents {T : Type} (model : T → List Nat) (values : List T) : List Nat :=
  values.flatMap model

def allocation {T : Type} (cost : T → Nat) (values : List T) : Nat :=
  (values.map cost).sum

theorem allocation_bound {T : Type} (cost : T → Nat) (values : List T) (maximum : Nat)
    (bounded : ∀ value ∈ values, cost value ≤ maximum) :
    allocation cost values ≤ values.length * maximum := by
  revert bounded
  induction values with
  | nil => intro bounded; simp [allocation]
  | cons first rest ih =>
    intro bounded
    have firstBound := bounded first (by simp)
    have restBound := ih (fun value member => bounded value (by simp [member]))
    simp only [allocation, List.map_cons, List.sum_cons, List.length_cons, Nat.succ_mul] at *
    omega

theorem contents_flatten {T : Type} (model : T → List Nat) (values : List T) :
    contents model values = (values.map model).flatten := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    simpa only [contents, List.flatMap_cons, List.map_cons, List.flatten_cons] using
      congrArg (List.append (model first)) ih

theorem contents_length {T : Type} (model : T → List Nat) (cost : T → Nat)
    (bounded : ∀ value, (model value).length ≤ cost value) (values : List T) :
    (contents model values).length ≤ allocation cost values := by
  induction values with
  | nil => simp [contents, allocation]
  | cons first rest ih =>
    have bound := bounded first
    simp only [contents, allocation, List.flatMap_cons, List.length_append,
      List.map_cons, List.sum_cons] at *
    omega

theorem array_model_length {T : Type} (model : T → List Nat) (cost : T → Nat)
    (bounded : ∀ value, (model value).length ≤ cost value) (values : List T) :
    (UnsignedWire.array (values.map model)).length ≤ 9 + allocation cost values := by
  have elements := contents_length model cost bounded values
  have head := encodeHead_length_le_nine ⟨4, values.length⟩
  simp only [UnsignedWire.array, List.length_append, List.length_map]
  rw [← contents_flatten]
  omega

def ExtensionStrings (value : auths_model.CriticalExtension) : Prop :=
  value.id.toByteArray.size ≤ U32.max

def AttachmentStrings (value : auths_model.AttachmentDescriptor) : Prop :=
  value.media_type.toByteArray.size ≤ U32.max ∧ value.disposition.toByteArray.size ≤ U32.max

def FactStrings (value : auths_model.observation.ObservationFact) : Prop :=
  value.name.toByteArray.size ≤ U32.max ∧ FactValueStrings value.value

private theorem permissions_stopped (self : cbor.Encoder) (values : Slice auths_model.Permission)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_permission_set_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_permission_set_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem permissions_suffix (values : Slice auths_model.Permission) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.Permission)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, PermissionStrings value)
    (space : self.output.val.length + allocation permissionCost rest ≤ Usize.max) :
    encode.encode_permission_set_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.permission rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_permission_set_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, PermissionStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + permissionCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_permission_set_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with UnsignedLeaves.permission_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := permission_length first
    have tailSpace : after.output.val.length + allocation permissionCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem permissions_exact (self : cbor.Encoder) (values : auths_model.PermissionSet)
    (fields : ∀ value ∈ values.val, PermissionStrings value)
    (space : self.output.val.length + 9 + allocation permissionCost values.val ≤ Usize.max) :
    encode.encode_permission_set self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.permission) ⦄ := by
  unfold encode.encode_permission_set
  simp only [auths_model.PermissionSet.impl.as_slice, auths_model.bounded.BoundedSet.impl.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation permissionCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with permissions_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem extensions_stopped (self : cbor.Encoder) (values : Slice auths_model.CriticalExtension)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_extensions_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_extensions_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem extensions_suffix (values : Slice auths_model.CriticalExtension) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.CriticalExtension)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, ExtensionStrings value)
    (space : self.output.val.length + allocation extensionCost rest ≤ Usize.max) :
    encode.encode_extensions_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.extension rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_extensions_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, ExtensionStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + extensionCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_extensions_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with UnsignedLeaves.extension_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := extension_length_bound first
    have tailSpace : after.output.val.length + allocation extensionCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem extensions_exact (self : cbor.Encoder) (values : auths_model.CriticalExtensions)
    (fields : ∀ value ∈ values.val, ExtensionStrings value)
    (space : self.output.val.length + 9 + allocation extensionCost values.val ≤ Usize.max) :
    encode.encode_extensions self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.extension) ⦄ := by
  unfold encode.encode_extensions
  simp only [auths_model.CriticalExtensions.impl.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation extensionCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with extensions_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem attachments_stopped (self : cbor.Encoder) (values : Slice auths_model.AttachmentDescriptor)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_attachments_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_attachments_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem attachments_suffix (values : Slice auths_model.AttachmentDescriptor) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.AttachmentDescriptor)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, AttachmentStrings value)
    (space : self.output.val.length + allocation attachmentCost rest ≤ Usize.max) :
    encode.encode_attachments_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.attachment rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_attachments_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, AttachmentStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + attachmentCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_attachments_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with UnsignedLeaves.attachment_exact self first firstValid.1 firstValid.2 firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := attachment_length_bound first
    have tailSpace : after.output.val.length + allocation attachmentCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem attachments_exact (self : cbor.Encoder) (values : Slice auths_model.AttachmentDescriptor)
    (fields : ∀ value ∈ values.val, AttachmentStrings value)
    (space : self.output.val.length + 9 + allocation attachmentCost values.val ≤ Usize.max) :
    encode.encode_attachments self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.attachment) ⦄ := by
  unfold encode.encode_attachments
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation attachmentCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with attachments_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem facts_stopped (self : cbor.Encoder) (values : Slice auths_model.observation.ObservationFact)
    (position : Std.Usize) (failure : error.CodecError) :
    observation.encode_observation_facts_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [observation.encode_observation_facts_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem facts_suffix (values : Slice auths_model.observation.ObservationFact) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.observation.ObservationFact)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, FactStrings value)
    (space : self.output.val.length + allocation factCost rest ≤ Usize.max) :
    observation.encode_observation_facts_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.fact rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [observation.encode_observation_facts_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, FactStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + factCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [observation.encode_observation_facts_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with UnsignedLeaves.fact_exact self first firstValid.1 firstValid.2 firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := fact_length_bound first
    have tailSpace : after.output.val.length + allocation factCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem facts_exact (self : cbor.Encoder) (values : Slice auths_model.observation.ObservationFact)
    (fields : ∀ value ∈ values.val, FactStrings value)
    (space : self.output.val.length + 9 + allocation factCost values.val ≤ Usize.max) :
    observation.encode_observation_facts self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.fact) ⦄ := by
  unfold observation.encode_observation_facts
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation factCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with facts_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

private theorem body_digests_stopped (self : cbor.Encoder) (values : Slice auths_model.Digest)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_body_digests_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_body_digests_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem body_digests_suffix (values : Slice auths_model.Digest) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.Digest)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, (fun _ => True) value)
    (space : self.output.val.length + allocation (fun _ => 41) rest ≤ Usize.max) :
    encode.encode_body_digests_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.digest rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_body_digests_loop.eq_def]
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
    rw [encode.encode_body_digests_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    simp only [auths_model.Digest.as_bytes, lift, Array.to_slice, bind_tc_ok]
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

@[step] theorem body_digests_exact (self : cbor.Encoder) (values : Slice auths_model.Digest)
    (fields : ∀ value ∈ values.val, (fun _ => True) value)
    (space : self.output.val.length + 9 + allocation (fun _ => 41) values.val ≤ Usize.max) :
    encode.encode_body_digests self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.digest) ⦄ := by
  unfold encode.encode_body_digests
  step with ProtocolWriter.array_exact self (Slice.len (values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation (fun _ => 41) values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with body_digests_suffix (values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

end Auths.Codec.ProtocolArrayWriters
