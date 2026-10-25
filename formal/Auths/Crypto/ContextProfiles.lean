import Auths.Crypto.ContextObjects
import Auths.Crypto.SnapshotArrays

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextProfiles
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

def Strings (value : auths_model.ProfileRef) : Prop := value.id.toByteArray.size ≤ U32.max

theorem profile_length (value : auths_model.ProfileRef) :
    (UnsignedObjects.profile value).length ≤ ContextObjects.profileCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.id),
    (1, UnsignedWire.uint value.version.val)]
  have id := UnsignedLeaves.identifier_length value.id
  have version := UnsignedWire.uint_length value.version.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.profileCost]
  omega

@[step] theorem profile_exact (self : cbor.Encoder) (value : auths_model.ProfileRef)
    (strings : Strings value)
    (space : self.output.val.length + ContextObjects.profileCost value ≤ Usize.max) :
    encode.encode_profile_ref self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.profile value ⦄ := by
  apply spec_mono (ProtocolObjectWriter.profile_exact self value strings
    (by simpa only [ContextObjects.profileCost] using space))
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [UnsignedLeaves.profile_schema] using written⟩

private theorem profiles_stopped (self : cbor.Encoder) (values : Slice auths_model.ProfileRef)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_profiles_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_profiles_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem profiles_suffix (values : Slice auths_model.ProfileRef) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.ProfileRef)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, Strings value)
    (space : self.output.val.length + allocation ContextObjects.profileCost rest ≤ Usize.max) :
    encode.encode_profiles_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.profile rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_profiles_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, Strings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + ContextObjects.profileCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_profiles_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with profile_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := profile_length first
    have tailSpace : after.output.val.length + allocation ContextObjects.profileCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem profiles_exact (self : cbor.Encoder) (values : Slice auths_model.ProfileRef)
    (fields : ∀ value ∈ values.val, Strings value)
    (space : self.output.val.length + 9 + allocation ContextObjects.profileCost values.val ≤ Usize.max) :
    encode.encode_profiles self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.profile) ⦄ := by
  unfold encode.encode_profiles
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation ContextObjects.profileCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with profiles_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

end Auths.Crypto.ContextProfiles
