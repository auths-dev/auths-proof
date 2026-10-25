import Auths.Crypto.SnapshotLeaves
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SnapshotArrays
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters

private theorem trust_stopped (self : cbor.Encoder) (values : Slice auths_model.StatusTrustRule)
    (position : Std.Usize) (failure : error.CodecError) :
    encode.encode_status_trust_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [encode.encode_status_trust_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem trust_suffix (values : Slice auths_model.StatusTrustRule) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.StatusTrustRule)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, SnapshotLeaves.TrustStrings value)
    (space : self.output.val.length + allocation SnapshotObjects.trustRuleCost rest ≤ Usize.max) :
    encode.encode_status_trust_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents SnapshotObjects.trustRule rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.encode_status_trust_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, SnapshotLeaves.TrustStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + SnapshotObjects.trustRuleCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [encode.encode_status_trust_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with SnapshotLeaves.trust_rule_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := SnapshotLeaves.trust_rule_length first
    have tailSpace : after.output.val.length + allocation SnapshotObjects.trustRuleCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem trust_exact (self : cbor.Encoder) (values : Slice auths_model.StatusTrustRule)
    (fields : ∀ value ∈ values.val, SnapshotLeaves.TrustStrings value)
    (space : self.output.val.length + 9 + allocation SnapshotObjects.trustRuleCost values.val ≤ Usize.max) :
    encode.encode_status_trust self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map SnapshotObjects.trustRule) ⦄ := by
  unfold encode.encode_status_trust
  step with ProtocolWriter.array_exact self (Slice.len values) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation SnapshotObjects.trustRuleCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with trust_suffix values 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

end Auths.Crypto.SnapshotArrays
