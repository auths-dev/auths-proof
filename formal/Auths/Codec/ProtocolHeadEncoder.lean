import qualification.aeneas.generated.protocol_codec.Funs
import Auths.Codec.Encoder

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open Auths.Codec Auths.Codec.Refinement
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolHeadEncoder
set_option maxHeartbeats 2000000

/- Actual complete-protocol CBOR heads use the same independent shortest-head
and big-endian byte grammar. The consuming loop below is proved recursively,
matching this route's loops-to-rec extraction configuration. No expected
source encoding, successful caller or opaque Auths-owned loop is assumed. -/

abbrev bigEndian_cons := Auths.Codec.Refinement.Encoder.bigEndian_cons
abbrev cast_byte := Auths.Codec.Refinement.Encoder.cast_byte

@[step] theorem append_tail_exact (output : alloc.vec.Vec Std.U8)
    (value : Std.U64) (remaining : Std.U8)
    (width : remaining.val ≤ 8)
    (capacity : output.val.length + remaining.val ≤ Usize.max) :
    cbor.append_tail output value remaining ⦃ encoded =>
      byteList encoded.val = byteList output.val ++ bigEndian remaining.val value.val ⦄ := by
  have general : ∀ count (current : alloc.vec.Vec Std.U8) (left : Std.U8),
      left.val = count → left.val ≤ 8 → current.val.length + left.val ≤ Usize.max →
      cbor.append_tail current value left ⦃ encoded =>
        byteList encoded.val = byteList current.val ++ bigEndian left.val value.val ⦄ := by
    intro count
    induction count using Nat.strong_induction_on with
    | h count ih =>
      intro current left sized leftWidth leftCapacity
      unfold cbor.append_tail
      rw [cbor.append_tail_loop.eq_def]
      split <;> rename_i nonzero
      · have positive : 0 < left.val := by scalar_tac
        step as ⟨nextLeft, nextLeftEq⟩
        simp only [lift, bind_tc_ok]
        step as ⟨shift, shiftEq⟩
        step as ⟨shifted, shiftedEq, shiftedBits⟩
        step as ⟨nextOutput, nextOutputEq⟩
        have smaller : nextLeft.val < count := by omega
        have nextWidth : nextLeft.val ≤ 8 := by omega
        have nextCapacity : nextOutput.val.length + nextLeft.val ≤ Usize.max := by
          simp only [nextOutputEq, List.length_append, List.length_singleton]
          omega
        apply spec_mono (ih nextLeft.val smaller nextOutput nextLeft rfl nextWidth nextCapacity)
        intro encoded encodedEq
        have chunk := bigEndian_cons (left.val - 1) value.val
        have leftEq : left.val - 1 + 1 = left.val := by omega
        rw [leftEq] at chunk
        have shiftAmount : shift.val = (left.val - 1) * 8 := by
          simpa [nextLeftEq] using shiftEq
        have power : 2 ^ ((left.val - 1) * 8) = 256 ^ (left.val - 1) := by
          rw [Nat.mul_comm, Nat.pow_mul]
        have digit : (UScalar.cast .U8 shifted).val = value.val / 256 ^ (left.val - 1) % 256 := by
          rw [cast_byte, shiftedEq, Nat.shiftRight_eq_div_pow, shiftAmount, power]
        have appended : byteList nextOutput.val =
            byteList current.val ++ [value.val / 256 ^ (left.val - 1) % 256] := by
          simp [byteList, nextOutputEq, digit]
        rw [encodedEq, appended, nextLeftEq, chunk]
        simp [List.append_assoc]
      · have zero : left.val = 0 := by scalar_tac
        simp [spec_ok, zero, bigEndian]
  exact general remaining.val output remaining rfl width capacity

def EncodingRefines (major : Std.U8) (argument : Std.U64)
    (result : core.result.Result (alloc.vec.Vec Std.U8) cbor.Error) : Prop :=
  match result with
  | .Err _ => 7 < major.val
  | .Ok output => major.val < 8 ∧
      byteList output.val = encodeHead ⟨major.val, argument.val⟩

theorem encode_head_refines (major : Std.U8) (argument : Std.U64) :
    cbor.encode_head major argument ⦃ result => EncodingRefines major argument result ⦄ := by
  have emptyFits : (alloc.vec.Vec.with_capacity Std.U8 9#usize).val.length < Usize.max := by
    simp only [alloc.vec.with_capacity_contents]
    scalar_tac
  unfold cbor.encode_head
  split <;> rename_i invalid
  · simp only [spec_ok, EncodingRefines]
    scalar_tac
  · have majorValid : major.val < 8 := by scalar_tac
    step as ⟨prefixByte, prefixEq⟩
    split <;> rename_i inline
    · have inlineNat : argument.val < 24 := by scalar_tac
      have castEq : (UScalar.cast .U8 argument).val = argument.val := by
        rw [cast_byte, Nat.mod_eq_of_lt (by omega)]
      simp only [lift, bind_tc_ok]
      step as ⟨header, headerEq⟩
      step as ⟨output, outputEq⟩
      simp only [EncodingRefines]
      refine ⟨majorValid, ?_⟩
      simp [byteList, outputEq, alloc.vec.with_capacity_contents,
        encodeHead, additionalTag, argumentWidth, inlineNat, bigEndian, headerEq, prefixEq, castEq]
    · split <;> rename_i fitsByte
      · step as ⟨header, headerEq⟩
        step as ⟨output, outputEq⟩
        have tailFits : output.val.length + 8 ≤ Usize.max := by
          simp only [outputEq, alloc.vec.with_capacity_contents, List.length_append, List.length_cons, List.length_nil]
          scalar_tac
        step as ⟨encoded, encodedEq⟩
        simp only [EncodingRefines]
        refine ⟨majorValid, ?_⟩
        have aboveInline : ¬ argument.val < 24 := by scalar_tac
        have withinByte : argument.val < 256 := by scalar_tac
        simpa [encodeHead, additionalTag, argumentWidth, aboveInline, withinByte,
          byteList, outputEq, alloc.vec.with_capacity_contents, headerEq, prefixEq] using encodedEq
      · split <;> rename_i fitsShort
        · step as ⟨header, headerEq⟩
          step as ⟨output, outputEq⟩
          have tailFits : output.val.length + 8 ≤ Usize.max := by
            simp only [outputEq, alloc.vec.with_capacity_contents, List.length_append, List.length_cons, List.length_nil]
            scalar_tac
          step as ⟨encoded, encodedEq⟩
          simp only [EncodingRefines]
          refine ⟨majorValid, ?_⟩
          have aboveInline : ¬ argument.val < 24 := by scalar_tac
          have aboveByte : ¬ argument.val < 256 := by scalar_tac
          have withinShort : argument.val < 65536 := by scalar_tac
          simpa [encodeHead, additionalTag, argumentWidth, aboveInline, aboveByte, withinShort,
            byteList, outputEq, alloc.vec.with_capacity_contents, headerEq, prefixEq] using encodedEq
        · split <;> rename_i fitsWord
          · step as ⟨header, headerEq⟩
            step as ⟨output, outputEq⟩
            have tailFits : output.val.length + 8 ≤ Usize.max := by
              simp only [outputEq, alloc.vec.with_capacity_contents, List.length_append, List.length_cons, List.length_nil]
              scalar_tac
            step as ⟨encoded, encodedEq⟩
            simp only [EncodingRefines]
            refine ⟨majorValid, ?_⟩
            have aboveInline : ¬ argument.val < 24 := by scalar_tac
            have aboveByte : ¬ argument.val < 256 := by scalar_tac
            have aboveShort : ¬ argument.val < 65536 := by scalar_tac
            have withinWord : argument.val < 4294967296 := by scalar_tac
            simpa [encodeHead, additionalTag, argumentWidth, aboveInline, aboveByte, aboveShort, withinWord,
              byteList, outputEq, alloc.vec.with_capacity_contents, headerEq, prefixEq] using encodedEq
          · step as ⟨header, headerEq⟩
            step as ⟨output, outputEq⟩
            have tailFits : output.val.length + 8 ≤ Usize.max := by
              simp only [outputEq, alloc.vec.with_capacity_contents, List.length_append, List.length_cons, List.length_nil]
              scalar_tac
            step as ⟨encoded, encodedEq⟩
            simp only [EncodingRefines]
            refine ⟨majorValid, ?_⟩
            have aboveInline : ¬ argument.val < 24 := by scalar_tac
            have aboveByte : ¬ argument.val < 256 := by scalar_tac
            have aboveShort : ¬ argument.val < 65536 := by scalar_tac
            have aboveWord : ¬ argument.val < 4294967296 := by scalar_tac
            simpa [encodeHead, additionalTag, argumentWidth, aboveInline, aboveByte, aboveShort, aboveWord,
              byteList, outputEq, alloc.vec.with_capacity_contents, headerEq, prefixEq] using encodedEq


theorem encode_head_byte_bound (major : Std.U8) (argument : Std.U64) :
    cbor.encode_head major argument ⦃ result =>
      match result with
      | .Err _ => 7 < major.val
      | .Ok output => 1 ≤ output.val.length ∧ output.val.length ≤ 9 ⦄ := by
  apply spec_mono (encode_head_refines major argument)
  intro result refines
  cases result with
  | Err => exact refines
  | Ok output =>
    obtain ⟨valid, encoded⟩ := refines
    have lengthEq := congrArg List.length encoded
    simp only [byteList, List.length_map] at lengthEq
    have positive : 1 ≤ (encodeHead ⟨major.val, argument.val⟩).length := by
      simp [encodeHead]
    have bounded := encodeHead_length_le_nine ⟨major.val, argument.val⟩
    omega


end Auths.Codec.ProtocolHeadEncoder
