import Auths.Codec.Refinement

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open Auths.Codec Auths.Codec.Refinement
open auths_codec

namespace Auths.Codec.Refinement.Encoder

set_option maxHeartbeats 2000000

theorem bigEndian_cons (width value : Nat) :
    bigEndian (width + 1) value =
      (value / 256 ^ width % 256) :: bigEndian width value := by
  induction width generalizing value with
  | zero => simp [bigEndian]
  | succ width ih =>
    rw [bigEndian, ih, bigEndian]
    simp only [List.cons_append]
    congr 2
    rw [Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm]

theorem cast_byte (value : Std.U64) :
    (UScalar.cast .U8 value).val = value.val % 256 := by
  simp only [UScalar.cast, UScalar.val, BitVec.zeroExtend, BitVec.toNat_setWidth]
  rfl

@[step] theorem append_tail_exact (output : alloc.vec.Vec Std.U8)
    (value : Std.U64) (remaining : Std.U8)
    (width : remaining.val ≤ 8)
    (capacity : output.val.length + remaining.val ≤ Usize.max) :
    cbor.append_tail output value remaining ⦃ encoded =>
      byteList encoded.val = byteList output.val ++ bigEndian remaining.val value.val ⦄ := by
  let expected := byteList output.val ++ bigEndian remaining.val value.val
  unfold cbor.append_tail cbor.append_tail_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.2.val)
    (inv := fun state => state.2.val ≤ 8 ∧
      state.1.val.length + state.2.val ≤ Usize.max ∧
      byteList state.1.val ++ bigEndian state.2.val value.val = expected)
  · rintro ⟨current, left⟩ ⟨leftWidth, leftCapacity, meaning⟩
    dsimp only at leftWidth leftCapacity meaning
    unfold cbor.append_tail_loop.body
    dsimp only
    split <;> rename_i nonzero
    · have positive : 0 < left.val := by scalar_tac
      step as ⟨nextLeft, nextLeftEq⟩
      simp only [lift, bind_tc_ok]
      step as ⟨shift, shiftEq⟩
      step as ⟨shifted, shiftedEq, shiftedBits⟩
      step as ⟨nextOutput, nextOutputEq⟩
      refine ⟨by omega, ?_, ?_, by omega⟩
      · simp [nextOutputEq]
        omega
      · have chunk := bigEndian_cons (left.val - 1) value.val
        have leftEq : left.val - 1 + 1 = left.val := by omega
        rw [leftEq] at chunk
        rw [chunk] at meaning
        have shiftAmount : shift.val = (left.val - 1) * 8 := by
          simpa [nextLeftEq] using shiftEq
        have power : 2 ^ ((left.val - 1) * 8) = 256 ^ (left.val - 1) := by
          rw [Nat.mul_comm, Nat.pow_mul]
        have digit : (UScalar.cast .U8 shifted).val = value.val / 256 ^ (left.val - 1) % 256 := by
          rw [cast_byte, shiftedEq, Nat.shiftRight_eq_div_pow, shiftAmount, power]
        have after : byteList nextOutput.val = byteList current.val ++ [value.val / 256 ^ (left.val - 1) % 256] := by
          simp [byteList, nextOutputEq, digit]
        rw [after, nextLeftEq]
        simpa [List.append_assoc] using meaning
    · simp only [spec_ok]
      have zero : left.val = 0 := by scalar_tac
      simpa [zero, bigEndian] using meaning
  · exact ⟨width, capacity, rfl⟩

def EncodingRefines (major : Std.U8) (argument : Std.U64)
    (result : core.result.Result (alloc.vec.Vec Std.U8) cbor.Error) : Prop :=
  match result with
  | .Err _ => 7 < major.val
  | .Ok output => major.val < 8 ∧
      byteList output.val = encodeHead ⟨major.val, argument.val⟩

theorem encode_head_refines (major : Std.U8) (argument : Std.U64) :
    cbor.encode_head major argument ⦃ result => EncodingRefines major argument result ⦄ := by
  have emptyFits : (alloc.vec.Vec.with_capacity Std.U8 9#usize).val.length < Usize.max := by
    simp only [alloc.vec.Vec.with_capacity, alloc.vec.Vec.new]
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
      simp [byteList, outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
        encodeHead, additionalTag, argumentWidth, inlineNat, bigEndian, headerEq, prefixEq, castEq]
    · split <;> rename_i fitsByte
      · step as ⟨header, headerEq⟩
        step as ⟨output, outputEq⟩
        have tailFits : output.val.length + 8 ≤ Usize.max := by
          simp only [outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, List.length_append, List.length_cons, List.length_nil]
          scalar_tac
        step as ⟨encoded, encodedEq⟩
        simp only [EncodingRefines]
        refine ⟨majorValid, ?_⟩
        have aboveInline : ¬ argument.val < 24 := by scalar_tac
        have withinByte : argument.val < 256 := by scalar_tac
        simpa [encodeHead, additionalTag, argumentWidth, aboveInline, withinByte,
          byteList, outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, headerEq, prefixEq] using encodedEq
      · split <;> rename_i fitsShort
        · step as ⟨header, headerEq⟩
          step as ⟨output, outputEq⟩
          have tailFits : output.val.length + 8 ≤ Usize.max := by
            simp only [outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, List.length_append, List.length_cons, List.length_nil]
            scalar_tac
          step as ⟨encoded, encodedEq⟩
          simp only [EncodingRefines]
          refine ⟨majorValid, ?_⟩
          have aboveInline : ¬ argument.val < 24 := by scalar_tac
          have aboveByte : ¬ argument.val < 256 := by scalar_tac
          have withinShort : argument.val < 65536 := by scalar_tac
          simpa [encodeHead, additionalTag, argumentWidth, aboveInline, aboveByte, withinShort,
            byteList, outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, headerEq, prefixEq] using encodedEq
        · split <;> rename_i fitsWord
          · step as ⟨header, headerEq⟩
            step as ⟨output, outputEq⟩
            have tailFits : output.val.length + 8 ≤ Usize.max := by
              simp only [outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, List.length_append, List.length_cons, List.length_nil]
              scalar_tac
            step as ⟨encoded, encodedEq⟩
            simp only [EncodingRefines]
            refine ⟨majorValid, ?_⟩
            have aboveInline : ¬ argument.val < 24 := by scalar_tac
            have aboveByte : ¬ argument.val < 256 := by scalar_tac
            have aboveShort : ¬ argument.val < 65536 := by scalar_tac
            have withinWord : argument.val < 4294967296 := by scalar_tac
            simpa [encodeHead, additionalTag, argumentWidth, aboveInline, aboveByte, aboveShort, withinWord,
              byteList, outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, headerEq, prefixEq] using encodedEq
          · step as ⟨header, headerEq⟩
            step as ⟨output, outputEq⟩
            have tailFits : output.val.length + 8 ≤ Usize.max := by
              simp only [outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, List.length_append, List.length_cons, List.length_nil]
              scalar_tac
            step as ⟨encoded, encodedEq⟩
            simp only [EncodingRefines]
            refine ⟨majorValid, ?_⟩
            have aboveInline : ¬ argument.val < 24 := by scalar_tac
            have aboveByte : ¬ argument.val < 256 := by scalar_tac
            have aboveShort : ¬ argument.val < 65536 := by scalar_tac
            have aboveWord : ¬ argument.val < 4294967296 := by scalar_tac
            simpa [encodeHead, additionalTag, argumentWidth, aboveInline, aboveByte, aboveShort, aboveWord,
              byteList, outputEq, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, headerEq, prefixEq] using encodedEq


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

theorem encode_head_roundtrip (major : Std.U8) (argument : Std.U64)
    (valid : major.val < 8) :
    cbor.encode_head major argument ⦃ result =>
      ∃ output, result = .Ok output ∧
        ∀ (input : Slice Std.U8) (position : Std.Usize) (tail : List Nat),
          (byteList input.val).drop position.val = byteList output.val ++ tail →
          cbor.read_head input position ⦃ decoded =>
            ∃ head, decoded = .Ok head ∧
              headView head = ⟨major.val, argument.val⟩ ∧
              (byteList input.val).drop head.next.val = tail ∧
              head.next.val ≤ input.val.length ⦄ ⦄ := by
  apply spec_mono (encode_head_refines major argument)
  intro result refines
  cases result with
  | Err => simp only [EncodingRefines] at refines; omega
  | Ok output =>
    refine ⟨output, rfl, ?_⟩
    intro input position tail encoded
    have headValid : (Head.mk major.val argument.val).Valid := by
      exact ⟨valid, by scalar_tac⟩
    apply read_head_accepts_encoding input position ⟨major.val, argument.val⟩ tail headValid
    simpa only [refines.2] using encoded


end Auths.Codec.Refinement.Encoder
