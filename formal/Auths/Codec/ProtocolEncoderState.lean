import Auths.Codec.ProtocolHeadEncoder
import Auths.Crypto.ProtocolFramingTotality
import Auths.Codec.Evaluation
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec
namespace Auths.Codec.ProtocolEncoderState
open Refinement

private theorem append_exact (output : alloc.vec.Vec Std.U8) (input : Slice Std.U8)
    (fits : output.val.length + input.val.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 output input ⦃ actual =>
      actual.val = output.val ++ input.val ⦄ := by
  exact Auths.Crypto.ProtocolFramingTotality.append_total output input fits

@[step] theorem new_exact (output : alloc.vec.Vec Std.U8) :
    cbor.Encoder.new output ⦃ actual => actual.output = output ⦄ := by rfl

@[step] theorem into_writer_exact (self : cbor.Encoder) :
    cbor.Encoder.into_writer self ⦃ actual => actual = self.output ⦄ := by rfl

@[step] theorem head_exact (self : cbor.Encoder) (major : Std.U8) (argument : Std.U64)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    cbor.Encoder.head self major argument ⦃ actual =>
      actual.1 = (if major.val < 8 then .Ok () else .Err ()) ∧
      byteList actual.2.output.val =
        (if major.val < 8 then byteList self.output.val ++ encodeHead ⟨major.val, argument.val⟩
         else byteList self.output.val) ⦄ := by
  unfold cbor.Encoder.head
  step with ProtocolHeadEncoder.encode_head_refines as ⟨head, meaning⟩
  cases head with
  | Err error =>
    have invalid : ¬ major.val < 8 := by simp only [ProtocolHeadEncoder.EncodingRefines] at meaning; omega
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, invalid]
  | Ok head =>
    obtain ⟨valid, encoded⟩ := meaning
    have encodedLength := congrArg List.length encoded
    have headBound := encodeHead_length_le_nine ⟨major.val, argument.val⟩
    have fits : self.output.val.length + head.val.length ≤ Usize.max := by
      simp only [byteList, List.length_map] at encodedLength
      omega
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with append_exact self.output (alloc.vec.Vec.deref head) (by simpa only [alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref] using fits) as ⟨output, outputMeaning⟩
    simp [valid, byteList, outputMeaning, List.map_append, ← encoded, alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref]


@[step] theorem map_exact (self : cbor.Encoder) (entries : Std.U64)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    cbor.Encoder.map self entries ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨5, entries.val⟩ ⦄ := by
  unfold cbor.Encoder.map
  simpa using head_exact self 5#u8 entries space

@[step] theorem array_exact (self : cbor.Encoder) (entries : Std.U64)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    cbor.Encoder.array self entries ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨4, entries.val⟩ ⦄ := by
  unfold cbor.Encoder.array
  simpa using head_exact self 4#u8 entries space

@[step] theorem u64_exact (self : cbor.Encoder) (value : Std.U64)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    cbor.Encoder.u64 self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨0, value.val⟩ ⦄ := by
  unfold cbor.Encoder.u64
  simpa using head_exact self 0#u8 value space

@[step] theorem u32_exact (self : cbor.Encoder) (value : Std.U32)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    cbor.Encoder.u32 self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨0, value.val⟩ ⦄ := by
  unfold cbor.Encoder.u32
  simp only [lift, bind_tc_ok]
  have wider : (core.convert.num.FromU64U32.from value).val = value.val := by
    apply UScalar.cast_val_mod_pow_of_inBounds_eq
    scalar_tac
  simpa only [wider] using u64_exact self (core.convert.num.FromU64U32.from value) space

@[step] theorem u16_exact (self : cbor.Encoder) (value : Std.U16)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    cbor.Encoder.u16 self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨0, value.val⟩ ⦄ := by
  unfold cbor.Encoder.u16
  simp only [lift, bind_tc_ok]
  have wider : (core.convert.num.FromU64U16.from value).val = value.val := by
    apply UScalar.cast_val_mod_pow_of_inBounds_eq
    scalar_tac
  simpa only [wider] using u64_exact self (core.convert.num.FromU64U16.from value) space

@[step] theorem u8_exact (self : cbor.Encoder) (value : Std.U8)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    cbor.Encoder.u8 self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨0, value.val⟩ ⦄ := by
  unfold cbor.Encoder.u8
  simp only [lift, bind_tc_ok]
  have wider : (core.convert.num.FromU64U8.from value).val = value.val := by
    apply UScalar.cast_val_mod_pow_of_inBounds_eq
    scalar_tac
  simpa only [wider] using u64_exact self (core.convert.num.FromU64U8.from value) space

theorem size_word_exact (value : Std.Usize) :
    U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from value ⦃ actual =>
      match actual with | .Ok word => word.val = value.val | .Err _ => False ⦄ := by
  unfold U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from core.num.tryFromUScalar
  have within : value.val ≤ UScalar.max .U64 := by
    simp only [UScalar.max_UScalarTy_U64_eq]
    have bounded : value.val ≤ Usize.max := by scalar_tac
    have platform := Usize.bounds_eq
    rcases platform with platform | platform
    · rw [platform] at bounded
      scalar_tac
    · simpa only [platform] using bounded
  simp only [within, ↓reduceIte, spec_ok]
  apply UScalar.cast_val_mod_pow_of_inBounds_eq
  scalar_tac

def payloadEncoding (major : Nat) (bytes : List Nat) : List Nat :=
  encodeHead ⟨major, bytes.length⟩ ++ bytes

@[step] theorem payload_exact (self : cbor.Encoder) (major : Std.U8) (bytes : Slice Std.U8)
    (space : self.output.val.length + 9 + bytes.val.length ≤ Usize.max) :
    cbor.Encoder.payload self major bytes ⦃ actual =>
      actual.1 = (if major.val < 8 then .Ok () else .Err ()) ∧
      byteList actual.2.output.val =
        if major.val < 8 then byteList self.output.val ++ payloadEncoding major.val (byteList bytes.val)
        else byteList self.output.val ⦄ := by
  unfold cbor.Encoder.payload
  step with size_word_exact as ⟨length, lengthMeaning⟩
  cases length with
  | Err error => simp at lengthMeaning
  | Ok length =>
    simp only at lengthMeaning
    simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
    have headSpace : self.output.val.length + 9 ≤ Usize.max := by omega
    step with head_exact self major length headSpace as ⟨verdict, afterHead, outcome, headBytes⟩
    by_cases valid : major.val < 8
    · have success : verdict = .Ok () := by simpa [valid] using outcome
      have headPrefix : byteList afterHead.output.val =
          byteList self.output.val ++ encodeHead ⟨major.val, bytes.val.length⟩ := by
        simpa [valid, lengthMeaning] using headBytes
      have outputLength := congrArg List.length headPrefix
      simp only [byteList, List.length_map, List.length_append] at outputLength
      have headBound := encodeHead_length_le_nine ⟨major.val, bytes.val.length⟩
      have fits : afterHead.output.val.length + bytes.val.length ≤ Usize.max := by omega
      simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with append_exact afterHead.output bytes fits as ⟨output, outputMeaning⟩
      have resultBytes : byteList output.val = byteList afterHead.output.val ++ byteList bytes.val := by
        simp [byteList, outputMeaning, List.map_append]
      simp only [spec_ok]
      constructor
      · simp [valid]
      · simp only [resultBytes, headPrefix, valid, ↓reduceIte, payloadEncoding,
          byteList, List.length_map, List.append_assoc]
    · have refusal : verdict = .Err () := by simpa [valid] using outcome
      simp [refusal, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, valid, headBytes]

@[step] theorem bytes_exact (self : cbor.Encoder) (bytes : Slice Std.U8)
    (space : self.output.val.length + 9 + bytes.val.length ≤ Usize.max) :
    cbor.Encoder.bytes self bytes ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ payloadEncoding 2 (byteList bytes.val) ⦄ := by
  unfold cbor.Encoder.bytes
  simpa using payload_exact self 2#u8 bytes space

@[step] theorem str_exact (self : cbor.Encoder) (text : Str)
    (space : self.output.val.length + 9 + text.val.length ≤ Usize.max) :
    cbor.Encoder.str self text ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ payloadEncoding 3 (byteList text.val) ⦄ := by
  unfold cbor.Encoder.str
  simp only [core.str.Str.as_bytes, bind_tc_ok]
  simpa using payload_exact self 3#u8 text space

@[step] theorem null_exact (self : cbor.Encoder)
    (space : self.output.val.length + 1 ≤ Usize.max) :
    cbor.Encoder.null self ⦃ actual =>
      byteList actual.output.val = byteList self.output.val ++ [246] ⦄ := by
  unfold cbor.Encoder.null
  have fits : self.output.val.length < Usize.max := by omega
  step with alloc.vec.push_spec self.output 246#u8 fits as ⟨output, outputMeaning⟩
  simp [byteList, outputMeaning, List.map_append]

@[step] theorem bool_exact (self : cbor.Encoder) (value : Bool)
    (space : self.output.val.length + 1 ≤ Usize.max) :
    cbor.Encoder.bool self value ⦃ actual =>
      byteList actual.output.val = byteList self.output.val ++
        (if value then [245] else [244]) ⦄ := by
  have fits : self.output.val.length < Usize.max := by omega
  cases value with
  | false =>
    unfold cbor.Encoder.bool
    step with alloc.vec.push_spec self.output 244#u8 fits as ⟨output, outputMeaning⟩
    simp [byteList, outputMeaning, List.map_append]
  | true =>
    unfold cbor.Encoder.bool
    step with alloc.vec.push_spec self.output 245#u8 fits as ⟨output, outputMeaning⟩
    simp [byteList, outputMeaning, List.map_append]

end Auths.Codec.ProtocolEncoderState
