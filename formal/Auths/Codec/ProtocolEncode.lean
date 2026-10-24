import Auths.Codec.EncoderState
import Auths.Codec.String
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ProtocolEncode
open Refinement EncoderState

/-- Exact UTF-8 byte view, independent of the source encoder. -/
def stringBytes (value : String) : List Nat := value.toByteArray.toList.map UInt8.toNat

theorem borrowed_bytes (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    byteList (toStr value bounded).val = stringBytes value := by
  simp only [toStr, byteList, stringBytes, List.map_map]
  rfl

theorem stringBytes_length (value : String) : (stringBytes value).length = value.toByteArray.size := by
  simp [stringBytes, Auths.Model.Identifier.byte_array_list]

theorem output_length {before after : cbor.Encoder} {written : List Nat}
    (exactBytes : byteList after.output.val = byteList before.output.val ++ written) :
    after.output.val.length = before.output.val.length + written.length := by
  have lengths := congrArg List.length exactBytes
  simpa [byteList] using lengths

@[step] theorem length_exact (value : Std.Usize) :
    encode.length value ⦃ actual =>
      match actual with | .Ok word => word.val = value.val | .Err _ => False ⦄ := by
  unfold encode.length
  step with EncoderState.size_word_exact as ⟨word, meaning⟩
  cases word with
  | Err error => simp at meaning
  | Ok word => simpa [core.result.Result.map_err] using meaning

@[step] theorem map_exact (self : cbor.Encoder) (entries : Std.U64)
    (space : self.output.val.length + (9) ≤ Usize.max) :
    encode.map self entries ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨5, entries.val⟩ ⦄ := by
  unfold encode.map
  step with EncoderState.map_exact self entries (by omega) as ⟨verdict, next, success, written⟩
  simp [success, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    written]

@[step] theorem key_exact (self : cbor.Encoder) (value : Std.U8)
    (space : self.output.val.length + (9) ≤ Usize.max) :
    encode.key self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨0, value.val⟩ ⦄ := by
  unfold encode.key
  step with EncoderState.u8_exact self value (by omega) as ⟨verdict, next, success, written⟩
  simp [success, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    written]

@[step] theorem bytes_exact (self : cbor.Encoder) (value : Slice Std.U8)
    (space : self.output.val.length + (9 + value.val.length) ≤ Usize.max) :
    encode.bytes self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ payloadEncoding 2 (byteList value.val) ⦄ := by
  unfold encode.bytes
  step with EncoderState.bytes_exact self value (by omega) as ⟨verdict, next, success, written⟩
  simp [success, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    written]

@[step] theorem text_exact (self : cbor.Encoder) (value : Str)
    (space : self.output.val.length + (9 + value.val.length) ≤ Usize.max) :
    encode.text self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ payloadEncoding 3 (byteList value.val) ⦄ := by
  unfold encode.text
  step with EncoderState.str_exact self value (by omega) as ⟨verdict, next, success, written⟩
  simp [success, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    written]

@[step] theorem array_exact (self : cbor.Encoder) (entries : Std.Usize)
    (space : self.output.val.length + 9 ≤ Usize.max) :
    encode.array self entries ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ encodeHead ⟨4, entries.val⟩ ⦄ := by
  unfold encode.array
  step with length_exact as ⟨word, meaning⟩
  cases word with
  | Err error => simp at meaning
  | Ok word =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with EncoderState.array_exact self word space as ⟨verdict, next, success, written⟩
    simp [success, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      written, meaning]

end Auths.Codec.ProtocolEncode
