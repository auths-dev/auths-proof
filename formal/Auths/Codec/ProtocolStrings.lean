import Auths.Codec.ProtocolWriter
import Auths.Crypto.UnsignedObjects
import Auths.Crypto.UnsignedLeaves
import Auths.Codec.ProtocolFields

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolStrings
open Auths.Codec.Refinement Auths.Crypto

/- The existing explicit standard UTF-8/string-copy model, with its complete
accepted output bytes. No Auths parser is abstracted here. These consequences
let accepted source parsers earn lexical validity without an expected String
or a caller-supplied successful string-copy flag. -/
def owned (value : Str) (valid : (Auths.Codec.StdModel.bytes value).IsValidUTF8) : String :=
  String.fromUTF8 (Auths.Codec.StdModel.bytes value) valid

theorem copy_exact (value : Str) (valid : (Auths.Codec.StdModel.bytes value).IsValidUTF8) :
    alloc.string.String.Insts.CoreConvertFromShared0Str.from value = ok (owned value valid) := by
  simp [alloc.string.String.Insts.CoreConvertFromShared0Str.from, String.fromUTF8?, valid, owned]

theorem owned_bytes (value : Str) (valid : (Auths.Codec.StdModel.bytes value).IsValidUTF8) :
    UnsignedObjects.utf8 (owned value valid) = byteList value.val := by
  simp only [owned, String.fromUTF8, Auths.Codec.StdModel.bytes,
    Auths.Model.Identifier.byte_array_list, List.toList_data_toByteArray,
    List.map_map, UnsignedObjects.utf8, byteList]
  apply List.map_congr_left
  intro byte member
  have bound : byte.val < 256 := by scalar_tac
  simp [UInt8.toNat_ofNat, Nat.mod_eq_of_lt bound]

theorem copy_accepted (value : Str) (output : String)
    (accepted : alloc.string.String.Insts.CoreConvertFromShared0Str.from value = ok output) :
    UnsignedObjects.utf8 output = byteList value.val := by
  by_cases valid : (Auths.Codec.StdModel.bytes value).IsValidUTF8
  · rw [copy_exact value valid] at accepted
    have same : owned value valid = output := by simpa using accepted
    rw [← same]
    exact owned_bytes value valid
  · simp [alloc.string.String.Insts.CoreConvertFromShared0Str.from, String.fromUTF8?, valid] at accepted

theorem copied_carrier (value : Str) (output : String)
    (accepted : alloc.string.String.Insts.CoreConvertFromShared0Str.from value = ok output)
    (bounded : value.val.length ≤ U32.max) :
    ∃ carrierBound : output.toByteArray.size ≤ U32.max, value = toStr output carrierBound := by
  have bytes := copy_accepted value output accepted
  have length : output.toByteArray.size = value.val.length := by
    have same := congrArg List.length bytes
    simpa only [UnsignedLeaves.utf8_length, byteList, List.length_map] using same
  have carrierBound : output.toByteArray.size ≤ U32.max := by omega
  refine ⟨carrierBound, ?_⟩
  apply Subtype.ext
  have injective : Function.Injective (fun values : List Std.U8 => byteList values) := by
    apply List.map_injective_iff.mpr
    intro left right same
    exact UScalar.eq_of_val_eq same
  apply injective
  rw [ProtocolWriter.borrowed_bytes]
  simpa only [ProtocolWriter.stringBytes, UnsignedObjects.utf8] using bytes.symm

theorem text_valid (self next : cbor.Decoder) (output : Str)
    (accepted : decode.text self = ok (.Ok output, next)) :
    (Auths.Codec.StdModel.bytes output).IsValidUTF8 := by
  have behavior := ProtocolFields.text_exact self
  rw [accepted, spec_ok] at behavior
  have bytes := congrArg Prod.fst behavior.1
  simp only [ProtocolFields.codecBytesView, ProtocolFields.textAt, ProtocolPayload.textAt] at bytes
  cases payload : ProtocolPayload.payloadAt (ProtocolReadHead.byteList self.input.val) self.position.val 3 with
  | mk value position =>
    rw [payload] at bytes
    cases value with
    | none => simp at bytes
    | some value =>
      by_cases valid : ProtocolPayload.validUtf8 value = true
      · have same : byteList output.val = value := by simpa [Option.filter, valid] using bytes
        have utf8 : ProtocolPayload.validUtf8 (byteList output.val) = true := by rw [same]; exact valid
        simpa only [ProtocolPayload.validUtf8, Auths.Codec.StdModel.bytes, byteList,
          List.map_map, Function.comp_def, decide_eq_true_eq] using utf8
      · simp [Option.filter, valid] at bytes

end Auths.Codec.ProtocolStrings
