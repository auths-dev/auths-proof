import Auths.Codec.NativeFieldInverse
import Auths.Codec.AttachmentInverse
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.PrimitiveInverse
open Refinement ProtocolEncode EncoderState WireInverse NativeFieldInverse

@[step] theorem map_inverse (self : cbor.Decoder) (fields : Std.U64) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨5, fields.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    decode.map self fields ⦃ actual => actual.1 = .Ok () ∧
      actual.2.position.val = leading.length + (encodeHead ⟨5, fields.val⟩).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (Fields.map_exact self fields)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, map_consumes fields.val (by scalar_tac) leading trailing] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, inputSame⟩

@[step] theorem key_inverse (self : cbor.Decoder) (key : Std.U8) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨0, key.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    decode.key self key ⦃ actual => actual.1 = .Ok () ∧
      actual.2.position.val = leading.length + (encodeHead ⟨0, key.val⟩).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (Fields.key_exact self key)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, key_consumes key.val (by scalar_tac) leading trailing] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, inputSame⟩

theorem size_fits_u64 (value : Std.Usize) : value.val < 2 ^ 64 := by
  have bound : value.val ≤ Usize.max := by scalar_tac
  rcases Usize.bounds_eq with width | width <;> rw [width] at bound <;> scalar_tac

theorem array_consumes (count : Nat) (maximum : Nat) (fits : count ≤ maximum) (bounded : count < 2 ^ 64) :
    Consumes (fun input position => Fields.arrayAt input position maximum) (encodeHead ⟨4, count⟩) count := by
  intro leading trailing
  have exactHead := typed_head_prefix ⟨4, count⟩ ⟨by decide, bounded⟩ leading trailing
  have noMarker := header_not_indefinite ⟨4, count⟩
  have firstByte : (leading ++ encodeHead ⟨4, count⟩ ++ trailing)[leading.length]? ≠ some 159 := by
    simpa [List.getElem?_append, encodeHead] using noMarker
  simp [Fields.arrayAt, Collection.collectionAt, firstByte, exactHead, fits]

@[step] theorem array_inverse (self : cbor.Decoder) (maximum count : Std.Usize)
    (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨4, count.val⟩ ++ trailing)
    (start : self.position.val = leading.length) (fits : count.val ≤ maximum.val) :
    decode.array self maximum ⦃ actual => actual.1 = .Ok count ∧
      actual.2.position.val = leading.length + (encodeHead ⟨4, count.val⟩).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (Fields.array_exact self maximum)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, array_consumes count.val maximum.val fits (size_fits_u64 count) leading trailing] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, Fields.sizeView] at sameView
  | Ok decoded =>
    have same : decoded = count := UScalar.eq_of_val_eq (by simpa [Fields.sizeView, result] using sameView)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem text_inverse (self : cbor.Decoder) (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ payloadEncoding 3 (stringBytes value) ++ trailing)
    (start : self.position.val = leading.length) :
    decode.text self ⦃ actual => actual.1 = .Ok (toStr value bounded) ∧
      actual.2.position.val = leading.length + (payloadEncoding 3 (stringBytes value)).length ∧
      actual.2.input = self.input ⦄ := by
  have lengthBound : (stringBytes value).length < 2 ^ 64 := by
    rw [stringBytes_length]
    scalar_tac
  apply spec_mono (Fields.text_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, text_consumes (stringBytes value) lengthBound (native_utf8 value) leading trailing] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, Fields.codecBytesView] at sameView
  | Ok decoded =>
    have exactBytes : byteList decoded.val = byteList (toStr value bounded).val := by
      simpa [Fields.codecBytesView, result, borrowed_bytes] using sameView
    have same : decoded = toStr value bounded := Subtype.ext (AttachmentInverse.bytes_injective exactBytes)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem bytes_inverse (self : cbor.Decoder) (maximum : Std.Usize)
    (value : alloc.vec.Vec Std.U8) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ payloadEncoding 2 (byteList value.val) ++ trailing)
    (start : self.position.val = leading.length)
    (nonempty : 0 < value.val.length) (fits : value.val.length ≤ maximum.val)
    (lengthBound : value.val.length < 2 ^ 64) :
    decode.bounded_bytes self maximum true ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (payloadEncoding 2 (byteList value.val)).length ∧
      actual.2.input = self.input ⦄ := by
  have notEmpty : byteList value.val ≠ [] := by
    simp only [byteList, List.map_eq_nil_iff]
    exact List.ne_nil_of_length_pos nonempty
  apply spec_mono (Fields.bounded_bytes_exact self maximum true)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, AttachmentInverse.bounded_bytes_consumes (byteList value.val) maximum.val
    notEmpty (by simpa [byteList] using fits) (by simpa [byteList] using lengthBound) leading trailing] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, Fields.vecView] at sameView
  | Ok decoded =>
    have exactBytes : byteList decoded.val = byteList value.val := by simpa [result, Fields.vecView] using sameView
    have same : decoded = value := Subtype.ext (AttachmentInverse.bytes_injective exactBytes)
    exact ⟨by simpa only [result, same], position, inputSame⟩

end Auths.Codec.PrimitiveInverse
