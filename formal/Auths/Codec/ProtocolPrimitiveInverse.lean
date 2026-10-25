import Auths.Codec.ProtocolFields
import Auths.Codec.ProtocolEncoderState
import Auths.Codec.ProtocolWriter

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolPrimitiveInverse
open Auths.Codec.Refinement Auths.Codec.ProtocolEncoderState Auths.Codec.ProtocolWriter

/- Actual complete-protocol primitive readers on independent grammar prefixes.
No successful decoder, constructor result or expected intermediate state is
assumed. A suffix is permitted here; public object acceptance must separately
prove complete input consumption and the canonical byte comparison. -/
def Consumes {Value : Type} (read : List Nat → Nat → core.result.Result Value error.CodecError × Nat)
    (encoding : List Nat) (value : Value) : Prop :=
  ∀ leading trailing, read (leading ++ encoding ++ trailing) leading.length =
    (.Ok value, leading.length + encoding.length)

theorem native_utf8 (value : String) : ProtocolPayload.validUtf8 (stringBytes value) = true := by
  have bytes : ((stringBytes value).map UInt8.ofNat).toByteArray = value.toByteArray := by
    apply ByteArray.ext
    apply _root_.Array.toList_inj.mp
    simp [stringBytes, List.map_map, Function.comp_def, UInt8.ofNat_toNat,
      List.toList_data_toByteArray, Auths.Model.Identifier.byte_array_list]
  simp only [ProtocolPayload.validUtf8, bytes, decide_eq_true_eq]
  exact value.isValidUTF8

theorem bytes_injective : Function.Injective (fun bytes : List Std.U8 => byteList bytes) := by
  apply List.map_injective_iff.mpr
  intro left right same
  exact UScalar.eq_of_val_eq same

theorem typed_head_prefix (head : Head) (valid : head.Valid) (leading trailing : List Nat) :
    ProtocolCursor.typedHead (leading ++ encodeHead head ++ trailing) leading.length head.major =
      (some head.argument, leading.length + (encodeHead head).length) := by
  have parsed := readHead_encodeHead head valid trailing
  simp only [ProtocolCursor.typedHead, List.drop_left, parsed, ↓reduceIte,
    List.length_append]
  omega

theorem header_not_indefinite (head : Head) :
    (encodeHead head)[0]? ≠ some (head.major * 32 + 31) := by
  have bound : additionalTag head.argument ≤ 27 := by
    unfold additionalTag
    split_ifs <;> omega
  simp only [encodeHead, List.getElem?_cons_zero, ne_eq, Option.some.injEq]
  omega

theorem map_consumes (fields : Nat) (bounded : fields < 2 ^ 64) :
    Consumes (fun input position => ProtocolFields.mapAt input position fields) (encodeHead ⟨5, fields⟩) () := by
  intro leading trailing
  have headExact := typed_head_prefix ⟨5, fields⟩ ⟨by decide, bounded⟩ leading trailing
  have noMarker := header_not_indefinite ⟨5, fields⟩
  have firstByte : (leading ++ encodeHead ⟨5, fields⟩ ++ trailing)[leading.length]? ≠ some 191 := by
    simpa [List.getElem?_append, encodeHead] using noMarker
  simp [ProtocolFields.mapAt, ProtocolCollection.collectionAt, firstByte, headExact]

theorem key_consumes (key : Nat) (bounded : key ≤ 255) :
    Consumes (fun input position => ProtocolFields.keyAt input position key) (encodeHead ⟨0, key⟩) () := by
  intro leading trailing
  have valid : (Head.mk 0 key).Valid := ⟨by decide, by omega⟩
  have headExact := typed_head_prefix ⟨0, key⟩ valid leading trailing
  simp [ProtocolFields.keyAt, ProtocolCursor.narrowHead, headExact, bounded, Option.filter]

theorem payload_prefix (major : Nat) (majorBound : major < 8) (bytes leading trailing : List Nat)
    (lengthBound : bytes.length < 2 ^ 64) :
    ProtocolPayload.payloadAt (leading ++ payloadEncoding major bytes ++ trailing) leading.length major =
      (some bytes, leading.length + (payloadEncoding major bytes).length) := by
  have headExact := typed_head_prefix ⟨major, bytes.length⟩ ⟨majorBound, lengthBound⟩ leading
    (bytes ++ trailing)
  have suffix : (leading ++ payloadEncoding major bytes ++ trailing).drop
      (leading.length + (encodeHead ⟨major, bytes.length⟩).length) = bytes ++ trailing := by
    simp [payloadEncoding, List.append_assoc, List.drop_append, List.drop_drop]
  have available : leading.length + (encodeHead ⟨major, bytes.length⟩).length + bytes.length ≤
      (leading ++ payloadEncoding major bytes ++ trailing).length := by
    simp only [payloadEncoding, List.length_append]
    omega
  simp only [payloadEncoding, List.append_assoc] at headExact
  simp only [ProtocolPayload.payloadAt, payloadEncoding, List.append_assoc, headExact, available,
    ↓reduceIte, suffix, List.take_left, List.length_append]
  omega

theorem text_consumes (bytes : List Nat) (lengthBound : bytes.length < 2 ^ 64)
    (utf8 : ProtocolPayload.validUtf8 bytes = true) :
    Consumes ProtocolFields.textAt (payloadEncoding 3 bytes) bytes := by
  intro leading trailing
  have payload := payload_prefix 3 (by decide) bytes leading trailing lengthBound
  simp [ProtocolFields.textAt, ProtocolPayload.textAt, payload, Option.filter, utf8]

@[step] theorem map_inverse (self : cbor.Decoder) (fields : Std.U64) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨5, fields.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    decode.map self fields ⦃ actual => actual.1 = .Ok () ∧
      actual.2.position.val = leading.length + (encodeHead ⟨5, fields.val⟩).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (ProtocolFields.map_exact self fields)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, map_consumes fields.val (by scalar_tac) leading trailing] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, inputSame⟩

@[step] theorem key_inverse (self : cbor.Decoder) (key : Std.U8) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨0, key.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    decode.key self key ⦃ actual => actual.1 = .Ok () ∧
      actual.2.position.val = leading.length + (encodeHead ⟨0, key.val⟩).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (ProtocolFields.key_exact self key)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, key_consumes key.val (by scalar_tac) leading trailing] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, inputSame⟩

theorem size_fits_u64 (value : Std.Usize) : value.val < 2 ^ 64 := by
  have bound : value.val ≤ Usize.max := by scalar_tac
  rcases Usize.bounds_eq with width | width <;> rw [width] at bound <;> scalar_tac

theorem array_consumes (count : Nat) (maximum : Nat) (fits : count ≤ maximum) (bounded : count < 2 ^ 64) :
    Consumes (fun input position => ProtocolFields.arrayAt input position maximum) (encodeHead ⟨4, count⟩) count := by
  intro leading trailing
  have exactHead := typed_head_prefix ⟨4, count⟩ ⟨by decide, bounded⟩ leading trailing
  have noMarker := header_not_indefinite ⟨4, count⟩
  have firstByte : (leading ++ encodeHead ⟨4, count⟩ ++ trailing)[leading.length]? ≠ some 159 := by
    simpa [List.getElem?_append, encodeHead] using noMarker
  simp [ProtocolFields.arrayAt, ProtocolCollection.collectionAt, firstByte, exactHead, fits]

@[step] theorem array_inverse (self : cbor.Decoder) (maximum count : Std.Usize)
    (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨4, count.val⟩ ++ trailing)
    (start : self.position.val = leading.length) (fits : count.val ≤ maximum.val) :
    decode.array self maximum ⦃ actual => actual.1 = .Ok count ∧
      actual.2.position.val = leading.length + (encodeHead ⟨4, count.val⟩).length ∧
      actual.2.input = self.input ⦄ := by
  apply spec_mono (ProtocolFields.array_exact self maximum)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, array_consumes count.val maximum.val fits (size_fits_u64 count) leading trailing] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolFields.sizeView] at sameView
  | Ok decoded =>
    have same : decoded = count := UScalar.eq_of_val_eq (by simpa [ProtocolFields.sizeView, result] using sameView)
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
  apply spec_mono (ProtocolFields.text_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, text_consumes (stringBytes value) lengthBound (native_utf8 value) leading trailing] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolFields.codecBytesView] at sameView
  | Ok decoded =>
    have exactBytes : byteList decoded.val = byteList (toStr value bounded).val := by
      simpa [ProtocolFields.codecBytesView, result, borrowed_bytes] using sameView
    have same : decoded = toStr value bounded := Subtype.ext (bytes_injective exactBytes)
    exact ⟨by simpa only [result, same], position, inputSame⟩

theorem bounded_bytes_consumes (bytes : List Nat) (maximum : Nat) (nonempty : Bool)
    (required : nonempty = true → bytes ≠ []) (fits : bytes.length ≤ maximum)
    (lengthBound : bytes.length < 2 ^ 64) :
    Consumes (fun input position => ProtocolFields.boundedBytesAt input position maximum nonempty)
      (payloadEncoding 2 bytes) bytes := by
  intro leading trailing
  have payload := payload_prefix 2 (by decide) bytes leading trailing lengthBound
  simp only [ProtocolFields.boundedBytesAt, payload]
  have noFailure : ¬ (maximum < bytes.length ∨ nonempty = true ∧ bytes = []) := by
    simp_all
  simp [noFailure]

@[step] theorem bytes_inverse (self : cbor.Decoder) (maximum : Std.Usize) (nonempty : Bool)
    (value : alloc.vec.Vec Std.U8) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ payloadEncoding 2 (byteList value.val) ++ trailing)
    (start : self.position.val = leading.length)
    (required : nonempty = true → 0 < value.val.length) (fits : value.val.length ≤ maximum.val)
    (lengthBound : value.val.length < 2 ^ 64) :
    decode.bounded_bytes self maximum nonempty ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (payloadEncoding 2 (byteList value.val)).length ∧
      actual.2.input = self.input ⦄ := by
  have notEmpty : nonempty = true → byteList value.val ≠ [] := by
    intro mandatory
    simp only [byteList, List.map_eq_nil_iff]
    exact List.ne_nil_of_length_pos (required mandatory)
  apply spec_mono (ProtocolFields.bounded_bytes_exact self maximum nonempty)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start, bounded_bytes_consumes (byteList value.val) maximum.val nonempty
    notEmpty (by simpa [byteList] using fits) (by simpa [byteList] using lengthBound) leading trailing] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolFields.vecView] at sameView
  | Ok decoded =>
    have exactBytes : byteList decoded.val = byteList value.val := by simpa [result, ProtocolFields.vecView] using sameView
    have same : decoded = value := Subtype.ext (bytes_injective exactBytes)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem digest_inverse (self : cbor.Decoder) (value : Array Std.U8 32#usize)
    (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ payloadEncoding 2 (byteList value.val) ++ trailing)
    (start : self.position.val = leading.length) :
    decode.digest_bytes self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (payloadEncoding 2 (byteList value.val)).length ∧
      actual.2.input = self.input ⦄ := by
  have length : value.val.length = 32 := by simpa using value.property
  have payload := payload_prefix 2 (by decide) (byteList value.val) leading trailing (by simp [byteList, length])
  apply spec_mono (ProtocolFields.digest_bytes_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start] at meaning
  simp only [ProtocolFields.digestAt, payload, byteList, List.length_map, length, ↓reduceIte] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolFields.digestView] at sameView
  | Ok decoded =>
    have exactBytes : byteList decoded.val = byteList value.val := by simpa [result, ProtocolFields.digestView] using sameView
    have same : decoded = value := Subtype.ext (bytes_injective exactBytes)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem u8_inverse (self : cbor.Decoder) (value : Std.U8) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨0, value.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    cbor.Decoder.u8 self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (encodeHead ⟨0, value.val⟩).length ∧ actual.2.input = self.input ⦄ := by
  have head := typed_head_prefix ⟨0, value.val⟩ ⟨by decide, by scalar_tac⟩ leading trailing
  apply spec_mono (ProtocolCursor.u8_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start] at meaning
  have fits : value.val ≤ 255 := by scalar_tac
  simp only [ProtocolCursor.narrowHead, head, Option.filter, fits, decide_true, ↓reduceIte] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolCursor.wordView] at sameView
  | Ok decoded =>
    have same : decoded = value := UScalar.eq_of_val_eq (by simpa [result, ProtocolCursor.wordView] using sameView)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem u16_inverse (self : cbor.Decoder) (value : Std.U16) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨0, value.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    cbor.Decoder.u16 self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (encodeHead ⟨0, value.val⟩).length ∧ actual.2.input = self.input ⦄ := by
  have head := typed_head_prefix ⟨0, value.val⟩ ⟨by decide, by scalar_tac⟩ leading trailing
  apply spec_mono (ProtocolCursor.u16_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start] at meaning
  have fits : value.val ≤ 65535 := by scalar_tac
  simp only [ProtocolCursor.narrowHead, head, Option.filter, fits, decide_true, ↓reduceIte] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolCursor.wordView] at sameView
  | Ok decoded =>
    have same : decoded = value := UScalar.eq_of_val_eq (by simpa [result, ProtocolCursor.wordView] using sameView)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem u32_inverse (self : cbor.Decoder) (value : Std.U32) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨0, value.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    cbor.Decoder.u32 self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (encodeHead ⟨0, value.val⟩).length ∧ actual.2.input = self.input ⦄ := by
  have head := typed_head_prefix ⟨0, value.val⟩ ⟨by decide, by scalar_tac⟩ leading trailing
  apply spec_mono (ProtocolCursor.u32_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start] at meaning
  have fits : value.val ≤ 4294967295 := by scalar_tac
  simp only [ProtocolCursor.narrowHead, head, Option.filter, fits, decide_true, ↓reduceIte] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolCursor.wordView] at sameView
  | Ok decoded =>
    have same : decoded = value := UScalar.eq_of_val_eq (by simpa [result, ProtocolCursor.wordView] using sameView)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem u64_inverse (self : cbor.Decoder) (value : Std.U64) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ encodeHead ⟨0, value.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    cbor.Decoder.u64 self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (encodeHead ⟨0, value.val⟩).length ∧ actual.2.input = self.input ⦄ := by
  have head := typed_head_prefix ⟨0, value.val⟩ ⟨by decide, by scalar_tac⟩ leading trailing
  apply spec_mono (ProtocolCursor.u64_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start] at meaning
  rw [head] at meaning
  obtain ⟨sameView, position⟩ := Prod.mk.inj meaning
  cases result : actual.1 with
  | Err error => simp [result, ProtocolCursor.wordView] at sameView
  | Ok decoded =>
    have same : decoded = value := UScalar.eq_of_val_eq (by simpa [result, ProtocolCursor.wordView] using sameView)
    exact ⟨by simpa only [result, same], position, inputSame⟩

@[step] theorem null_inverse (self : cbor.Decoder) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ [246] ++ trailing)
    (start : self.position.val = leading.length) :
    decode.null self ⦃ actual => actual.1 = .Ok () ∧
      actual.2.position.val = leading.length + 1 ∧ actual.2.input = self.input ⦄ := by
  apply spec_mono (ProtocolFields.null_exact self)
  rintro actual ⟨meaning, inputSame⟩
  rw [input, start] at meaning
  simp only [ProtocolFields.nullAt, ProtocolCursor.nullAt, List.getElem?_append, List.length_cons,
    List.length_nil, List.getElem?_cons_zero, ↓reduceIte] at meaning
  exact ⟨(Prod.mk.inj meaning).1, (Prod.mk.inj meaning).2, inputSame⟩

@[step] theorem null_probe (self : cbor.Decoder) (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ [246] ++ trailing)
    (start : self.position.val = leading.length) : decode.is_null self ⦃ actual => actual = .Ok true ⦄ := by
  apply spec_mono (ProtocolFields.is_null_exact self)
  intro actual meaning
  simpa [input, start, ProtocolFields.isNullAt, ProtocolCursor.typeAt, List.getElem?_append] using meaning

@[step] theorem digest_probe (self : cbor.Decoder) (value : Array Std.U8 32#usize)
    (leading trailing : List Nat)
    (input : byteList self.input.val = leading ++ payloadEncoding 2 (byteList value.val) ++ trailing)
    (start : self.position.val = leading.length) : decode.is_null self ⦃ actual => actual = .Ok false ⦄ := by
  have length : value.val.length = 32 := by simpa using value.property
  apply spec_mono (ProtocolFields.is_null_exact self)
  intro actual meaning
  simpa [input, start, ProtocolFields.isNullAt, ProtocolCursor.typeAt, payloadEncoding,
    byteList, List.length_map, length, encodeHead, argumentWidth, additionalTag, bigEndian,
    List.getElem?_append] using meaning

end Auths.Codec.ProtocolPrimitiveInverse
