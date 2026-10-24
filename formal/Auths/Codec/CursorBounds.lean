import Auths.Codec.Fields
import Auths.Codec.CollectionWork

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec

namespace Auths.Codec.CursorBounds

/-- An argument reader returns precisely the suffix after its checked width. -/
private theorem argument_suffix (input : List Nat) (width value : Nat) (tail : List Nat)
    (accepted : readArgument width input = some (value, tail)) :
    width ≤ input.length ∧ tail.length = input.length - width := by
  unfold readArgument at accepted
  split at accepted
  · rename_i enough
    have same : unsigned (input.take width) = value ∧ input.drop width = tail := by
      simpa only [Option.some.injEq, Prod.mk.injEq] using accepted
    exact ⟨enough, by simp [← same.2]⟩
  · simp at accepted

private theorem extended_tail (rest : List Nat) (major width : Nat) (head : Head) (tail : List Nat)
    (positive : 0 < width) (bounded : width ≤ 8)
    (accepted : (readArgument width rest).map (fun (value, next) => (Head.mk major value, next)) =
      some (head, tail)) :
    tail.length + 1 ≤ rest.length + 1 ∧ rest.length + 1 ≤ tail.length + 9 := by
  cases argument : readArgument width rest with
  | none => simp [argument] at accepted
  | some pair =>
    rcases pair with ⟨value, remaining⟩
    have same : Head.mk major value = head ∧ remaining = tail := by
      simpa [argument] using accepted
    obtain ⟨available, suffix⟩ := argument_suffix rest width value remaining argument
    rw [same.2] at suffix
    constructor <;> omega

/-- Every accepted head consumes one through nine input bytes, for arbitrary
represented input lists. This is a syntactic bound, independent of canonical
minimality and the interpretation of the argument as a field or length. -/
theorem head_suffix_bound (input : List Nat) (head : Head) (tail : List Nat)
    (accepted : readHead input = some (head, tail)) :
    tail.length + 1 ≤ input.length ∧ input.length ≤ tail.length + 9 := by
  cases input with
  | nil => simp [readHead] at accepted
  | cons first rest =>
    by_cases byte : first < 256
    · by_cases inline : first % 32 < 24
      · have same : Head.mk (first / 32) (first % 32) = head ∧ rest = tail := by
          simpa [readHead, byte, inline] using accepted
        simp only [List.length_cons, ← same.2]
        omega
      · simp only [readHead, byte, inline, ↓reduceIte] at accepted
        split_ifs at accepted with one two four eight
        · simpa only [List.length_cons] using
            extended_tail rest (first / 32) 1 head tail (by decide) (by decide) accepted
        · simpa only [List.length_cons] using
            extended_tail rest (first / 32) 2 head tail (by decide) (by decide) accepted
        · simpa only [List.length_cons] using
            extended_tail rest (first / 32) 4 head tail (by decide) (by decide) accepted
        · simpa only [List.length_cons] using
            extended_tail rest (first / 32) 8 head tail (by decide) (by decide) accepted
        · simp at accepted
    · simp [readHead, byte] at accepted

/-- Refusing a typed head preserves its cursor. Accepting one advances within
input, so every result path is monotone and confined. -/
theorem typed_head_bound (input : List Nat) (position major : Nat)
    (within : position ≤ input.length) :
    position ≤ (Cursor.typedHead input position major).2 ∧
      (Cursor.typedHead input position major).2 ≤ input.length := by
  cases parsed : readHead (input.drop position) with
  | none => simpa [Cursor.typedHead, parsed] using And.intro (Nat.le_refl position) within
  | some pair =>
    rcases pair with ⟨head, tail⟩
    have suffix := head_suffix_bound (input.drop position) head tail parsed
    simp only [List.length_drop] at suffix
    by_cases same : head.major = major
    · simp only [Cursor.typedHead, parsed, same, ↓reduceIte]
      constructor <;> omega
    · simpa [Cursor.typedHead, parsed, same] using And.intro (Nat.le_refl position) within

theorem payload_bound (input : List Nat) (position major : Nat)
    (within : position ≤ input.length) :
    position ≤ (Payload.payloadAt input position major).2 ∧
      (Payload.payloadAt input position major).2 ≤ input.length := by
  have headBound := typed_head_bound input position major within
  cases header : Cursor.typedHead input position major with
  | mk length next =>
    have range : position ≤ next ∧ next ≤ input.length := by simpa [header] using headBound
    cases length with
    | none => simpa [Payload.payloadAt, header] using range
    | some length =>
      by_cases enough : next + length ≤ input.length
      · simp only [Payload.payloadAt, header, enough, ↓reduceIte]
        constructor <;> omega
      · simpa [Payload.payloadAt, header, enough] using range

theorem collection_bound (input : List Nat) (position major : Nat)
    (within : position ≤ input.length) :
    position ≤ (Collection.collectionAt input position major).2 ∧
      (Collection.collectionAt input position major).2 ≤ input.length := by
  by_cases indefinite : input[position]? = some (major * 32 + 31)
  · have present := (List.getElem?_eq_some_iff.mp indefinite).1
    simp only [Collection.collectionAt, indefinite, ↓reduceIte]
    constructor <;> omega
  · simpa [Collection.collectionAt, indefinite] using typed_head_bound input position major within

theorem null_bound (input : List Nat) (position : Nat) (within : position ≤ input.length) :
    position ≤ (Cursor.nullAt input position).2 ∧ (Cursor.nullAt input position).2 ≤ input.length := by
  by_cases present : input[position]? = some 246
  · have inside := (List.getElem?_eq_some_iff.mp present).1
    simp only [Cursor.nullAt, present, ↓reduceIte]
    constructor <;> omega
  · simpa [Cursor.nullAt, present] using And.intro (Nat.le_refl position) within

/-- Cursor frame shared by all protocol readers. The result may be an error;
input identity, monotonicity and confinement are still required. -/
def Frame (before after : cbor.Decoder) : Prop :=
  after.input = before.input ∧ before.position.val ≤ after.position.val ∧
    after.position.val ≤ before.input.val.length

private theorem frame_of_model {Value : Type} (before after : cbor.Decoder)
    (inputSame : after.input = before.input) (model : Value × Nat)
    (cursorSame : after.position.val = model.2)
    (bounded : before.position.val ≤ model.2 ∧ model.2 ≤ (Refinement.byteList before.input.val).length) :
    Frame before after := by
  refine ⟨inputSame, ?_, ?_⟩
  · simpa only [cursorSame] using bounded.1
  · simpa only [cursorSame, Refinement.byteList, List.length_map] using bounded.2

@[step] theorem source_head (self : cbor.Decoder) (major : Std.U8)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.head self major ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Cursor.head_exact self major)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (typed_head_bound _ _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_payload (self : cbor.Decoder) (major : Std.U8)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.payload self major ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Payload.payload_exact self major)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (payload_bound _ _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_collection (self : cbor.Decoder) (major : Std.U8)
    (majorValid : major.val < 8) (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.collection self major ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Collection.collection_exact self major majorValid)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (collection_bound _ _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_null (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.null self ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Cursor.null_exact self)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (null_bound _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_key (self : cbor.Decoder) (expected : Std.U8)
    (within : self.position.val ≤ self.input.val.length) :
    decode.key self expected ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Fields.key_exact self expected)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [Fields.keyAt, Cursor.narrowHead] using
    typed_head_bound (Refinement.byteList self.input.val) self.position.val 0
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_map (self : cbor.Decoder) (expected : Std.U64)
    (within : self.position.val ≤ self.input.val.length) :
    decode.map self expected ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Fields.map_exact self expected)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [Fields.mapAt] using
    collection_bound (Refinement.byteList self.input.val) self.position.val 5
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_array (self : cbor.Decoder) (maximum : Std.Usize)
    (within : self.position.val ≤ self.input.val.length) :
    decode.array self maximum ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Fields.array_exact self maximum)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [Fields.arrayAt] using
    collection_bound (Refinement.byteList self.input.val) self.position.val 4
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_text (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    decode.text self ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Fields.text_exact self)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [Fields.textAt, Payload.textAt] using
    payload_bound (Refinement.byteList self.input.val) self.position.val 3
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_bounded_bytes (self : cbor.Decoder) (maximum : Std.Usize) (nonempty : Bool)
    (within : self.position.val ≤ self.input.val.length) :
    decode.bounded_bytes self maximum nonempty ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Fields.bounded_bytes_exact self maximum nonempty)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [Fields.boundedBytesAt] using
    payload_bound (Refinement.byteList self.input.val) self.position.val 2
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_digest (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    decode.digest_bytes self ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (Fields.digest_bytes_exact self)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [Fields.digestAt] using
    payload_bound (Refinement.byteList self.input.val) self.position.val 2
      (by simpa [Refinement.byteList] using within)

end Auths.Codec.CursorBounds
