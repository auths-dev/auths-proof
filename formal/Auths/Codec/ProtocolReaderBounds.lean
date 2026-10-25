/- Complete-protocol source cursor/resource foundations, including every
typed refusal. These bodies use the actual complete-protocol reader equations;
no identity with an earlier extraction namespace is assumed. -/
import Auths.Codec.ProtocolFields
import Auths.Codec.ProtocolStrings
import Auths.Codec.CollectionWork

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolReaderBounds

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
    position ≤ (ProtocolCursor.typedHead input position major).2 ∧
      (ProtocolCursor.typedHead input position major).2 ≤ input.length := by
  cases parsed : readHead (input.drop position) with
  | none => simpa [ProtocolCursor.typedHead, parsed] using And.intro (Nat.le_refl position) within
  | some pair =>
    rcases pair with ⟨head, tail⟩
    have suffix := head_suffix_bound (input.drop position) head tail parsed
    simp only [List.length_drop] at suffix
    by_cases same : head.major = major
    · simp only [ProtocolCursor.typedHead, parsed, same, ↓reduceIte]
      constructor <;> omega
    · simpa [ProtocolCursor.typedHead, parsed, same] using And.intro (Nat.le_refl position) within

theorem payload_bound (input : List Nat) (position major : Nat)
    (within : position ≤ input.length) :
    position ≤ (ProtocolPayload.payloadAt input position major).2 ∧
      (ProtocolPayload.payloadAt input position major).2 ≤ input.length := by
  have headBound := typed_head_bound input position major within
  cases header : ProtocolCursor.typedHead input position major with
  | mk length next =>
    have range : position ≤ next ∧ next ≤ input.length := by simpa [header] using headBound
    cases length with
    | none => simpa [ProtocolPayload.payloadAt, header] using range
    | some length =>
      by_cases enough : next + length ≤ input.length
      · simp only [ProtocolPayload.payloadAt, header, enough, ↓reduceIte]
        constructor <;> omega
      · simpa [ProtocolPayload.payloadAt, header, enough] using range

theorem collection_bound (input : List Nat) (position major : Nat)
    (within : position ≤ input.length) :
    position ≤ (ProtocolCollection.collectionAt input position major).2 ∧
      (ProtocolCollection.collectionAt input position major).2 ≤ input.length := by
  by_cases indefinite : input[position]? = some (major * 32 + 31)
  · have present := (List.getElem?_eq_some_iff.mp indefinite).1
    simp only [ProtocolCollection.collectionAt, indefinite, ↓reduceIte]
    constructor <;> omega
  · simpa [ProtocolCollection.collectionAt, indefinite] using typed_head_bound input position major within

theorem null_bound (input : List Nat) (position : Nat) (within : position ≤ input.length) :
    position ≤ (ProtocolCursor.nullAt input position).2 ∧ (ProtocolCursor.nullAt input position).2 ≤ input.length := by
  by_cases present : input[position]? = some 246
  · have inside := (List.getElem?_eq_some_iff.mp present).1
    simp only [ProtocolCursor.nullAt, present, ↓reduceIte]
    constructor <;> omega
  · simpa [ProtocolCursor.nullAt, present] using And.intro (Nat.le_refl position) within

/-- Cursor frame shared by all protocol readers. The result may be an error;
input identity, monotonicity and confinement are still required. -/
def Frame (before after : cbor.Decoder) : Prop :=
  after.input = before.input ∧ before.position.val ≤ after.position.val ∧
    after.position.val ≤ before.input.val.length

theorem frame_refl (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) : Frame self self :=
  ⟨rfl, Nat.le_refl _, within⟩

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
  apply spec_mono (ProtocolCursor.head_exact self major)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (typed_head_bound _ _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_payload (self : cbor.Decoder) (major : Std.U8)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.payload self major ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolPayload.payload_exact self major)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (payload_bound _ _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_collection (self : cbor.Decoder) (major : Std.U8)
    (majorValid : major.val < 8) (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.collection self major ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolCollection.collection_exact self major majorValid)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (collection_bound _ _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_null (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.null self ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolCursor.null_exact self)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  exact frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
    (null_bound _ _ (by simpa [Refinement.byteList] using within))

@[step] theorem source_key (self : cbor.Decoder) (expected : Std.U8)
    (within : self.position.val ≤ self.input.val.length) :
    decode.key self expected ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolFields.key_exact self expected)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [ProtocolFields.keyAt, ProtocolCursor.narrowHead] using
    typed_head_bound (Refinement.byteList self.input.val) self.position.val 0
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_map (self : cbor.Decoder) (expected : Std.U64)
    (within : self.position.val ≤ self.input.val.length) :
    decode.map self expected ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolFields.map_exact self expected)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [ProtocolFields.mapAt] using
    collection_bound (Refinement.byteList self.input.val) self.position.val 5
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_array (self : cbor.Decoder) (maximum : Std.Usize)
    (within : self.position.val ≤ self.input.val.length) :
    decode.array self maximum ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolFields.array_exact self maximum)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [ProtocolFields.arrayAt] using
    collection_bound (Refinement.byteList self.input.val) self.position.val 4
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_text (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    decode.text self ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolFields.text_exact self)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [ProtocolFields.textAt, ProtocolPayload.textAt] using
    payload_bound (Refinement.byteList self.input.val) self.position.val 3
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_bounded_bytes (self : cbor.Decoder) (maximum : Std.Usize) (nonempty : Bool)
    (within : self.position.val ≤ self.input.val.length) :
    decode.bounded_bytes self maximum nonempty ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolFields.bounded_bytes_exact self maximum nonempty)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [ProtocolFields.boundedBytesAt] using
    payload_bound (Refinement.byteList self.input.val) self.position.val 2
      (by simpa [Refinement.byteList] using within)

@[step] theorem source_digest (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    decode.digest_bytes self ⦃ actual => Frame self actual.2 ⦄ := by
  apply spec_mono (ProtocolFields.digest_bytes_exact self)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  apply frame_of_model self next inputSame _ (congrArg Prod.snd meaning)
  simpa [ProtocolFields.digestAt] using
    payload_bound (Refinement.byteList self.input.val) self.position.val 2
      (by simpa [Refinement.byteList] using within)

/-- Source cursor frames compose across successful calls and the final failed
call. No input or consumed prefix can be replaced between those calls. -/
theorem frame_trans (before middle after : cbor.Decoder)
    (first : Frame before middle) (second : Frame middle after) : Frame before after := by
  rcases first with ⟨firstInput, firstStart, firstEnd⟩
  rcases second with ⟨secondInput, secondStart, secondEnd⟩
  exact ⟨secondInput.trans firstInput, by omega, by simpa only [firstInput] using secondEnd⟩

theorem frame_within (before after : cbor.Decoder) (frame : Frame before after) :
    after.position.val ≤ after.input.val.length := by
  simpa only [frame.1] using frame.2.2

/-- The header branch has at most nine bytes of cursor advancement on every
result, including narrowing and wrong-major refusal. -/
theorem typed_head_step_bound (input : List Nat) (position major : Nat)
    (within : position ≤ input.length) :
    (ProtocolCursor.typedHead input position major).2 ≤ position + 9 := by
  cases parsed : readHead (input.drop position) with
  | none => simp [ProtocolCursor.typedHead, parsed]
  | some pair =>
    rcases pair with ⟨head, tail⟩
    have suffix := head_suffix_bound (input.drop position) head tail parsed
    simp only [List.length_drop] at suffix
    by_cases same : head.major = major
    · simp only [ProtocolCursor.typedHead, parsed, same, ↓reduceIte]
      omega
    · simp [ProtocolCursor.typedHead, parsed, same]

@[step] theorem source_head_step (self : cbor.Decoder) (major : Std.U8)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.head self major ⦃ actual => Frame self actual.2 ∧
      actual.2.position.val ≤ self.position.val + 9 ⦄ := by
  apply spec_mono (ProtocolCursor.head_exact self major)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  have cursor := congrArg Prod.snd meaning
  refine ⟨frame_of_model self next inputSame _ cursor
    (typed_head_bound _ _ _ (by simpa [Refinement.byteList] using within)), ?_⟩
  rw [cursor]
  exact typed_head_step_bound _ _ _ (by simpa [Refinement.byteList] using within)

@[step] theorem source_u16 (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.u16 self ⦃ actual => Frame self actual.2 ∧
      actual.2.position.val ≤ self.position.val + 9 ⦄ := by
  apply spec_mono (ProtocolCursor.u16_exact self)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  have cursor := congrArg Prod.snd meaning
  have modelBound := typed_head_bound (Refinement.byteList self.input.val) self.position.val 0
    (by simpa [Refinement.byteList] using within)
  have stepBound := typed_head_step_bound (Refinement.byteList self.input.val) self.position.val 0
    (by simpa [Refinement.byteList] using within)
  have headCursor : next.position.val =
      (ProtocolCursor.typedHead (Refinement.byteList self.input.val) self.position.val 0).2 := by
    simpa only [ProtocolCursor.narrowHead] using cursor
  refine ⟨?_, ?_⟩
  · exact frame_of_model self next inputSame _ cursor
      (by simpa only [ProtocolCursor.narrowHead] using modelBound)
  · rw [headCursor]
    exact stepBound

/-- Every returned payload is a contiguous borrowed span. Its size is at
most the cursor advancement, so disjoint sequential fields cannot each consume
the whole input while their aggregate is omitted from accounting. -/
theorem payload_span (input : List Nat) (position major : Nat)
    (within : position ≤ input.length) (bytes : List Nat) (finish : Nat)
    (accepted : ProtocolPayload.payloadAt input position major = (some bytes, finish)) :
    position ≤ finish ∧ finish ≤ input.length ∧ bytes.length ≤ finish - position := by
  have headerBound := typed_head_bound input position major within
  cases header : ProtocolCursor.typedHead input position major with
  | mk length start =>
    have startBound : position ≤ start ∧ start ≤ input.length := by simpa only [header] using headerBound
    cases length with
    | none => simp [ProtocolPayload.payloadAt, header] at accepted
    | some length =>
      by_cases fits : start + length ≤ input.length
      · simp only [ProtocolPayload.payloadAt, header, fits, ↓reduceIte,
          Prod.mk.injEq, Option.some.injEq] at accepted
        have size : bytes.length = length := by
          rw [← accepted.1]
          simp only [List.length_take, List.length_drop]
          omega
        obtain ⟨sameBytes, sameFinish⟩ := accepted
        exact ⟨by omega, by omega, by omega⟩
      · simp [ProtocolPayload.payloadAt, header, fits] at accepted

theorem text_span (input : List Nat) (position : Nat)
    (within : position ≤ input.length) (bytes : List Nat) (finish : Nat)
    (accepted : ProtocolPayload.textAt input position = (some bytes, finish)) :
    position ≤ finish ∧ finish ≤ input.length ∧ bytes.length ≤ finish - position := by
  cases payload : ProtocolPayload.payloadAt input position 3 with
  | mk value next =>
    cases value with
    | none => simp [ProtocolPayload.textAt, payload] at accepted
    | some value =>
      by_cases valid : ProtocolPayload.validUtf8 value = true
      · have same : value = bytes ∧ next = finish := by
          simpa [ProtocolPayload.textAt, payload, Option.filter, valid] using accepted
        obtain ⟨sameBytes, sameFinish⟩ := same
        subst value
        subst next
        exact payload_span input position 3 within bytes finish payload
      · simp [ProtocolPayload.textAt, payload, Option.filter, valid] at accepted

@[step] theorem source_text_span (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    decode.text self ⦃ actual => Frame self actual.2 ∧
      ∀ text, actual.1 = .Ok text →
        text.val.length ≤ actual.2.position.val - self.position.val ∧
        text.val.length ≤ self.input.val.length ∧
        (Auths.Codec.StdModel.bytes text).IsValidUTF8 ⦄ := by
  obtain ⟨⟨result, next⟩, run, meaning, inputSame⟩ := spec_imp_exists (ProtocolFields.text_exact self)
  rw [run, spec_ok]
  refine ⟨frame_of_model self next inputSame _ (congrArg Prod.snd meaning) ?_, ?_⟩
  · simpa only [ProtocolFields.textAt, ProtocolPayload.textAt] using
      payload_bound (Refinement.byteList self.input.val) self.position.val 3
        (by simpa [Refinement.byteList] using within)
  · intro text accepted
    subst result
    cases parsed : ProtocolPayload.textAt (Refinement.byteList self.input.val) self.position.val with
    | mk value finish =>
      cases value with
      | none => simp [ProtocolFields.textAt, parsed, ProtocolFields.codecBytesView] at meaning
      | some value =>
        have same : Refinement.byteList text.val = value ∧ next.position.val = finish := by
          simpa [ProtocolFields.textAt, parsed, ProtocolFields.codecBytesView] using meaning
        have span := text_span (Refinement.byteList self.input.val) self.position.val
          (by simpa [Refinement.byteList] using within) value finish parsed
        have size := congrArg List.length same.1
        simp only [Refinement.byteList, List.length_map] at size span
        refine ⟨by omega, by omega, ?_⟩
        exact ProtocolStrings.text_valid self next text run

@[step] theorem source_bounded_bytes_span (self : cbor.Decoder) (maximum : Std.Usize) (nonempty : Bool)
    (within : self.position.val ≤ self.input.val.length) :
    decode.bounded_bytes self maximum nonempty ⦃ actual => Frame self actual.2 ∧
      ∀ bytes, actual.1 = .Ok bytes →
        bytes.val.length ≤ maximum.val ∧
        bytes.val.length ≤ actual.2.position.val - self.position.val ∧
        bytes.val.length ≤ self.input.val.length ⦄ := by
  obtain ⟨⟨result, next⟩, run, meaning, inputSame⟩ :=
    spec_imp_exists (ProtocolFields.bounded_bytes_exact self maximum nonempty)
  rw [run, spec_ok]
  refine ⟨frame_of_model self next inputSame _ (congrArg Prod.snd meaning) ?_, ?_⟩
  · simpa only [ProtocolFields.boundedBytesAt] using
      payload_bound (Refinement.byteList self.input.val) self.position.val 2
        (by simpa [Refinement.byteList] using within)
  · intro bytes accepted
    subst result
    cases payload : ProtocolPayload.payloadAt (Refinement.byteList self.input.val) self.position.val 2 with
    | mk value finish =>
      cases value with
      | none => simp [ProtocolFields.boundedBytesAt, payload, ProtocolFields.vecView] at meaning
      | some value =>
        by_cases invalid : maximum.val < value.length ∨ (nonempty = true ∧ value = [])
        · simp [ProtocolFields.boundedBytesAt, payload, invalid, ProtocolFields.vecView] at meaning
        · have same : Refinement.byteList bytes.val = value ∧ next.position.val = finish := by
            simpa [ProtocolFields.boundedBytesAt, payload, invalid, ProtocolFields.vecView] using meaning
          have span := payload_span (Refinement.byteList self.input.val) self.position.val 2
            (by simpa [Refinement.byteList] using within) value finish payload
          have size := congrArg List.length same.1
          simp only [Refinement.byteList, List.length_map] at size span
          refine ⟨by omega, by omega, by omega⟩

/-- Bytes presented to the UTF-8 leaf, including bytes that leaf rejects.
The payload itself remains borrowed and performs no owned text copy. -/
def utf8Bytes (payload : core.result.Result (Slice Std.U8) cbor.Error) : Nat :=
  match payload with | .Err _ => 0 | .Ok bytes => bytes.val.length

def utf8Outcome (payload : core.result.Result (Slice Std.U8) cbor.Error) :
    core.result.Result Str cbor.Error :=
  match payload with
  | .Err reason => .Err reason
  | .Ok bytes => if (Auths.Codec.StdModel.bytes bytes).IsValidUTF8 then .Ok bytes else .Err ()

/-- Actual source subcall trace for text validation. Unlike a successful-text
span lemma, this retains the bytes inspected before invalid UTF-8 is refused. -/
@[step] theorem source_str_trace (self : cbor.Decoder)
    (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.str self ⦃ actual => Frame self actual.2 ∧
      ∃ payload, cbor.Decoder.payload self 3#u8 = ok (payload, actual.2) ∧
        actual.1 = utf8Outcome payload ∧
        utf8Bytes payload ≤ actual.2.position.val - self.position.val ∧
        utf8Bytes payload ≤ self.input.val.length ⦄ := by
  obtain ⟨⟨payload, next⟩, payloadRun, payloadMeaning⟩ :=
    spec_imp_exists (ProtocolPayload.payload_exact self 3#u8)
  have frame := source_payload self 3#u8 within
  rw [payloadRun, spec_ok] at frame
  unfold cbor.Decoder.str
  rw [payloadRun]
  cases payload with
  | Err reason =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, spec_ok]
    exact ⟨frame, .Err reason, payloadRun, rfl, by simp [utf8Bytes], by simp [utf8Bytes]⟩
  | Ok bytes =>
    have spans := ProtocolPayload.success_earns_span self 3#u8
    rw [payloadRun, spec_ok] at spans
    obtain ⟨start, length, header, sameBytes, finish, bounded, size⟩ := spans.2 bytes rfl
    have headerBound := typed_head_bound (Refinement.byteList self.input.val) self.position.val 3
      (by simpa [Refinement.byteList] using within)
    have startBound : self.position.val ≤ start := by simpa only [header] using headerBound.1
    have charged : bytes.val.length ≤ next.position.val - self.position.val ∧
        bytes.val.length ≤ self.input.val.length := by omega
    have trace : Frame self next ∧
        ∃ payload, cbor.Decoder.payload self 3#u8 = ok (payload, next) ∧
          utf8Outcome (.Ok bytes) = utf8Outcome payload ∧
          utf8Bytes payload ≤ next.position.val - self.position.val ∧
          utf8Bytes payload ≤ self.input.val.length :=
      ⟨frame, .Ok bytes, payloadRun, rfl, charged.1, charged.2⟩
    by_cases valid : (Auths.Codec.StdModel.bytes bytes).IsValidUTF8
    all_goals
      simpa [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok, spec_ok,
        core.str.converts.from_utf8, valid, utf8Outcome] using trace

@[step] theorem source_array_limit (self : cbor.Decoder) (maximum : Std.Usize) :
    decode.array self maximum ⦃ actual =>
      match actual.1 with | .Err _ => True | .Ok count => count.val ≤ maximum.val ⦄ := by
  apply spec_mono (ProtocolFields.array_exact self maximum)
  rintro ⟨result, next⟩ ⟨meaning, inputSame⟩
  cases result with
  | Err reason => trivial
  | Ok count =>
    have verdict := congrArg Prod.fst meaning
    simp only [ProtocolFields.sizeView, ProtocolFields.arrayAt] at verdict
    cases header : ProtocolCollection.collectionAt (Refinement.byteList self.input.val) self.position.val 4 with
    | mk value finish =>
      rw [header] at verdict
      cases value with
      | none => simp at verdict
      | some length =>
        cases length with
        | none => simp at verdict
        | some length =>
          by_cases bounded : length ≤ maximum.val
          · simp only [bounded, ↓reduceIte, core.result.Result.Ok.injEq] at verdict
            omega
          · simp [bounded] at verdict

end Auths.Codec.ProtocolReaderBounds
