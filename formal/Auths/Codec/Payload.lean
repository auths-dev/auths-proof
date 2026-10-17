import Auths.Codec.Cursor
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.Payload
open Cursor

def payloadAt (input : List Nat) (position major : Nat) : Option (List Nat) × Nat :=
  let (length, next) := typedHead input position major
  match length with
  | none => (none, next)
  | some length =>
    if next + length ≤ input.length then
      (some ((input.drop next).take length), next + length)
    else (none, next)

def bytesView (value : core.result.Result (Slice Std.U8) cbor.Error) : Option (List Nat) :=
  match value with
  | .Err _ => none
  | .Ok value => some (Refinement.byteList value.val)

private theorem size_cast (value : Std.U64) :
    Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from value ⦃ actual =>
      match actual with
      | .Ok size => size.val = value.val
      | .Err _ => Usize.max < value.val ⦄ := by
  unfold Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from core.num.tryFromUScalar
  split <;> rename_i bound
  · have inside : value.val < 2 ^ UScalarTy.Usize.numBits := by
      simp only [UScalar.max] at bound
      have positive : 0 < 2 ^ UScalarTy.Usize.numBits := by positivity
      omega
    simpa only [spec_ok] using UScalar.cast_val_mod_pow_of_inBounds_eq .Usize value inside
  · simpa only [spec_ok, UScalar.max_USize_eq] using Nat.lt_of_not_ge bound

private theorem malformed_map {T : Type} (value : core.result.Result T cbor.Error) :
    core.result.Result.map_err (BuiltinFnOnce core.num.error.TryFromIntError cbor.Error)
      value cbor.malformed = ok value := by
  cases value <;> simp [core.result.Result.map_err, BuiltinFnOnce, cbor.malformed]

private theorem range_get (input : Slice Std.U8) (start finish : Std.Usize) :
    core.slice.Slice.get (core.slice.index.SliceIndexRangeUsizeSlice Std.U8) input
      ⟨start, finish⟩ ⦃ actual =>
        (actual.map fun bytes => Refinement.byteList bytes.val) =
          if start.val ≤ finish.val ∧ finish.val ≤ input.val.length then
            some ((Refinement.byteList input.val).drop start.val |>.take (finish.val - start.val))
          else none ⦄ := by
  simp only [core.slice.Slice.get, core.slice.index.SliceIndexRangeUsizeSlice,
    core.slice.index.SliceIndexRangeUsizeSlice.get]
  split <;> rename_i bounds
  · simp only [UScalar.le_equiv, Slice.length] at bounds
    simp [bounds, spec_ok, Refinement.byteList, List.slice]
  · have absent : ¬ (start.val ≤ finish.val ∧ finish.val ≤ input.val.length) := by
      simpa only [UScalar.le_equiv, Slice.length] using bounds
    simp [absent, spec_ok]

@[step] theorem payload_exact (self : cbor.Decoder) (major : Std.U8) :
    cbor.Decoder.payload self major ⦃ actual =>
      (bytesView actual.1, actual.2.position.val) =
        payloadAt (Refinement.byteList self.input.val) self.position.val major.val ∧
      actual.2.input = self.input ⦄ := by
  have inputLength : (Refinement.byteList self.input.val).length = self.input.val.length := by
    simp [Refinement.byteList]
  unfold cbor.Decoder.payload
  step with Cursor.head_exact as ⟨head, next, headMeaning, inputSame⟩
  cases head with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, payloadAt, ← headMeaning, wordView, bytesView, inputSame]
  | Ok argument =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with size_cast as ⟨converted, castMeaning⟩
    simp only [malformed_map, bind_tc_ok]
    cases converted with
    | Err error =>
      have tooLong : ¬ next.position.val + argument.val ≤ self.input.val.length := by
        have bounded := self.input.property
        omega
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, payloadAt, ← headMeaning, wordView, bytesView, inputSame, tooLong, inputLength]
    | Ok length =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      have checked := Usize.checked_add_bv_spec next.position length
      cases sum : Usize.checked_add next.position length with
      | none =>
        simp only [sum] at checked
        have tooLong : ¬ next.position.val + argument.val ≤ self.input.val.length := by
          have bounded := self.input.property
          simp only at castMeaning
          omega
        simp [sum, lift, core.option.Option.ok_or,
          core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, payloadAt, ← headMeaning, wordView, bytesView, inputSame, tooLong, inputLength]
      | some finish =>
        simp only [sum] at checked
        have finishMeaning : finish.val = next.position.val + argument.val := by
          simp only at castMeaning
          omega
        simp only [sum, lift, bind_tc_ok, core.option.Option.ok_or,
          core.result.Result.Insts.CoreOpsTry.branch]
        step with range_get as ⟨bytes, rangeMeaning⟩
        have ordered : next.position.val ≤ finish.val := by omega
        cases bytes with
        | none =>
          have tooLong : ¬ next.position.val + argument.val ≤ self.input.val.length := by
            by_contra within
            simp [ordered, finishMeaning, inputSame, within] at rangeMeaning
          simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from, payloadAt, ← headMeaning, wordView, bytesView, inputSame, tooLong, inputLength]
        | some bytes =>
          have within : next.position.val + argument.val ≤ self.input.val.length := by
            by_contra outside
            simp [finishMeaning, inputSame, outside] at rangeMeaning
          have exactBytes : Refinement.byteList bytes.val =
              ((Refinement.byteList self.input.val).drop next.position.val).take argument.val := by
            simpa [ordered, finishMeaning, inputSame, within] using rangeMeaning
          simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
            payloadAt, ← headMeaning, wordView, bytesView, inputSame, within, finishMeaning, exactBytes, inputLength]

@[step] theorem bytes_exact (self : cbor.Decoder) :
    cbor.Decoder.bytes self ⦃ actual =>
      (bytesView actual.1, actual.2.position.val) =
        payloadAt (Refinement.byteList self.input.val) self.position.val 2 ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.bytes
  simpa using payload_exact self 2#u8

/-- UTF-8 validity is the existing explicit standard-library leaf contract.
The Auths payload/cursor/branching algorithm is translated and proved here. -/
def validUtf8 (bytes : List Nat) : Bool :=
  decide ((bytes.map UInt8.ofNat).toByteArray.IsValidUTF8)

def textAt (input : List Nat) (position : Nat) : Option (List Nat) × Nat :=
  let (bytes, next) := payloadAt input position 3
  (bytes.filter validUtf8, next)

@[step] theorem str_exact (self : cbor.Decoder) :
    cbor.Decoder.str self ⦃ actual =>
      (bytesView actual.1, actual.2.position.val) =
        textAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.str
  step with payload_exact as ⟨payload, next, meaning, inputSame⟩
  cases payload with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, textAt, ← meaning, bytesView, inputSame]
  | Ok bytes =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
      core.str.converts.from_utf8]
    have utf8Meaning : validUtf8 (Refinement.byteList bytes.val) =
        decide ((Auths.Codec.StdModel.bytes bytes).IsValidUTF8) := by
      simp [validUtf8, Refinement.byteList, Auths.Codec.StdModel.bytes, List.map_map, Function.comp_def]
    by_cases valid : (Auths.Codec.StdModel.bytes bytes).IsValidUTF8
    all_goals simp [textAt, ← meaning, bytesView, Option.filter, utf8Meaning, valid, inputSame]

/-- Accepted payloads identify the exact contiguous span and its bounds. -/
private theorem accepted_span (input : List Nat) (position major : Nat)
    (bytes : List Nat) (finish : Nat)
    (accepted : payloadAt input position major = (some bytes, finish)) :
    ∃ start length, typedHead input position major = (some length, start) ∧
      bytes = (input.drop start).take length ∧ finish = start + length ∧
      finish ≤ input.length ∧ bytes.length = length := by
  cases headEq : typedHead input position major with
  | mk length start =>
    cases length with
    | none => simp [payloadAt, headEq] at accepted
    | some length =>
      by_cases within : start + length ≤ input.length
      · simp only [payloadAt, headEq, within, ↓reduceIte, Prod.mk.injEq, Option.some.injEq] at accepted
        have bytesEq : bytes = (input.drop start).take length := accepted.1.symm
        have finishEq : finish = start + length := accepted.2.symm
        refine ⟨start, length, rfl, bytesEq, finishEq, ?_, ?_⟩
        · omega
        · simp only [bytesEq, List.length_take, List.length_drop]
          omega
      · simp [payloadAt, headEq, within] at accepted

@[step] theorem success_earns_span (self : cbor.Decoder) (major : Std.U8) :
    cbor.Decoder.payload self major ⦃ actual =>
      actual.2.input = self.input ∧
      ∀ bytes, actual.1 = .Ok bytes →
        ∃ start length,
          typedHead (Refinement.byteList self.input.val) self.position.val major.val = (some length, start) ∧
          Refinement.byteList bytes.val = ((Refinement.byteList self.input.val).drop start).take length ∧
          actual.2.position.val = start + length ∧
          actual.2.position.val ≤ self.input.val.length ∧ bytes.val.length = length ⦄ := by
  apply spec_mono (payload_exact self major)
  rintro ⟨result, next⟩ ⟨meaning, preserved⟩
  refine ⟨preserved, ?_⟩
  intro bytes equal
  change result = .Ok bytes at equal
  subst result
  have accepted : payloadAt (Refinement.byteList self.input.val) self.position.val major.val =
      (some (Refinement.byteList bytes.val), next.position.val) := meaning.symm
  obtain ⟨start, length, headEq, bytesEq, finishEq, within, sizeEq⟩ :=
    accepted_span _ _ _ _ _ accepted
  exact ⟨start, length, headEq, bytesEq, finishEq,
    by simpa [Refinement.byteList] using within,
    by simpa [Refinement.byteList] using sizeEq⟩

end Auths.Codec.Payload
