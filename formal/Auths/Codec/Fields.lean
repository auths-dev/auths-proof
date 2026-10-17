import Auths.Codec.Payload
import Auths.Codec.Collection
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.Fields
open Cursor Payload Collection

def keyAt (input : List Nat) (position expected : Nat) :
    core.result.Result Unit error.CodecError × Nat :=
  let (value, next) := narrowHead input position 255
  let verdict := match value with
    | none => .Err error.CodecError.Malformed
    | some value => if value = expected then .Ok () else .Err error.CodecError.NonCanonical
  (verdict, next)

@[step] theorem key_exact (self : cbor.Decoder) (expected : Std.U8) :
    decode.key self expected ⦃ actual =>
      (actual.1, actual.2.position.val) = keyAt (Refinement.byteList self.input.val) self.position.val expected.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.key
  step with Cursor.u8_exact as ⟨value, next, meaning, inputSame⟩
  cases value with
  | Err error =>
    simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, keyAt, ← meaning, Cursor.wordView, inputSame]
  | Ok value =>
    simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
    by_cases equal : value = expected
    · have sameValue := congrArg UScalar.val equal
      simp [equal, sameValue, keyAt, ← meaning, Cursor.wordView, inputSame]
    · have different : value.val ≠ expected.val := by
        intro same
        exact equal ((UScalar.eq_equiv _ _).mpr same)
      simp [equal, different, keyAt, ← meaning, Cursor.wordView, inputSame]

def mapAt (input : List Nat) (position expected : Nat) :
    core.result.Result Unit error.CodecError × Nat :=
  let (length, next) := collectionAt input position 5
  let verdict := match length with
    | some (some length) => if length = expected then .Ok () else .Err error.CodecError.Malformed
    | _ => .Err error.CodecError.Malformed
  (verdict, next)

@[step] theorem map_exact (self : cbor.Decoder) (expected : Std.U64) :
    decode.map self expected ⦃ actual =>
      (actual.1, actual.2.position.val) = mapAt (Refinement.byteList self.input.val) self.position.val expected.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.map
  step with Collection.map_exact as ⟨value, next, meaning, inputSame⟩
  cases value with
  | Err error =>
    simp [core.result.Result.unwrap_or, core.option.Option.Insts.CoreCmpPartialEqOption.eq,
      _root_.core.option.Option.Insts.CoreCmpPartialEqOption.eq,
      mapAt, ← meaning, collectionView, inputSame]
  | Ok value =>
    cases value with
    | none =>
      simp [core.result.Result.unwrap_or, core.option.Option.Insts.CoreCmpPartialEqOption.eq,
        _root_.core.option.Option.Insts.CoreCmpPartialEqOption.eq,
        mapAt, ← meaning, collectionView, inputSame]
    | some value =>
      by_cases equal : value.val = expected.val <;>
        simp [equal, core.result.Result.unwrap_or, core.option.Option.Insts.CoreCmpPartialEqOption.eq,
        _root_.core.option.Option.Insts.CoreCmpPartialEqOption.eq, core.cmp.PartialEqU64,
        core.cmp.impls.PartialEqU64.eq, UScalar.eq_equiv,
        mapAt, ← meaning, collectionView, inputSame]

def codecBytesView (value : core.result.Result Str error.CodecError) : core.result.Result (List Nat) error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok bytes => .Ok (Refinement.byteList bytes.val)

def textAt (input : List Nat) (position : Nat) : core.result.Result (List Nat) error.CodecError × Nat :=
  let (bytes, next) := Payload.textAt input position
  (match bytes with | some bytes => .Ok bytes | none => .Err error.CodecError.Malformed, next)

@[step] theorem text_exact (self : cbor.Decoder) :
    decode.text self ⦃ actual =>
      (codecBytesView actual.1, actual.2.position.val) = textAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.text
  step with Payload.str_exact as ⟨value, next, meaning, inputSame⟩
  cases value <;> simp [textAt, ← meaning, Payload.bytesView, codecBytesView, inputSame]

def nullAt (input : List Nat) (position : Nat) : core.result.Result Unit error.CodecError × Nat :=
  let (valid, next) := Cursor.nullAt input position
  (if valid then .Ok () else .Err error.CodecError.Malformed, next)

@[step] theorem null_exact (self : cbor.Decoder) :
    decode.null self ⦃ actual =>
      (actual.1, actual.2.position.val) = nullAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.null
  step with Cursor.null_exact as ⟨value, next, meaning, inputSame⟩
  cases value <;>
    simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      nullAt, ← meaning, Cursor.unitView, inputSame]

def isNullAt (input : List Nat) (position : Nat) : core.result.Result Bool error.CodecError :=
  match Cursor.typeAt input position with
  | .Err _ => .Err error.CodecError.Malformed
  | .Ok .Null => .Ok true
  | .Ok _ => .Ok false

@[step] theorem is_null_exact (self : cbor.Decoder) :
    decode.is_null self ⦃ actual => actual = isNullAt (Refinement.byteList self.input.val) self.position.val ⦄ := by
  unfold decode.is_null
  step with Cursor.datatype_exact as ⟨value, meaning⟩
  cases value with
  | Err error =>
    simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, isNullAt, ← meaning]
  | Ok kind =>
    cases kind <;>
      simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
        cbor.Type.Insts.CoreCmpPartialEqType.eq, cbor.Type.read_discriminant, isNullAt, ← meaning]


def sizeView (value : core.result.Result Std.Usize error.CodecError) : core.result.Result Nat error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok value => .Ok value.val

def arrayAt (input : List Nat) (position maximum : Nat) : core.result.Result Nat error.CodecError × Nat :=
  let (length, next) := collectionAt input position 4
  let verdict := match length with
    | some (some length) => if length ≤ maximum then .Ok length else .Err error.CodecError.LimitExceeded
    | _ => .Err error.CodecError.Malformed
  (verdict, next)

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

@[step] theorem array_exact (self : cbor.Decoder) (maximum : Std.Usize) :
    decode.array self maximum ⦃ actual =>
      (sizeView actual.1, actual.2.position.val) = arrayAt (Refinement.byteList self.input.val) self.position.val maximum.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.array
  step with Collection.array_exact as ⟨value, next, meaning, inputSame⟩
  cases value with
  | Err error =>
    simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, arrayAt, ← meaning, collectionView, sizeView, inputSame]
  | Ok value =>
    simp only [core.result.Result.map_err, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
    cases value with
    | none =>
      simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, arrayAt, ← meaning, collectionView, sizeView, inputSame]
    | some argument =>
      simp only [core.option.Option.ok_or, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
      step with size_cast as ⟨converted, castMeaning⟩
      cases converted with
      | Err error =>
        have tooLarge : ¬ argument.val ≤ maximum.val := by scalar_tac
        simp [core.result.Result.map_err, BuiltinFnOnce, auths_codec.error.limit_error,
          core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame.from, arrayAt, ← meaning, collectionView, sizeView, tooLarge, inputSame]
      | Ok length =>
        simp only at castMeaning
        by_cases within : argument.val ≤ maximum.val
        · have notGreater : ¬ maximum.val < argument.val := by omega
          simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
            UScalar.lt_equiv, castMeaning, within, notGreater,
            arrayAt, ← meaning, collectionView, sizeView, inputSame]
        · have greater : maximum.val < argument.val := by omega
          simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
            UScalar.lt_equiv, castMeaning, within, greater,
            arrayAt, ← meaning, collectionView, sizeView, inputSame]


def vecView (value : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError) :
    core.result.Result (List Nat) error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok value => .Ok (Refinement.byteList value.val)

def boundedBytesAt (input : List Nat) (position maximum : Nat) (nonempty : Bool) :
    core.result.Result (List Nat) error.CodecError × Nat :=
  let (bytes, next) := payloadAt input position 2
  let verdict := match bytes with
    | none => .Err error.CodecError.Malformed
    | some bytes =>
      if maximum < bytes.length ∨ (nonempty = true ∧ bytes = []) then
        .Err error.CodecError.LimitExceeded else .Ok bytes
  (verdict, next)

private theorem copy_bytes (bytes : Slice Std.U8) :
    alloc.slice.Slice.to_vec core.clone.CloneU8 bytes ⦃ actual => actual.val = bytes.val ⦄ := by
  apply spec_mono (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 bytes (by intros; rfl))
  intro copied equal
  simpa only [← equal]

@[step] theorem bounded_bytes_exact (self : cbor.Decoder) (maximum : Std.Usize) (nonempty : Bool) :
    decode.bounded_bytes self maximum nonempty ⦃ actual =>
      (vecView actual.1, actual.2.position.val) =
        boundedBytesAt (Refinement.byteList self.input.val) self.position.val maximum.val nonempty ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.bounded_bytes
  step with Payload.bytes_exact as ⟨value, next, meaning, inputSame⟩
  cases value with
  | Err error => simp [boundedBytesAt, ← meaning, Payload.bytesView, vecView, inputSame]
  | Ok bytes =>
    have bytesLength : (Refinement.byteList bytes.val).length = bytes.val.length := by simp [Refinement.byteList]
    have bytesEmpty : Refinement.byteList bytes.val = [] ↔ bytes.val = [] := by simp [Refinement.byteList]
    by_cases over : maximum.val < bytes.val.length
    · simp [UScalar.lt_equiv, Slice.length, over, boundedBytesAt, ← meaning,
        Payload.bytesView, vecView, bytesLength, inputSame]
    · simp only [UScalar.lt_equiv, Slice.len_val, over, ↓reduceIte]
      by_cases required : nonempty = true
      · simp only [required, Bool.false_eq_true, ↓reduceIte]
        step with core.slice.Slice.is_empty_spec as ⟨empty, emptyMeaning⟩
        by_cases noBytes : bytes.val = []
        · have isEmpty : empty = true := by simpa [noBytes, Slice.length] using emptyMeaning
          simp [isEmpty, boundedBytesAt, ← meaning, Payload.bytesView, vecView, bytesLength,
            over, bytesEmpty, noBytes, inputSame, required] <;> simp [Refinement.byteList]
        · have notEmpty : empty = false := by simpa [Slice.length, List.length_eq_zero_iff, noBytes] using emptyMeaning
          simp only [notEmpty, Bool.false_eq_true, ↓reduceIte]
          step with copy_bytes as ⟨copied, copyMeaning⟩
          simp [boundedBytesAt, ← meaning, Payload.bytesView, vecView, bytesLength,
            over, bytesEmpty, noBytes, copyMeaning, inputSame, required]
      · simp only [required, Bool.false_eq_true, ↓reduceIte]
        step with copy_bytes as ⟨copied, copyMeaning⟩
        simp [boundedBytesAt, ← meaning, Payload.bytesView, vecView, bytesLength,
          over, copyMeaning, inputSame, required]


def digestView (value : core.result.Result (Array Std.U8 32#usize) error.CodecError) :
    core.result.Result (List Nat) error.CodecError :=
  match value with
  | .Err error => .Err error
  | .Ok value => .Ok (Refinement.byteList value.val)

def digestAt (input : List Nat) (position : Nat) : core.result.Result (List Nat) error.CodecError × Nat :=
  let (bytes, next) := payloadAt input position 2
  let verdict := match bytes with
    | none => .Err error.CodecError.Malformed
    | some bytes => if bytes.length = 32 then .Ok bytes else .Err error.CodecError.Malformed
  (verdict, next)

@[step] theorem digest_bytes_exact (self : cbor.Decoder) :
    decode.digest_bytes self ⦃ actual =>
      (digestView actual.1, actual.2.position.val) =
        digestAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold decode.digest_bytes
  step with Payload.bytes_exact as ⟨value, next, meaning, inputSame⟩
  cases value with
  | Err error => simp [digestAt, ← meaning, Payload.bytesView, digestView, inputSame]
  | Ok bytes =>
    have bytesLength : (Refinement.byteList bytes.val).length = bytes.val.length := by simp [Refinement.byteList]
    step with core.array.TryFromArrayCopySlice.try_from.step as ⟨copied, copyMeaning⟩
    cases copied with
    | Err error =>
      have wrongLength : bytes.val.length ≠ 32 := by
        simpa only [Slice.length] using copyMeaning
      simp [core.result.Result.map_err, BuiltinFnOnce, decode.decode_error,
        digestAt, ← meaning, Payload.bytesView, digestView, bytesLength, wrongLength, inputSame]
    | Ok digest =>
      have lengthEq : bytes.val.length = 32 := by
        rw [← copyMeaning.1]
        simpa using digest.property
      simp [core.result.Result.map_err, digestAt, ← meaning, Payload.bytesView,
        digestView, bytesLength, lengthEq, copyMeaning.1, inputSame]

end Auths.Codec.Fields
