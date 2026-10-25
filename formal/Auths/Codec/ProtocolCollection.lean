/- Same shipping primitive/field algorithm, unfolded in the complete protocol
extraction context. These bodies do not assume an old/new extraction identity
or replace an Auths algorithm with an opaque model. Fresh interface and complete
compiled statement/axiom review remain required before qualification. -/
import Auths.Codec.ProtocolCursor
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec
namespace Auths.Codec.ProtocolCollection
open ProtocolCursor

def collectionAt (input : List Nat) (position major : Nat) : Option (Option Nat) × Nat :=
  if input[position]? = some (major * 32 + 31) then (some none, position + 1)
  else
    let (value, next) := typedHead input position major
    (value.map some, next)

def collectionView (value : core.result.Result (Option Std.U64) cbor.Error) : Option (Option Nat) :=
  match value with
  | .Err _ => none
  | .Ok value => some (value.map UScalar.val)

private theorem shift_marker (major : Std.U8) (valid : major.val < 8) :
    (major <<< 5#i32) ⦃ shifted => (shifted ||| 31#u8).val = major.val * 32 + 31 ⦄ := by
  apply spec_mono (U8.ShiftLeft_IScalar_spec major 5#i32 (by scalar_tac) (by scalar_tac))
  rintro shifted ⟨natural, bits⟩
  simp only [UScalar.val_or, natural]
  have shiftValue : (5#i32).toNat = 5 := rfl
  rw [shiftValue]
  have sizeEq : U8.size = 256 := by simp [U8.size, U8.numBits]
  rw [sizeEq]
  change ((major.val <<< 5) % 256) ||| 31 = major.val * 32 + 31
  rcases major with ⟨value, bounds⟩
  change value < 8 at valid
  change ((value <<< 5) % 256) ||| 31 = value * 32 + 31
  interval_cases value <;> decide

private theorem option_eq (left : Option Std.U8) (right : Std.U8) :
    core.option.Option.Insts.CoreCmpPartialEqOption.eq
      (core.cmp.PartialEqShared core.cmp.PartialEqU8) left (some right)
      = ok (decide (left = some right)) := by
  cases left <;> simp [core.option.Option.Insts.CoreCmpPartialEqOption.eq,
    _root_.core.option.Option.Insts.CoreCmpPartialEqOption.eq,
    core.cmp.PartialEqShared, core.cmp.impls.PartialEqShared.eq,
    core.cmp.PartialEqU8, core.cmp.impls.PartialEqU8.eq]

@[step] theorem collection_exact (self : cbor.Decoder) (major : Std.U8)
    (valid : major.val < 8) :
    cbor.Decoder.collection self major ⦃ actual =>
      (collectionView actual.1, actual.2.position.val) =
        collectionAt (ProtocolReadHead.byteList self.input.val) self.position.val major.val ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.collection
  step with ProtocolReadHead.slice_get_exact as ⟨first, firstAt⟩
  step with shift_marker major valid as ⟨shifted, markerMeaning⟩
  simp only [lift, bind_tc_ok]
  rw [option_eq]
  simp only [bind_tc_ok]
  by_cases indefinite : first = some (shifted ||| 31#u8)
  · have present : ∃ byte, self.input.val[self.position.val]? = some byte := by
      exact ⟨_, firstAt.symm.trans indefinite⟩
    obtain ⟨byte, byteAt⟩ := present
    have inside := (List.getElem?_eq_some_iff.mp byteAt).1
    have fits : self.position.val + 1 ≤ Usize.max := by
      have bound := self.input.property
      omega
    obtain ⟨next, addition, nextMeaning⟩ := spec_imp_exists
      (Usize.add_spec (x := self.position) (y := 1#usize) fits)
    have byteMeaning : (ProtocolReadHead.byteList self.input.val)[self.position.val]? =
        some (major.val * 32 + 31) := by
      simp [ProtocolReadHead.byteList, List.getElem?_map, ← firstAt, indefinite, markerMeaning]
    simp [indefinite, addition, collectionAt, byteMeaning, collectionView, nextMeaning]
  · simp only [indefinite, decide_false, Bool.false_eq_true, ↓reduceIte]
    step with ProtocolCursor.head_exact as ⟨head, next, meaning, inputSame⟩
    have different : (ProtocolReadHead.byteList self.input.val)[self.position.val]? ≠
        some (major.val * 32 + 31) := by
      intro equal
      apply indefinite
      cases first with
      | none => simp [ProtocolReadHead.byteList, List.getElem?_map, ← firstAt] at equal
      | some byte =>
        have eqValue : byte.val = (shifted ||| 31#u8).val := by
          simpa [ProtocolReadHead.byteList, List.getElem?_map, ← firstAt, ← markerMeaning] using equal
        exact congrArg some ((UScalar.eq_equiv _ _).mpr eqValue)
    cases head <;>
      simp [core.result.Result.map, BuiltinFnOnce, core.option.Option.Some,
        collectionView, collectionAt, different, ← meaning, ProtocolCursor.wordView, inputSame]

@[step] theorem map_exact (self : cbor.Decoder) :
    cbor.Decoder.map self ⦃ actual =>
      (collectionView actual.1, actual.2.position.val) =
        collectionAt (ProtocolReadHead.byteList self.input.val) self.position.val 5 ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.map
  simpa using collection_exact self 5#u8 (by decide)

@[step] theorem array_exact (self : cbor.Decoder) :
    cbor.Decoder.array self ⦃ actual =>
      (collectionView actual.1, actual.2.position.val) =
        collectionAt (ProtocolReadHead.byteList self.input.val) self.position.val 4 ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.array
  simpa using collection_exact self 4#u8 (by decide)

end Auths.Codec.ProtocolCollection
