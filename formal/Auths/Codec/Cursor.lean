import Mathlib.Tactic.IntervalCases
import Auths.Codec.Refinement
import Auths.Codec.Evaluation
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.Cursor

def wordView {ty : UScalarTy} (value : core.result.Result (UScalar ty) cbor.Error) : Option Nat :=
  match value with
  | .Ok value => some value.val
  | .Err _ => none

/-- Independent typed-head grammar. Refusal preserves the original cursor;
a matching definite head consumes precisely the grammar's prefix. -/
def typedHead (input : List Nat) (position major : Nat) : Option Nat × Nat :=
  match readHead (input.drop position) with
  | none => (none, position)
  | some (head, rest) =>
    if head.major = major then (some head.argument, input.length - rest.length)
    else (none, position)

@[step] theorem new_exact (input : Slice Std.U8) :
    cbor.Decoder.new input ⦃ actual => actual.input = input ∧ actual.position.val = 0 ⦄ := by
  simp [cbor.Decoder.new]

@[step] theorem at_exact (input : Slice Std.U8) (position : Std.Usize) :
    cbor.Decoder.at input position ⦃ actual =>
      actual = if position.val ≤ input.val.length then .Ok ⟨input, position⟩ else .Err () ⦄ := by
  unfold cbor.Decoder.at
  by_cases within : position.val ≤ input.val.length
  · have gate : ¬ position > Slice.len input := by simpa [Slice.length] using within.not_gt
    simp [gate, within]
  · have gate : position > Slice.len input := by simpa [Slice.length] using Nat.lt_of_not_ge within
    simp [gate, within]

@[step] theorem position_exact (self : cbor.Decoder) :
    cbor.Decoder.impl.position self ⦃ actual => actual = self.position ⦄ := by
  rfl

@[step] theorem head_exact (self : cbor.Decoder) (major : Std.U8) :
    cbor.Decoder.head self major ⦃ actual =>
      (wordView actual.1, actual.2.position.val) =
        typedHead (Refinement.byteList self.input.val) self.position.val major.val ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.head
  step with Refinement.read_head_refines self.input self.position as ⟨read, meaning⟩
  cases read with
  | Err error =>
    have refused : readHead ((Refinement.byteList self.input.val).drop self.position.val) = none := meaning
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from,
      wordView, typedHead, refused]
  | Ok head =>
    obtain ⟨grammar, advances, bounded, work⟩ := meaning
    have endPosition : (Refinement.byteList self.input.val).length -
        ((Refinement.byteList self.input.val).drop head.next.val).length = head.next.val := by
      simp only [Refinement.byteList, List.length_map, List.length_drop]
      omega
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    by_cases same : head.major = major
    · have sameValue : head.major.val = major.val := congrArg UScalar.val same
      simp [same, wordView, typedHead, grammar, Refinement.headView, sameValue]
      simp only [Refinement.byteList, List.length_map] at *
      omega
    · have differentValue : head.major.val ≠ major.val := by
        intro identical
        exact same ((UScalar.eq_equiv _ _).mpr identical)
      simp [same, wordView, typedHead, grammar, Refinement.headView, differentValue]

@[step] theorem u64_exact (self : cbor.Decoder) :
    cbor.Decoder.u64 self ⦃ actual =>
      (wordView actual.1, actual.2.position.val) =
        typedHead (Refinement.byteList self.input.val) self.position.val 0 ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.u64
  simpa using head_exact self 0#u8


def narrowHead (input : List Nat) (position maximum : Nat) : Option Nat × Nat :=
  let (value, next) := typedHead input position 0
  (value.filter (fun value => decide (value ≤ maximum)), next)

private theorem cast_u8_exact (value : Std.U64) :
    U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from value ⦃ actual =>
      wordView actual = if value.val ≤ 255 then some value.val else none ⦄ := by
  unfold U8.Insts.CoreConvertTryFromU64TryFromIntError.try_from
  rw [Evaluation.try_from]
  have concrete : UScalar.cMax .U8 = 255 := rfl
  have logical : UScalar.max .U8 = 255 := by scalar_tac
  by_cases fits : value.val ≤ 255 <;>
    simp [concrete, logical, fits, wordView, UScalar.ofNat]

private theorem cast_u16_exact (value : Std.U64) :
    U16.Insts.CoreConvertTryFromU64TryFromIntError.try_from value ⦃ actual =>
      wordView actual = if value.val ≤ 65535 then some value.val else none ⦄ := by
  unfold U16.Insts.CoreConvertTryFromU64TryFromIntError.try_from
  rw [Evaluation.try_from]
  have concrete : UScalar.cMax .U16 = 65535 := rfl
  have logical : UScalar.max .U16 = 65535 := by scalar_tac
  by_cases fits : value.val ≤ 65535 <;>
    simp [concrete, logical, fits, wordView, UScalar.ofNat]

private theorem map_malformed {T : Type} (value : core.result.Result T cbor.Error) :
    core.result.Result.map_err (BuiltinFnOnce core.num.error.TryFromIntError cbor.Error)
      value cbor.malformed = ok value := by
  cases value <;> simp [core.result.Result.map_err, BuiltinFnOnce, cbor.malformed]

@[step] theorem u8_exact (self : cbor.Decoder) :
    cbor.Decoder.u8 self ⦃ actual =>
      (wordView actual.1, actual.2.position.val) =
        narrowHead (Refinement.byteList self.input.val) self.position.val 255 ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.u8
  step with u64_exact as ⟨result, next, meaning, inputSame⟩
  cases result with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, wordView, narrowHead, ← meaning, inputSame]
  | Ok value =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with cast_u8_exact as ⟨cast, castMeaning⟩
    simp only [map_malformed, bind_tc_ok, spec_ok]
    constructor
    · rw [castMeaning]
      simp only [narrowHead, ← meaning, wordView]
      by_cases fits : value.val ≤ 255 <;> simp [fits, Option.filter]
    · exact inputSame

@[step] theorem u16_exact (self : cbor.Decoder) :
    cbor.Decoder.u16 self ⦃ actual =>
      (wordView actual.1, actual.2.position.val) =
        narrowHead (Refinement.byteList self.input.val) self.position.val 65535 ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.u16
  step with u64_exact as ⟨result, next, meaning, inputSame⟩
  cases result with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, wordView, narrowHead, ← meaning, inputSame]
  | Ok value =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with cast_u16_exact as ⟨cast, castMeaning⟩
    simp only [map_malformed, bind_tc_ok, spec_ok]
    constructor
    · rw [castMeaning]
      simp only [narrowHead, ← meaning, wordView]
      by_cases fits : value.val ≤ 65535 <;> simp [fits, Option.filter]
    · exact inputSame

def nullAt (input : List Nat) (position : Nat) : Bool × Nat :=
  if input[position]? = some 246 then (true, position + 1) else (false, position)
def unitView (value : core.result.Result Unit cbor.Error) : Bool :=
  match value with | .Ok _ => true | .Err _ => false

private theorem option_byte_ne (left right : Option Std.U8) :
    core.cmp.PartialEq.ne.trait_default
      (core.option.Option.Insts.CoreCmpPartialEqOption (core.cmp.PartialEqShared core.cmp.PartialEqU8))
      left right = ok (decide (left ≠ right)) := by
  cases left <;> cases right <;>
    simp [core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
      auths_codec.core.option.Option.Insts.CoreCmpPartialEqOption, _root_.core.option.Option.Insts.CoreCmpPartialEqOption.eq,
      core.cmp.PartialEqShared, core.cmp.impls.PartialEqShared.eq, core.cmp.PartialEqU8, core.cmp.impls.PartialEqU8.eq, UScalar.eq_equiv]

@[step] theorem null_exact (self : cbor.Decoder) :
    cbor.Decoder.null self ⦃ actual =>
      (unitView actual.1, actual.2.position.val) = nullAt (Refinement.byteList self.input.val) self.position.val ∧
      actual.2.input = self.input ⦄ := by
  unfold cbor.Decoder.null
  step with Refinement.slice_get_exact as ⟨byte, byteAt⟩
  simp only [option_byte_ne, bind_tc_ok]
  cases byte with
  | none => simp [unitView, nullAt, Refinement.byteList, List.getElem?_map, ← byteAt]
  | some byte =>
    by_cases sameByte : byte = 246#u8
    · have present : self.input.val[self.position.val]? = some byte := byteAt.symm
      have inside := (List.getElem?_eq_some_iff.mp present).1
      have fits : self.position.val + 1 ≤ Usize.max := by have bound := self.input.property; omega
      obtain ⟨next, addition, nextMeaning⟩ := spec_imp_exists (Usize.add_spec (x := self.position) (y := 1#usize) fits)
      simp [sameByte, addition, unitView, nullAt, Refinement.byteList, List.getElem?_map, ← byteAt, nextMeaning]
    · have different : byte.val ≠ 246 := by
        intro equal
        apply sameByte
        apply (UScalar.eq_equiv _ _).mpr
        simpa using equal
      simp [sameByte, unitView, nullAt, Refinement.byteList, List.getElem?_map, ← byteAt, different]


/-- Peeking classifies the first byte only; it neither consumes a head nor
establishes canonicality or availability of the following payload. -/
def classify (byte : Nat) : cbor.Type :=
  let additional := byte % 32
  match byte / 32 with
  | 0 => if additional ≤ 24 then .U8
         else if additional = 25 then .U16
         else if additional = 26 then .U32
         else if additional = 27 then .U64 else .Other
  | 2 => if additional ≤ 27 then .Bytes else .Other
  | 3 => if additional ≤ 27 then .String else .Other
  | 7 => if additional = 22 then .Null else .Other
  | _ => .Other

private theorem classify_ranges (byte : Nat) (bound : byte < 256) :
    classify byte =
      if byte ≤ 24 then .U8
      else if byte = 25 then .U16
      else if byte = 26 then .U32
      else if byte = 27 then .U64
      else if byte = 246 then .Null
      else if 64 ≤ byte ∧ byte ≤ 91 then .Bytes
      else if 96 ≤ byte ∧ byte ≤ 123 then .String
      else .Other := by
  interval_cases byte <;> norm_num [classify]

def typeAt (input : List Nat) (position : Nat) : core.result.Result cbor.Type cbor.Error :=
  match input[position]? with
  | none => .Err ()
  | some byte => .Ok (classify byte)

@[step] theorem datatype_exact (self : cbor.Decoder) :
    cbor.Decoder.datatype self ⦃ actual =>
      actual = typeAt (Refinement.byteList self.input.val) self.position.val ⦄ := by
  unfold cbor.Decoder.datatype
  step with Refinement.slice_get_exact as ⟨byte, byteAt⟩
  cases byte with
  | none =>
    simp [core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, typeAt, Refinement.byteList, List.getElem?_map, ← byteAt]
  | some byte =>
    simp only [core.option.Option.ok_or, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
    simp only [typeAt, Refinement.byteList, List.getElem?_map, ← byteAt, Option.map_some]
    rcases byte with ⟨value, bounds⟩
    have upper : value < 256 := by scalar_tac
    refine spec_mono (P₀ := fun actual => actual = .Ok
      (if value ≤ 24 then cbor.Type.U8
       else if value = 25 then .U16
       else if value = 26 then .U32
       else if value = 27 then .U64
       else if value = 246 then .Null
       else if 64 ≤ value ∧ value ≤ 91 then .Bytes
       else if 96 ≤ value ∧ value ≤ 123 then .String
       else .Other)) ?_ ?_
    · interval_cases value <;> rfl
    · intro actual meaning
      change actual = .Ok (classify value)
      rw [classify_ranges value upper]
      exact meaning

/-- Completeness compares the cursor with the explicitly supplied input. A
caller must separately establish that this is the cursor's own input. -/
@[step] theorem ensure_complete_exact (self : cbor.Decoder) (input : Slice Std.U8) :
    decode.ensure_complete self input ⦃ actual => actual =
      if self.position.val = input.val.length then .Ok () else .Err .Malformed ⦄ := by
  unfold decode.ensure_complete
  simp only [cbor.Decoder.impl.position, bind_tc_ok]
  split <;> rename_i complete
  all_goals simp_all [spec_ok, UScalar.eq_equiv, Slice.length]

end Auths.Codec.Cursor
