import Auths.Codec.Semantics
import qualification.aeneas.generated.codec.Funs

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Codec.Refinement

open auths_codec

set_option maxHeartbeats 2000000

def byteList (bytes : List Std.U8) : List Nat := bytes.map (·.val)

def headView (head : cbor.Head) : Auths.Codec.Head :=
  ⟨head.major.val, head.argument.val⟩

@[step] theorem slice_get_exact (input : Slice Std.U8) (position : Std.Usize) :
    core.slice.Slice.get (core.slice.index.SliceIndexUsizeSlice Std.U8)
      input position ⦃ result => result = input.val[position.val]? ⦄ := by
  simp [core.slice.Slice.get, core.slice.index.Usize.get]

theorem read_head_absent (input : Slice Std.U8) (position : Std.Usize)
    (absent : input.val[position.val]? = none) :
    cbor.read_head input position = ok (core.result.Result.Err ()) := by
  simp [cbor.read_head, core.slice.Slice.get, core.slice.index.Usize.get, absent]

@[step] theorem read_head_inline (input : Slice Std.U8) (position : Std.Usize)
    (first : Std.U8) (present : input.val[position.val]? = some first)
    (inline : first.val % 32 < 24) :
    cbor.read_head input position ⦃ result =>
      ∃ head, result = core.result.Result.Ok head ∧
        head.major.val = first.val / 32 ∧
        head.argument.val = first.val % 32 ∧
        head.next.val = position.val + 1 ⦄ := by
  have inBounds : position.val < input.val.length := by
    exact List.getElem?_eq_some_iff.mp present |>.1
  have nextFits : position.val + 1 ≤ Usize.max := by
    have := input.property
    omega
  unfold cbor.read_head
  simp only [core.slice.Slice.get, core.slice.index.Usize.get,
    Slice.getElem?_Usize_eq, present, bind_tc_ok]
  step as ⟨additional, additionalEq⟩
  step as ⟨next, nextEq⟩
  have isInline : additional < 24#u8 := by scalar_tac
  simp only [isInline, if_true]
  simp only [lift, bind_tc_ok]
  step as ⟨major, majorEq⟩
  exact ⟨_, rfl, majorEq, by simpa using additionalEq, nextEq⟩

@[step] theorem read_tail_safety (input : Slice Std.U8) (position : Std.Usize)
    (remaining : Std.U8) (value : Std.U64)
    (within : position.val ≤ input.val.length) :
    cbor.read_tail input position remaining value ⦃ result =>
      match result with
      | .Err _ => True
      | .Ok (_, next) => next.val ≤ input.val.length ∧
          next.val = position.val + remaining.val ⦄ := by
  unfold cbor.read_tail cbor.read_tail_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.2.1.val)
    (inv := fun state => state.1.val ≤ input.val.length ∧
      state.1.val + state.2.1.val = position.val + remaining.val)
  · rintro ⟨current, left, accumulator⟩ ⟨currentBound, total⟩
    dsimp only at currentBound total
    unfold cbor.read_tail_loop.body
    dsimp only
    split <;> rename_i nonzero
    · simp only [core.slice.Slice.get, core.slice.index.Usize.get,
        Slice.getElem?_Usize_eq, bind_tc_ok]
      split
      · simp [spec_ok]
      · rename_i byte present
        simp only [lift, bind_tc_ok]
        split
        · simp [spec_ok]
        · split
          · simp [spec_ok]
          · have byteWithin : current.val < input.val.length :=
              List.getElem?_eq_some_iff.mp present |>.1
            have incrementFits : current.val + 1 ≤ Usize.max := by
              have := input.property
              omega
            step as ⟨next, nextEq⟩
            step as ⟨leftNext, leftNextEq⟩
            exact ⟨by omega, by omega, by scalar_tac⟩
    · simp only [spec_ok]
      exact ⟨currentBound, by scalar_tac⟩
  · exact ⟨within, rfl⟩

theorem byte_chunk_cons (input : Slice Std.U8) (position width : Nat)
    (byte : Std.U8) (present : input.val[position]? = some byte) :
    ((byteList input.val).drop position).take (width + 1) =
      byte.val :: ((byteList input.val).drop (position + 1)).take width := by
  have atByte := List.getElem?_eq_some_iff.mp present
  have mappedBound : position < (byteList input.val).length := by
    simpa [byteList] using atByte.1
  rw [List.drop_eq_getElem_cons mappedBound]
  simp only [List.take_succ_cons, byteList, List.getElem_map, atByte.2]

/-- Exact source-level left-to-right byte interpretation. The range premise
ensures that every intermediate checked arithmetic operation succeeds. -/
@[step] theorem read_tail_exact (input : Slice Std.U8) (position : Std.Usize)
    (remaining : Std.U8) (value : Std.U64)
    (fits : position.val + remaining.val ≤ input.val.length)
    (numericFits : accumulate value.val
      (((byteList input.val).drop position.val).take remaining.val) ≤ U64.max) :
    cbor.read_tail input position remaining value ⦃ result =>
      ∃ decoded next, result = .Ok (decoded, next) ∧
        decoded.val = accumulate value.val
          (((byteList input.val).drop position.val).take remaining.val) ∧
        next.val = position.val + remaining.val ⦄ := by
  let expected := accumulate value.val
    (((byteList input.val).drop position.val).take remaining.val)
  unfold cbor.read_tail cbor.read_tail_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.2.1.val)
    (inv := fun state =>
      state.1.val + state.2.1.val = position.val + remaining.val ∧
      accumulate state.2.2.val
        (((byteList input.val).drop state.1.val).take state.2.1.val) = expected)
  · rintro ⟨current, left, accumulator⟩ ⟨total, meaning⟩
    dsimp only at total meaning
    unfold cbor.read_tail_loop.body
    dsimp only
    split <;> rename_i nonzero
    · have positive : 0 < left.val := by scalar_tac
      have currentWithin : current.val < input.val.length := by omega
      have present : input.val[current.val]? = some input.val[current.val] :=
        List.getElem?_eq_getElem currentWithin
      have chunk := byte_chunk_cons input current.val (left.val - 1) _ present
      have leftEq : left.val - 1 + 1 = left.val := by omega
      rw [leftEq] at chunk
      rw [chunk, accumulate] at meaning
      have stepBound := accumulate_ge_initial
        (accumulator.val * 256 + input.val[current.val].val)
        (((byteList input.val).drop (current.val + 1)).take (left.val - 1))
      have nextBound : accumulator.val * 256 + input.val[current.val].val ≤ U64.max := by
        dsimp only [expected] at meaning
        omega
      simp only [core.slice.Slice.get, core.slice.index.Usize.get,
        Slice.getElem?_Usize_eq, present, bind_tc_ok, lift]
      have multiplied := U64.checked_mul_bv_spec accumulator 256#u64
      cases mulEq : U64.checked_mul accumulator 256#u64 with
      | none =>
          rw [mulEq] at multiplied
          simp at multiplied
          omega
      | some shifted =>
          rw [mulEq] at multiplied
          obtain ⟨_, shiftedEq, _⟩ := multiplied
          simp at shiftedEq
          dsimp only
          have added := U64.checked_add_bv_spec shifted
            (core.convert.num.FromU64U8.from input.val[current.val])
          cases addEq : U64.checked_add shifted
              (core.convert.num.FromU64U8.from input.val[current.val]) with
          | none =>
              rw [addEq] at added
              simp only [core.convert.num.FromU64U8.from_val_eq] at added
              omega
          | some nextValue =>
              rw [addEq] at added
              obtain ⟨_, nextValueEq, _⟩ := added
              simp only [core.convert.num.FromU64U8.from_val_eq] at nextValueEq
              dsimp only
              have incrementFits : current.val + 1 ≤ Usize.max := by
                have := input.property
                omega
              step as ⟨next, nextEq⟩
              step as ⟨leftNext, leftNextEq⟩
              refine ⟨by omega, ?_, by scalar_tac⟩
              simpa only [nextEq, leftNextEq, nextValueEq, shiftedEq] using meaning
    · have atEnd : left.val = 0 := by scalar_tac
      simp only [spec_ok]
      refine ⟨_, _, rfl, ?_, by omega⟩
      simpa only [atEnd, List.take_zero, accumulate] using meaning
  · exact ⟨rfl, rfl⟩

theorem byteList_valid (bytes : List Std.U8) : BytesValid (byteList bytes) := by
  intro byte member
  obtain ⟨source, _, rfl⟩ := List.mem_map.mp member
  scalar_tac

/-- The complete success/error contract of a CBOR argument read. -/
@[step] theorem read_tail_bounded (input : Slice Std.U8) (position : Std.Usize)
    (remaining : Std.U8) (within : position.val ≤ input.val.length)
    (width : remaining.val ≤ 8) :
    cbor.read_tail input position remaining 0#u64 ⦃ result =>
      match result with
      | .Err _ => input.val.length < position.val + remaining.val
      | .Ok (decoded, next) =>
          position.val + remaining.val ≤ input.val.length ∧
          decoded.val = unsigned
            (((byteList input.val).drop position.val).take remaining.val) ∧
          next.val = position.val + remaining.val ⦄ := by
  by_cases fits : position.val + remaining.val ≤ input.val.length
  · have chunkValid : BytesValid
        (((byteList input.val).drop position.val).take remaining.val) := by
      intro byte member
      exact byteList_valid input.val byte
        (List.mem_of_mem_drop (List.mem_of_mem_take member))
    have numericBound := unsigned_lt_power _ chunkValid
    have lengthBound :
        (((byteList input.val).drop position.val).take remaining.val).length ≤ 8 := by
      exact Nat.le_trans (List.length_take_le ..) width
    have powerBound := Nat.pow_le_pow_right (by decide : 0 < 256) lengthBound
    have numericFits : accumulate (0#u64).val
        (((byteList input.val).drop position.val).take remaining.val) ≤ U64.max := by
      simp only [accumulate_eq]
      simp
      rw [U64.max_eq]
      have powerEight : (256 : Nat) ^ 8 = 18446744073709551616 := by decide
      rw [powerEight] at powerBound
      omega
    apply spec_mono (read_tail_exact input position remaining 0#u64 fits numericFits)
    rintro _ ⟨decoded, next, rfl, decodedEq, nextEq⟩
    exact ⟨fits, by simpa [accumulate_eq] using decodedEq, nextEq⟩
  · apply spec_mono (read_tail_safety input position remaining 0#u64 within)
    intro result safe
    cases result with
    | Err => omega
    | Ok pair =>
      obtain ⟨decoded, next⟩ := pair
      obtain ⟨nextWithin, nextEq⟩ := safe
      omega

def HeadRefines (input : Slice Std.U8) (position : Std.Usize)
    (result : core.result.Result cbor.Head cbor.Error) : Prop :=
  match result with
  | .Err _ => readHead ((byteList input.val).drop position.val) = none
  | .Ok head =>
      readHead ((byteList input.val).drop position.val) =
        some (headView head, (byteList input.val).drop head.next.val) ∧
      position.val < head.next.val ∧ head.next.val ≤ input.val.length ∧
      head.next.val ≤ position.val + 9

/-- Every translated head read is total and agrees with the independent byte
grammar, including all reserved tags and truncated extended arguments. -/
@[step] theorem read_head_refines (input : Slice Std.U8) (position : Std.Usize) :
    cbor.read_head input position ⦃ result => HeadRefines input position result ⦄ := by
  cases present : input.val[position.val]? with
  | none =>
      rw [read_head_absent input position present]
      have beyond : input.val.length ≤ position.val :=
        List.getElem?_eq_none_iff.mp present
      have empty : (byteList input.val).drop position.val = [] := by
        apply List.drop_eq_nil_iff.mpr
        simpa [byteList] using beyond
      simp [spec_ok, HeadRefines, empty, readHead]
  | some first =>
      have atByte := List.getElem?_eq_some_iff.mp present
      have inBounds : position.val < input.val.length := atByte.1
      have mappedBound : position.val < (byteList input.val).length := by
        simpa [byteList] using atByte.1
      have firstEq : (byteList input.val).drop position.val =
          first.val :: (byteList input.val).drop (position.val + 1) := by
        rw [List.drop_eq_getElem_cons mappedBound]
        simp only [byteList, List.getElem_map, atByte.2]
      have byteBound : first.val < 256 := by scalar_tac
      have nextFits : position.val + 1 ≤ Usize.max := by
        have := input.property
        omega
      by_cases inline : first.val % 32 < 24
      · apply spec_mono (read_head_inline input position first present inline)
        rintro _ ⟨head, rfl, majorEq, argumentEq, nextEq⟩
        simp only [HeadRefines, firstEq, readHead, byteBound, if_true, inline,
          headView, majorEq, argumentEq, nextEq]
        exact ⟨trivial, by omega, by omega, by omega⟩
      · unfold cbor.read_head
        simp only [core.slice.Slice.get, core.slice.index.Usize.get,
          Slice.getElem?_Usize_eq, present, bind_tc_ok]
        step as ⟨additional, additionalEq⟩
        step as ⟨start, startEq⟩
        have notInline : ¬ additional < 24#u8 := by scalar_tac
        simp only [notInline, if_false]
        split <;> rename_i tag
        case h_5 =>
          rename_i unmatched ne24S ne25S ne26S
          simp [UScalar.eq_equiv] at ne24S ne25S ne26S tag
          change additional.val ≠ 24 at ne24S
          change additional.val ≠ 25 at ne25S
          change additional.val ≠ 26 at ne26S
          change additional.val ≠ 27 at tag
          have ne24 : first.val % 32 ≠ 24 := by scalar_tac
          have ne25 : first.val % 32 ≠ 25 := by scalar_tac
          have ne26 : first.val % 32 ≠ 26 := by scalar_tac
          have ne27 : first.val % 32 ≠ 27 := by scalar_tac
          simp [spec_ok, HeadRefines, firstEq, readHead, byteBound, inline,
            ne24, ne25, ne26, ne27]
        all_goals
          first
          | change 24 = first.val % 32 at additionalEq
          | change 25 = first.val % 32 at additionalEq
          | change 26 = first.val % 32 at additionalEq
          | change 27 = first.val % 32 at additionalEq
          step with read_tail_bounded as ⟨tail, tailSpec⟩
          cases tail with
          | Err =>
            simp only [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              bind_tc_ok, spec_ok]
            simp only [HeadRefines, firstEq, readHead, byteBound, if_true, inline,
              if_false]
            rw [← additionalEq]
            dsimp only at tailSpec
            simp [readArgument, byteList, List.length_drop, startEq] at *
            omega
          | Ok pair =>
            obtain ⟨decoded, next⟩ := pair
            obtain ⟨fits, decodedEq, nextEq⟩ := tailSpec
            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            step as ⟨major, majorEq⟩
            simp only [HeadRefines, firstEq, readHead, byteBound, if_true, inline,
              if_false, headView, majorEq]
            rw [← additionalEq]
            simp only [startEq] at fits decodedEq nextEq
            have chunkFits :
                next.val - (position.val + 1) ≤
                  ((byteList input.val).drop (position.val + 1)).length := by
              simp only [byteList, List.length_drop, List.length_map]
              omega
            simp only [nextEq, Nat.add_sub_cancel_left] at chunkFits
            simp only [byteList, List.length_map, List.length_drop] at chunkFits
            simp [readArgument, byteList, chunkFits, decodedEq, nextEq, List.drop_drop]
            omega

theorem read_head_accepts_encoding (input : Slice Std.U8) (position : Std.Usize)
    (head : Auths.Codec.Head) (tail : List Nat) (valid : head.Valid)
    (encoding : (byteList input.val).drop position.val = encodeHead head ++ tail) :
    cbor.read_head input position ⦃ result =>
      ∃ decoded, result = .Ok decoded ∧ headView decoded = head ∧
        (byteList input.val).drop decoded.next.val = tail ∧
        decoded.next.val ≤ input.val.length ⦄ := by
  have grammar := readHead_encodeHead head valid tail
  apply spec_mono (read_head_refines input position)
  intro result refines
  cases result with
  | Err =>
    simp only [HeadRefines, encoding, grammar] at refines
    contradiction
  | Ok decoded =>
    obtain ⟨meaning, _, within, _⟩ := refines
    rw [encoding, grammar] at meaning
    obtain ⟨headEq, tailEq⟩ := Prod.mk.inj (Option.some.inj meaning)
    exact ⟨decoded, rfl, headEq.symm, tailEq.symm, within⟩

end Auths.Codec.Refinement
