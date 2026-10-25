import qualification.aeneas.generated.protocol_codec.Funs
import Auths.Codec.PrincipalSchemeModel
import Auths.Verifier.StatusLeaves
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.Codec.ProtocolPrincipalScheme
open Auths.PrincipalScheme
set_option maxHeartbeats 2000000
local instance (byte : Nat) : Decidable (Model.lower byte) := inferInstanceAs (Decidable (_ ∧ _))
local instance (byte : Nat) : Decidable (Model.allowed byte) := inferInstanceAs (Decidable (_ ∨ _))

theorem byte_allowed (byte : Std.U8) :
    AuthsProtocolCodec.auths_model.identifier.principal_scheme_byte_valid byte = ok (decide (Model.allowed byte.val)) := by
  unfold AuthsProtocolCodec.auths_model.identifier.principal_scheme_byte_valid
  simp only [UScalar.le_equiv, UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
  split_ifs <;> simp_all [Model.allowed, Model.lower]
  all_goals
    apply Bool.eq_iff_iff.mpr
    simp only [decide_eq_true_eq]
    simp_all only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
    omega

def finish (bytes : Slice Std.U8) (state : Std.Usize × Bool × Bool) : Bool :=
  state.2.1 && state.2.2 && decide (state.1.val < bytes.val.length)

theorem stopped_invalid (bytes : Slice Std.U8) (position : Std.Usize) (found : Bool) :
    AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop bytes position false found = ok (position, false, found) := by
  rw [AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop.eq_def]
  by_cases guard : position < bytes.len <;> simp [guard]

theorem stopped_found (bytes : Slice Std.U8) (position : Std.Usize) :
    AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop bytes position true true = ok (position, true, true) := by
  rw [AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop.eq_def]
  by_cases guard : position < bytes.len <;> simp [guard]

theorem loop_tail (remaining : List Std.U8) (bytes : Slice Std.U8) (position : Std.Usize)
    (suffix : bytes.val.drop position.val = remaining) :
    AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop bytes position true false ⦃ actual =>
      finish bytes actual = Model.tailValid (remaining.map (·.val)) ⦄ := by
  induction remaining generalizing position with
  | nil =>
    have finished : ¬ position < bytes.len := by
      have size := congrArg List.length suffix
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop.eq_def]
    simp [finished, finish, Model.tailValid]
  | cons head rest ih =>
    obtain ⟨guard, atHead⟩ := Auths.StatusSelection.indexed_head bytes position head rest suffix
    obtain ⟨next, step, nextValue, nextSuffix⟩ := Auths.StatusSelection.indexed_next bytes position head rest suffix
    have indexed : Slice.index_usize bytes position = ok head := atHead
    rw [AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop.eq_def]
    simp only [guard, ↓reduceIte, Bool.false_eq_true, indexed, bind_tc_ok]
    by_cases colon : head.val = 58
    · have nativeColon : head = 58#u8 := by scalar_tac
      simp only [nativeColon, ↓reduceIte, bind_tc_ok, step]
      change AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop bytes next true true ⦃ actual => finish bytes actual = Model.tailValid (58 :: rest.map (·.val)) ⦄
      rw [stopped_found]
      simp only [spec_ok]
      have remainingSize := congrArg List.length nextSuffix
      simp only [List.length_drop] at remainingSize
      have inBounds : position.val < bytes.val.length := by
        simpa only [UScalar.lt_equiv, Slice.len_val, Slice.length] using guard
      have afterBound : next.val ≤ bytes.val.length := by omega
      simp only [finish, Bool.true_and, Model.tailValid]
      by_cases empty : rest = []
      · simp only [empty, List.map_nil, List.isEmpty_nil, Bool.not_true]
        simp only [empty, List.length_nil] at remainingSize
        have atEnd : ¬next.val < bytes.val.length := by omega
        simp [atEnd]
      · have positive : 0 < rest.length := List.length_pos_iff.mpr empty
        have notEmpty : (rest.map (·.val)).isEmpty = false := by simpa using empty
        have beforeEnd : next.val < bytes.val.length := by omega
        simp [notEmpty, beforeEnd]
    · have nativeColon : head ≠ 58#u8 := by scalar_tac
      simp only [nativeColon, ↓reduceIte, byte_allowed, bind_tc_ok, step]
      by_cases allowed : Model.allowed head.val
      · simp only [allowed, decide_true]
        change AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop bytes next true false ⦃ actual => finish bytes actual = Model.tailValid (head.val :: rest.map (·.val)) ⦄
        simpa only [List.map_cons, Model.tailValid, colon, ↓reduceIte, allowed, decide_true, Bool.true_and] using ih next nextSuffix
      · simp only [allowed, decide_false]
        change AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid_loop bytes next false false ⦃ actual => finish bytes actual = Model.tailValid (head.val :: rest.map (·.val)) ⦄
        rw [stopped_invalid]
        simp [spec_ok, finish, Model.tailValid, colon, allowed]

theorem scheme_refines (value : Str) :
    AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid value ⦃ actual =>
      actual = Model.evaluate (value.val.map (·.val)) ⦄ := by
  unfold AuthsProtocolCodec.auths_model.identifier.principal_scheme_valid
  simp only [AuthsProtocolCodec.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
  by_cases short : value.len < 3#usize
  · have small : (value.val.map (·.val)).length < 3 := by
      simpa only [List.length_map, UScalar.lt_equiv, Slice.len_val, Slice.length, UScalar.ofNatCore_val_eq] using short
    have refused : Model.evaluate (value.val.map (·.val)) = false := by
      cases result : Model.evaluate (value.val.map (·.val)) with
      | false => rfl
      | true =>
        have minimum := Model.grammar_minimum _ ((Model.evaluate_iff_grammar _).mp result)
        omega
    simp [short, refused]
  · simp only [short, ↓reduceIte]
    cases values : value.val with
    | nil =>
      have size : value.len.val = 0 := by simp [values]
      have : value.len < 3#usize := by scalar_tac
      contradiction
    | cons first rest =>
      have indexed : Slice.index_usize value 0#usize = ok first := by simp [Slice.index_usize, values]
      simp only [indexed, bind_tc_ok, UScalar.le_equiv, UScalar.ofNatCore_val_eq]
      by_cases low : 97 ≤ first.val
      · simp only [low, ↓reduceIte]
        by_cases high : first.val ≤ 122
        · simp only [high, ↓reduceIte]
          have loop := loop_tail rest value 1#usize (by simp [values])
          apply spec_bind loop
          rintro ⟨position, valid, found⟩ meaning
          cases valid <;> cases found <;>
            simpa [finish, Model.evaluate, Model.lower, values, low, high,
              UScalar.lt_equiv, Slice.len_val, Slice.length] using meaning
        · simp [high, Model.evaluate, Model.lower]
      · simp [low, Model.evaluate, Model.lower]

end Auths.Codec.ProtocolPrincipalScheme
