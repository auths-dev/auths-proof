import qualification.aeneas.generated.model.Funs
import Auths.Model.IdentifierSemantics
open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1000000
namespace Auths.Refinement.Identifier

def threeExcluded (first second third : Std.U8) : Prop :=
  (first.val = 225 ∧ second.val = 154 ∧ third.val = 128) ∨
  (first.val = 226 ∧
    ((second.val = 128 ∧ (128 ≤ third.val ∧ third.val ≤ 138 ∨
      third.val = 168 ∨ third.val = 169 ∨ third.val = 175)) ∨
     (second.val = 129 ∧ third.val = 159))) ∨
  (first.val = 227 ∧ second.val = 128 ∧ third.val = 128)
instance (a b c : Std.U8) : Decidable (threeExcluded a b c) :=
  inferInstanceAs (Decidable (_ ∨ _))

@[step] theorem three_excluded_exact (first second third : Std.U8) :
    auths_model.identifier.forbidden_three_byte_prefix first second third
      ⦃ result => result = decide (threeExcluded first second third) ⦄ := by
  unfold auths_model.identifier.forbidden_three_byte_prefix
  split_ifs <;> simp_all [threeExcluded, UScalar.le_equiv, UScalar.eq_equiv]

/-- A byte grammar for the fixed Unicode control/whitespace exclusions. -/
def excludedPrefix : List Std.U8 → Bool
  | [] => false
  | first :: rest =>
    decide (first.val ≤ 32 ∨ first.val = 127) ||
    match rest with
    | [] => false
    | second :: tail =>
      decide (first.val = 194 ∧ 128 ≤ second.val ∧ second.val ≤ 160) ||
      match tail with
      | [] => false
      | third :: _ => decide (threeExcluded first second third)

@[step] theorem forbidden_at_exact (input : Slice Std.U8) (position : Std.Usize) :
    auths_model.identifier.forbidden_identifier_at input position
      ⦃ result => result = excludedPrefix (input.val.drop position.val) ⦄ := by
  unfold auths_model.identifier.forbidden_identifier_at
  simp only [core.slice.Slice.get, core.slice.index.Usize.get,
    Slice.getElem?_Usize_eq, bind_tc_ok]
  cases present : input.val[position.val]? with
  | none =>
    have absent := List.getElem?_eq_none_iff.mp present
    simp [List.drop_eq_nil_of_le absent, excludedPrefix]
  | some first =>
    have bound := (List.getElem?_eq_some_iff.mp present).1
    have suffix : input.val.drop position.val =
        first :: input.val.drop (position.val + 1) := by
      rw [List.drop_eq_getElem_cons bound]
      simp only [(List.getElem?_eq_some_iff.mp present).2]
    rw [suffix]
    clear suffix present
    by_cases low : first ≤ 32#u8
    all_goals simp only [low, ↓reduceIte]
    · have lowNat : first.val ≤ 32 := by scalar_tac
      simp [excludedPrefix, lowNat]
    · by_cases del : first = 127#u8
      all_goals simp only [del, ↓reduceIte]
      · simp [excludedPrefix]
      · have notLow : ¬ first.val ≤ 32 := by scalar_tac
        have notDel : first.val ≠ 127 := by scalar_tac
        step as ⟨remaining, remainingEq⟩
        by_cases short : remaining < 2#usize
        all_goals simp only [short, ↓reduceIte]
        · have one : input.val.drop (position.val + 1) = [] := by
            apply List.drop_eq_nil_of_le
            scalar_tac
          simp [one, excludedPrefix, notLow, notDel]
        · step as ⟨secondAt, secondAtEq⟩
          step as ⟨second, secondEq⟩
          have secondBound : position.val + 1 < input.val.length := by scalar_tac
          have secondSuffix : input.val.drop (position.val + 1) =
              second :: input.val.drop (position.val + 2) := by
            rw [List.drop_eq_getElem_cons secondBound]
            have eq : second = input.val[position.val + 1] := by
              simpa [secondAtEq] using secondEq
            simp [eq, Nat.add_assoc]
          rw [secondSuffix]
          clear secondSuffix
          by_cases c2 : first = 194#u8
          all_goals simp only [c2, ↓reduceIte]
          · have firstVal : first.val = 194 := by scalar_tac
            cases tail : input.val.drop (position.val + 2) with
            | nil => split_ifs <;> simp_all [excludedPrefix, UScalar.le_equiv,
                UScalar.eq_equiv]
            | cons byte tail => split_ifs <;> simp_all [excludedPrefix,
                threeExcluded, UScalar.le_equiv, UScalar.eq_equiv]
          · step as ⟨remaining2, remaining2Eq⟩
            by_cases short2 : remaining2 < 3#usize
            all_goals simp only [short2, ↓reduceIte]
            · have two : input.val.drop (position.val + 2) = [] := by
                apply List.drop_eq_nil_of_le
                scalar_tac
              simp [two, excludedPrefix, notLow, notDel,
                show first.val ≠ 194 by scalar_tac]
            · step as ⟨thirdAt, thirdAtEq⟩
              step as ⟨third, thirdEq⟩
              have thirdBound : position.val + 2 < input.val.length := by scalar_tac
              have thirdSuffix : input.val.drop (position.val + 2) =
                  third :: input.val.drop (position.val + 3) := by
                rw [List.drop_eq_getElem_cons thirdBound]
                have eq : third = input.val[position.val + 2] := by
                  simpa [thirdAtEq] using thirdEq
                simp [eq, Nat.add_assoc]
              rw [thirdSuffix]
              clear thirdSuffix
              step as ⟨matched, matchedEq⟩
              simp [excludedPrefix, notLow, notDel, matchedEq,
                show first.val ≠ 194 by scalar_tac]

def containsExcluded : List Std.U8 → Bool
  | [] => false
  | first :: rest => excludedPrefix (first :: rest) || containsExcluded rest

theorem contains_drop_cons (bytes : List Std.U8) (position : Nat)
    (within : position < bytes.length) :
    containsExcluded (bytes.drop position) =
      (excludedPrefix (bytes.drop position) || containsExcluded (bytes.drop (position + 1))) := by
  rw [List.drop_eq_getElem_cons within]
  rfl

@[step] theorem scan_exact (input : Slice Std.U8) (position : Std.Usize) :
    auths_model.identifier.contains_forbidden_identifier_loop input position
      ⦃ result => result = containsExcluded (input.val.drop position.val) ⦄ := by
  unfold auths_model.identifier.contains_forbidden_identifier_loop
  apply loop.spec_decr_nat
    (measure := fun current => input.val.length - current.val)
    (inv := fun current =>
      containsExcluded (input.val.drop current.val) =
        containsExcluded (input.val.drop position.val))
  · intro current invariant
    unfold auths_model.identifier.contains_forbidden_identifier_loop.body
    by_cases within : current < Slice.len input
    all_goals simp only [within, ↓reduceIte]
    · have withinNat : current.val < input.val.length := by scalar_tac
      step as ⟨excluded, excludedEq⟩
      by_cases found : excluded = true
      all_goals simp only [found, ↓reduceIte]
      · change true = containsExcluded (input.val.drop position.val)
        rw [← invariant, contains_drop_cons input.val current.val withinNat,
          ← excludedEq, found]
        rfl
      · have absent : excluded = false := by simp_all
        simp only [Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextEq⟩
        refine ⟨?_, ?_⟩
        · rw [← invariant, contains_drop_cons input.val current.val withinNat,
            ← excludedEq, absent, Bool.false_or]
          simp only [nextEq]
        · omega
    · have atEnd : input.val.length ≤ current.val := by scalar_tac
      change false = containsExcluded (input.val.drop position.val)
      simpa only [List.drop_eq_nil_of_le atEnd, containsExcluded] using invariant
  · rfl

@[step] theorem identifier_exact (value : Str) (maximum : Std.Usize) :
    auths_model.identifier.bounded_identifier_valid value maximum
      ⦃ result => result =
        (!value.val.isEmpty && decide (value.val.length ≤ maximum.val) &&
          !containsExcluded value.val) ⦄ := by
  unfold auths_model.identifier.bounded_identifier_valid
  simp only [core.str.Str.is_empty, core.str.Str.len, core.str.Str.as_bytes,
    bind_tc_ok]
  by_cases empty : value.val.isEmpty = true
  all_goals simp only [empty, Bool.false_eq_true, ↓reduceIte]
  · simp
  · by_cases fits : Slice.len value ≤ maximum
    all_goals simp only [fits, ↓reduceIte]
    · simp only [auths_model.identifier.contains_forbidden_identifier]
      step with scan_exact as ⟨excluded, excludedEq⟩
      simp [excludedEq,
        List.drop_zero, show value.val.length ≤ maximum.val by scalar_tac]
    · simp [show ¬ value.val.length ≤ maximum.val by scalar_tac]

/-- The proof-facing byte grammar is the independent scalar-digit grammar. -/
theorem prefix_view (bytes : List Std.U8) :
    excludedPrefix bytes = Auths.Model.Identifier.excludedPrefix (bytes.map (·.val)) := by
  cases bytes with
  | nil => rfl
  | cons first rest =>
    cases rest with
    | nil => rfl
    | cons second tail =>
      cases tail with
      | nil => rfl
      | cons third tail => rfl

theorem scan_view (bytes : List Std.U8) :
    containsExcluded bytes = Auths.Model.Identifier.containsExcluded (bytes.map (·.val)) := by
  induction bytes with
  | nil => rfl
  | cons first rest ih =>
    simp only [containsExcluded, List.map_cons,
      Auths.Model.Identifier.containsExcluded, prefix_view, List.map_cons, ih]

/-- Exact source-to-policy refinement on any represented UTF-8 scalar stream.
The byte representation premise is explicit; this does not assume that an
arbitrary Aeneas `Str` carrier has already been validated as UTF-8. -/
theorem identifier_unicode_exact (value : Str) (maximum : Std.Usize)
    (scalars : List Nat)
    (represented : value.val.map (·.val) = scalars.flatMap Auths.Model.Identifier.utf8)
    (bounded : ∀ scalar ∈ scalars, scalar ≤ 1114111) :
    auths_model.identifier.bounded_identifier_valid value maximum
      ⦃ result => result =
        (!value.val.isEmpty && decide (value.val.length ≤ maximum.val) &&
          !(scalars.any (fun scalar => decide (Auths.Model.Identifier.excluded scalar)))) ⦄ := by
  step with identifier_exact as ⟨result, resultEq⟩
  rw [scan_view, represented, Auths.Model.Identifier.contains_encoded_scalars scalars bounded]
    at resultEq
  exact resultEq

end Auths.Refinement.Identifier
