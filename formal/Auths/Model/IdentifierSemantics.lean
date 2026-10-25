import Std.Tactic
namespace Auths.Model.Identifier
/-- The fixed protocol exclusion set: control scalars and Unicode White_Space. -/
def excluded (scalar : Nat) : Prop :=
  scalar ≤ 32 ∨ (127 ≤ scalar ∧ scalar ≤ 160) ∨ scalar = 5760 ∨
  (8192 ≤ scalar ∧ scalar ≤ 8202) ∨ scalar = 8232 ∨ scalar = 8233 ∨
  scalar = 8239 ∨ scalar = 8287 ∨ scalar = 12288
instance (scalar : Nat) : Decidable (excluded scalar) := inferInstanceAs (Decidable (_ ∨ _))
/-- Mathematical UTF-8 encoding, independently expressed using scalar digits. -/
def utf8 (scalar : Nat) : List Nat :=
  if scalar < 128 then [scalar]
  else if scalar < 2048 then [192 + scalar / 64, 128 + scalar % 64]
  else if scalar < 65536 then
    [224 + scalar / 4096, 128 + scalar / 64 % 64, 128 + scalar % 64]
  else [240 + scalar / 262144, 128 + scalar / 4096 % 64,
    128 + scalar / 64 % 64, 128 + scalar % 64]
def excludedPrefix : List Nat → Bool
  | [] => false
  | first :: rest =>
    decide (first ≤ 32 ∨ first = 127) ||
    match rest with
    | [] => false
    | second :: tail =>
      decide (first = 194 ∧ 128 ≤ second ∧ second ≤ 160) ||
      match tail with
      | [] => false
      | third :: _ => decide (
          (first = 225 ∧ second = 154 ∧ third = 128) ∨
          (first = 226 ∧
            ((second = 128 ∧
              (128 ≤ third ∧ third ≤ 138 ∨ third = 168 ∨
                third = 169 ∨ third = 175)) ∨
             (second = 129 ∧ third = 159))) ∨
          (first = 227 ∧ second = 128 ∧ third = 128))
/-- Every scalar, including all non-ASCII whitespace, agrees with the byte grammar. -/
theorem utf8_excluded_exact (scalar : Nat) (bounded : scalar ≤ 1114111) :
    excludedPrefix (utf8 scalar) = decide (excluded scalar) := by
  unfold utf8
  by_cases one : scalar < 128
  · simp only [if_pos one, excludedPrefix, Bool.or_false]
    apply Bool.eq_iff_iff.mpr
    simp only [decide_eq_true_eq, excluded]
    omega
  · by_cases two : scalar < 2048
    · simp only [if_neg one, if_pos two, excludedPrefix, Bool.or_false]
      apply Bool.eq_iff_iff.mpr
      simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
      omega
    · by_cases three : scalar < 65536
      · simp only [if_neg one, if_neg two, if_pos three, excludedPrefix]
        apply Bool.eq_iff_iff.mpr
        simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
        omega
      · simp only [if_neg one, if_neg two, if_neg three, excludedPrefix]
        apply Bool.eq_iff_iff.mpr
        simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
        omega

/-- Adding following characters cannot change this scalar's classification. -/
theorem utf8_excluded_append (scalar : Nat) (bounded : scalar ≤ 1114111)
    (tail : List Nat) :
    excludedPrefix (utf8 scalar ++ tail) = decide (excluded scalar) := by
  cases tail with
  | nil => simpa using utf8_excluded_exact scalar bounded
  | cons a rest =>
    cases rest with
    | nil =>
      unfold utf8
      by_cases one : scalar < 128
      · simp only [if_pos one, List.cons_append, List.nil_append, excludedPrefix]
        apply Bool.eq_iff_iff.mpr
        simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.false_eq_true, or_false, excluded]
        omega
      · by_cases two : scalar < 2048
        · simp only [if_neg one, if_pos two, List.cons_append, List.nil_append, excludedPrefix]
          apply Bool.eq_iff_iff.mpr
          simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
          omega
        · by_cases three : scalar < 65536
          · simp only [if_neg one, if_neg two, if_pos three,
              List.cons_append, List.nil_append, excludedPrefix]
            apply Bool.eq_iff_iff.mpr
            simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
            omega
          · simp only [if_neg one, if_neg two, if_neg three,
              List.cons_append, List.nil_append, excludedPrefix]
            apply Bool.eq_iff_iff.mpr
            simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
            omega
    | cons b rest =>
      unfold utf8
      by_cases one : scalar < 128
      · simp only [if_pos one, List.cons_append, List.nil_append, excludedPrefix]
        apply Bool.eq_iff_iff.mpr
        simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
        omega
      · by_cases two : scalar < 2048
        · simp only [if_neg one, if_pos two, List.cons_append, List.nil_append, excludedPrefix]
          apply Bool.eq_iff_iff.mpr
          simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
          omega
        · by_cases three : scalar < 65536
          · simp only [if_neg one, if_neg two, if_pos three,
              List.cons_append, List.nil_append, excludedPrefix]
            apply Bool.eq_iff_iff.mpr
            simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
            omega
          · simp only [if_neg one, if_neg two, if_neg three,
              List.cons_append, List.nil_append, excludedPrefix]
            apply Bool.eq_iff_iff.mpr
            simp only [Bool.or_eq_true, decide_eq_true_eq, excluded]
            omega

/-- Continuation bytes never begin an excluded scalar. -/
theorem continuation_prefix (first : Nat) (low : 128 ≤ first) (high : first < 192)
    (tail : List Nat) : excludedPrefix (first :: tail) = false := by
  cases tail with
  | nil => simp [excludedPrefix]; omega
  | cons second rest =>
    cases rest with
    | nil => simp [excludedPrefix]; omega
    | cons third rest => simp [excludedPrefix]; omega

def containsExcluded : List Nat → Bool
  | [] => false
  | first :: tail => excludedPrefix (first :: tail) || containsExcluded tail

/-- Scanning one well-formed scalar consumes at most four bytes and leaves
classification of all later scalars independent. -/
theorem contains_utf8_append (scalar : Nat) (bounded : scalar ≤ 1114111)
    (tail : List Nat) :
    containsExcluded (utf8 scalar ++ tail) =
      (decide (excluded scalar) || containsExcluded tail) := by
  have head := utf8_excluded_append scalar bounded tail
  unfold utf8 at head ⊢
  split <;> rename_i one
  · simp only [if_pos one, List.cons_append, List.nil_append, containsExcluded] at head ⊢
    rw [head]
  · split <;> rename_i two
    · simp only [if_neg one, if_pos two, List.cons_append, List.nil_append, containsExcluded] at head ⊢
      simp (disch := omega) only [continuation_prefix, Bool.false_or]
      rw [head]
    · split <;> rename_i three
      · simp only [if_neg one, if_neg two, if_pos three, List.cons_append, List.nil_append, containsExcluded] at head ⊢
        simp (disch := omega) only [continuation_prefix, Bool.false_or]
        rw [head]
      · simp only [if_neg one, if_neg two, if_neg three, List.cons_append, List.nil_append, containsExcluded] at head ⊢
        simp (disch := omega) only [continuation_prefix, Bool.false_or]
        rw [head]


/-- Scanning any finite UTF-8 scalar stream rejects exactly the prohibited
scalars; continuation bytes cannot create false matches across boundaries. -/
theorem contains_encoded_scalars (scalars : List Nat)
    (bounded : ∀ scalar ∈ scalars, scalar ≤ 1114111) :
    containsExcluded (scalars.flatMap utf8) =
      scalars.any (fun scalar => decide (excluded scalar)) := by
  induction scalars with
  | nil => rfl
  | cons scalar rest ih =>
    rw [List.flatMap_cons, contains_utf8_append scalar (bounded scalar (by simp))]
    rw [ih (fun value member => bounded value (by simp [member]))]
    rfl
end Auths.Model.Identifier
