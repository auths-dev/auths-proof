import Mathlib.Tactic
namespace Auths.PrincipalScheme.Model

def lower (byte : Nat) : Prop := 97 ≤ byte ∧ byte ≤ 122
def allowed (byte : Nat) : Prop := lower byte ∨ (48 ≤ byte ∧ byte ≤ 57) ∨ byte = 43 ∨ byte = 45 ∨ byte = 46
local instance (byte : Nat) : Decidable (lower byte) := inferInstanceAs (Decidable (_ ∧ _))
local instance (byte : Nat) : Decidable (allowed byte) := inferInstanceAs (Decidable (_ ∨ _))

def tailValid : List Nat → Bool
  | [] => false
  | byte :: rest => if byte = 58 then !rest.isEmpty else decide (allowed byte) && tailValid rest

/-- Independent grammar: a possibly empty scheme tail, a colon and a
    nonempty remainder. Every scheme-tail byte is permitted ASCII. -/
def tailGrammar (values : List Nat) : Prop :=
  ∃ scheme remainder, values = scheme ++ 58 :: remainder ∧ remainder ≠ [] ∧ ∀ byte ∈ scheme, allowed byte

theorem allowed_not_colon (byte : Nat) (permitted : allowed byte) : byte ≠ 58 := by
  simp only [allowed, lower] at permitted
  omega

theorem tail_valid_iff (values : List Nat) : tailValid values = true ↔ tailGrammar values := by
  induction values with
  | nil => simp [tailValid, tailGrammar]
  | cons byte rest ih =>
    by_cases colon : byte = 58
    · subst byte
      have condition : (!rest.isEmpty) = true ↔ rest ≠ [] := by cases rest <;> simp
      simp only [tailValid, ↓reduceIte, condition]
      constructor
      · intro nonempty; exact ⟨[], rest, rfl, nonempty, by simp⟩
      · rintro ⟨scheme, remainder, exactBytes, nonempty, permitted⟩
        cases scheme with
        | nil => simpa using (List.cons.inj exactBytes).2.symm ▸ nonempty
        | cons first tail =>
          have same : first = 58 := (List.cons.inj exactBytes).1.symm
          exact False.elim ((allowed_not_colon first (permitted first (by simp))) same)
    · simp only [tailValid, colon, ↓reduceIte, Bool.and_eq_true, decide_eq_true_eq, ih]
      constructor
      · rintro ⟨firstAllowed, scheme, remainder, exactBytes, nonempty, permitted⟩
        exact ⟨byte :: scheme, remainder, by simp [exactBytes], nonempty, by simpa using And.intro firstAllowed permitted⟩
      · rintro ⟨scheme, remainder, exactBytes, nonempty, permitted⟩
        cases scheme with
        | nil => exact False.elim (colon (List.cons.inj exactBytes).1)
        | cons first tail =>
          obtain ⟨same, suffix⟩ := List.cons.inj exactBytes
          subst first
          exact ⟨permitted byte (by simp), tail, remainder, suffix, nonempty,
            fun item member => permitted item (by simp [member])⟩

def evaluate : List Nat → Bool
  | [] => false
  | first :: rest => decide (lower first) && tailValid rest

/-- A lowercase ASCII initial letter and the independent scheme-tail grammar. -/
def grammar (values : List Nat) : Prop :=
  ∃ first rest, values = first :: rest ∧ lower first ∧ tailGrammar rest

theorem evaluate_iff_grammar (values : List Nat) : evaluate values = true ↔ grammar values := by
  cases values with
  | nil => simp [evaluate, grammar]
  | cons first rest => simp [evaluate, grammar, tail_valid_iff]

theorem grammar_minimum (values : List Nat) (valid : grammar values) : 3 ≤ values.length := by
  rcases valid with ⟨first, rest, rfl, _, scheme, remainder, rfl, nonempty, _⟩
  have positive : 0 < remainder.length := List.length_pos_iff.mpr nonempty
  simp only [List.length_cons, List.length_append]
  omega

theorem ordinary_scheme : evaluate [114, 97, 119, 58, 120] = true := rfl
theorem uppercase_initial_refused : evaluate [65, 58, 120] = false := rfl
theorem empty_remainder_refused : evaluate [97, 58] = false := rfl
theorem separator_in_remainder : evaluate [97, 58, 58] = true := rfl

end Auths.PrincipalScheme.Model
