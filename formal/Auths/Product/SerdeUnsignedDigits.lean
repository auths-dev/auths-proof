import Auths.Product.JsonNumberLexeme
import Auths.Product.JcsIntegerDecimal

/-!
Closed reference for the digit-accumulation loop after serde's initial
nonzero digit. Checked updates keep the u64 domain and exact original prefix
meaning. Overflow retains the unconsumed digit and original partial word for
parse_long_integer; ordinary stop retains the first nondigit for parse_number.
This is not the leading-zero rule, floating conversion, native read/cursor/
primitive adequacy, diagnostics or complete parser/visitor correspondence.
-/
namespace Auths.Product.SerdeUnsignedDigits
abbrev Bytes := List Nat

def maximum : Nat := 18446744073709551615

def overflow (value digit : Nat) : Bool :=
  decide (value ≥ maximum / 10 ∧ (value > maximum / 10 ∨ digit > maximum % 10))

theorem overflow_earns_exact_arithmetic (value digit : Nat) (decimal : digit ≤ 9) :
    overflow value digit = true ↔ maximum < value * 10 + digit := by
  simp only [overflow, decide_eq_true_eq]
  change (1844674407370955161 ≤ value ∧ (1844674407370955161 < value ∨ 5 < digit)) ↔
    18446744073709551615 < value * 10 + digit
  omega

theorem no_overflow_earns_word_bound (value digit : Nat) (decimal : digit ≤ 9) :
    overflow value digit = false ↔ value * 10 + digit ≤ maximum := by
  have opposite : overflow value digit = false ↔ ¬ overflow value digit = true := by
    cases original : overflow value digit <;> simp
  rw [opposite, overflow_earns_exact_arithmetic value digit decimal]
  omega

def accumulate (initial : Nat) (input : Bytes) : Nat :=
  input.foldl (fun previous byte => previous * 10 + (byte - 48)) initial

inductive Mode where
  | stopped | overflow
  deriving DecidableEq

def Boundary : Mode → Nat → Bytes → Prop
  | .stopped, _, [] => True
  | .stopped, _, byte :: _ => JsonNumberLexeme.digit byte = false
  | .overflow, _, [] => False
  | .overflow, value, byte :: _ => JsonNumberLexeme.digit byte = true ∧ overflow value (byte - 48) = true

structure Scanned (initial : Nat) (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  value : Nat
  mode : Mode
  original : input = prefix ++ rest
  digits : ∀ byte ∈ prefix, JsonNumberLexeme.digit byte = true
  meaning : value = accumulate initial prefix
  bounded : value ≤ maximum
  boundary : Boundary mode value rest

def scan : (initial : Nat) → (bounded : initial ≤ maximum) → (input : Bytes) → Scanned initial input
  | initial, bounded, [] => ⟨[], [], initial, .stopped, rfl, by simp, rfl, bounded, trivial⟩
  | initial, bounded, byte :: rest =>
      if decimal : JsonNumberLexeme.digit byte = true then
        if blocked : overflow initial (byte - 48) = true then
          ⟨[], byte :: rest, initial, .overflow, rfl, by simp, rfl, bounded, ⟨decimal, blocked⟩⟩
        else
          have digitBound : byte - 48 ≤ 9 := by
            have ascii : 48 ≤ byte ∧ byte ≤ 57 := by simpa only [JsonNumberLexeme.digit, decide_eq_true_eq] using decimal
            omega
          have unblocked : overflow initial (byte - 48) = false := by
            cases original : overflow initial (byte - 48) <;> simp_all
          have nextBound := (no_overflow_earns_word_bound initial (byte - 48) digitBound).mp unblocked
          let suffix := scan (initial * 10 + (byte - 48)) nextBound rest
          ⟨byte :: suffix.prefix, suffix.rest, suffix.value, suffix.mode,
            by rw [suffix.original]; rfl,
            by intro next present; rcases List.mem_cons.mp present with rfl | later
               · exact decimal
               · exact suffix.digits next later,
            by simpa only [accumulate, List.foldl_cons] using suffix.meaning,
            suffix.bounded, suffix.boundary⟩
      else
        have stopped : JsonNumberLexeme.digit byte = false := by
          cases original : JsonNumberLexeme.digit byte <;> simp_all
        ⟨[], byte :: rest, initial, .stopped, rfl, by simp, rfl, bounded, stopped⟩
termination_by initial bounded input => input.length
decreasing_by all_goals simp_wf

def view (initial : Nat) (bounded : initial ≤ maximum) (input : Bytes) : Nat × Bytes × Bytes × Mode :=
  let read := scan initial bounded input
  (read.value, read.prefix, read.rest, read.mode)

theorem accumulate_keeps_initial_lower_bound (initial : Nat) (input : Bytes) : initial ≤ accumulate initial input := by
  induction input generalizing initial with
  | nil => exact Nat.le_refl _
  | cons byte rest ih =>
      have later := ih (initial * 10 + (byte - 48))
      change initial ≤ accumulate (initial * 10 + (byte - 48)) rest
      omega

theorem accumulate_keeps_original_append (initial : Nat) (prefix suffix : Bytes) :
    accumulate initial (prefix ++ suffix) = accumulate (accumulate initial prefix) suffix := by
  simp only [accumulate, List.foldl_append]

theorem scanned_keeps_original_prefix_and_rest {initial : Nat} {input : Bytes} (read : Scanned initial input) :
    input = read.prefix ++ read.rest ∧ read.value = accumulate initial read.prefix ∧ read.value ≤ maximum :=
  ⟨read.original, read.meaning, read.bounded⟩

theorem scanned_rest_never_grows {initial : Nat} {input : Bytes} (read : Scanned initial input) : read.rest.length ≤ input.length := by
  have original := congrArg List.length read.original
  simp only [List.length_append] at original
  omega

theorem loop_after_original_first_byte_earns_progress {initial : Nat} {input : Bytes}
    (first : Nat) (read : Scanned initial input) :
    first :: input = (first :: read.prefix) ++ read.rest ∧ read.rest.length < (first :: input).length := by
  have remaining := scanned_rest_never_grows read
  refine ⟨by rw [read.original]; rfl, ?_⟩
  simp only [List.length_cons]
  omega

theorem every_completed_prefix_stays_in_word {initial : Nat} {input : Bytes} (read : Scanned initial input)
    (prefix suffix : Bytes) (original : read.prefix = prefix ++ suffix) : accumulate initial prefix ≤ maximum := by
  have later := accumulate_keeps_initial_lower_bound (accumulate initial prefix) suffix
  have valueAt : read.value = accumulate (accumulate initial prefix) suffix := by
    rw [read.meaning, original, accumulate_keeps_original_append]
  have bounded := read.bounded
  omega

theorem overflow_keeps_original_unconsumed_digit {initial : Nat} {input : Bytes} (read : Scanned initial input)
    (blocked : read.mode = .overflow) :
    ∃ byte rest, read.rest = byte :: rest ∧ JsonNumberLexeme.digit byte = true ∧
      maximum < read.value * 10 + (byte - 48) ∧ input = read.prefix ++ byte :: rest := by
  have edge := read.boundary
  cases original : read.rest with
  | nil => simp only [blocked, original, Boundary] at edge
  | cons byte rest =>
      have stopped : JsonNumberLexeme.digit byte = true ∧ overflow read.value (byte - 48) = true := by
        simpa only [blocked, original, Boundary] using edge
      have digitBound : byte - 48 ≤ 9 := by
        have ascii : 48 ≤ byte ∧ byte ≤ 57 := by simpa only [JsonNumberLexeme.digit, decide_eq_true_eq] using stopped.1
        omega
      exact ⟨byte, rest, original, stopped.1, (overflow_earns_exact_arithmetic _ _ digitBound).mp stopped.2,
        by simpa only [original] using read.original⟩

theorem ordinary_stop_keeps_original_nondigit {initial : Nat} {input : Bytes} (read : Scanned initial input)
    (stopped : read.mode = .stopped) :
    read.rest = [] ∨ ∃ byte rest, read.rest = byte :: rest ∧ JsonNumberLexeme.digit byte = false := by
  cases original : read.rest with
  | nil => exact Or.inl original
  | cons byte rest =>
      exact Or.inr ⟨byte, rest, original, by simpa only [stopped, original, Boundary] using read.boundary⟩

end Auths.Product.SerdeUnsignedDigits
