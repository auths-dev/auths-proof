import Auths.Product.SerdeUnsignedDigits

/-!
Closed nonnegative i32 exponent-digit loop. Unlike mantissa accumulation,
serde consumes the triggering digit BEFORE testing overflow. Committed digits
and that consumed-but-uncommitted trigger are retained separately. Native
read/loop/i32 primitive and full parser/visitor adequacy remain separate.
-/
namespace Auths.Product.SerdeExponentDigits
abbrev Bytes := List Nat

def maximum : Nat := 2147483647
def overflow (value digit : Nat) : Bool :=
  decide (value ≥ maximum / 10 ∧ (value > maximum / 10 ∨ digit > maximum % 10))

theorem overflow_earns_exact_i32_arithmetic (value digit : Nat) (decimal : digit ≤ 9) :
    overflow value digit = true ↔ maximum < value * 10 + digit := by
  simp only [overflow, decide_eq_true_eq]
  change (214748364 ≤ value ∧ (214748364 < value ∨ 7 < digit)) ↔ 2147483647 < value * 10 + digit
  omega

theorem no_overflow_earns_i32_bound (value digit : Nat) (decimal : digit ≤ 9) :
    overflow value digit = false ↔ value * 10 + digit ≤ maximum := by
  have opposite : overflow value digit = false ↔ ¬ overflow value digit = true := by
    cases selected : overflow value digit <;> simp
  rw [opposite, overflow_earns_exact_i32_arithmetic value digit decimal]
  omega

def Boundary : Option Nat → Nat → Bytes → Prop
  | none, _, [] => True
  | none, _, byte :: _ => JsonNumberLexeme.digit byte = false
  | some trigger, value, _ => JsonNumberLexeme.digit trigger = true ∧ overflow value (trigger - 48) = true

structure Scanned (initial : Nat) (input : Bytes) where
  committed : Bytes
  trigger : Option Nat
  rest : Bytes
  value : Nat
  original : input = (committed ++ trigger.toList) ++ rest
  digits : ∀ byte ∈ committed, JsonNumberLexeme.digit byte = true
  meaning : value = SerdeUnsignedDigits.accumulate initial committed
  bounded : value ≤ maximum
  boundary : Boundary trigger value rest

def scan : (initial : Nat) → (bounded : initial ≤ maximum) → (input : Bytes) → Scanned initial input
  | initial, bounded, [] => ⟨[], none, [], initial, rfl, by simp, rfl, bounded, trivial⟩
  | initial, bounded, byte :: rest =>
      if decimal : JsonNumberLexeme.digit byte = true then
        if blocked : overflow initial (byte - 48) = true then
          ⟨[], some byte, rest, initial, rfl, by simp, rfl, bounded, ⟨decimal, blocked⟩⟩
        else
          have digitBound : byte - 48 ≤ 9 := by
            have ascii : 48 ≤ byte ∧ byte ≤ 57 := by simpa only [JsonNumberLexeme.digit, decide_eq_true_eq] using decimal
            omega
          have unblocked : overflow initial (byte - 48) = false := by
            cases selected : overflow initial (byte - 48) <;> simp_all
          have nextBound := (no_overflow_earns_i32_bound initial (byte - 48) digitBound).mp unblocked
          let suffix := scan (initial * 10 + (byte - 48)) nextBound rest
          ⟨byte :: suffix.committed, suffix.trigger, suffix.rest, suffix.value,
            by rw [suffix.original]; rfl,
            by intro next present; rcases List.mem_cons.mp present with rfl | later
               · exact decimal
               · exact suffix.digits next later,
            by simpa only [SerdeUnsignedDigits.accumulate, List.foldl_cons] using suffix.meaning,
            suffix.bounded, suffix.boundary⟩
      else
        have stopped : JsonNumberLexeme.digit byte = false := by cases selected : JsonNumberLexeme.digit byte <;> simp_all
        ⟨[], none, byte :: rest, initial, rfl, by simp, rfl, bounded, stopped⟩
termination_by initial bounded input => input.length
decreasing_by all_goals simp_wf

def consumed {initial : Nat} {input : Bytes} (read : Scanned initial input) : Bytes := read.committed ++ read.trigger.toList

def view (initial : Nat) (bounded : initial ≤ maximum) (input : Bytes) : Nat × Bytes × Bytes × Option Nat :=
  let read := scan initial bounded input
  (read.value, consumed read, read.rest, read.trigger)

theorem exponent_scan_keeps_original_prefix {initial : Nat} {input : Bytes} (read : Scanned initial input) :
    input = consumed read ++ read.rest ∧ read.value = SerdeUnsignedDigits.accumulate initial read.committed ∧ read.value ≤ maximum :=
  ⟨read.original, read.meaning, read.bounded⟩

theorem exponent_overflow_keeps_consumed_trigger {initial : Nat} {input : Bytes} (read : Scanned initial input)
    (trigger : Nat) (blocked : read.trigger = some trigger) :
    input = (read.committed ++ [trigger]) ++ read.rest ∧ JsonNumberLexeme.digit trigger = true ∧
      maximum < read.value * 10 + (trigger - 48) := by
  have edge : JsonNumberLexeme.digit trigger = true ∧ overflow read.value (trigger - 48) = true := by
    simpa only [blocked, Boundary] using read.boundary
  have digitBound : trigger - 48 ≤ 9 := by
    have ascii : 48 ≤ trigger ∧ trigger ≤ 57 := by simpa only [JsonNumberLexeme.digit, decide_eq_true_eq] using edge.1
    omega
  exact ⟨by simpa [blocked] using read.original, edge.1,
    (overflow_earns_exact_i32_arithmetic _ _ digitBound).mp edge.2⟩

theorem every_committed_exponent_prefix_stays_in_i32 {initial : Nat} {input : Bytes} (read : Scanned initial input)
    (prefix suffix : Bytes) (original : read.committed = prefix ++ suffix) :
    SerdeUnsignedDigits.accumulate initial prefix ≤ maximum := by
  have remaining := SerdeUnsignedDigits.accumulate_keeps_initial_lower_bound (SerdeUnsignedDigits.accumulate initial prefix) suffix
  have whole : read.value = SerdeUnsignedDigits.accumulate (SerdeUnsignedDigits.accumulate initial prefix) suffix := by
    rw [read.meaning, original, SerdeUnsignedDigits.accumulate_keeps_original_append]
  have bounded := read.bounded
  omega

end Auths.Product.SerdeExponentDigits
