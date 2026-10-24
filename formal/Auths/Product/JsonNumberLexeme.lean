import Auths.Product.JsonStringScalars
import Auths.Product.JsonDocumentEnd

/-!
Closed raw JSON number-token reader. Original minus, decimal point, exponent
case/sign and every digit byte are retained, without integer or floating
conversion. Lexical success is separate from native finite/range admission,
number representation, canonical formatting and authorization. This accepts
raw -0, fractions and exponent forms; it is not the admitted-integer codec.
No supplied cursor, semantic fuel or expected token controls consumption.
-/
namespace Auths.Product.JsonNumberLexeme
open JsonStringScalars

inductive State where
  | start | minus | zero | integer | dot | fraction | exponent | exponentSign | exponentDigits
  deriving DecidableEq

def digit (byte : Nat) : Bool := decide (48 ≤ byte ∧ byte ≤ 57)

def accepts : State → Bool
  | .zero | .integer | .fraction | .exponentDigits => true
  | _ => false

def exponentMark (byte : Nat) : Bool := decide (byte = 69 ∨ byte = 101)

def transition : State → Nat → Option State
  | .start, byte =>
      if byte = 45 then some .minus else if byte = 48 then some .zero
      else if 49 ≤ byte ∧ byte ≤ 57 then some .integer else none
  | .minus, byte => if byte = 48 then some .zero else if 49 ≤ byte ∧ byte ≤ 57 then some .integer else none
  | .zero, byte => if byte = 46 then some .dot else if exponentMark byte then some .exponent else none
  | .integer, byte => if digit byte then some .integer else
      if byte = 46 then some .dot else if exponentMark byte then some .exponent else none
  | .dot, byte => if digit byte then some .fraction else none
  | .fraction, byte => if digit byte then some .fraction else if exponentMark byte then some .exponent else none
  | .exponent, byte => if byte = 43 ∨ byte = 45 then some .exponentSign else if digit byte then some .exponentDigits else none
  | .exponentSign, byte => if digit byte then some .exponentDigits else none
  | .exponentDigits, byte => if digit byte then some .exponentDigits else none

def run : State → Bytes → Option State
  | state, [] => some state
  | state, byte :: rest => (transition state byte).bind (fun next => run next rest)

def Language (bytes : Bytes) : Prop := ∃ final, run .start bytes = some final ∧ accepts final = true

def Stopped (state : State) : Bytes → Prop
  | [] => True
  | byte :: _ => transition state byte = none

structure Scanned (initial : State) (input : Bytes) where
  prefix : Bytes
  rest : Bytes
  final : State
  original : input = prefix ++ rest
  path : run initial prefix = some final
  accepted : accepts final = true
  stopped : Stopped final rest

def scan : (state : State) → (input : Bytes) → Except Unit (Scanned state input)
  | state, [] =>
      if accepted : accepts state = true then .ok ⟨[], [], state, rfl, rfl, accepted, trivial⟩ else .error ()
  | state, byte :: rest =>
      match nextAt : transition state byte with
      | some next => do
          let suffix ← scan next rest
          pure ⟨byte :: suffix.prefix, suffix.rest, suffix.final,
            by rw [suffix.original]; rfl,
            by simp only [run, nextAt, Option.bind_some]; exact suffix.path,
            suffix.accepted, suffix.stopped⟩
      | none =>
          if accepted : accepts state = true then
            .ok ⟨[], byte :: rest, state, rfl, rfl, accepted, nextAt⟩
          else .error ()
termination_by state input => input.length
decreasing_by all_goals simp_wf

structure Read (input : Bytes) extends Consumed input Bytes where
  sameValue : value = prefix
  final : State
  path : run .start prefix = some final
  accepted : accepts final = true
  stopped : Stopped final rest

def number : (input : Bytes) → Except Unit (Read input)
  | [] => .error ()
  | byte :: rest =>
      match nextAt : transition .start byte with
      | none => .error ()
      | some next => do
          let suffix ← scan next rest
          pure {
            value := byte :: suffix.prefix, prefix := byte :: suffix.prefix,
            rest := suffix.rest, final := suffix.final,
            original := by rw [suffix.original]; rfl,
            nonempty := by simp,
            sameValue := rfl,
            path := by simp only [run, nextAt, Option.bind_some]; exact suffix.path,
            accepted := suffix.accepted, stopped := suffix.stopped
          }

def prefixResult (input : Bytes) : Except Unit (Bytes × Bytes) := do
  let read ← number input
  pure (read.value, read.rest)

def document (input : Bytes) : Except Unit Bytes := do
  let read ← number (input.drop (JsonDocumentEnd.skip input))
  if JsonDocumentEnd.skip read.rest = read.rest.length then pure read.value else .error ()

theorem read_keeps_original_number_bytes {input : Bytes} (read : Read input) :
    input = read.value ++ read.rest := by rw [read.sameValue]; exact read.original

theorem read_earns_lexical_language {input : Bytes} (read : Read input) : Language read.value := by
  rw [read.sameValue]
  exact ⟨read.final, read.path, read.accepted⟩

theorem read_earns_strict_progress {input : Bytes} (read : Read input) : read.rest.length < input.length :=
  consumed_strict_progress read.toConsumed

theorem read_stops_at_first_other {input : Bytes} (read : Read input) :
    read.rest = [] ∨ ∃ byte rest, read.rest = byte :: rest ∧ transition read.final byte = none := by
  cases original : read.rest with
  | nil => exact Or.inl original
  | cons byte rest => exact Or.inr ⟨byte, rest, original, by simpa only [original, Stopped] using read.stopped⟩

theorem prefix_success_earns_original_trace (input token rest : Bytes)
    (accepted : prefixResult input = .ok (token, rest)) :
    ∃ read : Read input, number input = .ok read ∧ read.value = token ∧ read.rest = rest ∧
      input = token ++ rest ∧ token ≠ [] ∧ Language token ∧ rest.length < input.length := by
  cases readAt : number input with
  | error error => simp [prefixResult, readAt] at accepted
  | ok read =>
      have same : (read.value, read.rest) = (token, rest) := by simpa [prefixResult, readAt] using accepted
      have tokenAt : read.value = token := congrArg Prod.fst same
      have restAt : read.rest = rest := congrArg Prod.snd same
      refine ⟨read, readAt, tokenAt, restAt, ?_, ?_, ?_, ?_⟩
      · simpa only [tokenAt, restAt] using read_keeps_original_number_bytes read
      · intro empty
        apply read.nonempty
        rw [← read.sameValue, tokenAt, empty]
      · simpa only [tokenAt] using read_earns_lexical_language read
      · simpa only [restAt] using read_earns_strict_progress read

theorem document_success_earns_original_trace (input token : Bytes) (accepted : document input = .ok token) :
    ∃ read : Read (input.drop (JsonDocumentEnd.skip input)),
      number (input.drop (JsonDocumentEnd.skip input)) = .ok read ∧ read.value = token ∧
      input = input.take (JsonDocumentEnd.skip input) ++ token ++ read.rest ∧ Language token ∧
      (∀ byte ∈ input.take (JsonDocumentEnd.skip input), JsonDocumentEnd.whitespace byte = true) ∧
      (∀ byte ∈ read.rest, JsonDocumentEnd.whitespace byte = true) := by
  cases readAt : number (input.drop (JsonDocumentEnd.skip input)) with
  | error error => simp [document, readAt] at accepted
  | ok read =>
      by_cases ended : JsonDocumentEnd.skip read.rest = read.rest.length
      · have same : read.value = token := by simpa [document, readAt, ended] using accepted
        refine ⟨read, readAt, same, ?_, ?_, JsonDocumentEnd.skipped_prefix_is_whitespace input,
          (JsonDocumentEnd.skip_complete_exact _).mp ended⟩
        · calc
            input = input.take (JsonDocumentEnd.skip input) ++ input.drop (JsonDocumentEnd.skip input) :=
              (List.take_append_drop _ _).symm
            _ = input.take (JsonDocumentEnd.skip input) ++ token ++ read.rest := by
              rw [read_keeps_original_number_bytes read, same, List.append_assoc]
        · simpa only [same] using read_earns_lexical_language read
      · simp [document, readAt, ended] at accepted

theorem document_refuses_trailing_data (input : Bytes)
    (read : Read (input.drop (JsonDocumentEnd.skip input)))
    (parsed : number (input.drop (JsonDocumentEnd.skip input)) = .ok read)
    (trailing : JsonDocumentEnd.skip read.rest ≠ read.rest.length) : document input = .error () := by
  simp [document, parsed, trailing]

end Auths.Product.JsonNumberLexeme
