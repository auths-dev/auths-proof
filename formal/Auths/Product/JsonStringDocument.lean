import Auths.Product.JsonStringScalars
import Auths.Product.JsonDocumentEnd
import Auths.Product.JcsObjectBuffer

/-!
Concrete complete JSON-string document language for JsonProperty::new's key
reparse. Only the four JSON whitespace bytes may surround the quoted string.
Recursion decreases by actual consumed original bytes, without a supplied
cursor, success flag, semantic depth limit or fuel truncation. Errors describe
refusal only, not serde diagnostic text, error priority or failure cursor.
Native serde key-parser and Char/String adequacy remain separate obligations.
-/
namespace Auths.Product.JsonStringDocument
open JsonStringScalars

def contents : (input : Bytes) → Except Unit (Consumed input (List Char))
  | [] => .error ()
  | first :: rest => do
      if first = 34 then pure ⟨[], [first], rest, rfl, by simp⟩
      else
        let decoded ← stringScalar (first :: rest)
        let suffix ← contents decoded.rest
        pure ((decoded.chain suffix).map (fun pair => pair.1 :: pair.2))
termination_by input => input.length
decreasing_by
  all_goals
    have smaller := consumed_strict_progress decoded
    simp only [List.length_cons] at *
    omega

def quoted : (input : Bytes) → Except Unit (Consumed input (List Char))
  | 34 :: rest => do
      let parsed ← contents rest
      pure (parsed.prepend 34)
  | _ => .error ()

def document (input : Bytes) : Except Unit String := do
  let parsed ← quoted (input.drop (JsonDocumentEnd.skip input))
  if JsonDocumentEnd.skip parsed.rest = parsed.rest.length then
    pure (String.ofList parsed.value)
  else .error ()

def property (keyBytes valueBytes : Bytes) : Except Unit JcsObjectBuffer.Property := do
  let name ← document keyBytes
  pure ⟨JcsUtf16Keys.key name, keyBytes, valueBytes⟩

theorem contents_keeps_original_bytes (input : Bytes) (parsed : Consumed input (List Char))
    (read : contents input = .ok parsed) : input = parsed.prefix ++ parsed.rest := parsed.original

theorem contents_strict_progress (input : Bytes) (parsed : Consumed input (List Char))
    (read : contents input = .ok parsed) : parsed.rest.length < input.length := consumed_strict_progress parsed

theorem quoted_keeps_original_bytes (input : Bytes) (parsed : Consumed input (List Char))
    (read : quoted input = .ok parsed) : input = parsed.prefix ++ parsed.rest := parsed.original

theorem quoted_strict_progress (input : Bytes) (parsed : Consumed input (List Char))
    (read : quoted input = .ok parsed) : parsed.rest.length < input.length := consumed_strict_progress parsed

/-- A successful complete key read earns the concrete quoted-prefix result,
original byte decomposition, exact allowed leading/trailing whitespace and
returned String. None is supplied as an independent cursor/EOF premise. -/
theorem document_success_has_original_trace (input : Bytes) (output : String)
    (read : document input = .ok output) :
    ∃ parsed : Consumed (input.drop (JsonDocumentEnd.skip input)) (List Char),
      quoted (input.drop (JsonDocumentEnd.skip input)) = .ok parsed ∧
      input = input.take (JsonDocumentEnd.skip input) ++ parsed.prefix ++ parsed.rest ∧
      (∀ byte ∈ input.take (JsonDocumentEnd.skip input), JsonDocumentEnd.whitespace byte = true) ∧
      (∀ byte ∈ parsed.rest, JsonDocumentEnd.whitespace byte = true) ∧
      output = String.ofList parsed.value := by
  cases parsedAt : quoted (input.drop (JsonDocumentEnd.skip input)) with
  | error error => simp [document, parsedAt] at read
  | ok parsed =>
      by_cases ended : JsonDocumentEnd.skip parsed.rest = parsed.rest.length
      · simp [document, parsedAt, ended] at read
        refine ⟨parsed, parsedAt, ?_, JsonDocumentEnd.skipped_prefix_is_whitespace input,
          (JsonDocumentEnd.skip_complete_exact _).mp ended, read.symm⟩
        calc
          input = input.take (JsonDocumentEnd.skip input) ++ input.drop (JsonDocumentEnd.skip input) :=
            (List.take_append_drop _ _).symm
          _ = input.take (JsonDocumentEnd.skip input) ++ parsed.prefix ++ parsed.rest := by
            rw [parsed.original, List.append_assoc]
      · simp [document, parsedAt, ended] at read

theorem document_refuses_trailing_data (input : Bytes)
    (parsed : Consumed (input.drop (JsonDocumentEnd.skip input)) (List Char))
    (read : quoted (input.drop (JsonDocumentEnd.skip input)) = .ok parsed)
    (trailing : JsonDocumentEnd.skip parsed.rest ≠ parsed.rest.length) : document input = .error () := by
  simp [document, read, trailing]

theorem property_retains_complete_key_and_value (keyBytes valueBytes : Bytes) (output : JcsObjectBuffer.Property)
    (created : property keyBytes valueBytes = .ok output) :
    output.keyBytes = keyBytes ∧ output.valueBytes = valueBytes := by
  cases decoded : document keyBytes with
  | error error => simp [property, decoded] at created
  | ok name =>
      simp [property, decoded] at created
      subst output
      exact ⟨rfl, rfl⟩

theorem property_earns_decoded_sorting_key (keyBytes valueBytes : Bytes) (output : JcsObjectBuffer.Property)
    (created : property keyBytes valueBytes = .ok output) :
    ∃ name, document keyBytes = .ok name ∧ output.sortingKey = JcsUtf16Keys.key name ∧
      output.keyBytes = keyBytes ∧ output.valueBytes = valueBytes := by
  cases decoded : document keyBytes with
  | error error => simp [property, decoded] at created
  | ok name =>
      simp [property, decoded] at created
      subst output
      exact ⟨name, decoded, rfl, rfl, rfl⟩

theorem invalid_key_refuses_property (keyBytes valueBytes : Bytes) (refused : document keyBytes = .error ()) :
    property keyBytes valueBytes = .error () := by simp [property, refused]

end Auths.Product.JsonStringDocument
