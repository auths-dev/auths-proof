import Auths.Product.JsonNumberLexeme
import Auths.Product.JsonStringDocument
import Auths.Product.StrictJsonMemberCorrectness

/-!
Complete original JSON syntax reader before native numeric conversion/typed
serde. Number lexemes and quoted String spellings are retained. Objects are
original ordered member lists, including duplicates and ignored fields; only
the strict-member check uses a scalar-erasing shape. Numeric finite/range
conversion, native recursion/resource limits, error diagnostics/cursors and
actual serde/visitor adequacy remain separate requirements. No semantic fuel
or selected original JSON value is supplied to this reader.
-/
namespace Auths.Product.JsonRawReader
open JsonStringScalars

structure StringToken where
  original : Bytes
  decoded : String
  deriving DecidableEq

structure NumberToken where
  original : Bytes
  wellFormed : JsonNumberLexeme.Language original
  deriving DecidableEq

inductive Value where
  | null | boolean (value : Bool) | number (token : NumberToken) | text (token : StringToken)
  | array (values : List Value)
  | object (members : List (StringToken × Value))
  deriving DecidableEq

def withWhitespace {T : Type} (input : Bytes)
    (read : Consumed (input.drop (JsonDocumentEnd.skip input)) T) : Consumed input T :=
  ⟨read.value, input.take (JsonDocumentEnd.skip input) ++ read.prefix, read.rest, by
    rw [List.append_assoc, ← read.original]
    exact (List.take_append_drop _ _).symm,
    by intro empty; exact read.nonempty (List.append_eq_nil.mp empty).2⟩

def literal (expected input : Bytes) : Except Unit (Consumed input Unit) :=
  if nonempty : expected ≠ [] then
    if same : input.take expected.length = expected then
      .ok ⟨(), expected, input.drop expected.length, by
        calc
          input = input.take expected.length ++ input.drop expected.length := (List.take_append_drop _ _).symm
          _ = expected ++ input.drop expected.length := by rw [same], nonempty⟩
    else .error ()
  else .error ()

def punctuation (expected : Nat) (input : Bytes) : Except Unit (Consumed input Unit) := do
  let read ← literal [expected] (input.drop (JsonDocumentEnd.skip input))
  pure (withWhitespace input read)

def string (input : Bytes) : Except Unit (Consumed input StringToken) := do
  let read ← JsonStringDocument.quoted (input.drop (JsonDocumentEnd.skip input))
  pure (withWhitespace input (read.map (fun chars => ⟨read.prefix, String.ofList chars⟩)))

mutual
  def value (input : Bytes) : Except Unit (Consumed input Value) := do
    have trimmed : (input.drop (JsonDocumentEnd.skip input)).length ≤ input.length := by simp
    let read ← bareValue (input.drop (JsonDocumentEnd.skip input))
    pure (withWhitespace input read)
  termination_by (input.length, 1)
  decreasing_by all_goals simp_wf <;> omega

  def bareValue : (input : Bytes) → Except Unit (Consumed input Value)
    | [] => .error ()
    | input@(byte :: rest) =>
        if byte = 110 then do
          let read ← literal [110, 117, 108, 108] input
          pure (read.map (fun _ => .null))
        else if byte = 116 then do
          let read ← literal [116, 114, 117, 101] input
          pure (read.map (fun _ => .boolean true))
        else if byte = 102 then do
          let read ← literal [102, 97, 108, 115, 101] input
          pure (read.map (fun _ => .boolean false))
        else if byte = 34 then do
          let read ← string input
          pure (read.map Value.text)
        else if byte = 91 then do
          let read ← arrayStart rest
          pure ((read.prepend byte).map Value.array)
        else if byte = 123 then do
          let read ← objectStart rest
          pure ((read.prepend byte).map Value.object)
        else do
          let read ← JsonNumberLexeme.number input
          pure (read.toConsumed.map (fun _ => .number ⟨read.value, JsonNumberLexeme.read_earns_lexical_language read⟩))
  termination_by input => (input.length, 0)
  decreasing_by all_goals simp_wf <;> omega

  def arrayStart (input : Bytes) : Except Unit (Consumed input (List Value)) :=
    if (input.drop (JsonDocumentEnd.skip input)).head? = some 93 then do
      let close ← punctuation 93 input
      pure (close.map (fun _ => []))
    else do
      let first ← value input
      have progressed := consumed_strict_progress first
      let later ← arrayTail first.rest
      pure ((first.chain later).map (fun pair => pair.1 :: pair.2))
  termination_by (input.length, 3)
  decreasing_by all_goals simp_wf <;> omega

  def arrayTail (input : Bytes) : Except Unit (Consumed input (List Value)) :=
    if (input.drop (JsonDocumentEnd.skip input)).head? = some 93 then do
      let close ← punctuation 93 input
      pure (close.map (fun _ => []))
    else if (input.drop (JsonDocumentEnd.skip input)).head? = some 44 then do
      let comma ← punctuation 44 input
      have commaProgress := consumed_strict_progress comma
      let first ← value comma.rest
      have childProgress := consumed_strict_progress first
      let later ← arrayTail first.rest
      pure ((comma.chain (first.chain later)).map (fun pair => pair.2.1 :: pair.2.2))
    else .error ()
  termination_by (input.length, 2)
  decreasing_by all_goals simp_wf <;> omega

  def objectStart (input : Bytes) : Except Unit (Consumed input (List (StringToken × Value))) :=
    if (input.drop (JsonDocumentEnd.skip input)).head? = some 125 then do
      let close ← punctuation 125 input
      pure (close.map (fun _ => []))
    else do
      let first ← member input
      have progressed := consumed_strict_progress first
      let later ← objectTail first.rest
      pure ((first.chain later).map (fun pair => pair.1 :: pair.2))
  termination_by (input.length, 3)
  decreasing_by all_goals simp_wf <;> omega

  def objectTail (input : Bytes) : Except Unit (Consumed input (List (StringToken × Value))) :=
    if (input.drop (JsonDocumentEnd.skip input)).head? = some 125 then do
      let close ← punctuation 125 input
      pure (close.map (fun _ => []))
    else if (input.drop (JsonDocumentEnd.skip input)).head? = some 44 then do
      let comma ← punctuation 44 input
      have commaProgress := consumed_strict_progress comma
      let first ← member comma.rest
      have childProgress := consumed_strict_progress first
      let later ← objectTail first.rest
      pure ((comma.chain (first.chain later)).map (fun pair => pair.2.1 :: pair.2.2))
    else .error ()
  termination_by (input.length, 2)
  decreasing_by all_goals simp_wf <;> omega

  def member (input : Bytes) : Except Unit (Consumed input (StringToken × Value)) := do
    let key ← string input
    have keyProgress := consumed_strict_progress key
    let colon ← punctuation 58 key.rest
    have colonProgress := consumed_strict_progress colon
    let child ← value colon.rest
    pure ((key.chain (colon.chain child)).map (fun pair => (pair.1, pair.2.2)))
  termination_by (input.length, 2)
  decreasing_by all_goals simp_wf <;> omega
end

def prefixResult (input : Bytes) : Except Unit (Value × Bytes) := do
  let read ← value input
  pure (read.value, read.rest)

def document (input : Bytes) : Except Unit Value := do
  let read ← value input
  if JsonDocumentEnd.skip read.rest = read.rest.length then pure read.value else .error ()

mutual
  def memberShape : Value → StrictJsonMembers.Value
    | .null | .boolean _ | .number _ | .text _ => .scalar
    | .array values => .array (valueShapes values)
    | .object members => .object (memberShapes members)
  termination_by input => sizeOf input
  decreasing_by all_goals simp_wf <;> omega

  def valueShapes : List Value → List StrictJsonMembers.Value
    | [] => []
    | first :: rest => memberShape first :: valueShapes rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def memberShapes : List (StringToken × Value) → List (String × StrictJsonMembers.Value)
    | [] => []
    | (key, child) :: rest => (key.decoded, memberShape child) :: memberShapes rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

def uniqueSyntaxDocument (input : Bytes) : Except Unit Value := do
  let original ← document input
  StrictJsonMembers.check (memberShape original)
  pure original

theorem member_shapes_keep_decoded_names (members : List (StringToken × Value)) :
    (memberShapes members).map Prod.fst = members.map (fun member => member.1.decoded) := by
  induction members with
  | nil => rfl
  | cons first rest ih => cases first; simp [memberShapes, ih]

theorem value_shapes_keep_count (values : List Value) : (valueShapes values).length = values.length := by
  induction values <;> simp_all [valueShapes]

theorem member_shapes_keep_count (members : List (StringToken × Value)) : (memberShapes members).length = members.length := by
  induction members with
  | nil => rfl
  | cons first rest ih => cases first; simp [memberShapes, ih]

theorem value_success_keeps_original_bytes (input : Bytes) (read : Consumed input Value)
    (parsed : value input = .ok read) : input = read.prefix ++ read.rest := read.original

theorem value_success_earns_strict_progress (input : Bytes) (read : Consumed input Value)
    (parsed : value input = .ok read) : read.rest.length < input.length := consumed_strict_progress read

theorem document_success_earns_original_trace (input : Bytes) (output : Value) (parsed : document input = .ok output) :
    ∃ read : Consumed input Value, value input = .ok read ∧ read.value = output ∧
      input = read.prefix ++ read.rest ∧ read.rest.length < input.length ∧
      ∀ byte ∈ read.rest, JsonDocumentEnd.whitespace byte = true := by
  cases readAt : value input with
  | error error => simp [document, readAt] at parsed
  | ok read =>
      by_cases ended : JsonDocumentEnd.skip read.rest = read.rest.length
      · have same : read.value = output := by simpa [document, readAt, ended] using parsed
        exact ⟨read, readAt, same, read.original, consumed_strict_progress read, (JsonDocumentEnd.skip_complete_exact _).mp ended⟩
      · simp [document, readAt, ended] at parsed

theorem document_refuses_trailing_data (input : Bytes) (read : Consumed input Value)
    (parsed : value input = .ok read) (trailing : JsonDocumentEnd.skip read.rest ≠ read.rest.length) :
    document input = .error () := by simp [document, parsed, trailing]

theorem unique_syntax_document_acceptance_exact (input : Bytes) (output : Value) :
    uniqueSyntaxDocument input = .ok output ↔ document input = .ok output ∧ StrictJsonMembers.Unique (memberShape output) := by
  cases originalAt : document input with
  | error error => simp [uniqueSyntaxDocument, originalAt]
  | ok original =>
      cases checked : StrictJsonMembers.check (memberShape original) with
      | error error =>
          cases error
          have invalid := (StrictJsonMembers.check_refusal_exact _).mp checked
          constructor
          · intro impossible
            simp [uniqueSyntaxDocument, originalAt, checked] at impossible
          · rintro ⟨parsed, unique⟩
            have same : original = output := by simpa [originalAt] using parsed
            cases same
            exact False.elim (invalid unique)
      | ok unit =>
          cases unit
          have unique := StrictJsonMembers.check_sound _ checked
          constructor
          · intro accepted
            have same : original = output := by simpa [uniqueSyntaxDocument, originalAt, checked] using accepted
            refine ⟨?_, ?_⟩
            · simpa [originalAt] using same
            · rw [← same]; exact unique
          · rintro ⟨parsed, valid⟩
            have same : original = output := by simpa [originalAt] using parsed
            simpa [uniqueSyntaxDocument, originalAt, checked] using same

theorem unique_syntax_document_earns_complete_original (input : Bytes) (output : Value)
    (parsed : uniqueSyntaxDocument input = .ok output) :
    StrictJsonMembers.Unique (memberShape output) ∧
      ∃ read : Consumed input Value, value input = .ok read ∧ read.value = output ∧
        input = read.prefix ++ read.rest ∧ read.rest.length < input.length ∧
        ∀ byte ∈ read.rest, JsonDocumentEnd.whitespace byte = true := by
  obtain ⟨original, unique⟩ := (unique_syntax_document_acceptance_exact input output).mp parsed
  exact ⟨unique, document_success_earns_original_trace input output original⟩

theorem duplicate_original_members_refuse (input : Bytes) (members : List (StringToken × Value))
    (original : document input = .ok (.object members))
    (repeated : ¬ (members.map (fun member => member.1.decoded)).Nodup) : uniqueSyntaxDocument input = .error () := by
  have invalid : ¬ StrictJsonMembers.Unique (memberShape (.object members)) := by
    intro unique
    cases unique with
    | object values names each =>
        apply repeated
        simpa only [member_shapes_keep_decoded_names] using names
  have refused := (StrictJsonMembers.check_refusal_exact _).mpr invalid
  simp [uniqueSyntaxDocument, original, refused]

end Auths.Product.JsonRawReader
