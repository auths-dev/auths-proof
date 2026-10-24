import Auths.Product.JsonNumberPlan
import Auths.Product.JsonRawReader
import Auths.Product.SerdeNumberStages

/-!
Complete numeric preparation without dropping original syntax or members.
Every prepared numeric node retains its original token, coarse representation
plan and actual composed number-helper call, including partial refusal state.
Floating conversion/finite admission is unresolved, never fabricated.
Restore reconstructs the exact original raw tree, including duplicate and
typed-ignored members, raw String spellings and numeric lexemes. This is not
native serde conversion/Decode adequacy or canonical/hash provenance.
-/
namespace Auths.Product.JsonPreparedValue
open JsonStringScalars

structure Number where
  original : JsonRawReader.NumberToken
  plan : JsonNumberPlan.Plan
  prepared : plan = JsonNumberPlan.classify original.original
  stages : List Nat × List Nat × SerdeNumberStages.Next
  staged : stages = SerdeNumberStages.view original.original
  deriving DecidableEq

def prepareNumber (token : JsonRawReader.NumberToken) : Number :=
  ⟨token, JsonNumberPlan.classify token.original, rfl, SerdeNumberStages.view token.original, rfl⟩

inductive Value where
  | null | boolean (value : Bool) | number (token : Number) | text (token : JsonRawReader.StringToken)
  | array (values : List Value)
  | object (members : List (JsonRawReader.StringToken × Value))
  deriving DecidableEq

mutual
  def prepare : JsonRawReader.Value → Value
    | .null => .null
    | .boolean value => .boolean value
    | .number token => .number (prepareNumber token)
    | .text token => .text token
    | .array values => .array (prepareValues values)
    | .object members => .object (prepareMembers members)
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def prepareValues : List JsonRawReader.Value → List Value
    | [] => []
    | first :: rest => prepare first :: prepareValues rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def prepareMembers : List (JsonRawReader.StringToken × JsonRawReader.Value) → List (JsonRawReader.StringToken × Value)
    | [] => []
    | (name, child) :: rest => (name, prepare child) :: prepareMembers rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

mutual
  def rawNumbers : JsonRawReader.Value → List JsonRawReader.NumberToken
    | .null | .boolean _ | .text _ => []
    | .number token => [token]
    | .array children => rawValueNumbers children
    | .object members => rawMemberNumbers members
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def rawValueNumbers : List JsonRawReader.Value → List JsonRawReader.NumberToken
    | [] => []
    | first :: rest => rawNumbers first ++ rawValueNumbers rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def rawMemberNumbers : List (JsonRawReader.StringToken × JsonRawReader.Value) → List JsonRawReader.NumberToken
    | [] => []
    | (_, child) :: rest => rawNumbers child ++ rawMemberNumbers rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

mutual
  def numbers : Value → List Number
    | .null | .boolean _ | .text _ => []
    | .number token => [token]
    | .array children => valueNumbers children
    | .object members => memberNumbers members
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def valueNumbers : List Value → List Number
    | [] => []
    | first :: rest => numbers first ++ valueNumbers rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def memberNumbers : List (JsonRawReader.StringToken × Value) → List Number
    | [] => []
    | (_, child) :: rest => numbers child ++ memberNumbers rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

mutual
  theorem preparation_carries_every_original_numeric_call (value : JsonRawReader.Value) :
      numbers (prepare value) = (rawNumbers value).map prepareNumber := by
    cases value with
    | null | boolean _ | number _ | text _ => rfl
    | array children => exact preparation_carries_all_child_numeric_calls children
    | object members => exact preparation_carries_all_member_numeric_calls members
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  theorem preparation_carries_all_child_numeric_calls (values : List JsonRawReader.Value) :
      valueNumbers (prepareValues values) = (rawValueNumbers values).map prepareNumber := by
    cases values with
    | nil => rfl
    | cons first rest =>
        simp only [prepareValues, valueNumbers, rawValueNumbers, List.map_append,
          preparation_carries_every_original_numeric_call, preparation_carries_all_child_numeric_calls]
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  theorem preparation_carries_all_member_numeric_calls (members : List (JsonRawReader.StringToken × JsonRawReader.Value)) :
      memberNumbers (prepareMembers members) = (rawMemberNumbers members).map prepareNumber := by
    cases members with
    | nil => rfl
    | cons first rest =>
        cases first
        simp only [prepareMembers, memberNumbers, rawMemberNumbers, List.map_append,
          preparation_carries_every_original_numeric_call, preparation_carries_all_member_numeric_calls]
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

theorem original_number_carries_actual_composed_stage (token : JsonRawReader.NumberToken) :
    (prepareNumber token).original = token ∧ (prepareNumber token).stages = SerdeNumberStages.view token.original := ⟨rfl, rfl⟩

theorem every_retained_number_has_its_actual_stage (number : Number) :
    number.stages = SerdeNumberStages.view number.original.original := number.staged

theorem preparation_keeps_original_numeric_count (value : JsonRawReader.Value) :
    (numbers (prepare value)).length = (rawNumbers value).length := by
  rw [preparation_carries_every_original_numeric_call, List.length_map]

mutual
  def restore : Value → JsonRawReader.Value
    | .null => .null
    | .boolean value => .boolean value
    | .number token => .number token.original
    | .text token => .text token
    | .array values => .array (restoreValues values)
    | .object members => .object (restoreMembers members)
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def restoreValues : List Value → List JsonRawReader.Value
    | [] => []
    | first :: rest => restore first :: restoreValues rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def restoreMembers : List (JsonRawReader.StringToken × Value) → List (JsonRawReader.StringToken × JsonRawReader.Value)
    | [] => []
    | (name, child) :: rest => (name, restore child) :: restoreMembers rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

mutual
  theorem preparation_retains_complete_original (value : JsonRawReader.Value) : restore (prepare value) = value := by
    cases value with
    | null | boolean _ | number _ | text _ => rfl
    | array values => simp only [prepare, restore, preparation_retains_all_values]
    | object members => simp only [prepare, restore, preparation_retains_all_members]
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  theorem preparation_retains_all_values (values : List JsonRawReader.Value) : restoreValues (prepareValues values) = values := by
    cases values with
    | nil => rfl
    | cons first rest => simp only [prepareValues, restoreValues, preparation_retains_complete_original, preparation_retains_all_values]
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  theorem preparation_retains_all_members (members : List (JsonRawReader.StringToken × JsonRawReader.Value)) :
      restoreMembers (prepareMembers members) = members := by
    cases members with
    | nil => rfl
    | cons first rest =>
        cases first
        simp only [prepareMembers, restoreMembers, preparation_retains_complete_original, preparation_retains_all_members]
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

def document (input : Bytes) : Except Unit Value := (JsonRawReader.document input).map prepare
def uniqueSyntaxDocument (input : Bytes) : Except Unit Value := (JsonRawReader.uniqueSyntaxDocument input).map prepare

theorem prepared_document_earns_original_raw_tree (input : Bytes) (output : Value) (accepted : document input = .ok output) :
    ∃ original, JsonRawReader.document input = .ok original ∧ output = prepare original ∧ restore output = original := by
  cases originalAt : JsonRawReader.document input with
  | error error => simp [document, originalAt] at accepted
  | ok original =>
      have same : prepare original = output := by simpa [document, originalAt] using accepted
      exact ⟨original, originalAt, same.symm, by rw [← same, preparation_retains_complete_original]⟩

theorem prepared_unique_document_earns_complete_original (input : Bytes) (output : Value)
    (accepted : uniqueSyntaxDocument input = .ok output) :
    ∃ original, JsonRawReader.uniqueSyntaxDocument input = .ok original ∧ output = prepare original ∧
      restore output = original ∧ StrictJsonMembers.Unique (JsonRawReader.memberShape (restore output)) ∧
      ∃ read : Consumed input JsonRawReader.Value, JsonRawReader.value input = .ok read ∧ read.value = original ∧
        input = read.prefix ++ read.rest ∧ read.rest.length < input.length ∧
        ∀ byte ∈ read.rest, JsonDocumentEnd.whitespace byte = true := by
  cases originalAt : JsonRawReader.uniqueSyntaxDocument input with
  | error error => simp [uniqueSyntaxDocument, originalAt] at accepted
  | ok original =>
      have same : prepare original = output := by simpa [uniqueSyntaxDocument, originalAt] using accepted
      have retained : restore output = original := by rw [← same, preparation_retains_complete_original]
      obtain ⟨unique, trace⟩ := JsonRawReader.unique_syntax_document_earns_complete_original input original originalAt
      exact ⟨original, originalAt, same.symm, retained, by simpa only [retained] using unique, trace⟩

/-- Syntax preparation can retain numeric refusal annotations. This does not
upgrade syntax success to native numeric/visitor success or preserve the native
online parser's first-error priority. Every original occurrence is retained. -/
theorem prepared_document_carries_all_original_numeric_calls (input : Bytes) (output : Value)
    (accepted : document input = .ok output) :
    ∃ original, JsonRawReader.document input = .ok original ∧
      numbers output = (rawNumbers original).map prepareNumber ∧ restore output = original := by
  obtain ⟨original, parsed, prepared, retained⟩ := prepared_document_earns_original_raw_tree input output accepted
  exact ⟨original, parsed, by rw [prepared, preparation_carries_every_original_numeric_call], retained⟩

theorem prepared_unique_document_carries_all_original_numeric_calls (input : Bytes) (output : Value)
    (accepted : uniqueSyntaxDocument input = .ok output) :
    ∃ original, JsonRawReader.uniqueSyntaxDocument input = .ok original ∧
      numbers output = (rawNumbers original).map prepareNumber ∧ restore output = original := by
  obtain ⟨original, parsed, prepared, retained, unique, trace⟩ := prepared_unique_document_earns_complete_original input output accepted
  exact ⟨original, parsed, by rw [prepared, preparation_carries_every_original_numeric_call], retained⟩

end Auths.Product.JsonPreparedValue
