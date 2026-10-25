import Auths.Product.ScalarProjection
import Auths.Product.OperationIdentity

namespace Auths.Product.FieldProjection
open RequestConstruction
open ScalarProjection

structure Field where
  name : Bytes
  schema : Schema

abbrev Inputs := List (Bytes × Scalar)

def names (fields : List Field) : List Bytes := fields.map (·.name)

def LayoutValid (fields : List Field) : Prop :=
  fields.length ≤ 32 ∧ (names fields).Nodup ∧
    ∀ field ∈ fields, OperationIdentity.validToken field.name 64 = true

def schemaFor (name : Bytes) : List Field → Option Schema
  | [] => none
  | field :: rest => if field.name = name then some field.schema else schemaFor name rest

def RowAccepted (fields : List Field) (input : Bytes × Scalar) : Prop :=
  OperationIdentity.validToken input.1 64 = true ∧
    match schemaFor input.1 fields with
    | none => False
    | some schema => Accepts schema input.2

def RowsAccepted (fields : List Field) (inputs : Inputs) : Prop :=
  fields.length ≤ 32 ∧ inputs.length ≤ 32 ∧ ∀ input ∈ inputs, RowAccepted fields input

def RowProjects (fields : List Field) (input : Bytes × Scalar) (output : Bytes × Arg) : Prop :=
  output.1 = input.1 ∧ OperationIdentity.validToken input.1 64 = true ∧
    ∃ schema, schemaFor input.1 fields = some schema ∧
      Projects schema input.2 output.2 ∧ PayloadLength output.2 ≤ 4096

def RowsMeaning (fields : List Field) (inputs : Inputs) (outputs : ArgumentBinding.Environment) : Prop :=
  List.Forall₂ (RowProjects fields) inputs outputs

def ObjectAccepted (fields : List Field) (inputs : Inputs) : Prop :=
  LayoutValid fields ∧ inputs.length = fields.length ∧ RowsAccepted fields inputs ∧
    (inputs.map Prod.fst).Perm (names fields)

def RowsOutcome (fields : List Field) (inputs : Inputs) : Except ConstructError ArgumentBinding.Environment → Prop
  | .error error => error = .argumentMismatch ∧ ¬RowsAccepted fields inputs
  | .ok outputs => RowsAccepted fields inputs ∧ RowsMeaning fields inputs outputs

def ObjectOutcome (fields : List Field) (inputs : Inputs) : Except ConstructError (List Arg) → Prop
  | .error error => error = .argumentMismatch ∧ ¬ObjectAccepted fields inputs
  | .ok values => ObjectAccepted fields inputs ∧
    ∃ outputs, RowsMeaning fields inputs outputs ∧ ArgumentBinding.bind (names fields) outputs = .ok values

instance (fields : List Field) : Decidable (LayoutValid fields) := by unfold LayoutValid; infer_instance
instance (fields : List Field) (input : Bytes × Scalar) : Decidable (RowAccepted fields input) := by
  unfold RowAccepted
  cases schemaFor input.1 fields <;> infer_instance
instance (fields : List Field) (inputs : Inputs) : Decidable (RowsAccepted fields inputs) := by
  unfold RowsAccepted
  infer_instance
instance (fields : List Field) (inputs : Inputs) : Decidable (ObjectAccepted fields inputs) := by
  unfold ObjectAccepted
  infer_instance

theorem projects_accepts (schema : Schema) (input : Scalar) (output : Arg)
    (projected : Projects schema input output) : Accepts schema input := by
  cases schema <;> cases input <;> cases output <;> simp_all [Projects, Accepts]

theorem token_length (name : Bytes) (valid : OperationIdentity.validToken name 64 = true) : name.length ≤ 64 := by
  cases name with
  | nil => simp [OperationIdentity.validToken] at valid
  | cons first rest =>
    simp only [OperationIdentity.validToken, Bool.and_eq_true, decide_eq_true_eq] at valid
    exact valid.1.1

theorem row_projects_accepts (fields : List Field) (input : Bytes × Scalar) (output : Bytes × Arg)
    (projected : RowProjects fields input output) : RowAccepted fields input := by
  obtain ⟨same, nameValid, schema, found, meaning, bounded⟩ := projected
  exact ⟨nameValid, by simpa [found] using projects_accepts schema input.2 output.2 meaning⟩

theorem rows_all_accepted (fields : List Field) (inputs : Inputs) (outputs : ArgumentBinding.Environment)
    (projected : RowsMeaning fields inputs outputs) : ∀ input ∈ inputs, RowAccepted fields input := by
  induction projected with
  | nil => simp
  | cons first rest ih =>
    intro input member
    rcases List.mem_cons.mp member with same | member
    · subst input
      exact row_projects_accepts _ _ _ first
    · exact ih input member

theorem rows_preserve_names (fields : List Field) (inputs : Inputs) (outputs : ArgumentBinding.Environment)
    (projected : RowsMeaning fields inputs outputs) : outputs.map Prod.fst = inputs.map Prod.fst := by
  induction projected with
  | nil => rfl
  | cons first rest ih => simp [first.1, ih]

theorem rows_preserve_length (fields : List Field) (inputs : Inputs) (outputs : ArgumentBinding.Environment)
    (projected : RowsMeaning fields inputs outputs) : outputs.length = inputs.length :=
  projected.length_eq.symm

theorem rows_earn_payloads (fields : List Field) (inputs : Inputs) (outputs : ArgumentBinding.Environment)
    (projected : RowsMeaning fields inputs outputs) :
    ∀ output ∈ outputs, PayloadLength output.2 ≤ 4096 := by
  induction projected with
  | nil => simp
  | cons first rest ih =>
    intro output member
    rcases List.mem_cons.mp member with same | member
    · subst output
      obtain ⟨schema, found, meaning, bounded⟩ := first.2.2
      exact bounded
    · exact ih output member

theorem schema_for_present (fields : List Field) (name : Bytes) (schema : Schema)
    (found : schemaFor name fields = some schema) : name ∈ names fields := by
  induction fields with
  | nil => simp [schemaFor] at found
  | cons field rest ih =>
    by_cases same : field.name = name
    · simp [names, same]
    · simp only [schemaFor, same, ↓reduceIte] at found
      simpa [names] using List.mem_cons_of_mem field.name (ih found)

theorem lookup_present (name : Bytes) (outputs : ArgumentBinding.Environment)
    (present : name ∈ outputs.map Prod.fst) : ArgumentBinding.lookup name outputs ≠ none := by
  induction outputs with
  | nil => simp at present
  | cons output rest ih =>
    obtain ⟨key, value⟩ := output
    by_cases same : key = name
    · simp [ArgumentBinding.lookup, same]
    · have tail : name ∈ rest.map Prod.fst := by simpa [same, Ne.symm same] using present
      simpa [ArgumentBinding.lookup, same] using ih tail

/-- Independent object acceptance and source-earned complete row projection
are sufficient for the earlier binder, with no positional-alignment premise. -/
theorem accepted_rows_bind (fields : List Field) (inputs : Inputs) (outputs : ArgumentBinding.Environment)
    (admitted : ObjectAccepted fields inputs) (projected : RowsMeaning fields inputs outputs) :
    ∃ values, ArgumentBinding.bind (names fields) outputs = .ok values := by
  obtain ⟨layout, lengths, rows, exactNames⟩ := admitted
  have outputNames := rows_preserve_names fields inputs outputs projected
  have outputLength := rows_preserve_length fields inputs outputs projected
  apply ArgumentBinding.complete_layout_accepts (names fields) outputs
  · simpa [names] using layout.1
  · exact layout.2.1
  · simpa [names] using outputLength.trans lengths
  · intro name member
    apply lookup_present name outputs
    rw [outputNames]
    exact exactNames.mem_iff.mpr member

theorem object_result_earns_named_alignment (fields : List Field) (inputs : Inputs) (values : List Arg)
    (meaning : ObjectOutcome fields inputs (.ok values)) :
    ∃ outputs, RowsMeaning fields inputs outputs ∧
      SchemaIndex.Aligned (names fields) values (fun name => ArgumentBinding.lookup name outputs) := by
  obtain ⟨admitted, outputs, projected, bound⟩ := meaning
  exact ⟨outputs, projected, (ArgumentBinding.bind_earns_layout _ _ _ bound).2.2.2⟩

theorem object_output_payloads_bounded (fields : List Field) (inputs : Inputs) (values : List Arg)
    (meaning : ObjectOutcome fields inputs (.ok values)) :
    ∀ value ∈ values, ScalarProjection.PayloadLength value ≤ 4096 := by
  obtain ⟨outputs, projected, aligned⟩ := object_result_earns_named_alignment _ _ _ meaning
  have rowsBound := rows_earn_payloads fields inputs outputs projected
  intro value member
  obtain ⟨index, atValue⟩ := List.mem_iff_getElem?.mp member
  have inside : index < values.length := (List.getElem?_eq_some_iff.mp atValue).1
  have namesInside : index < (names fields).length := by omega
  have atName : (names fields)[index]? = some ((names fields)[index]) := List.getElem?_eq_getElem namesInside
  have found : ArgumentBinding.lookup ((names fields)[index]) outputs = some value := by
    rw [← aligned.2 index ((names fields)[index]) atName]
    exact atValue
  exact rowsBound _ (ArgumentBinding.lookup_member _ _ _ found)

theorem binder_error_class (fieldNames : List Bytes) (outputs : ArgumentBinding.Environment)
    (error : ConstructError) (refused : ArgumentBinding.bind fieldNames outputs = .error error) :
    error = .argumentMismatch := by
  have projectError : ∀ fields : List Bytes, ArgumentBinding.project fields outputs = .error error → error = .argumentMismatch := by
    intro fields
    induction fields with
    | nil => simp [ArgumentBinding.project]
    | cons name rest ih =>
      cases found : ArgumentBinding.lookup name outputs with
      | none =>
        intro refused
        simpa [ArgumentBinding.project, found] using refused.symm
      | some value =>
        cases tail : ArgumentBinding.project rest outputs with
        | ok values => simp [ArgumentBinding.project, found, tail]
        | error actual =>
          intro refused
          have same : actual = error := by simpa [ArgumentBinding.project, found, tail] using refused
          subst actual
          exact ih tail
  unfold ArgumentBinding.bind at refused
  split at refused
  · simpa using refused.symm
  · exact projectError fieldNames refused

end Auths.Product.FieldProjection
