import Auths.Product.FieldProjection
import Auths.Product.DerivedTokens

namespace Auths.Product.FieldProjection
open RequestConstruction ScalarProjection

def namespaceName : Bytes := [111,112,101,114,97,116,111,114,95,110,97,109,101,115,112,97,99,101]
def recipeName : Bytes := [114,101,99,105,112,101,95,100,105,103,101,115,116]
def operationName : Bytes := [111,112,101,114,97,116,105,111,110,95,105,100]

def scalarText : Scalar → Option Bytes
  | .text bytes => some bytes
  | _ => none

def argumentText : Arg → Option Bytes
  | .text bytes => some bytes
  | _ => none

/-- Exact first-member semantics, including a wrong-kind first duplicate. -/
def textMember (name : Bytes) : Inputs → Option Bytes
  | [] => none
  | input :: rest => if input.1 = name then scalarText input.2 else textMember name rest

def RequestFrame (fields : List Field) (inputs : Inputs) (namespace recipe : Bytes) : Prop :=
  fields.length ≤ 32 ∧ inputs.length = fields.length ∧
    OperationIdentity.validToken namespace 64 = true ∧
    textMember namespaceName inputs = some namespace ∧ textMember recipeName inputs = some recipe

def OperationAccepted (inputs : Inputs) : Prop :=
  ∃ operation, textMember operationName inputs = some operation ∧
    OperationIdentity.validToken operation 128 = true

def RequestAccepted (fields : List Field) (inputs : Inputs) (namespace recipe : Bytes) : Prop :=
  RequestFrame fields inputs namespace recipe ∧ ObjectAccepted fields inputs ∧ OperationAccepted inputs

instance (fields : List Field) (inputs : Inputs) (namespace recipe : Bytes) :
    Decidable (RequestFrame fields inputs namespace recipe) := by unfold RequestFrame; infer_instance

instance (inputs : Inputs) : Decidable (OperationAccepted inputs) := by
  cases found : textMember operationName inputs with
  | none => exact isFalse (by simp [OperationAccepted, found])
  | some operation =>
    simpa [OperationAccepted, found] using
      (inferInstance : Decidable (OperationIdentity.validToken operation 128 = true))

instance (fields : List Field) (inputs : Inputs) (namespace recipe : Bytes) :
    Decidable (RequestAccepted fields inputs namespace recipe) := by unfold RequestAccepted; infer_instance

inductive BindingError where
  | actionMismatch
  | projection (error : ConstructError)
  | operationId
  deriving DecidableEq

structure BoundArguments where
  values : List Arg
  operation : Bytes

/-- Exact typed refusal precedence and complete success meaning. The object
projection is a semantic relation, not a second implementation of the writer. -/
def RequestOutcome (fields : List Field) (inputs : Inputs) (namespace recipe : Bytes) :
    Except BindingError BoundArguments → Prop
  | .error .actionMismatch => ¬RequestFrame fields inputs namespace recipe
  | .error (.projection error) =>
      RequestFrame fields inputs namespace recipe ∧ ObjectOutcome fields inputs (.error error)
  | .error .operationId => RequestFrame fields inputs namespace recipe ∧
      (∃ values, ObjectOutcome fields inputs (.ok values)) ∧ ¬OperationAccepted inputs
  | .ok actual => RequestFrame fields inputs namespace recipe ∧
      ObjectOutcome fields inputs (.ok actual.values) ∧
      textMember operationName inputs = some actual.operation ∧
      OperationIdentity.validToken actual.operation 128 = true

theorem projected_text_is_original (schema : Schema) (input : Scalar) (output : Arg)
    (meaning : Projects schema input output) : argumentText output = scalarText input := by
  cases schema <;> cases input <;> cases output <;>
    simp_all [Projects, argumentText, scalarText]

theorem rows_preserve_text_lookup (fields : List Field) (inputs : Inputs)
    (environment : ArgumentBinding.Environment) (rows : RowsMeaning fields inputs environment)
    (name : Bytes) : (ArgumentBinding.lookup name environment).bind argumentText = textMember name inputs := by
  induction rows with
  | nil => rfl
  | @cons input output inputs outputs first rest ih =>
    obtain ⟨schema, selected, projected, bounded⟩ := first.2.2
    have same := first.1
    by_cases equal : input.1 = name
    · simpa [ArgumentBinding.lookup, textMember, same, equal] using
        projected_text_is_original schema input.2 output.2 projected
    · simpa [ArgumentBinding.lookup, textMember, same, equal] using ih

theorem request_success_is_accepted (fields : List Field) (inputs : Inputs) (namespace recipe : Bytes)
    (actual : BoundArguments) (meaning : RequestOutcome fields inputs namespace recipe (.ok actual)) :
    RequestAccepted fields inputs namespace recipe :=
  ⟨meaning.1, meaning.2.1.1, actual.operation, meaning.2.2⟩

theorem request_refusal_excludes_acceptance (fields : List Field) (inputs : Inputs)
    (namespace recipe : Bytes) (error : BindingError)
    (meaning : RequestOutcome fields inputs namespace recipe (.error error)) :
    ¬RequestAccepted fields inputs namespace recipe := by
  intro accepted
  cases error with
  | actionMismatch => exact meaning accepted.1
  | projection error => exact meaning.2.2 accepted.2.1
  | operationId => exact meaning.2.2 accepted.2.2

/-- Successful binding earns both preimage token domains and obtains every
reserved text from the same complete projected environment as rendered fields. -/
theorem request_success_earns_named_bindings (fields : List Field) (inputs : Inputs)
    (namespace recipe : Bytes) (actual : BoundArguments)
    (meaning : RequestOutcome fields inputs namespace recipe (.ok actual)) :
    ∃ environment, RowsMeaning fields inputs environment ∧
      SchemaIndex.Aligned (names fields) actual.values (fun name => ArgumentBinding.lookup name environment) ∧
      (ArgumentBinding.lookup namespaceName environment).bind argumentText = some namespace ∧
      (ArgumentBinding.lookup recipeName environment).bind argumentText = some recipe ∧
      (ArgumentBinding.lookup operationName environment).bind argumentText = some actual.operation ∧
      OperationIdentity.validToken namespace 64 = true ∧
      OperationIdentity.validToken actual.operation 128 = true := by
  obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ meaning.2.1
  refine ⟨environment, rows, aligned, ?_, ?_, ?_, meaning.1.2.2.1, meaning.2.2.2⟩
  · rw [rows_preserve_text_lookup _ _ _ rows]
    exact meaning.1.2.2.2.1
  · rw [rows_preserve_text_lookup _ _ _ rows]
    exact meaning.1.2.2.2.2
  · rw [rows_preserve_text_lookup _ _ _ rows]
    exact meaning.2.2.1

theorem request_success_earns_token_lengths (fields : List Field) (inputs : Inputs)
    (namespace recipe : Bytes) (actual : BoundArguments)
    (meaning : RequestOutcome fields inputs namespace recipe (.ok actual)) :
    namespace.length ≤ 64 ∧ actual.operation.length ≤ 128 := by
  have token_bound : ∀ (bytes : Bytes) (maximum : Nat),
      OperationIdentity.validToken bytes maximum = true → bytes.length ≤ maximum := by
    intro bytes maximum valid
    cases bytes with
    | nil => simp [OperationIdentity.validToken] at valid
    | cons first rest =>
      simp only [OperationIdentity.validToken, Bool.and_eq_true, decide_eq_true_eq] at valid
      omega
  exact ⟨token_bound _ _ meaning.1.2.2.1, token_bound _ _ meaning.2.2.2⟩

end Auths.Product.FieldProjection
