import Auths.Product.RecipeLockAdmission
import Auths.Product.RecipeOriginAdmission
import Auths.Product.RecipeCredentialAdmission
import Auths.Product.RecipeRuleAdmission
import Auths.Product.ProfileSchema

/-!
Independent complete constructor admission in shipping source order. Inputs are
the original decoded columns and original complete serialization/URL outcomes.
The only function parameters are the named hash and stable error-code mapping;
no Auths validator, selected native field table or admission flag is supplied.
-/
namespace Auths.Product.RecipeConstructorAdmission
open RequestConstruction
open NativeCompiler

structure Errors (E : Type) where
  invalidSource : E
  invalidProfileLock : E
  profileMismatch : E
  invalidNamespace : E
  invalidCredential : E
  unsafeOrigin : E
  ruleError : RecipeConsumption.Error → E

structure Source where
  schema : Bytes
  binding : RecipeBinding.Binding
  namespaceBytes : Bytes
  credential : RecipeCredentialAdmission.Requirement
  origin : Bytes
  rules : RecipeRuleAdmission.Source

structure Lock where
  metadata : RecipeBinding.Metadata
  commandSchema : ProfileSchema.Value
  canonicalSchema : RecipeLockAdmission.CanonicalOutcome
  canonicalSource : RecipeLockAdmission.CanonicalOutcome

structure Value where
  fields : List (Bytes × ScalarProjection.Schema)
  namespaceBytes : Bytes
  host : Bytes
  canonicalSource : RecipeLockAdmission.CanonicalOutcome
  deriving DecidableEq

def fieldPairs (fields : List FieldProjection.Field) : List (Bytes × ScalarProjection.Schema) :=
  fields.map (fun field => (field.name, field.schema))

def finish {E : Type} (errors : Errors E) (source : Source) (lock : Lock)
    (parsedOrigin : Except Unit RecipeOriginAdmission.Parsed) (fields : List FieldProjection.Field)
    (namespaceBytes : Bytes) (table : List Rules.Entry) : Except E Value := do
  RecipeCredentialAdmission.validateRequirement errors.invalidCredential source.credential
  let host ← RecipeOriginAdmission.validate errors.unsafeOrigin source.origin parsedOrigin
  ((RecipeRuleAdmission.validate table source.rules).1).mapError errors.ruleError
  .ok ⟨fieldPairs fields, namespaceBytes, host, lock.canonicalSource⟩

def withFields {E : Type} (errors : Errors E) (source : Source) (lock : Lock)
    (parsedOrigin : Except Unit RecipeOriginAdmission.Parsed) (fields : List FieldProjection.Field) : Except E Value := do
  let namespaceBytes ← if OperationIdentity.validToken source.namespaceBytes 64 then .ok source.namespaceBytes
    else .error errors.invalidNamespace
  if ProfileSchema.BindingFields fields namespaceBytes then .ok () else .error errors.profileMismatch
  let table ← (Rules.build [] fields).mapError (fun _ => errors.invalidProfileLock)
  finish errors source lock parsedOrigin fields namespaceBytes table

def withProfile {E : Type} (errors : Errors E) (source : Source) (lock : Lock)
    (parsedOrigin : Except Unit RecipeOriginAdmission.Parsed) : Except E Value := do
  let fields ← match ProfileSchema.parseRoot lock.commandSchema with
    | none => .error errors.invalidProfileLock
    | some fields => .ok fields
  withFields errors source lock parsedOrigin fields

def afterLock {E : Type} (errors : Errors E) (source : Source) (lock : Lock)
    (parsedOrigin : Except Unit RecipeOriginAdmission.Parsed) : Except E Value := do
  if RecipeBinding.SourceMatches source.binding lock.metadata.binding then .ok () else .error errors.profileMismatch
  withProfile errors source lock parsedOrigin

def afterTag {E : Type} (errors : Errors E) (hash : Bytes → Bytes) (source : Source) (lock : Lock)
    (parsedOrigin : Except Unit RecipeOriginAdmission.Parsed) : Except E Value := do
  RecipeLockAdmission.validateLock ⟨errors.invalidSource, errors.invalidProfileLock⟩ hash lock.metadata lock.canonicalSchema
  afterLock errors source lock parsedOrigin

def validate {E : Type} (errors : Errors E) (hash : Bytes → Bytes) (source : Source) (lock : Lock)
    (parsedOrigin : Except Unit RecipeOriginAdmission.Parsed) : Except E Value := do
  if source.schema = RecipeBinding.sourceSchema then .ok () else .error errors.invalidSource
  afterTag errors hash source lock parsedOrigin

theorem unsupported_schema_refuses_first {E : Type} (errors : Errors E) (hash : Bytes → Bytes)
    (source : Source) (lock : Lock) (parsed : Except Unit RecipeOriginAdmission.Parsed)
    (unsupported : source.schema ≠ RecipeBinding.sourceSchema) :
    validate errors hash source lock parsed = .error errors.invalidSource := by
  simp [validate, unsupported]

theorem mismatched_profile_refuses_before_schema {E : Type} (errors : Errors E)
    (source : Source) (lock : Lock) (parsed : Except Unit RecipeOriginAdmission.Parsed)
    (mismatch : ¬RecipeBinding.SourceMatches source.binding lock.metadata.binding) :
    afterLock errors source lock parsed = .error errors.profileMismatch := by
  simp [afterLock, mismatch]

theorem finish_preserves_original_fields {E : Type} (errors : Errors E) (source : Source) (lock : Lock)
    (parsed : Except Unit RecipeOriginAdmission.Parsed) (fields : List FieldProjection.Field)
    (namespaceBytes : Bytes) (table : List Rules.Entry) (value : Value)
    (accepted : finish errors source lock parsed fields namespaceBytes table = .ok value) :
    value.fields = fieldPairs fields ∧ value.namespaceBytes = namespaceBytes ∧ value.canonicalSource = lock.canonicalSource := by
  unfold finish at accepted
  cases credential : RecipeCredentialAdmission.validateRequirement errors.invalidCredential source.credential with
  | error error => simp [credential] at accepted
  | ok unit =>
      cases unit
      cases origin : RecipeOriginAdmission.validate errors.unsafeOrigin source.origin parsed with
      | error error => simp [credential, origin] at accepted
      | ok host =>
          cases rules : (RecipeRuleAdmission.validate table source.rules).1 with
          | error error => simp [credential, origin, rules] at accepted
          | ok unit =>
              cases unit
              have same : (⟨fieldPairs fields, namespaceBytes, host, lock.canonicalSource⟩ : Value) = value := by
                simpa [credential, origin, rules] using accepted
              subst value
              exact ⟨rfl, rfl, rfl⟩

end Auths.Product.RecipeConstructorAdmission
