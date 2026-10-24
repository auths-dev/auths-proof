import Auths.Product.RecipePlanModel

namespace Auths.Product.RecipePlanModel
open RequestConstruction

def CredentialColumns (context : ReadContext) (plan : CredentialPlan) : Prop :=
  plan.origin = context.origin ∧ plan.versions = context.headers.versions

theorem credential_read_columns {E : Type} (errors : Errors E) (context : ReadContext)
    (method : Method) (source : List PathSegment) (output : CredentialPlan)
    (compiled : credentialRead errors context method source = .ok output) :
    CredentialColumns context output ∧ output.method = method ∧
      PathCompiler.lowerFixedPath (source.map pathSegment) = .ok output.path := by
  have columns := NativeCompiler.ReadModel.credential_success_columns errors.invalidSource method
    context.origin context.headers.versions (source.map pathSegment) output compiled
  exact ⟨⟨columns.2.1, columns.2.2.1⟩, columns.1, columns.2.2.2⟩

theorem optional_credential_columns {E : Type} (errors : Errors E) (context : ReadContext)
    (source : Option (List PathSegment)) (output : Option CredentialPlan)
    (compiled : optionalCredential errors context source = .ok output) :
    ∀ plan, output = some plan → CredentialColumns context plan ∧ plan.method = .get := by
  cases source with
  | none => simp [optionalCredential] at compiled; subst output; simp
  | some path =>
      cases lowered : credentialRead errors context .get path with
      | error error => simp [optionalCredential, lowered] at compiled
      | ok value =>
          have same : some value = output := by simpa [optionalCredential, lowered] using compiled
          subst output
          intro plan accepted
          cases accepted
          have columns := credential_read_columns errors context .get path value lowered
          exact ⟨columns.1, columns.2.1⟩

theorem denied_reads_columns {E : Type} (errors : Errors E) (context : ReadContext)
    (source : List DeniedRead) (output : List CredentialPlan)
    (compiled : deniedReads errors context source = .ok output) :
    List.Forall₂ (fun read plan => CredentialColumns context plan ∧ plan.method = deniedMethod read ∧
      PathCompiler.lowerFixedPath (read.path.map pathSegment) = .ok plan.path) source output := by
  induction source generalizing output with
  | nil => simp [deniedReads] at compiled; subst output; exact .nil
  | cons read rest ih =>
      cases headAt : credentialRead errors context (deniedMethod read) read.path with
      | error error => simp [deniedReads, headAt] at compiled
      | ok head =>
          cases tailAt : deniedReads errors context rest with
          | error error => simp [deniedReads, headAt, tailAt] at compiled
          | ok tail =>
              have same : head :: tail = output := by simpa [deniedReads, headAt, tailAt] using compiled
              subst output
              exact .cons (credential_read_columns errors context _ _ _ headAt) (ih tail tailAt)

/-- A plan bundle cannot substitute its original complete field/schema pairs
or the compiled write while optional reads are assembled. -/
theorem remaining_plans_keep_write_and_fields {E : Type} (errors : Errors E)
    (fields : List FieldProjection.Field) (source : Source) (write : RequestCompiler.Compiled)
    (output : Plans) (compiled : remainingPlans errors fields source write = .ok output) :
    output.fields = fields ∧ output.write = write.plan := by
  simp only [remainingPlans, Bind.bind, Except.bind] at compiled
  repeat' split at compiled <;> simp_all

theorem compile_success_components {E : Type} (errors : Errors E)
    (fields : List FieldProjection.Field) (host : Bytes) (source : Source) (output : Plans)
    (accepted : compile errors fields host source = .ok output) :
    ∃ body compiled,
      namedBody errors source.body source.echo = .ok body ∧
      RequestCompiler.compile fields (writeSource source host body) = .ok compiled ∧
      RequestCompiler.CompilationMeaning fields (writeSource source host body) compiled ∧
      remainingPlans errors fields source compiled = .ok output ∧
      output.fields = fields ∧ output.write = compiled.plan := by
  unfold compile at accepted
  cases bodyAt : namedBody errors source.body source.echo with
  | error error => simp [bodyAt] at accepted
  | ok body =>
      cases writeAt : RequestCompiler.compile fields (writeSource source host body) with
      | error error => simp [bodyAt, writeAt] at accepted
      | ok compiled =>
          have remaining : remainingPlans errors fields source compiled = .ok output := by
            simpa [bodyAt, writeAt] using accepted
          have columns := remaining_plans_keep_write_and_fields errors fields source compiled output remaining
          exact ⟨body, compiled, bodyAt, writeAt, RequestCompiler.compile_sound _ _ _ writeAt, remaining, columns⟩

end Auths.Product.RecipePlanModel
