import Auths.Product.RecipePlanProperties
import Auths.Product.RecipeCredentialAdmission

namespace Auths.Product.RecipePlanModel
open RequestConstruction
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

def GuardPathsAdmissible : Option Guard → Prop
  | none => True
  | some guard =>
      (match guard.probe with | none => True | some path => RecipeCredentialAdmission.FixedPathAdmitted path) ∧
      (match guard.account with | none => True | some path => RecipeCredentialAdmission.FixedPathAdmitted path) ∧
      ∀ read ∈ guard.denied.getD [], RecipeCredentialAdmission.FixedPathAdmitted read.path

/-- Admission of original read syntax. This contains no selected read plan,
compiler verdict, callback, rendered argument or credential value. Response
observations have no initial read plan, as in the shipping lowering caller. -/
structure ReadPathsAdmissible (names : List Bytes) (source : Source) : Prop where
  observation : ∀ path, source.observation = some path → path.any responseField = false →
    PathCompiler.PathAdmissible names (path.map pathSegment)
  preEntry : ∀ path, source.preEntry = some path → PathCompiler.PathAdmissible names (path.map pathSegment)
  relativeCeiling : ∀ path, source.relativeCeiling = some path → PathCompiler.PathAdmissible names (path.map pathSegment)
  credential : GuardPathsAdmissible (guard source.credential)

private theorem lower_fixed_values (values : List Bytes)
    (admitted : ∀ value ∈ values, PathCompiler.FixedValid value) :
    PathCompiler.lowerFixedList (values.map PathCompiler.SourceSegment.fixed) = .ok values := by
  induction values with
  | nil => rfl
  | cons value rest ih =>
      simp [PathCompiler.lowerFixedList, admitted value (by simp),
        ih (fun item member => admitted item (by simp [member]))]

theorem fixed_path_admission_earns_lowering (source : List PathSegment)
    (admitted : RecipeCredentialAdmission.FixedPathAdmitted source) :
    ∃ path, PathCompiler.lowerFixedPath (source.map pathSegment) = .ok path := by
  obtain ⟨values, original, positive, count, literals⟩ :=
    RecipeCredentialAdmission.fixed_paths_earn_original_bounds source admitted
  refine ⟨values, ?_⟩
  have mapped : source.map pathSegment = values.map PathCompiler.SourceSegment.fixed := by
    simp [original, List.map_map, Function.comp_def, pathSegment]
  simp [PathCompiler.lowerFixedPath, mapped, positive, count, lower_fixed_values values literals]

theorem action_read_admission_is_useful {E : Type} (errors : Errors E) (context : ReadContext)
    (source : List PathSegment) (admitted : PathCompiler.PathAdmissible context.names (source.map pathSegment)) :
    ∃ output, actionRead errors context source = .ok output := by
  obtain ⟨path, compiled⟩ := PathCompiler.lower_path_complete _ _ admitted
  exact ⟨⟨context.origin, path, context.headers⟩,
    by simp [actionRead, NativeCompiler.ReadModel.action, compiled]⟩

theorem credential_read_admission_is_useful {E : Type} (errors : Errors E) (context : ReadContext)
    (method : Method) (source : List PathSegment) (admitted : RecipeCredentialAdmission.FixedPathAdmitted source) :
    ∃ output, credentialRead errors context method source = .ok output := by
  obtain ⟨path, compiled⟩ := fixed_path_admission_earns_lowering source admitted
  exact ⟨⟨method, context.origin, path, context.headers.versions⟩,
    by simp [credentialRead, NativeCompiler.ReadModel.credential, compiled]⟩

theorem optional_action_admission_is_useful {E : Type} (errors : Errors E) (context : ReadContext)
    (source : Option (List PathSegment))
    (admitted : ∀ path, source = some path → PathCompiler.PathAdmissible context.names (path.map pathSegment)) :
    ∃ output, optionalAction errors context source = .ok output := by
  cases source with
  | none => exact ⟨none, rfl⟩
  | some path =>
      obtain ⟨output, compiled⟩ := action_read_admission_is_useful errors context path (admitted path rfl)
      exact ⟨some output, by simp [optionalAction, compiled]⟩

theorem optional_credential_admission_is_useful {E : Type} (errors : Errors E) (context : ReadContext)
    (source : Option (List PathSegment))
    (admitted : match source with | none => True | some path => RecipeCredentialAdmission.FixedPathAdmitted path) :
    ∃ output, optionalCredential errors context source = .ok output := by
  cases source with
  | none => exact ⟨none, rfl⟩
  | some path =>
      obtain ⟨output, compiled⟩ := credential_read_admission_is_useful errors context .get path admitted
      exact ⟨some output, by simp [optionalCredential, compiled]⟩

theorem denied_reads_admission_is_useful {E : Type} (errors : Errors E) (context : ReadContext)
    (source : List DeniedRead)
    (admitted : ∀ read ∈ source, RecipeCredentialAdmission.FixedPathAdmitted read.path) :
    ∃ output, deniedReads errors context source = .ok output := by
  induction source with
  | nil => exact ⟨[], rfl⟩
  | cons read rest ih =>
      obtain ⟨head, first⟩ := credential_read_admission_is_useful errors context (deniedMethod read) read.path
        (admitted read (by simp))
      obtain ⟨tail, remaining⟩ := ih (fun later member => admitted later (by simp [member]))
      exact ⟨head :: tail, by simp [deniedReads, first, remaining]⟩

/-- Every read in the remaining bundle is constructed from admitted original
paths. The write's original field-name column is shared throughout, including
the response-observation suppression branch and all credential-only reads. -/
theorem remaining_paths_admission_is_useful {E : Type} (errors : Errors E)
    (fields : List FieldProjection.Field) (source : Source) (write : RequestCompiler.Compiled)
    (names : write.names = FieldProjection.names fields) (admitted : ReadPathsAdmissible (FieldProjection.names fields) source) :
    ∃ output, remainingPlans errors fields source write = .ok output ∧ output.fields = fields ∧ output.write = write.plan := by
  let context := readContext write
  have contextNames : context.names = FieldProjection.names fields := names
  have observation : ∃ output, (match source.observation with
      | none => .ok none
      | some path => if path.any responseField then .ok none else (actionRead errors context path).map some) =
        (.ok output : Except E (Option ReadPlan)) := by
    cases present : source.observation with
    | none => exact ⟨none, rfl⟩
    | some path =>
        cases responseAt : path.any responseField with
        | true => exact ⟨none, by simp [responseAt]⟩
        | false =>
            obtain ⟨output, compiled⟩ := action_read_admission_is_useful errors context path
              (by simpa only [contextNames] using admitted.observation path present responseAt)
            exact ⟨some output, by simp [responseAt, compiled]⟩
  obtain ⟨observed, observedAt⟩ := observation
  obtain ⟨preEntry, preEntryAt⟩ := optional_action_admission_is_useful errors context source.preEntry
    (by simpa only [contextNames] using admitted.preEntry)
  obtain ⟨relative, relativeAt⟩ := optional_action_admission_is_useful errors context source.relativeCeiling
    (by simpa only [contextNames] using admitted.relativeCeiling)
  have guardParts :
      (match (guard source.credential).bind Guard.probe with | none => True | some path => RecipeCredentialAdmission.FixedPathAdmitted path) ∧
      (match (guard source.credential).bind Guard.account with | none => True | some path => RecipeCredentialAdmission.FixedPathAdmitted path) ∧
      (∀ read ∈ ((guard source.credential).bind Guard.denied).getD [], RecipeCredentialAdmission.FixedPathAdmitted read.path) := by
    cases present : guard source.credential with
    | none => simp [present]
    | some guard => simpa [GuardPathsAdmissible, present] using admitted.credential
  obtain ⟨probe, probeAt⟩ := optional_credential_admission_is_useful errors context _ guardParts.1
  obtain ⟨account, accountAt⟩ := optional_credential_admission_is_useful errors context _ guardParts.2.1
  obtain ⟨denied, deniedAt⟩ := denied_reads_admission_is_useful errors context _ guardParts.2.2
  exact ⟨⟨fields, write.plan, observed, preEntry, relative, probe, account, denied⟩,
    by simp [remainingPlans, context, observedAt, preEntryAt, relativeAt, probeAt, accountAt, deniedAt], rfl, rfl⟩

/-- A typed admissible write and admitted original reads yield a whole plan
bundle without any expected plan or successful write/read compiler premise. -/
theorem write_and_read_admission_is_useful {E : Type} (errors : Errors E)
    (fields : List FieldProjection.Field) (host : Bytes) (source : Source) (body : TemplateAst.NamedTemplate)
    (named : namedBody errors source.body source.echo = .ok body)
    (writeAdmitted : RequestCompiler.Admissible fields (writeSource source host body))
    (readsAdmitted : ReadPathsAdmissible (FieldProjection.names fields) source) :
    ∃ output, compile errors fields host source = .ok output ∧ output.fields = fields := by
  obtain ⟨write, compiled⟩ := RequestCompiler.compile_complete fields _ writeAdmitted
  have meaning := RequestCompiler.compile_sound fields _ write compiled
  obtain ⟨output, remaining, originalFields, _⟩ := remaining_paths_admission_is_useful errors fields source write
    meaning.names readsAdmitted
  exact ⟨output, by simp [compile, named, compiled, remaining], originalFields⟩

end Auths.Product.RecipePlanModel
