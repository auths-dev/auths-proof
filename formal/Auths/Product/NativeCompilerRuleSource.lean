import Auths.Product.RecipeRuleAdmission
import Auths.Product.NativeCompilerPlanInputs

open Aeneas Aeneas.Std

namespace Auths.Product.NativeCompiler

def ruleSegment : NativePathSource → RecipeRuleAdmission.Segment
  | .Fixed value => .fixed value
  | .Field name => .field name
  | .ResponseField pointer maximum => .responseField (textBytes pointer) maximum.val
  | .Echo => .echo

def ruleObservation (source : AuthsNativeRecipe.recipe.source.ObservationSource) : RecipeRuleAdmission.Observation :=
  ⟨source.path.val.map ruleSegment, textBytes source.json_pointer, source.expected_field,
    source.maximum_response_bytes.val⟩

def rulePreEntry (source : AuthsNativeRecipe.recipe.source.PreEntrySource) : RecipeRuleAdmission.PreEntry :=
  ⟨source.path.val.map ruleSegment, source.pointers.val.map textBytes, source.maximum_response_bytes.val⟩

def rulePreconditions (source : AuthsNativeRecipe.recipe.source.PreconditionSource) : RecipeRuleAdmission.Preconditions :=
  ⟨source.read_back_subject, source.verified.val⟩

def ruleBind (source : AuthsNativeRecipe.recipe.source.BindSource) : RecipeRuleAdmission.Bind :=
  ⟨textBytes source.pointer, source.field⟩

def ruleRelativeCeiling (source : AuthsNativeRecipe.recipe.source.RelativeCeilingSource) : RecipeRuleAdmission.RelativeCeiling := {
  argument := source.argument
  basisPoints := source.basis_points.val
  maximum := source.maximum_response_bytes.val
  pointer := textBytes source.json_pointer
  subtract := source.subtract_pointer.map textBytes
  binds := source.bind.map (fun binds => binds.val.map ruleBind)
  path := source.path.val.map ruleSegment
}

def ruleScope (source : AuthsNativeRecipe.recipe.source.AccountScopeSource) : RecipeRuleAdmission.Scope :=
  ⟨textBytes source.header, source.field⟩

def ruleBounds (source : AuthsNativeRecipe.recipe.source.BoundsSource) : RecipeRuleAdmission.Bounds :=
  ⟨source.sum.map (fun sum => ⟨sum.argument, sum.partition⟩)⟩

def ruleProbeLiteral : Json → RecipeCredentialAdmission.Literal
  | .Bool value => .boolean value
  | .String value => .text (textBytes value)
  | .Number (.PosInt value) => .integer (Int.ofNat value.val)
  | .Number (.NegInt value) => .integer value.val
  | .Number (.Float _) | .Null | .Array _ | .Object _ => .unsupported

def ruleGuard (source : NativeGuardSource) : RecipeCredentialAdmission.Guard := {
  prefixes := source.prefixes.val.map textBytes
  probe := source.probe.map (fun probe => {
    path := probe.path.val.map planPathSegment
    pointer := textBytes probe.json_pointer
    maximumResponseBytes := probe.maximum_response_bytes.val
    equals := ruleProbeLiteral probe.equals
  })
  account := source.account.map (fun account =>
    ⟨account.path.val.map planPathSegment, textBytes account.json_pointer, account.maximum_response_bytes.val⟩)
  denied := source.denied_reads.map (fun reads => reads.val.map fun read =>
    ⟨textBytes read.method, read.path.val.map planPathSegment, read.refused_status.val.map (·.val)⟩)
}

/-- All source policy columns are projected. The body argument must separately
have the complete existing `BodySourceMeaning` relation to this same source;
no selected child, compiled AST, admission flag or expected plan replaces it. -/
def ruleSource (source : NativeRecipeSource) (body : TemplateAst.Body) : RecipeRuleAdmission.Source := {
  writePath := source.write.path.val.map ruleSegment
  body
  idempotency := source.write.idempotency.map planIdempotency
  observation := source.observation.map ruleObservation
  echo := source.echo.map (fun echo => ⟨textBytes echo.observe, planEchoSource echo.write⟩)
  preEntry := source.pre_entry.map rulePreEntry
  relativeCeiling := source.relative_ceiling.map ruleRelativeCeiling
  preconditions := source.preconditions.map rulePreconditions
  providerHeaders := source.provider_headers.map originalHeaders
  guard := (originalGuard source.credential).map ruleGuard
  scope := source.account_scope.map ruleScope
  bounds := source.bounds.map ruleBounds
}

theorem rule_segment_has_original_plan_meaning (source : NativePathSource) :
    RecipeRuleAdmission.originalSegment (ruleSegment source) = planPathSegment source := by
  cases source <;> rfl

theorem rule_source_has_original_guard_paths (source : NativeRecipeSource) (body : TemplateAst.Body) :
    RecipeRuleAdmission.paths (ruleSource source body) = {
      write := planPath source.write.path
      observation := source.observation.map (fun read => planPath read.path)
      preEntry := source.pre_entry.map (fun read => planPath read.path)
      relativeCeiling := source.relative_ceiling.map (fun read => planPath read.path)
    } := by
  simp [RecipeRuleAdmission.paths, ruleSource, ruleObservation, rulePreEntry, ruleRelativeCeiling,
    planPath, List.map_map, Function.comp_def, rule_segment_has_original_plan_meaning]

end Auths.Product.NativeCompiler
