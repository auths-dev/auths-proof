import Auths.Product.RecipeRulePathAdmission
import Auths.Product.RecipePlanReadAdmission

namespace Auths.Product.RecipeRuleAdmission
open NativeCompiler RecipeConsumption RequestConstruction
set_option maxHeartbeats 20000000
set_option maxRecDepth 4096

def guardPlanView (guard : RecipeCredentialAdmission.Guard) : RecipePlanModel.Guard := {
  probe := guard.probe.map (·.path)
  account := guard.account.map (·.path)
  denied := guard.denied.map (fun reads => reads.map fun read => ⟨read.method, read.path⟩)
}

/-- Exact original-data links for the columns considered here. Body, method,
echo placement and other policy columns have separate admission obligations;
these links cannot substitute an unrelated path, header or credential guard. -/
structure PlanPathLinks (source : Source) (lowering : RecipePlanModel.Source) : Prop where
  write : lowering.path = source.writePath.map originalSegment
  observation : lowering.observation = source.observation.map (fun read => read.path.map originalSegment)
  preEntry : lowering.preEntry = source.preEntry.map (fun read => read.path.map originalSegment)
  relativeCeiling : lowering.relativeCeiling = source.relativeCeiling.map (fun read => read.path.map originalSegment)
  versions : lowering.versions = source.providerHeaders
  scope : lowering.scope = source.scope.map (fun scope => ⟨scope.header, textBytes scope.field⟩)
  credential : RecipePlanModel.guard lowering.credential = source.guard.map guardPlanView

theorem segment_response_projection (segment : Segment) :
    RecipePlanModel.responseField (originalSegment segment) = isResponseField segment := by
  cases segment <;> rfl

theorem admitted_guard_has_plan_paths (guard : RecipeCredentialAdmission.Guard)
    (source : RecipeCredentialAdmission.SourcePaths) (admitted : RecipeCredentialAdmission.GuardAdmitted guard source) :
    RecipePlanModel.GuardPathsAdmissible (some (guardPlanView guard)) := by
  refine ⟨?_, ?_, ?_⟩
  · cases present : guard.probe with
    | none => trivial
    | some probe =>
        have policy : RecipeCredentialAdmission.ProbeAdmitted probe := by
          simpa [RecipeCredentialAdmission.OptionalAdmitted, present] using admitted.2.1
        exact policy.1
  · cases present : guard.account with
    | none => trivial
    | some account =>
        have policy : RecipeCredentialAdmission.ReadAdmitted account := by
          simpa [RecipeCredentialAdmission.OptionalAdmitted, present] using admitted.2.2.1
        exact policy.1
  · cases present : guard.denied with
    | none => simp [guardPlanView, present]
    | some reads =>
        have policy : RecipeCredentialAdmission.DeniedReadsAdmitted reads
            (RecipeCredentialAdmission.guardReserved guard source) := by
          simpa [RecipeCredentialAdmission.OptionalAdmitted, present] using admitted.2.2.2
        intro projected member
        have originalMember : projected ∈ reads.map (fun read => (⟨read.method, read.path⟩ : RecipePlanModel.DeniedRead)) := by
          simpa [guardPlanView, present] using member
        obtain ⟨read, readMember, same⟩ := List.mem_map.mp originalMember
        subst projected
        exact (policy.2.2.1 read readMember).2.1

theorem header_guard_success_earns_versions (source : Source)
    (admitted : headerGuardRules source = .ok ()) :
    ∀ headers, source.providerHeaders = some headers → HeaderCompiler.VersionsValid headers := by
  intro headers present
  by_contra refused
  simp [headerGuardRules, present, refused] at admitted

/-- Write/read path and header conditions are earned from complete original
rule admission and the actual original field/map relation. Method, origin and
body/echo obligations remain separate. Observation response
paths are retained as source data and omitted by the initial plan branch;
ordinary observations must earn a lowerable original path. -/
theorem complete_rules_earn_plan_path_admission (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (source : Source) (lowering : RecipePlanModel.Source) (links : PlanPathLinks source lowering)
    (admitted : (validate fields source).1 = .ok ()) :
    PathCompiler.PathAdmissible (FieldProjection.names original) (lowering.path.map RecipePlanModel.pathSegment) ∧
      HeaderCompiler.HeaderAdmissible (FieldProjection.names original) lowering.versions lowering.scope ∧
      RecipePlanModel.ReadPathsAdmissible (FieldProjection.names original) lowering := by
  have stages := complete_rules_from_success_earns_stage_verdicts fields source empty admitted
  obtain ⟨written, responded, facts, headers, bounds⟩ := stages
  have responsePaths := response_rules_success_earns_read_paths fields source _ responded
  have relativePaths := fact_rules_success_earns_relative_path fields source _ facts
  have scopePolicy := bound_rules_success_earns_scope fields source _ bounds
  have guardPolicy := header_guard_success_earns_original_guard source headers
  have namesBound : (FieldProjection.names original).length ≤ 32 := by simpa [FieldProjection.names] using layout.1
  refine ⟨?_, ?_, ?_⟩
  · rw [links.write]
    exact closed_role_path_has_plan_admission original fields layout meaning .write rfl _ empty
      (write_rules_success_earns_path fields source empty written)
  · constructor
    · rw [links.versions]
      cases present : source.providerHeaders with
      | none => trivial
      | some values => exact header_guard_success_earns_versions source headers values present
    · rw [links.scope]
      cases present : source.scope with
      | none => trivial
      | some scope =>
          obtain ⟨header, field⟩ := scopePolicy scope present
          obtain ⟨token, named⟩ := field_test_earns_original_plan_name original fields layout meaning pathSchema scope.field field
          exact ⟨header, namesBound, token, named⟩
  · refine ⟨?_, ?_, ?_, ?_⟩
    · intro path present ordinary
      have originalAt := links.observation.symm.trans present
      cases selected : source.observation with
      | none => simp [selected] at originalAt
      | some read =>
          have same : read.path.map originalSegment = path := by simpa [selected] using originalAt
          subst path
          obtain ⟨before, checked⟩ := responsePaths.1 read selected
          apply path_without_response_has_plan_admission original fields layout meaning .observation read.path before checked
          simpa [List.any_map, Function.comp_def, segment_response_projection] using ordinary
    · intro path present
      have originalAt := links.preEntry.symm.trans present
      cases selected : source.preEntry with
      | none => simp [selected] at originalAt
      | some read =>
          have same : read.path.map originalSegment = path := by simpa [selected] using originalAt
          subst path
          obtain ⟨before, checked⟩ := responsePaths.2 read selected
          exact closed_role_path_has_plan_admission original fields layout meaning .preEntry rfl read.path before checked
    · intro path present
      have originalAt := links.relativeCeiling.symm.trans present
      cases selected : source.relativeCeiling with
      | none => simp [selected] at originalAt
      | some read =>
          have same : read.path.map originalSegment = path := by simpa [selected] using originalAt
          subst path
          exact closed_role_path_has_plan_admission original fields layout meaning .relativeCeiling rfl read.path _
            (relativePaths read selected)
    · rw [links.credential]
      cases selected : source.guard with
      | none => trivial
      | some guard => exact admitted_guard_has_plan_paths guard (paths source) (guardPolicy guard selected)

end Auths.Product.RecipeRuleAdmission
