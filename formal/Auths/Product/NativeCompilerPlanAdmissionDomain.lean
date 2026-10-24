import Auths.Product.NativeCompilerConstructorAdmission
import Auths.Product.NativeCompilerPlans
import Auths.Product.RecipeRuleAdmissionConsequences

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

theorem rule_path_representation_earns_plan_representation (segment : NativePathSource)
    (fits : RulePathFits segment) : NativePathFits segment := by
  cases segment <;> simp_all [RulePathFits, NativePathFits]

/-- An admitted original guard path contains only the same complete fixed
byte strings. This earns lowering's String domain even for source variants
whose Field payload was deliberately not read by guard validation. -/
theorem admitted_guard_path_earns_plan_representation (path : List NativePathSource)
    (admitted : RecipeCredentialAdmission.FixedPathAdmitted (path.map planPathSegment)) :
    ∀ segment ∈ path, NativePathFits segment := by
  obtain ⟨values, original, _, _, literals⟩ :=
    RecipeCredentialAdmission.fixed_paths_earn_original_bounds _ admitted
  intro segment member
  have projected : planPathSegment segment ∈ values.map RecipePlanModel.PathSegment.fixed := by
    rw [← original]
    exact List.mem_map.mpr ⟨segment, member, rfl⟩
  obtain ⟨value, belongs, same⟩ := List.mem_map.mp projected
  cases segment with
  | Fixed text =>
      have bytesAt : value = textBytes text := by simpa [planPathSegment] using same
      have length : text.toByteArray.size ≤ 128 := by
        simpa [bytesAt, textBytes] using (literals value belongs).2.1
      unfold NativePathFits TextFits
      scalar_tac
  | Field name => simp [planPathSegment] at same
  | ResponseField pointer maximum => simp [planPathSegment] at same
  | Echo => simp [planPathSegment] at same

theorem admitted_guard_earns_plan_paths (guard : NativeGuardSource)
    (source : RecipeCredentialAdmission.SourcePaths) (fits : GuardAdmissionFits guard)
    (admitted : RecipeCredentialAdmission.GuardAdmitted (ruleGuard guard) source) : GuardPathsFit guard := by
  refine ⟨?_, ?_, ?_⟩
  · intro probe present
    have policy : RecipeCredentialAdmission.ProbeAdmitted {
        path := probe.path.val.map planPathSegment
        pointer := textBytes probe.json_pointer
        maximumResponseBytes := probe.maximum_response_bytes.val
        equals := ruleProbeLiteral probe.equals } := by
      simpa [ruleGuard, present, RecipeCredentialAdmission.OptionalAdmitted] using admitted.2.1
    exact admitted_guard_path_earns_plan_representation probe.path.val policy.1
  · intro account present
    have policy : RecipeCredentialAdmission.ReadAdmitted
        ⟨account.path.val.map planPathSegment, textBytes account.json_pointer, account.maximum_response_bytes.val⟩ := by
      simpa [ruleGuard, present, RecipeCredentialAdmission.OptionalAdmitted] using admitted.2.2.1
    exact admitted_guard_path_earns_plan_representation account.path.val policy.1
  · intro reads present read member
    have policy : RecipeCredentialAdmission.DeniedReadsAdmitted
        (reads.val.map ruleGuardDeniedRead) (RecipeCredentialAdmission.guardReserved (ruleGuard guard) source) := by
      simpa [ruleGuard, present, ruleGuardDeniedRead, RecipeCredentialAdmission.OptionalAdmitted] using admitted.2.2.2
    have readPolicy := policy.2.2.1 (ruleGuardDeniedRead read) (List.mem_map.mpr ⟨read, member, rfl⟩)
    exact ⟨(fits.denied reads present read member).1,
      admitted_guard_path_earns_plan_representation read.path.val readPolicy.2.1⟩

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

/-- Real constructor success earns the lowering domain from its original
source checks and parsed host. In particular no bounded checked-record,
successful lowering, chosen field table or admitted guard is a premise.
This is a representation domain, not an allocator or total-cost theorem. -/
theorem native_constructor_success_earns_plan_input_domain (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema)
    (schemaMeaning : JsonMeaning lock.command_schema schema) (body : TemplateAst.Body)
    (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source)
    (checked : NativeConstructorRecord)
    (completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    PlanInputFits checked := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  obtain ⟨_, fields, _, _, rules⟩ := native_constructor_success_earns_complete_rules source lock canonical
    checked schemaBounds schema schemaMeaning body bodyMeaning fits.rules completed
  have headerGuard := RecipeRuleAdmission.complete_rules_success_earns_header_guard _ _ rules
  have originalGuardPolicy := RecipeRuleAdmission.header_guard_success_earns_original_guard _ headerGuard
  obtain ⟨parsed, _, origin⟩ := native_constructor_success_earns_origin source lock canonical fits.origin checked completed
  have hostBound := (RecipeOriginAdmission.parsed_origin_retains_exact_host _ _ _ origin).2.2
  have hostSize : checked.parsed_host.toByteArray.size ≤ 253 := by
    simpa [textBytes] using hostBound
  refine {
    origin := by simpa only [trace.originalSource] using fits.origin
    host := by scalar_tac
    body := by simpa only [trace.originalSource] using fits.rules.write.2.1
    echo := ?_
    writePath := ?_
    headers := ?_
    observation := ?_
    preEntry := ?_
    relativeCeiling := ?_
    credential := ?_
  }
  · rw [trace.originalSource]
    intro echo present
    exact (fits.rules.response.echo echo present).2
  · rw [trace.originalSource]
    intro segment member
    exact rule_path_representation_earns_plan_representation segment (fits.rules.write.1 segment member)
  · rw [trace.originalSource]
    constructor
    · cases present : source.provider_headers with
      | none => trivial
      | some headers => exact fits.rules.headers.headers headers present
    · cases present : source.account_scope with
      | none => trivial
      | some scope => exact fits.rules.scope scope present
  · rw [trace.originalSource]
    intro read present segment member
    exact rule_path_representation_earns_plan_representation segment
      ((fits.rules.response.observation read present).1 segment member)
  · rw [trace.originalSource]
    intro read present segment member
    exact rule_path_representation_earns_plan_representation segment
      ((fits.rules.response.preEntry read present).1 segment member)
  · rw [trace.originalSource]
    intro read present segment member
    exact rule_path_representation_earns_plan_representation segment
      ((fits.rules.facts.relative read present).2.2.2.2 segment member)
  · rw [trace.originalSource]
    intro guard present
    have policy : RecipeCredentialAdmission.GuardAdmitted (ruleGuard guard) (ruleGuardSourcePaths source) := by
      have projected := originalGuardPolicy (ruleGuard guard) (by simp [ruleSource, present])
      simpa only [← original_guard_reservation_paths source body] using projected
    exact admitted_guard_earns_plan_paths guard _ (fits.rules.headers.guard guard present) policy

/-- Total constructor refinement strengthened with an earned plan domain.
The actual successful run is obtained from the total relation; it is not a
caller premise. An implementation failure/divergence contradicts that relation. -/
@[step] theorem native_constructor_admission_with_plan_domain (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock)
    (hashRoom : NativeCanonicalFits 0 canonical.schema) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.validate constructorErrors hash
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual ∧
        ∀ checked, actual = .Ok checked → PlanInputFits checked ⦄ := by
  have total := native_constructor_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits hashRoom
  cases run : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical with
  | fail error => simp [run] at total
  | div => simp [run] at total
  | ok actual =>
      have facts : constructorOutcome actual = RecipeConstructorAdmission.validate constructorErrors hash
          (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
          (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual := by
        simpa [run] using total
      obtain ⟨semantic, frame⟩ := facts
      simp only [run, spec_ok]
      refine ⟨semantic, frame, ?_⟩
      intro checked accepted
      have completed : AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = ok (.Ok checked) := by
        simpa only [accepted] using run
      exact native_constructor_success_earns_plan_input_domain source lock canonical schema schemaBounds schemaMeaning
        body bodyMeaning fits checked completed

end Auths.Product.NativeCompiler.Refinement
