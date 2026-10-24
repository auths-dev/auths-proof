import Auths.Product.RecipeRuleNumericConsequences
import Auths.Product.NativeCompilerRuleSource

/-!
Numeric domains of the actual original native recipe carrier. Complete model
rule admission and the original body relation earn these field-by-field;
serialized bytes, a checked source flag or selected output are not premises.
This is native-data/model correspondence, not actual rule/serde call adequacy.
-/
namespace Auths.Product.NativeCompiler
open AuthsNativeRecipe.recipe

inductive AstIntegersSafe : SourceAst → Prop where
  | text (value : String) : AstIntegersSafe (.String value)
  | integer (value : Aeneas.Std.I64) (safe : value.val.natAbs ≤ 9007199254740991) : AstIntegersSafe (.Integer value)
  | boolean (value : Bool) : AstIntegersSafe (.Boolean value)
  | field (name : String) : AstIntegersSafe (.Field name)
  | array (values : NativeVec SourceAst) (each : ∀ value ∈ values.val, AstIntegersSafe value) : AstIntegersSafe (.Array values)
  | object (members : SourceMap SourceAst) (each : ∀ member ∈ members.entries.val, AstIntegersSafe member.2) :
      AstIntegersSafe (.Object members)

def FormIntegersSafe : SourceForm → Prop
  | .String _ | .Field _ => True
  | .Json value => AstIntegersSafe value
  | .Echo => False

def BodyIntegersSafe : SourceBody → Prop
  | .Json value => AstIntegersSafe value
  | .Form members => ∀ member ∈ members.entries.val, FormIntegersSafe member.2

mutual
  theorem original_ast_earns_safe_integers {input : SourceAst} {model : TemplateAst.Value}
      (original : AstSourceMeaning input model) (safe : RecipeRuleAdmission.JsonIntegersSafe model) : AstIntegersSafe input := by
    cases original with
    | text value => exact .text value
    | integer value => cases safe with | integer literal bounded => exact .integer value bounded
    | boolean value => exact .boolean value
    | field name => exact .field name
    | echo => cases safe
    | array children =>
        cases safe with
        | array values each => exact .array _ (original_ast_values_earn_safe_integers children each)
    | object children =>
        cases safe with
        | object members each => exact .object _ (original_ast_members_earn_safe_integers children each)
  termination_by structural original

  theorem original_ast_values_earn_safe_integers {inputs : List SourceAst} {models : List TemplateAst.Value}
      (original : AstSourceValuesMeaning inputs models) (safe : ∀ model ∈ models, RecipeRuleAdmission.JsonIntegersSafe model) :
      ∀ input ∈ inputs, AstIntegersSafe input := by
    cases original with
    | nil => simp
    | cons head tail =>
        intro input present
        rcases List.mem_cons.mp present with rfl | later
        · exact original_ast_earns_safe_integers head (safe _ (by simp))
        · exact original_ast_values_earn_safe_integers tail
            (fun model member => safe model (List.mem_cons_of_mem _ member)) input later
  termination_by structural original

  theorem original_ast_members_earn_safe_integers {inputs : List (String × SourceAst)}
      {models : List (List Nat × TemplateAst.Value)} (original : AstSourceMembersMeaning inputs models)
      (safe : ∀ model ∈ models, RecipeRuleAdmission.JsonIntegersSafe model.2) :
      ∀ input ∈ inputs, AstIntegersSafe input.2 := by
    cases original with
    | nil => simp
    | cons head tail =>
        intro input present
        rcases List.mem_cons.mp present with rfl | later
        · exact original_ast_earns_safe_integers head (safe _ (by simp))
        · exact original_ast_members_earn_safe_integers tail
            (fun model member => safe model (List.mem_cons_of_mem _ member)) input later
  termination_by structural original
end

theorem original_form_earns_safe_integers {input : SourceForm} {model : TemplateAst.FormValue}
    (original : FormSourceMeaning input model) (safe : RecipeRuleAdmission.FormIntegersSafe model) : FormIntegersSafe input := by
  cases original with
  | text value | field name => trivial
  | echo => exact False.elim safe
  | json child => exact original_ast_earns_safe_integers child safe

theorem original_form_members_earn_safe_integers {inputs : List (String × SourceForm)}
    {models : List (List Nat × TemplateAst.FormValue)} (original : List.Forall₂ SourceFormMemberMeaning inputs models)
    (safe : ∀ model ∈ models, RecipeRuleAdmission.FormIntegersSafe model.2) :
    ∀ input ∈ inputs, FormIntegersSafe input.2 := by
  revert safe
  induction original with
  | nil => intro _; simp
  | cons head tail ih =>
      intro safe input present
      rcases List.mem_cons.mp present with rfl | later
      · exact original_form_earns_safe_integers head.2 (safe _ (by simp))
      · exact ih (fun model member => safe model (List.mem_cons_of_mem _ member)) input later

theorem original_body_earns_safe_integers {input : SourceBody} {model : TemplateAst.Body}
    (original : BodySourceMeaning input model) (safe : RecipeRuleAdmission.BodyIntegersSafe model) : BodyIntegersSafe input := by
  cases original with
  | json child => exact original_ast_earns_safe_integers child safe
  | form children => exact original_form_members_earn_safe_integers children safe

def PathNumbersSafe (path : NativeVec NativePathSource) : Prop :=
  ∀ segment ∈ path.val, match segment with
    | .ResponseField _ maximum => 1 ≤ maximum.val ∧ maximum.val ≤ 255
    | _ => True

theorem original_rule_path_earns_numeric_bounds (path : NativeVec NativePathSource)
    (safe : RecipeRuleAdmission.PathNumbersSafe (path.val.map ruleSegment)) : PathNumbersSafe path := by
  intro segment present
  have original := safe (ruleSegment segment) (List.mem_map.mpr ⟨segment, present, rfl⟩)
  cases segment <;> simpa only [ruleSegment] using original

theorem original_fixed_path_has_no_numeric_response (path : NativeVec NativePathSource)
    (fixed : RecipeCredentialAdmission.FixedPathAdmitted (path.val.map planPathSegment)) : PathNumbersSafe path := by
  obtain ⟨values, original, _, _, _⟩ := RecipeCredentialAdmission.fixed_paths_earn_original_bounds _ fixed
  intro segment present
  have mapped : planPathSegment segment ∈ values.map RecipePlanModel.PathSegment.fixed := by
    rw [← original]
    exact List.mem_map.mpr ⟨segment, present, rfl⟩
  cases segment with
  | Fixed value | Field name | Echo => trivial
  | ResponseField pointer maximum =>
      obtain ⟨value, _, impossible⟩ := List.mem_map.mp mapped
      cases impossible

structure GuardNumericDomain (guard : NativeGuardSource) : Prop where
  probe : ∀ probe, guard.probe = some probe → PathNumbersSafe probe.path ∧
    RecipeAdmissionAtoms.ReadBound probe.maximum_response_bytes.val ∧
    RecipeCredentialAdmission.ProbeLiteralAdmitted (ruleProbeLiteral probe.equals)
  account : ∀ account, guard.account = some account → PathNumbersSafe account.path ∧
    RecipeAdmissionAtoms.ReadBound account.maximum_response_bytes.val
  denied : ∀ reads, guard.denied_reads = some reads → ∀ read ∈ reads.val,
    PathNumbersSafe read.path ∧ ∀ status ∈ read.refused_status.val, RecipeAdmissionAtoms.RefusedStatus status.val

theorem admitted_original_guard_earns_numeric_domain (guard : NativeGuardSource)
    (paths : RecipeCredentialAdmission.SourcePaths) (admitted : RecipeCredentialAdmission.GuardAdmitted (ruleGuard guard) paths) :
    GuardNumericDomain guard := by
  refine ⟨?_, ?_, ?_⟩
  · intro probe present
    have checked : RecipeCredentialAdmission.ProbeAdmitted {
        path := probe.path.val.map planPathSegment, pointer := textBytes probe.json_pointer,
        maximumResponseBytes := probe.maximum_response_bytes.val, equals := ruleProbeLiteral probe.equals} := by
      simpa only [ruleGuard, present, Option.map_some, RecipeCredentialAdmission.OptionalAdmitted] using admitted.2.1
    exact ⟨original_fixed_path_has_no_numeric_response probe.path checked.1, checked.2.2.2, checked.2.2.1⟩
  · intro account present
    have checked : RecipeCredentialAdmission.ReadAdmitted
        ⟨account.path.val.map planPathSegment, textBytes account.json_pointer, account.maximum_response_bytes.val⟩ := by
      simpa only [ruleGuard, present, Option.map_some, RecipeCredentialAdmission.OptionalAdmitted] using admitted.2.2.1
    exact ⟨original_fixed_path_has_no_numeric_response account.path checked.1, checked.2.2⟩
  · intro reads present read member
    have checked := admitted.2.2.2
    simp only [ruleGuard, present, Option.map_some, RecipeCredentialAdmission.OptionalAdmitted] at checked
    have original := checked.2.2.1
      ⟨textBytes read.method, read.path.val.map planPathSegment, read.refused_status.val.map (·.val)⟩
      (List.mem_map.mpr ⟨read, member, rfl⟩)
    refine ⟨original_fixed_path_has_no_numeric_response read.path original.2.1, ?_⟩
    intro status belongs
    exact original.2.2.2.2.2 status.val (List.mem_map.mpr ⟨status, belongs, rfl⟩)

def nativeRetention : source.IdempotencySource → Nat
  | .DerivedHeader seconds | .OperationIdField _ seconds => seconds.val

theorem original_retention_is_preserved (input : source.IdempotencySource) :
    RecipeRuleAdmission.retention (planIdempotency input) = nativeRetention input := by cases input <;> rfl

structure SourceNumericDomain (source : NativeRecipeSource) : Prop where
  body : BodyIntegersSafe source.write.body
  writePath : PathNumbersSafe source.write.path
  idempotency : ∀ current, source.write.idempotency = some current →
    1 ≤ nativeRetention current ∧ nativeRetention current ≤ 2592000
  observation : ∀ current, source.observation = some current → PathNumbersSafe current.path ∧
    RecipeAdmissionAtoms.ReadBound current.maximum_response_bytes.val
  preEntry : ∀ current, source.pre_entry = some current → PathNumbersSafe current.path ∧
    RecipeAdmissionAtoms.ReadBound current.maximum_response_bytes.val
  relativeCeiling : ∀ current, source.relative_ceiling = some current →
    (1 ≤ current.basis_points.val ∧ current.basis_points.val ≤ 10000) ∧
    RecipeAdmissionAtoms.ReadBound current.maximum_response_bytes.val ∧ PathNumbersSafe current.path
  guard : ∀ current, originalGuard source.credential = some current → GuardNumericDomain current

/-- The original whole source-rule result earns every original native numeric
domain, including all body children, read paths, optional counters and guard
branches. No separately supplied checked numeric record is used. -/
theorem complete_original_rules_earn_native_numeric_domain (fields : RecipeRuleAdmission.Fields)
    (source : NativeRecipeSource) (body : TemplateAst.Body) (original : BodySourceMeaning source.write.body body)
    (admitted : (RecipeRuleAdmission.validate fields (ruleSource source body)).1 = .ok ()) : SourceNumericDomain source := by
  have safe := RecipeRuleAdmission.complete_rules_success_earns_all_numeric_domains fields (ruleSource source body) admitted
  refine ⟨original_body_earns_safe_integers original safe.body,
    original_rule_path_earns_numeric_bounds source.write.path safe.writePath, ?_, ?_, ?_, ?_, ?_⟩
  · intro current present
    have checked := safe.idempotency (planIdempotency current) (by simp [ruleSource, present])
    simpa only [original_retention_is_preserved] using checked
  · intro current present
    have checked := safe.observation (ruleObservation current) (by simp [ruleSource, present])
    exact ⟨original_rule_path_earns_numeric_bounds current.path checked.1, checked.2⟩
  · intro current present
    have checked := safe.preEntry (rulePreEntry current) (by simp [ruleSource, present])
    exact ⟨original_rule_path_earns_numeric_bounds current.path checked.1, checked.2⟩
  · intro current present
    have checked := safe.relativeCeiling (ruleRelativeCeiling current) (by simp [ruleSource, present])
    exact ⟨checked.1, checked.2.1, original_rule_path_earns_numeric_bounds current.path checked.2.2⟩
  · intro current present
    exact admitted_original_guard_earns_numeric_domain current _
      (safe.guard (ruleGuard current) (by simp [ruleSource, present]))

end Auths.Product.NativeCompiler
