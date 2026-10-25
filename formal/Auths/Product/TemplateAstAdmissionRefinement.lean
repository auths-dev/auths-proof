import Auths.Product.TemplateAstShapeCoverage
import Auths.Product.TemplateAstCompilerRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel

namespace Auths.Product.TemplateAst.Refinement

/-- Every independently admitted original JSON/form body returns a concrete
template through the actual public compiler. No native/model success,
expected template, selected source index or validity bit is a caller premise.
Coverage of all native-valid inputs remains a separate required theorem. -/
theorem source_admitted_body_compiles (body : template_ast.Body) (echo : Option template_ast.Echo)
    (admissible : BodyAdmissible (bodyOf body) (echo.map echoOf)) :
    template_ast.compile_body body echo ⦃ actual => ∃ output, actual = .Ok output ∧ TemplateDomain (namedTemplateOf output) ⦄ := by
  obtain ⟨expected, expectedRun⟩ := admitted_body_compiles (bodyOf body) (echo.map echoOf) admissible
  apply spec_mono (compile_body_exact body echo)
  intro actual meaning
  cases actual with
  | Err error =>
    rw [expectedRun] at meaning
    simp [templateResult] at meaning
  | Ok output =>
    have compiled : compileBody (bodyOf body) (echo.map echoOf) = .ok (namedTemplateOf output) := by
      simpa [templateResult] using meaning.symm
    exact ⟨output, rfl, compile_body_earns_template_domain _ _ _ compiled⟩

/-- Original shape rules plus the existing 64-node limit suffice for useful
source compilation. All aggregate budgets and nested piece caps are earned
internally; native validation/JSON/profile provenance must earn the shape. -/
theorem source_bounded_shape_body_compiles (body : template_ast.Body) (echo : Option template_ast.Echo)
    (shape : BodyShape (bodyOf body) (echo.map echoOf)) (nodes : bodyNodes (bodyOf body) ≤ 64) :
    template_ast.compile_body body echo ⦃ actual => ∃ output, actual = .Ok output ∧ TemplateDomain (namedTemplateOf output) ⦄ :=
  source_admitted_body_compiles body echo (bounded_shape_is_admissible (bodyOf body) (echo.map echoOf) shape nodes)

/-- Complete useful scalar-body acceptance from original syntax. Neither a
successful native/model compiler call, expected template, resource-fit flag
nor returned validity bit is an input. This is the scalar shortcut to the
complete source-shape acceptance theorem above. -/
theorem source_leaf_body_admission_compiles (value : template_ast.Value) (admitted : LeafAdmission (valueOf value)) :
    template_ast.compile_body (.Json value) none ⦃ actual => ∃ output, actual = .Ok output ∧ TemplateDomain (namedTemplateOf output) ⦄ := by
  obtain ⟨expected, expectedRun⟩ := admitted_leaf_body_compiles (valueOf value) admitted
  apply spec_mono (compile_body_exact (.Json value) none)
  intro actual meaning
  change templateResult namedTemplateOf actual = compileBody (.json (valueOf value)) none at meaning
  cases actual with
  | Err error =>
    rw [expectedRun] at meaning
    simp [templateResult] at meaning
  | Ok output =>
    have compiled : compileBody (.json (valueOf value)) none = .ok (namedTemplateOf output) := by
      simpa [templateResult] using meaning.symm
    exact ⟨output, rfl, compile_body_earns_template_domain _ _ _ compiled⟩

end Auths.Product.TemplateAst.Refinement
