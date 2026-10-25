import Auths.Product.NativeCompilerBodyEmission
import Auths.Product.TemplateAstShapeCoverage
import Auths.Product.TemplateAstCorrespondence

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open TemplateAst

/-- Useful native acceptance is earned from independent original syntax and
hard resource demand. No compiler success or emitted template is an input. -/
theorem native_admitted_body_compiles (body : KernelBody) (meaning : TemplateAst.Body)
    (original : BodyKernelMeaning body meaning) (echo : Option NativeEcho)
    (admitted : BodyAdmissible meaning (echo.map nativeEchoMeaning)) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.compile_body body echo ⦃ actual =>
      ∃ output, actual = .Ok output ∧ TemplateDomain (nativeTemplate output) ⦄ := by
  obtain ⟨expected, expectedRun⟩ := admitted_body_compiles meaning (echo.map nativeEchoMeaning) admitted
  apply spec_mono (native_compile_body_exact body meaning original echo)
  intro actual exact
  cases actual with
  | Err error => rw [expectedRun] at exact; simp [nativeTemplateResult] at exact
  | Ok output =>
      have compiled : compileBody meaning (echo.map nativeEchoMeaning) = .ok (nativeTemplate output) := by
        simpa only [nativeTemplateResult] using exact.symm
      exact ⟨output, rfl, compile_body_earns_template_domain _ _ _ compiled⟩

theorem native_shape_body_compiles (body : KernelBody) (meaning : TemplateAst.Body)
    (original : BodyKernelMeaning body meaning) (echo : Option NativeEcho)
    (shape : BodyShape meaning (echo.map nativeEchoMeaning)) (nodes : bodyNodes meaning ≤ 64) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.compile_body body echo ⦃ actual =>
      ∃ output, actual = .Ok output ∧ TemplateDomain (nativeTemplate output) ⦄ :=
  native_admitted_body_compiles body meaning original echo
    (bounded_shape_is_admissible meaning (echo.map nativeEchoMeaning) shape nodes)

/-- Successful actual compilation has the independent original-AST named
rendering, including the final modeled body-size/validity result. Actual Rust
argument projection and wire-writer consumption remain outer obligations. -/
theorem native_body_has_original_rendering (body : KernelBody) (meaning : TemplateAst.Body)
    (original : BodyKernelMeaning body meaning) (echo : Option NativeEcho)
    (environment : RequestConstruction.Bytes → Option RequestConstruction.Arg)
    (token : RequestConstruction.Bytes) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.compile_body body echo ⦃ actual =>
      ∀ output, actual = .Ok output → referenceBody meaning (echo.map nativeEchoMeaning) environment token = .ok
        (RequestConstruction.finishNamedBody (renderedTemplate (nativeTemplate output) environment token).valid
          (renderedTemplate (nativeTemplate output) environment token).bytes) ⦄ := by
  apply spec_mono (native_compile_body_exact body meaning original echo)
  intro actual exact output accepted
  rw [accepted] at exact
  exact compiled_body_reference_exact _ _ _ (by simpa only [nativeTemplateResult] using exact.symm) environment token

end Auths.Product.NativeCompiler.Refinement
