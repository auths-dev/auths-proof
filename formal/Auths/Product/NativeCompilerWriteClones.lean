import Auths.Product.NativeCompilerBodyClones
import Auths.Product.NativeCompilerPlanClones

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler
abbrev NativeWritePlan := AuthsNativeRecipe.auths_gateway_kernel.construct.WritePlan
end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000

@[step] theorem native_named_json_clone_exact (input : NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  cases input with
  | Raw value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact core.clone.CloneU8 value (by intro byte _; rfl)
        as ⟨copied, same⟩
      simpa only [same]
  | Field name =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact core.clone.CloneU8 name (by intro byte _; rfl)
        as ⟨copied, same⟩
      simpa only [same]
  | Echo => simp [AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece.Insts.CoreCloneClone.clone]

theorem native_named_json_clone_result (input : NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece.Insts.CoreCloneClone.clone input = ok input := by
  obtain ⟨actual, run, same⟩ := spec_imp_exists (native_named_json_clone_exact input)
  simpa only [same] using run

@[step] theorem native_named_form_clone_exact (input : NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  cases input with
  | Raw value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact core.clone.CloneU8 value (by intro byte _; rfl)
        as ⟨copied, same⟩
      simpa only [same]
  | Field name =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact core.clone.CloneU8 name (by intro byte _; rfl)
        as ⟨copied, same⟩
      simpa only [same]
  | Json pieces =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece.Insts.CoreCloneClone
        pieces (by intro piece _; exact native_named_json_clone_result piece) as ⟨copied, same⟩
      simpa only [same]
  | Echo => simp [AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece.Insts.CoreCloneClone.clone]

theorem native_named_form_clone_result (input : NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece.Insts.CoreCloneClone.clone input = ok input := by
  obtain ⟨actual, run, same⟩ := spec_imp_exists (native_named_form_clone_exact input)
  simpa only [same] using run

@[step] theorem native_named_template_clone_exact (input : NativeNamedTemplate) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  cases input with
  | Json pieces =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece.Insts.CoreCloneClone
        pieces (by intro piece _; exact native_named_json_clone_result piece) as ⟨copied, same⟩
      simpa only [same]
  | Form pieces =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece.Insts.CoreCloneClone
        pieces (by intro piece _; exact native_named_form_clone_result piece) as ⟨copied, same⟩
      simpa only [same]

@[step] theorem native_write_plan_clone_exact (input : NativeWritePlan) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.WritePlan.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.WritePlan.Insts.CoreCloneClone.clone
    AuthsNativeRecipe.auths_gateway_kernel.construct.RequestMethod.Insts.CoreCloneClone.clone
  step with native_vector_clone_exact core.clone.CloneU8 input.origin (by intro byte _; rfl)
    as ⟨origin, originMeaning⟩
  step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.SegmentPlan.Insts.CoreCloneClone
    input.path (by
      intro segment _
      obtain ⟨actual, run, same⟩ := spec_imp_exists (native_segment_clone_exact segment)
      simpa only [same] using run) as ⟨path, pathMeaning⟩
  step with native_header_plan_clone_exact input.headers as ⟨headers, headersMeaning⟩
  step with native_option_clone_exact (AuthsNativeRecipe.core.clone.CloneallocvecVec core.clone.CloneU8)
    input.idempotency_header (by intro name _; exact native_vector_clone_result core.clone.CloneU8 name (by intro byte _; rfl))
    as ⟨idempotency, idempotencyMeaning⟩
  step with native_body_plan_clone_exact input.body as ⟨body, bodyMeaning⟩
  cases input
  simp_all

end Auths.Product.NativeCompiler.Refinement
