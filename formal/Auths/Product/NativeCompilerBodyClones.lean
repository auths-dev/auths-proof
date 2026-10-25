import Auths.Product.NativeCompilerBodyViews

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000

@[step] theorem native_json_piece_clone_exact (input : NativeJsonPiece) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  cases input with
  | Raw value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact core.clone.CloneU8 value (by intro byte _; rfl)
        as ⟨copied, same⟩
      simpa only [same]
  | Field index =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone.clone,
        core.clone.impls.CloneUsize.clone]
  | Echo => simp [AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone.clone]

theorem native_json_piece_clone_result (input : NativeJsonPiece) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone.clone input = ok input := by
  obtain ⟨actual, run, same⟩ := spec_imp_exists (native_json_piece_clone_exact input)
  simpa only [same] using run

@[step] theorem native_form_piece_clone_exact (input : NativeFormPiece) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  cases input with
  | Raw value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact core.clone.CloneU8 value (by intro byte _; rfl)
        as ⟨copied, same⟩
      simpa only [same]
  | Field index =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone.clone,
        core.clone.impls.CloneUsize.clone]
  | Json pieces =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone
        pieces (by intro piece _; exact native_json_piece_clone_result piece) as ⟨copied, same⟩
      simpa only [same]
  | Echo => simp [AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone.clone]

theorem native_form_piece_clone_result (input : NativeFormPiece) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone.clone input = ok input := by
  obtain ⟨actual, run, same⟩ := spec_imp_exists (native_form_piece_clone_exact input)
  simpa only [same] using run

@[step] theorem native_body_plan_clone_exact (input : NativeBodyPlan) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.BodyPlan.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  cases input with
  | Json pieces =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.BodyPlan.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone
        pieces (by intro piece _; exact native_json_piece_clone_result piece) as ⟨copied, same⟩
      simpa only [same]
  | Form pieces =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.construct.BodyPlan.Insts.CoreCloneClone.clone
      step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone
        pieces (by intro piece _; exact native_form_piece_clone_result piece) as ⟨copied, same⟩
      simpa only [same]

end Auths.Product.NativeCompiler.Refinement
