import Auths.Product.RecipePublicInputBounds
import qualification.aeneas.generated.native_recipe.Funs

/-!
Written against the shipping scalar root newly selected for extraction. The
generated unit must be refreshed from this source at the final generation/
verification stage; no generated definition or inventory is authored here.
This is the size helper, not the full strict-parser/canonicalization caller.
-/
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement

@[step] theorem native_source_lengths_bounded_exact (sourceBytes lockBytes : Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_lengths_bounded sourceBytes lockBytes ⦃ actual =>
      actual = decide (RecipePublicInputBounds.Admitted sourceBytes.val lockBytes.val) ⦄ := by
  simp [AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_lengths_bounded,
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.MAX_SOURCE_BYTES,
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.MAX_LOCK_BYTES,
    RecipePublicInputBounds.Admitted, RecipePublicInputBounds.maximumSourceBytes,
    RecipePublicInputBounds.maximumLockBytes]

theorem native_source_lengths_bounded_acceptance (sourceBytes lockBytes : Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.source_lengths_bounded sourceBytes lockBytes ⦃ actual =>
      actual = true ↔ RecipePublicInputBounds.Admitted sourceBytes.val lockBytes.val ⦄ := by
  apply spec_mono (native_source_lengths_bounded_exact sourceBytes lockBytes)
  intro actual exact
  simp [exact]

end Auths.Product.NativeCompiler.Refinement
