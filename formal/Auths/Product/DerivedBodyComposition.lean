import Auths.Product.BodyCompilerComposition
import Auths.Product.DerivedTokensRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement
open Auths.Product.FieldProjection
open Auths.Product.FieldProjection.Refinement

namespace Auths.Product.BodyCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-- The actual fixed-digest echo encoder feeds the actual compiler/projector/
writer composition. The echo-size bound is earned from source output; there
is no template/value/alignment/success/size premise. Native hash selection,
ASCII-to-String adaptation, sealed provenance and full AST meaning remain
separate caller boundaries. -/
theorem source_json_body_with_derived_echo (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (source : Slice body_compiler.NamedJsonPiece)
    (digest : Array Std.U8 32#usize) :
    (do
      let echo ← derived_tokens.echo_token_bytes digest
      let compiledNames ← field_projection.field_names fields
      match compiledNames with
      | .Err _ => ok none
      | .Ok compiledNames => do
        let plan ← body_compiler.lower_json (alloc.vec.Vec.deref compiledNames) source
        match plan with
        | .Err _ => ok none
        | .Ok plan => do
          let projected ← field_projection.project_object fields supplied
          match projected with
          | .Err _ => ok none
          | .Ok values => do
            let bytes ← construct.build_body (.Json plan) (alloc.vec.Vec.deref values) (alloc.vec.Vec.deref echo)
            ok (some bytes)) ⦃ actual =>
      ∀ bytes, actual = some bytes → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf vecBytes bytes =
            finishNamedBody ((jsonSource source).all (namedJsonValid (fun name => ArgumentBinding.lookup name environment)))
              (namedJson (fun name => ArgumentBinding.lookup name environment)
                (DerivedTokens.token .echo (DerivedTokens.Refinement.digestBytes digest)) (jsonSource source)) ⦄ := by
  step with DerivedTokens.Refinement.echo_token_exact as ⟨echo, meaning⟩
  have size : echo.val.length = 73 := by
    have produced := DerivedTokens.token_length .echo _ (DerivedTokens.Refinement.digest_size digest)
    rw [← meaning] at produced
    simpa [vecBytes, byteList] using produced
  apply spec_mono (source_json_body_refines_named_template fields supplied source
    (alloc.vec.Vec.deref echo) (by simpa using (show echo.val.length ≤ 128 by omega)))
  intro actual bodyMeaning bytes accepted
  obtain ⟨environment, rows, exactBody⟩ := bodyMeaning bytes accepted
  refine ⟨environment, rows, ?_⟩
  simpa [sliceBytes, vecBytes, meaning] using exactBody


/-- The actual fixed-digest echo encoder feeds the actual compiler/projector/
writer composition. The echo-size bound is earned from source output; there
is no template/value/alignment/success/size premise. Native hash selection,
ASCII-to-String adaptation, sealed provenance and full AST meaning remain
separate caller boundaries. -/
theorem source_form_body_with_derived_echo (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (source : Slice body_compiler.NamedFormPiece)
    (digest : Array Std.U8 32#usize) :
    (do
      let echo ← derived_tokens.echo_token_bytes digest
      let compiledNames ← field_projection.field_names fields
      match compiledNames with
      | .Err _ => ok none
      | .Ok compiledNames => do
        let plan ← body_compiler.lower_form (alloc.vec.Vec.deref compiledNames) source
        match plan with
        | .Err _ => ok none
        | .Ok plan => do
          let projected ← field_projection.project_object fields supplied
          match projected with
          | .Err _ => ok none
          | .Ok values => do
            let bytes ← construct.build_body (.Form plan) (alloc.vec.Vec.deref values) (alloc.vec.Vec.deref echo)
            ok (some bytes)) ⦃ actual =>
      ∀ bytes, actual = some bytes → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf vecBytes bytes =
            finishNamedBody ((formSource source).all (namedFormValid (fun name => ArgumentBinding.lookup name environment)))
              (namedForm (fun name => ArgumentBinding.lookup name environment)
                (DerivedTokens.token .echo (DerivedTokens.Refinement.digestBytes digest)) (formSource source)) ⦄ := by
  step with DerivedTokens.Refinement.echo_token_exact as ⟨echo, meaning⟩
  have size : echo.val.length = 73 := by
    have produced := DerivedTokens.token_length .echo _ (DerivedTokens.Refinement.digest_size digest)
    rw [← meaning] at produced
    simpa [vecBytes, byteList] using produced
  apply spec_mono (source_form_body_refines_named_template fields supplied source
    (alloc.vec.Vec.deref echo) (by simpa using (show echo.val.length ≤ 128 by omega)))
  intro actual bodyMeaning bytes accepted
  obtain ⟨environment, rows, exactBody⟩ := bodyMeaning bytes accepted
  refine ⟨environment, rows, ?_⟩
  simpa [sliceBytes, vecBytes, meaning] using exactBody


end Auths.Product.BodyCompiler.Refinement

