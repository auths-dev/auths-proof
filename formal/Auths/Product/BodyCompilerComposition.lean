import Auths.Product.BodyCompilerRefinement
import Auths.Product.BodyCompilerBounds

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

private theorem rows_bound_environment (fields : List Field) (inputs : Inputs)
    (environment : ArgumentBinding.Environment) (rows : RowsMeaning fields inputs environment) :
    EnvironmentBounded (fun name => ArgumentBinding.lookup name environment) := by
  intro name value found
  exact rows_earn_payloads fields inputs environment rows (name, value)
    (ArgumentBinding.lookup_member name environment value found)


/-- Actual name generation, complete template lowering, object projection and
body writing on one immutable field specification. Alignment and value bounds
are earned from the source projector; successful compilation earns aggregate
literal/dynamic bounds. Only the native echo envelope is an input premise.
Both bytes and typed writer refusals
are specified, and failed compilation/projection never invokes the writer. -/
theorem source_json_body_refines_named_template (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (source : Slice body_compiler.NamedJsonPiece)
    (echo : Slice Std.U8) (echoBound : echo.val.length ≤ 128) :
    (do
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
            let bytes ← construct.build_body (.Json plan) (alloc.vec.Vec.deref values) echo
            ok (some bytes)) ⦃ actual =>
      ∀ bytes, actual = some bytes → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf vecBytes bytes =
            finishNamedBody ((jsonSource source).all (namedJsonValid (fun name => ArgumentBinding.lookup name environment)))
              (namedJson (fun name => ArgumentBinding.lookup name environment) (sliceBytes echo) (jsonSource source)) ⦄ := by
  step with field_names_exact as ⟨compiledNames, namesMeaning⟩
  cases compiledNames with
  | Err error => simp
  | Ok compiledNames =>
    have layout : LayoutValid (fieldsView fields) := by
      by_contra invalid
      simp [invalid, resultOf] at namesMeaning
    have exactNames : namesView (alloc.vec.Vec.deref compiledNames) = names (fieldsView fields) := by
      have copied : compiledNames.val.map vecBytes = names (fieldsView fields) := by
        simpa [layout, resultOf] using namesMeaning
      simpa [namesView, vecBytes] using copied
    step with lower_json_exact as ⟨plan, planMeaning⟩
    cases plan with
    | Err error => simp
    | Ok plan =>
      have compiled : lowerJson (names (fieldsView fields)) (jsonSource source) =
          .ok (plan.val.map jsonPieceOf) := by
        simpa [resultOf, exactNames] using planMeaning.symm
      have domain := lower_json_earns_resources _ _ _ compiled
      step with project_object_exact as ⟨projected, objectMeaning⟩
      cases projected with
      | Err error => simp
      | Ok values =>
        have object : ObjectOutcome (fieldsView fields) (inputsView supplied) (.ok (values.val.map argOf)) := objectMeaning
        obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ object
        have bounded := rows_bound_environment _ _ _ rows
        have mapping := (lower_json_sound _ _ _ compiled).2.2
        have rendering := json_list_named _ _ _ (sliceBytes echo) aligned _ _ mapping
        have echoSize : (sliceBytes echo).length ≤ 128 := by
          simpa [sliceBytes, byteList] using echoBound
        have namedFits := json_resource_domain_earns_writer_fit _ _ bounded echoSize _ domain
        have fits : (renderBody (argsOf (alloc.vec.Vec.deref values)) (byteList echo.val)
            (bodyPlanOf (.Json plan))).length < 4294967295 := by
          simpa [renderBody, bodyPlanOf, argsOf, sliceBytes, rendering.1] using namedFits
        have modelBody := lowered_json_body_exact _ _ _ (sliceBytes echo) aligned _ _ compiled
        step with build_body_spec as ⟨bytes, bytesMeaning⟩
        simp only [spec_ok]
        intro actual same
        have equal : actual = bytes := (Option.some.inj same).symm
        subst actual
        refine ⟨environment, rows, ?_⟩
        calc
          resultOf vecBytes bytes =
              buildBody (.json (plan.val.map jsonPieceOf)) (values.val.map argOf) (sliceBytes echo) := by
            simpa [bodyPlanOf, argsOf, sliceBytes] using bytesMeaning
          _ = _ := modelBody


/-- Actual name generation, complete template lowering, object projection and
body writing on one immutable field specification. Alignment and value bounds
are earned from the source projector; successful compilation earns aggregate
literal/dynamic bounds. Only the native echo envelope is an input premise.
Both bytes and typed writer refusals
are specified, and failed compilation/projection never invokes the writer. -/
theorem source_form_body_refines_named_template (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (source : Slice body_compiler.NamedFormPiece)
    (echo : Slice Std.U8) (echoBound : echo.val.length ≤ 128) :
    (do
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
            let bytes ← construct.build_body (.Form plan) (alloc.vec.Vec.deref values) echo
            ok (some bytes)) ⦃ actual =>
      ∀ bytes, actual = some bytes → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf vecBytes bytes =
            finishNamedBody ((formSource source).all (namedFormValid (fun name => ArgumentBinding.lookup name environment)))
              (namedForm (fun name => ArgumentBinding.lookup name environment) (sliceBytes echo) (formSource source)) ⦄ := by
  step with field_names_exact as ⟨compiledNames, namesMeaning⟩
  cases compiledNames with
  | Err error => simp
  | Ok compiledNames =>
    have layout : LayoutValid (fieldsView fields) := by
      by_contra invalid
      simp [invalid, resultOf] at namesMeaning
    have exactNames : namesView (alloc.vec.Vec.deref compiledNames) = names (fieldsView fields) := by
      have copied : compiledNames.val.map vecBytes = names (fieldsView fields) := by
        simpa [layout, resultOf] using namesMeaning
      simpa [namesView, vecBytes] using copied
    step with lower_form_exact as ⟨plan, planMeaning⟩
    cases plan with
    | Err error => simp
    | Ok plan =>
      have compiled : lowerForm (names (fieldsView fields)) (formSource source) =
          .ok (plan.val.map formPieceOf) := by
        simpa [resultOf, exactNames] using planMeaning.symm
      have domain := lower_form_earns_resources _ _ _ compiled
      step with project_object_exact as ⟨projected, objectMeaning⟩
      cases projected with
      | Err error => simp
      | Ok values =>
        have object : ObjectOutcome (fieldsView fields) (inputsView supplied) (.ok (values.val.map argOf)) := objectMeaning
        obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ object
        have bounded := rows_bound_environment _ _ _ rows
        have mapping := (lower_form_sound _ _ _ compiled).2.2
        have rendering := form_list_named _ _ _ (sliceBytes echo) aligned _ _ mapping
        have echoSize : (sliceBytes echo).length ≤ 128 := by
          simpa [sliceBytes, byteList] using echoBound
        have namedFits := form_resource_domain_earns_writer_fit _ _ bounded echoSize _ domain
        have fits : (renderBody (argsOf (alloc.vec.Vec.deref values)) (byteList echo.val)
            (bodyPlanOf (.Form plan))).length < 4294967295 := by
          simpa [renderBody, bodyPlanOf, argsOf, sliceBytes, rendering.1] using namedFits
        have modelBody := lowered_form_body_exact _ _ _ (sliceBytes echo) aligned _ _ compiled
        step with build_body_spec as ⟨bytes, bytesMeaning⟩
        simp only [spec_ok]
        intro actual same
        have equal : actual = bytes := (Option.some.inj same).symm
        subst actual
        refine ⟨environment, rows, ?_⟩
        calc
          resultOf vecBytes bytes =
              buildBody (.form (plan.val.map formPieceOf)) (values.val.map argOf) (sliceBytes echo) := by
            simpa [bodyPlanOf, argsOf, sliceBytes] using bytesMeaning
          _ = _ := modelBody

end Auths.Product.BodyCompiler.Refinement
