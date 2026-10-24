import Auths.Product.HeaderCompilerRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement
open Auths.Product.FieldProjection
open Auths.Product.FieldProjection.Refinement

namespace Auths.Product.HeaderCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem compiled_plan_fits (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource)
    (plan : construct.HeaderPlan) (compiled : lowerHeaders names versions scope = .ok (headerPlanOf plan)) :
    HeaderPlanFits plan := by
  obtain ⟨count, rows, accountBound⟩ := lower_headers_earns_bounds _ _ _ _ compiled
  have nativeCount : plan.versions.val.length ≤ 2 := by simpa [headerPlanOf] using count
  refine ⟨by omega, ?_, ?_⟩
  · intro header member
    have bounds := rows (headerOf header) (List.mem_map.mpr ⟨header, member, rfl⟩)
    have nameBound : header.name.val.length ≤ 20 := by
      simpa [headerOf, vecBytes, byteList] using bounds.1
    have valueBound : header.value.val.length ≤ 64 := by
      simpa [headerOf, vecBytes, byteList] using bounds.2
    constructor <;> omega
  · intro account present
    have modelPresent : (headerPlanOf plan).scope = some (scopeOf account) := by
      simp [headerPlanOf, present]
    have size := accountBound (scopeOf account) modelPresent
    have nativeSize : account.name.val.length = 14 := by
      simpa [scopeOf, vecBytes, byteList] using size
    omega

theorem source_compilation_earns_header_writer_domain (names : Slice (alloc.vec.Vec Std.U8))
    (versions : Option (Slice header_compiler.NamedHeader)) (scope : Option header_compiler.NamedScope) :
    header_compiler.lower_headers names versions scope ⦃ actual => ∀ plan, actual = .Ok plan → HeaderPlanFits plan ⦄ := by
  apply spec_mono (lower_headers_exact names versions scope)
  intro actual meaning plan accepted
  rw [accepted] at meaning
  exact compiled_plan_fits _ _ _ plan (by simpa [compiledResult] using meaning.symm)

/-- Actual name generation, complete optional-source header compilation,
complete object projection and action-header writing use one immutable field
specification. Every size/alignment domain is earned from actual results;
there is no successful-helper, index, mapping, payload or capacity premise.
Typed writer refusals retain named meaning, including wrong scalar kinds and
invalid account grammar. JSON/AST/metadata and sealed provenance remain caller
bridges; this does not grant authority from a decoded field object. -/
theorem source_action_headers_refine_named_source (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (versions : Option (Slice header_compiler.NamedHeader))
    (scope : Option header_compiler.NamedScope) :
    (do
      let compiledNames ← field_projection.field_names fields
      match compiledNames with
      | .Err _ => ok none
      | .Ok compiledNames => do
        let plan ← header_compiler.lower_headers (alloc.vec.Vec.deref compiledNames) versions scope
        match plan with
        | .Err _ => ok none
        | .Ok plan => do
          let projected ← field_projection.project_object fields supplied
          match projected with
          | .Err _ => ok none
          | .Ok values => do
            let headers ← construct.action_headers plan (alloc.vec.Vec.deref values)
            ok (some headers)) ⦃ actual =>
      ∀ headers, actual = some headers → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf (fun output => output.val.map headerOf) headers =
            namedHeaders (fun name => ArgumentBinding.lookup name environment)
              (versions.map versionsView) (scope.map scopeSourceOf) ⦄ := by
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
    step with lower_headers_exact as ⟨plan, planMeaning⟩
    cases plan with
    | Err error => simp
    | Ok plan =>
      have compiled : lowerHeaders (names (fieldsView fields)) (versions.map versionsView)
          (scope.map scopeSourceOf) = .ok (headerPlanOf plan) := by
        simpa [compiledResult, exactNames] using planMeaning.symm
      have fits := compiled_plan_fits _ _ _ plan compiled
      step with project_object_exact as ⟨projected, objectMeaning⟩
      cases projected with
      | Err error => simp
      | Ok values =>
        have object : ObjectOutcome (fieldsView fields) (inputsView supplied) (.ok (values.val.map argOf)) := objectMeaning
        obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ object
        have modelExact := lowered_headers_preserve_named_rendering _ _ _ aligned _ _ _ compiled
        step with action_headers_spec as ⟨headers, headersMeaning⟩
        simp only [spec_ok]
        intro actual same
        have equal : actual = headers := (Option.some.inj same).symm
        subst actual
        refine ⟨environment, rows, ?_⟩
        simpa [argsOf, modelExact] using headersMeaning

end Auths.Product.HeaderCompiler.Refinement
