import Auths.Product.PathCompilerRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement
open Auths.Product.FieldProjection
open Auths.Product.FieldProjection.Refinement

namespace Auths.Product.PathCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem ready_meaning (fields : List Field) (inputs : Inputs)
    (source : List SourceSegment) (segments : List Segment) (values : List Arg)
    (compiled : lowerPath (names fields) source = .ok segments)
    (projected : ObjectOutcome fields inputs (.ok values)) :
    ∃ environment, RowsMeaning fields inputs environment ∧
      renderPath values segments = namedPath (fun name => ArgumentBinding.lookup name environment) source ∧
      pathError values segments = namedPathError (fun name => ArgumentBinding.lookup name environment) source ∧
      (renderPath values segments).length ≤ 196624 := by
  unfold lowerPath at compiled
  split at compiled
  · rename_i admitted
    have mapping := lower_list_sound _ _ _ compiled
    obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ projected
    have rendering := lowered_path_preserves_named_rendering _ _ _ _ _ aligned mapping
    have bound := lowered_path_length_bound _ _ _ _ (object_output_payloads_bounded _ _ _ projected) mapping
    exact ⟨environment, rows, rendering.1, rendering.2, by omega⟩
  · contradiction

/-- Calls actual compiler, object projector and URL writer on the same field
specification. The only input bound is the native compiler's origin envelope.
There is no successful-source, expected index, alignment or payload premise.
If compilation/projection refuse, no URL writer is invoked; otherwise both
the source writer's bytes and every typed URL refusal have named-source meaning.
JSON/AST-to-borrowed-view and physical HTTP transport remain caller boundaries. -/
theorem source_url_refines_named_path (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (source : Slice path_compiler.NamedSegment)
    (origin : Slice Std.U8) (originBound : origin.val.length ≤ 261) :
    (do
      let compiledNames ← field_projection.field_names fields
      match compiledNames with
      | .Err _ => ok none
      | .Ok compiledNames => do
        let path ← path_compiler.lower_path (alloc.vec.Vec.deref compiledNames) source
        match path with
        | .Err _ => ok none
        | .Ok path => do
          let projected ← field_projection.project_object fields supplied
          match projected with
          | .Err _ => ok none
          | .Ok values => do
            let url ← construct.build_url origin (alloc.vec.Vec.deref path) (alloc.vec.Vec.deref values)
            ok (some url)) ⦃ actual =>
      ∀ url, actual = some url → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf vecBytes url = namedUrl (sliceBytes origin)
            (fun name => ArgumentBinding.lookup name environment) (pathView source) ⦄ := by
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
    step with lower_path_exact as ⟨path, pathMeaning⟩
    cases path with
    | Err error => simp
    | Ok path =>
      have compiled : lowerPath (names (fieldsView fields)) (pathView source) = .ok (path.val.map segmentOf) := by
        simpa [resultOf, exactNames] using pathMeaning.symm
      step with project_object_exact as ⟨projected, objectMeaning⟩
      cases projected with
      | Err error => simp
      | Ok values =>
        have object : ObjectOutcome (fieldsView fields) (inputsView supplied) (.ok (values.val.map argOf)) := objectMeaning
        obtain ⟨environment, rows, rendering, errors, renderBound⟩ := ready_meaning _ _ _ _ _ compiled object
        have fits : origin.val.length +
            (renderPath (argsOf (alloc.vec.Vec.deref values)) (path.val.map segmentOf)).length < 4294967295 := by
          change origin.val.length + (renderPath (values.val.map argOf) (path.val.map segmentOf)).length < _
          omega
        step with build_url_spec as ⟨url, urlMeaning⟩
        simp only [spec_ok]
        intro actual same
        have equal : actual = url := (Option.some.inj same).symm
        subst actual
        refine ⟨environment, rows, ?_⟩
        simpa [buildUrl, namedUrl, argsOf, rendering, errors, sliceBytes] using urlMeaning

theorem source_fixed_path_contains_only_literals (source : Slice path_compiler.NamedSegment) :
    path_compiler.lower_fixed_path source ⦃ actual =>
      ∀ output, actual = .Ok output →
        List.Forall₂ (fun node bytes => node = .fixed bytes ∧ FixedValid bytes)
          (pathView source) (output.val.map vecBytes) ⦄ := by
  apply spec_mono (lower_fixed_path_exact source)
  intro actual meaning output accepted
  rw [accepted] at meaning
  have compiled : lowerFixedPath (pathView source) = .ok (output.val.map vecBytes) := by
    simpa [resultOf] using meaning.symm
  unfold lowerFixedPath at compiled
  split at compiled
  · exact lower_fixed_list_literals _ _ compiled
  · contradiction

theorem source_path_preserves_named_references (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice path_compiler.NamedSegment) :
    path_compiler.lower_path names source ⦃ actual =>
      ∀ output, actual = .Ok output →
        List.Forall₂ (SegmentMeaning (namesView names)) (pathView source) (output.val.map segmentOf) ⦄ := by
  apply spec_mono (lower_path_exact names source)
  intro actual meaning output accepted
  rw [accepted] at meaning
  have compiled : lowerPath (namesView names) (pathView source) = .ok (output.val.map segmentOf) := by
    simpa [resultOf] using meaning.symm
  unfold lowerPath at compiled
  split at compiled
  · exact lower_list_sound _ _ _ compiled
  · contradiction

theorem source_admissible_paths_lower (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice path_compiler.NamedSegment)
    (valid : PathAdmissible (namesView names) (pathView source)) :
    path_compiler.lower_path names source ⦃ actual => ∃ output,
      actual = .Ok output ∧ List.Forall₂ (SegmentMeaning (namesView names))
        (pathView source) (output.val.map segmentOf) ⦄ := by
  obtain ⟨segments, accepted⟩ := lower_path_complete _ _ valid
  apply spec_mono (lower_path_exact names source)
  intro actual meaning
  rw [accepted] at meaning
  cases actual with
  | Err error => simp [resultOf] at meaning
  | Ok output =>
    have same : output.val.map segmentOf = segments := by simpa [resultOf] using meaning
    exact ⟨output, rfl, by simpa [same] using lower_list_sound _ _ _ (show lowerList (namesView names) (pathView source) = .ok segments from by
      simpa [lowerPath, valid.1, valid.2.1, valid.2.2.1] using accepted)⟩

end Auths.Product.PathCompiler.Refinement
