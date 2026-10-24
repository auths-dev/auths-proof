import Auths.Product.PathCompilerLeaves

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.PathCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private def lowerFrom (built : List Segment) (names : List Bytes) : List SourceSegment → Except ConstructError (List Segment)
  | [] => .ok built
  | source :: rest => do
    let segment ← lowerOne names source
    lowerFrom (built ++ [segment]) names rest

private theorem lower_from_refines (built : List Segment) (names : List Bytes) (source : List SourceSegment) :
    lowerFrom built names source = (lowerList names source).map (built ++ ·) := by
  induction source generalizing built with
  | nil => simp [lowerFrom, lowerList]
  | cons head rest ih =>
    cases first : lowerOne names head <;>
      simp [lowerFrom, lowerList, first, ih, Except.map_map, Function.comp_def, List.append_assoc]

@[step] theorem path_loop_exact (names : Slice (alloc.vec.Vec Std.U8))
    (path : Slice path_compiler.NamedSegment) (bounded : path.val.length ≤ 16) :
    path_compiler.lower_path_loop names path (alloc.vec.Vec.new construct.SegmentPlan) 0#usize
      ⦃ actual => resultOf (fun output => output.val.map segmentOf) actual =
        lowerList (namesView names) (pathView path) ⦄ := by
  unfold path_compiler.lower_path_loop
  let wanted := lowerList (namesView names) (pathView path)
  apply loop.spec_decr_nat
    (measure := fun state => path.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ path.val.length ∧ state.1.val.length = state.2.val ∧
      wanted = lowerFrom (state.1.val.map segmentOf) (namesView names) ((pathView path).drop state.2.val))
  · rintro ⟨current, index⟩ invariant
    unfold path_compiler.lower_path_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < path.val.length := by simpa using within
      step as ⟨source, sourceAt⟩
      have suffix : (pathView path).drop index.val = sourceView source :: (pathView path).drop (index.val + 1) := by
        simpa [pathView, List.drop_map, sourceAt] using
          congrArg (List.map sourceView) (List.drop_eq_getElem_cons inside)
      rw [suffix, lowerFrom] at invariant
      step with lower_segment_exact as ⟨lowered, meaning⟩
      cases lowered with
      | Err error =>
        simp only [resultOf] at meaning
        simp only [spec_ok, resultOf]
        simpa [← meaning] using invariant.2.2.symm
      | Ok segment =>
        have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
        step as ⟨updated, updateValue⟩
        step as ⟨next, nextValue⟩
        refine ⟨by omega, by simp [updateValue]; omega, ?_, by omega⟩
        simpa [← meaning, resultOf, updateValue, List.map_append, nextValue]
          using invariant.2.2
    · simp only [spec_ok, resultOf]
      have atEnd : path.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (pathView path).length ≤ index.val := by simpa [pathView] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, lowerFrom] using invariant.2.2.symm
  · simp [wanted, lower_from_refines]

@[step] theorem lower_path_exact (names : Slice (alloc.vec.Vec Std.U8)) (path : Slice path_compiler.NamedSegment) :
    path_compiler.lower_path names path ⦃ actual =>
      resultOf (fun output => output.val.map segmentOf) actual = lowerPath (namesView names) (pathView path) ⦄ := by
  unfold path_compiler.lower_path path_compiler.MAX_PATH_SEGMENTS arguments.MAX_PROFILE_FIELDS
  by_cases empty : path.val = []
  · simp [empty, core.slice.Slice.is_empty, lowerPath, pathView, resultOf, errorOf]
  · have nonempty : 0 < path.val.length := List.length_pos.mpr empty
    by_cases long : 16 < path.val.length
    · have nativeLong : path.len > 16#usize := by scalar_tac
      simp [nativeLong, lowerPath, pathView, Nat.not_le.mpr long, resultOf, errorOf]
    · have bounded : path.val.length ≤ 16 := by omega
      have nativeBound : ¬path.len > 16#usize := by scalar_tac
      by_cases many : 32 < names.val.length
      · have nativeMany : names.len > 32#usize := by scalar_tac
        simp [nativeMany, lowerPath, namesView, Nat.not_le.mpr many, resultOf, errorOf]
      · have nativeNamesBound : ¬names.len > 32#usize := by scalar_tac
        have namesBound : names.val.length ≤ 32 := by omega
        simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false, nativeBound,
          nativeNamesBound, Bool.false_or, ↓reduceIte]
        apply spec_mono (path_loop_exact names path bounded)
        intro actual meaning
        simpa [lowerPath, namesView, pathView, nonempty, bounded, namesBound] using meaning

private def fixedFrom (built : List Bytes) : List SourceSegment → Except ConstructError (List Bytes)
  | [] => .ok built
  | .fixed bytes :: rest =>
    if FixedValid bytes then fixedFrom (built ++ [bytes]) rest else .error .unsafeSegment
  | _ => .error .argumentMismatch

private theorem fixed_from_refines (built : List Bytes) (source : List SourceSegment) :
    fixedFrom built source = (lowerFixedList source).map (built ++ ·) := by
  induction source generalizing built with
  | nil => simp [fixedFrom, lowerFixedList]
  | cons head rest ih =>
    cases head <;>
      simp [fixedFrom, lowerFixedList, ih, Except.map_map, Function.comp_def, List.append_assoc]

@[step] theorem fixed_path_loop_exact (path : Slice path_compiler.NamedSegment) (bounded : path.val.length ≤ 16) :
    path_compiler.lower_fixed_path_loop path (alloc.vec.Vec.new (alloc.vec.Vec Std.U8)) 0#usize
      ⦃ actual => resultOf (fun output => output.val.map vecBytes) actual = lowerFixedList (pathView path) ⦄ := by
  unfold path_compiler.lower_fixed_path_loop
  let wanted := lowerFixedList (pathView path)
  apply loop.spec_decr_nat
    (measure := fun state => path.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ path.val.length ∧ state.1.val.length = state.2.val ∧
      wanted = fixedFrom (state.1.val.map vecBytes) ((pathView path).drop state.2.val))
  · rintro ⟨current, index⟩ invariant
    unfold path_compiler.lower_fixed_path_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < path.val.length := by simpa using within
      step as ⟨source, sourceAt⟩
      have suffix : (pathView path).drop index.val = sourceView source :: (pathView path).drop (index.val + 1) := by
        simpa [pathView, List.drop_map, sourceAt] using
          congrArg (List.map sourceView) (List.drop_eq_getElem_cons inside)
      rw [suffix, fixedFrom] at invariant
      cases source with
      | Unsupported => simpa [sourceView, resultOf, errorOf] using invariant.2.2.symm
      | Field name => simpa [sourceView, resultOf, errorOf] using invariant.2.2.symm
      | Fixed text =>
        step with fixed_valid_exact as ⟨allowed, meaning⟩
        cases allowed
        · have invalid : ¬FixedValid (sliceBytes text) := by simpa using meaning.symm
          simpa [sourceView, invalid, resultOf, errorOf] using invariant.2.2.symm
        · have valid : FixedValid (sliceBytes text) := by simpa using meaning.symm
          have fits : text.val.length < 4294967295 := by
            have size := valid.2.1
            simp only [sliceBytes, byteList, List.length_map] at size
            omega
          simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
          step with copy_bytes_spec as ⟨copied, copyValue⟩
          have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
          step as ⟨updated, updateValue⟩
          step as ⟨next, nextValue⟩
          refine ⟨by omega, by simp [updateValue]; omega, ?_, by omega⟩
          simpa [sourceView, valid, updateValue, copyValue, vecBytes, sliceBytes, List.map_append, nextValue]
            using invariant.2.2
    · simp only [spec_ok, resultOf]
      have atEnd : path.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (pathView path).length ≤ index.val := by simpa [pathView] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, fixedFrom] using invariant.2.2.symm
  · simp [wanted, fixed_from_refines]

@[step] theorem lower_fixed_path_exact (path : Slice path_compiler.NamedSegment) :
    path_compiler.lower_fixed_path path ⦃ actual =>
      resultOf (fun output => output.val.map vecBytes) actual = lowerFixedPath (pathView path) ⦄ := by
  unfold path_compiler.lower_fixed_path path_compiler.MAX_PATH_SEGMENTS
  by_cases empty : path.val = []
  · simp [empty, core.slice.Slice.is_empty, lowerFixedPath, pathView, resultOf, errorOf]
  · have nonempty : 0 < path.val.length := List.length_pos.mpr empty
    by_cases long : 16 < path.val.length
    · have nativeLong : path.len > 16#usize := by scalar_tac
      simp [nativeLong, lowerFixedPath, pathView, Nat.not_le.mpr long, resultOf, errorOf]
    · have bounded : path.val.length ≤ 16 := by omega
      have nativeBound : ¬path.len > 16#usize := by scalar_tac
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false, nativeBound, Bool.false_or, ↓reduceIte]
      apply spec_mono (fixed_path_loop_exact path bounded)
      intro actual meaning
      simpa [lowerFixedPath, pathView, nonempty, bounded] using meaning

end Auths.Product.PathCompiler.Refinement
