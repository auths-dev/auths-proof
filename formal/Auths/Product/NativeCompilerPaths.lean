import Auths.Product.NativeCompilerConstruction
import Auths.Product.NativeCompilerRequestInputs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativePath (path : Slice NativeNamedSegment) : List PathCompiler.SourceSegment :=
  path.val.map loweredPathSegment

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction PathCompiler
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_fixed_scan_suffix (text : Slice Std.U8) (position : Std.Usize)
    (positionBound : position.val ≤ text.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.fixed_segment_valid_loop text position
      ⦃ actual => actual = decide (∀ byte ∈ text.val.drop position.val, pathLiteral byte.val = true) ⦄ := by
  generalize remaining : text.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.fixed_segment_valid_loop
      by_cases inside : position.val < text.val.length
      · have nativeInside : position < text.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec text position inside as ⟨byte, byteAt⟩
        have suffix : text.val.drop position.val = byte :: text.val.drop (position.val + 1) := by
          simpa only [byteAt] using List.drop_eq_getElem_cons inside
        step with native_path_literal_exact byte as ⟨literal, literalMeaning⟩
        cases literal with
        | false => simp [suffix, ← literalMeaning]
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) next (by omega) rfl)
            intro actual exact
            simpa only [suffix, List.mem_cons, forall_eq_or_imp, ← literalMeaning,
              true_and, nextValue] using exact
      · have ended : text.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < text.len := by scalar_tac
        simp [nativeEnded, List.drop_eq_nil_of_le ended]

@[step] theorem native_fixed_segment_exact (text : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.fixed_segment_valid text
      ⦃ actual => actual = decide (FixedValid (schemaSliceBytes text)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.fixed_segment_valid
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.MAX_FIXED_SEGMENT_BYTES
  by_cases large : 128 < text.val.length
  · have nativeLarge : text.len > 128#usize := by scalar_tac
    have invalid : ¬FixedValid (schemaSliceBytes text) := by
      intro valid
      have bound := valid.2.1
      simp only [schemaSliceBytes, List.length_map] at bound
      omega
    simp [nativeLarge, invalid]
  · have bounded : text.val.length ≤ 128 := by omega
    have nativeBound : ¬text.len > 128#usize := by scalar_tac
    simp only [nativeBound, ↓reduceIte]
    step with native_segment_value_exact text as ⟨base, baseMeaning⟩
    cases base with
    | false =>
        have invalid : ¬FixedValid (schemaSliceBytes text) := by
          intro valid
          have required := (fixed_iff_source_checks _).mp valid |>.2.1
          simp only [← baseMeaning, Bool.false_eq_true] at required
        simp [invalid]
    | true =>
        simp only [Bool.true_eq_true, ↓reduceIte]
        apply spec_mono (native_fixed_scan_suffix text 0#usize (by simp))
        intro actual exact
        have byteBound : (schemaSliceBytes text).length ≤ 128 := by
          simpa only [schemaSliceBytes, List.length_map] using bounded
        simpa only [fixed_iff_source_checks, byteBound, ← baseMeaning, true_and,
          schemaSliceBytes, List.forall_mem_map, List.drop_zero] using exact

@[step] theorem native_lower_field_exact (names : Slice (NativeVec Std.U8)) (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_field names name ⦃ actual =>
      nativeConstructResult UScalar.val actual = lowerField (nativeNameColumn names) (schemaSliceBytes name) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_field
    AuthsNativeRecipe.auths_gateway_kernel.arguments.MAX_PROFILE_FIELDS
  by_cases large : 32 < names.val.length
  · have nativeLarge : names.len > 32#usize := by scalar_tac
    simp [nativeLarge, lowerField, nativeNameColumn, Nat.not_le.mpr large,
      nativeConstructResult, nativeConstructError]
  · have bound : names.val.length ≤ 32 := by omega
    have nativeBound : ¬names.len > 32#usize := by scalar_tac
    simp only [nativeBound, ↓reduceIte]
    step with native_schema_token_exact name 64#usize as ⟨valid, validMeaning⟩
    cases valid with
    | false =>
        simp [lowerField, ← validMeaning, nativeConstructResult, nativeConstructError]
    | true =>
        simp only [Bool.true_eq_true, ↓reduceIte]
        step with native_schema_first_index_exact names name as ⟨index, indexMeaning⟩
        cases index <;> simp [lowerField, nativeNameColumn, bound, ← validMeaning,
          ← indexMeaning, nativeConstructResult, nativeConstructError]

@[step] theorem native_lower_segment_exact (names : Slice (NativeVec Std.U8))
    (source : NativeNamedSegment) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_segment names source ⦃ actual =>
      nativeConstructResult nativeSegment actual = lowerOne (nativeNameColumn names) (loweredPathSegment source) ⦄ := by
  cases source with
  | Fixed text =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_segment
      step with native_fixed_segment_exact (AuthsNativeRecipe.alloc.vec.Vec.deref text)
        as ⟨valid, meaning⟩
      cases valid with
      | false =>
          simp [loweredPathSegment, lowerOne, ← meaning, nativeConstructResult,
            nativeConstructError, schemaSliceBytes, native_deref_contents]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref text)
            as ⟨copied, copiedMeaning⟩
          simp [loweredPathSegment, lowerOne, ← meaning, nativeConstructResult,
            nativeSegment, bytes, schemaSliceBytes, native_deref_contents, copiedMeaning]
  | Field name =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_segment
      step with native_lower_field_exact names (AuthsNativeRecipe.alloc.vec.Vec.deref name)
        as ⟨index, meaning⟩
      cases index <;> simp [loweredPathSegment, lowerOne, ← meaning, nativeConstructResult,
        nativeSegment, bytes, schemaSliceBytes, native_deref_contents]
  | Unsupported =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_segment,
        loweredPathSegment, lowerOne, nativeConstructResult, nativeConstructError]

private theorem native_path_suffix (names : Slice (NativeVec Std.U8))
    (path : Slice NativeNamedSegment) (output : NativeVec NativeSegment) (position : Std.Usize)
    (positionBound : position.val ≤ path.val.length)
    (room : output.val.length + (path.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_path_loop names path output position
      ⦃ actual => nativeConstructResult (fun built => built.val.map nativeSegment) actual =
        (lowerList (nativeNameColumn names) ((nativePath path).drop position.val)).map
          (output.val.map nativeSegment ++ ·) ⦄ := by
  generalize remaining : path.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_path_loop
      by_cases inside : position.val < path.val.length
      · have nativeInside : position < path.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec path position inside as ⟨source, sourceAt⟩
        have suffix : (nativePath path).drop position.val = loweredPathSegment source ::
            (nativePath path).drop (position.val + 1) := by
          simpa only [nativePath, List.drop_map, List.map_cons, sourceAt] using
            congrArg (List.map loweredPathSegment) (List.drop_eq_getElem_cons inside)
        step with native_lower_segment_exact names source as ⟨lowered, meaning⟩
        cases lowered with
        | Err error =>
            simp [suffix, lowerList, ← meaning, nativeConstructResult]
        | Ok segment =>
            step with native_segment_clone_exact segment as ⟨copied, copyMeaning⟩
            step with native_push_exact output copied (by omega) as ⟨updated, appended⟩
            have updatedLength : updated.val.length = output.val.length + 1 := by
              simp only [appended, List.length_append, List.length_singleton]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) updated next (by omega) (by omega) rfl)
            intro actual exact
            simpa [suffix, lowerList, ← meaning, nativeConstructResult, appended, copyMeaning,
              List.map_append, List.map_singleton, nextValue, Except.map_map,
              Function.comp_def, List.append_assoc] using exact
      · have ended : path.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < path.len := by scalar_tac
        have modelEnded : (nativePath path).length ≤ position.val := by
          simpa only [nativePath, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, lowerList, nativeConstructResult]

/-- The complete native compiler check earns every field index and path
literal, including the first refusal. No input-admission premise is supplied. -/
@[step] theorem native_lower_path_exact (names : Slice (NativeVec Std.U8)) (path : Slice NativeNamedSegment) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_path names path ⦃ actual =>
      nativeConstructResult (fun built => built.val.map nativeSegment) actual =
        lowerPath (nativeNameColumn names) (nativePath path) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_path
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.MAX_PATH_SEGMENTS
    AuthsNativeRecipe.auths_gateway_kernel.arguments.MAX_PROFILE_FIELDS
  by_cases empty : path.val = []
  · simp [core.slice.Slice.is_empty, empty, lowerPath, nativePath,
      nativeConstructResult, nativeConstructError]
  · have positive : 0 < path.val.length := List.length_pos.mpr empty
    by_cases large : 16 < path.val.length
    · have nativeLarge : path.len > 16#usize := by scalar_tac
      simp [nativeLarge, lowerPath, nativePath, Nat.not_le.mpr large,
        nativeConstructResult, nativeConstructError]
    · have pathBound : path.val.length ≤ 16 := by omega
      have nativeBound : ¬path.len > 16#usize := by scalar_tac
      by_cases many : 32 < names.val.length
      · have nativeMany : names.len > 32#usize := by scalar_tac
        simp [nativeMany, lowerPath, nativeNameColumn, Nat.not_le.mpr many,
          nativeConstructResult, nativeConstructError]
      · have namesBound : names.val.length ≤ 32 := by omega
        have nativeNames : ¬names.len > 32#usize := by scalar_tac
        simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
          nativeBound, nativeNames, Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
        apply spec_mono (native_path_suffix names path (AuthsNativeRecipe.alloc.vec.Vec.new NativeSegment)
          0#usize (by simp) (by simp only [native_empty_contents, List.length_nil,
            Nat.zero_add, Nat.sub_zero]; scalar_tac))
        intro actual exact
        simpa [native_empty_contents, lowerPath, nativePath, nativeNameColumn,
          positive, pathBound, namesBound] using exact

private theorem native_fixed_path_suffix (path : Slice NativeNamedSegment)
    (output : NativeVec (NativeVec Std.U8)) (position : Std.Usize)
    (positionBound : position.val ≤ path.val.length)
    (room : output.val.length + (path.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_fixed_path_loop path output position
      ⦃ actual => nativeConstructResult (fun built => built.val.map bytes) actual =
        (lowerFixedList ((nativePath path).drop position.val)).map (output.val.map bytes ++ ·) ⦄ := by
  generalize remaining : path.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_fixed_path_loop
      by_cases inside : position.val < path.val.length
      · have nativeInside : position < path.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec path position inside as ⟨source, sourceAt⟩
        have suffix : (nativePath path).drop position.val = loweredPathSegment source ::
            (nativePath path).drop (position.val + 1) := by
          simpa only [nativePath, List.drop_map, List.map_cons, sourceAt] using
            congrArg (List.map loweredPathSegment) (List.drop_eq_getElem_cons inside)
        cases source with
        | Field name =>
            simp [suffix, lowerFixedList, loweredPathSegment, nativeConstructResult, nativeConstructError]
        | Unsupported =>
            simp [suffix, lowerFixedList, loweredPathSegment, nativeConstructResult, nativeConstructError]
        | Fixed text =>
            step with native_fixed_segment_exact (AuthsNativeRecipe.alloc.vec.Vec.deref text)
              as ⟨valid, validMeaning⟩
            cases valid with
            | false =>
                simp [suffix, lowerFixedList, loweredPathSegment, ← validMeaning,
                  schemaSliceBytes, bytes, native_deref_contents, nativeConstructResult, nativeConstructError]
            | true =>
                simp only [Bool.true_eq_true, ↓reduceIte]
                step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref text)
                  as ⟨copied, copiedMeaning⟩
                step with native_push_exact output copied (by omega) as ⟨updated, appended⟩
                have updatedLength : updated.val.length = output.val.length + 1 := by
                  simp only [appended, List.length_append, List.length_singleton]
                step as ⟨next, nextValue⟩
                apply spec_mono (ih _ (by omega) updated next (by omega) (by omega) rfl)
                intro actual exact
                simpa [suffix, lowerFixedList, loweredPathSegment, ← validMeaning,
                  schemaSliceBytes, bytes, native_deref_contents, appended, copiedMeaning,
                  nextValue, List.map_append, List.map_singleton, Except.map_map,
                  Function.comp_def, List.append_assoc] using exact
      · have ended : path.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < path.len := by scalar_tac
        have modelEnded : (nativePath path).length ≤ position.val := by
          simpa only [nativePath, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, lowerFixedList, nativeConstructResult]

@[step] theorem native_lower_fixed_path_exact (path : Slice NativeNamedSegment) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_fixed_path path ⦃ actual =>
      nativeConstructResult (fun built => built.val.map bytes) actual = lowerFixedPath (nativePath path) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_fixed_path
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.MAX_PATH_SEGMENTS
  by_cases empty : path.val = []
  · simp [core.slice.Slice.is_empty, empty, lowerFixedPath, nativePath,
      nativeConstructResult, nativeConstructError]
  · have positive : 0 < path.val.length := List.length_pos.mpr empty
    by_cases large : 16 < path.val.length
    · have nativeLarge : path.len > 16#usize := by scalar_tac
      simp [nativeLarge, lowerFixedPath, nativePath, Nat.not_le.mpr large,
        nativeConstructResult, nativeConstructError]
    · have pathBound : path.val.length ≤ 16 := by omega
      have nativeBound : ¬path.len > 16#usize := by scalar_tac
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
        nativeBound, Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
      apply spec_mono (native_fixed_path_suffix path
        (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec Std.U8)) 0#usize (by simp)
        (by simp only [native_empty_contents, List.length_nil, Nat.zero_add, Nat.sub_zero]; scalar_tac))
      intro actual exact
      simpa [native_empty_contents, lowerFixedPath, nativePath, positive, pathBound] using exact

/-- The native adapter's original names feed the actual complete path compiler.
Its original input may still be malformed; the compiler earns its own verdict. -/
theorem native_original_path_verdict (names : Slice (NativeVec Std.U8)) (source : Slice NativePathSource)
    (bounded : ∀ segment ∈ source.val, NativePathFits segment) :
    (do let converted ← AuthsNativeRecipe.recipe.lower.named_path source
        AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_path names
          (AuthsNativeRecipe.alloc.vec.Vec.deref converted)) ⦃ actual =>
      nativeConstructResult (fun built => built.val.map nativeSegment) actual =
        lowerPath (nativeNameColumn names) (source.val.map originalPathSegment) ⦄ := by
  step with native_path_input_exact source bounded as ⟨converted, convertedMeaning⟩
  apply spec_mono (native_lower_path_exact names (AuthsNativeRecipe.alloc.vec.Vec.deref converted))
  intro actual exact
  simpa only [nativePath, native_deref_contents, convertedMeaning] using exact

/-- Successful source conversion and compilation earns all original literal
bytes and every original-name/selected-index association, in source order. -/
theorem native_original_path_has_full_meaning (names : Slice (NativeVec Std.U8))
    (source : Slice NativePathSource)
    (bounded : ∀ segment ∈ source.val, NativePathFits segment) :
    (do let converted ← AuthsNativeRecipe.recipe.lower.named_path source
        AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_path names
          (AuthsNativeRecipe.alloc.vec.Vec.deref converted)) ⦃ actual =>
      ∀ built, actual = .Ok built →
        List.Forall₂ (SegmentMeaning (nativeNameColumn names))
          (source.val.map originalPathSegment) (built.val.map nativeSegment) ⦄ := by
  apply spec_mono (native_original_path_verdict names source bounded)
  intro actual exact built accepted
  rw [accepted] at exact
  have compiled : lowerPath (nativeNameColumn names) (source.val.map originalPathSegment) =
      .ok (built.val.map nativeSegment) := by simpa only [nativeConstructResult] using exact.symm
  unfold lowerPath at compiled
  split at compiled
  · exact lower_list_sound _ _ _ compiled
  · contradiction

/-- Independent admission of the original path earns useful compilation.
No successful conversion, chosen path plan or expected index is a premise. -/
theorem native_original_path_useful (names : Slice (NativeVec Std.U8))
    (source : Slice NativePathSource)
    (bounded : ∀ segment ∈ source.val, NativePathFits segment)
    (admitted : PathAdmissible (nativeNameColumn names) (source.val.map originalPathSegment)) :
    (do let converted ← AuthsNativeRecipe.recipe.lower.named_path source
        AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_path names
          (AuthsNativeRecipe.alloc.vec.Vec.deref converted)) ⦃ actual =>
      ∃ built, actual = .Ok built ∧
        List.Forall₂ (SegmentMeaning (nativeNameColumn names))
          (source.val.map originalPathSegment) (built.val.map nativeSegment) ⦄ := by
  obtain ⟨meaning, useful⟩ := lower_path_complete _ _ admitted
  apply spec_mono (native_original_path_verdict names source bounded)
  intro actual exact
  rw [useful] at exact
  cases actual with
  | Err error => simp only [nativeConstructResult, Except.error_ne_ok] at exact
  | Ok built =>
      have same : built.val.map nativeSegment = meaning := by
        simpa only [nativeConstructResult, Except.ok.injEq] using exact
      refine ⟨built, rfl, ?_⟩
      unfold lowerPath at useful
      split at useful
      · simpa only [same] using lower_list_sound _ _ _ useful
      · contradiction

theorem native_original_fixed_path_verdict (source : Slice NativePathSource)
    (bounded : ∀ segment ∈ source.val, NativePathFits segment) :
    (do let converted ← AuthsNativeRecipe.recipe.lower.named_path source
        AuthsNativeRecipe.auths_gateway_kernel.path_compiler.lower_fixed_path
          (AuthsNativeRecipe.alloc.vec.Vec.deref converted)) ⦃ actual =>
      nativeConstructResult (fun built => built.val.map bytes) actual =
        lowerFixedPath (source.val.map originalPathSegment) ⦄ := by
  step with native_path_input_exact source bounded as ⟨converted, convertedMeaning⟩
  apply spec_mono (native_lower_fixed_path_exact (AuthsNativeRecipe.alloc.vec.Vec.deref converted))
  intro actual exact
  simpa only [nativePath, native_deref_contents, convertedMeaning] using exact

end Auths.Product.NativeCompiler.Refinement
