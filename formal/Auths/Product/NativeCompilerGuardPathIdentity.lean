import Auths.Product.NativeCompilerGuardReads
import Auths.Product.NativeCompilerGuardStatuses

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def fixedPathColumn (paths : List (NativeVec String)) : List RecipeCredentialAdmission.FixedPath :=
  paths.map fun path => path.val.map textBytes

def FixedPathTextsFit (path : List String) : Prop := ∀ text ∈ path, TextFits text

def FixedPathColumnFits (paths : List (NativeVec String)) : Prop :=
  ∀ path ∈ paths, FixedPathTextsFit path.val

def ruleGuardDeniedRead (source : NativeDeniedSource) : RecipeCredentialAdmission.DeniedRead :=
  ⟨textBytes source.method, planPath source.path, source.refused_status.val.map (·.val)⟩

def GuardDeniedReadFits (source : NativeDeniedSource) : Prop :=
  TextFits source.method ∧ ∀ segment ∈ source.path.val, GuardPathFits segment

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission RecipeAdmissionAtoms
set_option maxHeartbeats 18000000
set_option maxRecDepth 4096

theorem admitted_original_fixed_texts_fit (path : RecipeCredentialAdmission.Path)
    (values : NativeVec String) (selected : fixedPathResult path = .ok (values.val.map textBytes)) :
    FixedPathTextsFit values.val := by
  obtain ⟨admitted, copied⟩ := (fixed_path_result_ok _ _).mp selected
  obtain ⟨original, same, segments⟩ := admitted.2.2
  have originalValues : original = values.val.map textBytes := Option.some.inj (same.symm.trans copied)
  subst original
  intro text member
  have byteBound := (segments (textBytes text) (List.mem_map.mpr ⟨text, member, rfl⟩)).2.1
  have size : text.toByteArray.size ≤ 128 := by simpa [textBytes] using byteBound
  unfold TextFits
  scalar_tac

private theorem native_fixed_paths_suffix (left right : Slice String) (position : Std.Usize)
    (equal : Bool) (sizes : left.val.length = right.val.length)
    (within : position.val ≤ left.val.length)
    (leftFits : FixedPathTextsFit left.val) (rightFits : FixedPathTextsFit right.val) :
    AuthsNativeRecipe.recipe.validate.fixed_paths_equal_loop left right position equal ⦃ actual =>
      actual = (equal && decide ((left.val.drop position.val).map textBytes =
        (right.val.drop position.val).map textBytes)) ⦄ := by
  generalize remaining : left.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position equal with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.fixed_paths_equal_loop
      by_cases inside : position.val < left.val.length
      · have nativeInside : position < left.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases equal with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec left position inside as ⟨first, firstAt⟩
            have firstFits := leftFits first (by rw [firstAt]; exact List.getElem_mem inside)
            step with borrow_text_exact first firstFits as ⟨firstBytes, firstMeaning⟩
            have rightInside : position.val < right.val.length := by omega
            step with Slice.index_usize_spec right position rightInside as ⟨second, secondAt⟩
            have secondFits := rightFits second (by rw [secondAt]; exact List.getElem_mem rightInside)
            step with borrow_text_exact second secondFits as ⟨secondBytes, secondMeaning⟩
            step with native_schema_byte_equality firstBytes secondBytes as ⟨same, equality⟩
            have originalEquality : same = decide (textBytes first = textBytes second) := by
              simpa [schemaSliceBytes, firstMeaning, secondMeaning] using equality
            step as ⟨next, nextValue⟩
            have leftSuffix : left.val.drop position.val = first :: left.val.drop next.val := by
              simpa [firstAt, nextValue] using List.drop_eq_getElem_cons inside
            have rightSuffix : right.val.drop position.val = second :: right.val.drop next.val := by
              simpa [secondAt, nextValue] using List.drop_eq_getElem_cons rightInside
            apply spec_mono (ih _ (by omega) next same (by omega) rfl)
            intro actual meaning
            simpa [leftSuffix, rightSuffix, List.cons.injEq, originalEquality, decide_and] using meaning
      · have nativeEnded : ¬position < left.len := by scalar_tac
        have leftEnded : left.val.length ≤ position.val := by omega
        have rightEnded : right.val.length ≤ position.val := by omega
        simp [nativeEnded, List.drop_eq_nil_of_le leftEnded, List.drop_eq_nil_of_le rightEnded]

/-- Equality compares the complete sequence and complete bytes of each
original segment. It neither joins segments nor normalizes case or pointers. -/
@[step] theorem native_guard_fixed_paths_equal_exact (left right : Slice String)
    (leftFits : FixedPathTextsFit left.val) (rightFits : FixedPathTextsFit right.val) :
    AuthsNativeRecipe.recipe.validate.fixed_paths_equal left right ⦃ actual =>
      actual = decide (left.val.map textBytes = right.val.map textBytes) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.fixed_paths_equal
  by_cases sizes : left.val.length = right.val.length
  · have nativeSizes : left.len = right.len := by scalar_tac
    simp only [nativeSizes, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
    simpa using native_fixed_paths_suffix left right 0#usize true sizes (by simp) leftFits rightFits
  · have nativeSizes : left.len ≠ right.len := by scalar_tac
    have different : left.val.map textBytes ≠ right.val.map textBytes := by
      intro same
      exact sizes (by simpa using congrArg List.length same)
    simp [nativeSizes, different]

private theorem native_path_seen_suffix (paths : Slice (NativeVec String)) (candidate : Slice String)
    (position : Std.Usize) (seen : Bool) (within : position.val ≤ paths.val.length)
    (fits : FixedPathColumnFits paths.val) (candidateFits : FixedPathTextsFit candidate.val) :
    AuthsNativeRecipe.recipe.validate.path_seen_loop paths candidate position seen ⦃ actual =>
      actual = (seen || decide (candidate.val.map textBytes ∈ (fixedPathColumn paths.val).drop position.val)) ⦄ := by
  generalize remaining : paths.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position seen with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.path_seen_loop
      by_cases inside : position.val < paths.val.length
      · have nativeInside : position < paths.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases seen with
        | true => simp
        | false =>
            simp only [Bool.false_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec paths position inside as ⟨current, currentAt⟩
            have currentFits := fits current (by rw [currentAt]; exact List.getElem_mem inside)
            step with native_guard_fixed_paths_equal_exact (AuthsNativeRecipe.alloc.vec.Vec.deref current)
              candidate currentFits candidateFits as ⟨same, equality⟩
            step as ⟨next, nextValue⟩
            have suffix : (fixedPathColumn paths.val).drop position.val =
                current.val.map textBytes :: (fixedPathColumn paths.val).drop next.val := by
              simpa [fixedPathColumn, List.drop_map, currentAt, nextValue] using
                congrArg (List.map (fun path => path.val.map textBytes)) (List.drop_eq_getElem_cons inside)
            apply spec_mono (ih _ (by omega) next same (by omega) rfl)
            intro actual meaning
            simpa [suffix, equality, native_deref_contents, List.mem_cons, eq_comm, decide_or] using meaning
      · have nativeEnded : ¬position < paths.len := by scalar_tac
        have ended : (fixedPathColumn paths.val).length ≤ position.val := by simp [fixedPathColumn]; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended]

@[step] theorem native_guard_path_seen_exact (paths : Slice (NativeVec String)) (candidate : Slice String)
    (fits : FixedPathColumnFits paths.val) (candidateFits : FixedPathTextsFit candidate.val) :
    AuthsNativeRecipe.recipe.validate.path_seen paths candidate ⦃ actual =>
      actual = decide (candidate.val.map textBytes ∈ fixedPathColumn paths.val) ⦄ := by
  simpa [AuthsNativeRecipe.recipe.validate.path_seen] using
    native_path_seen_suffix paths candidate 0#usize false (by simp) fits candidateFits

/-- All four checks use original method bytes, original status list and
complete path columns. A denied-read probe cannot alias a reserved request. -/
@[step] theorem native_guard_denied_path_allowed_exact (read : NativeDeniedSource) (path : Slice String)
    (seen reserved : Slice (NativeVec String)) (methodFits : TextFits read.method)
    (pathFits : FixedPathTextsFit path.val) (seenFits : FixedPathColumnFits seen.val)
    (reservedFits : FixedPathColumnFits reserved.val) :
    AuthsNativeRecipe.recipe.validate.denied_path_allowed read path seen reserved ⦃ actual =>
      actual = decide (((textBytes read.method = getMethod) ∨ (textBytes read.method = headMethod)) ∧
        RefusedStatuses (read.refused_status.val.map (·.val)) ∧
        path.val.map textBytes ∉ fixedPathColumn seen.val ∧
        path.val.map textBytes ∉ fixedPathColumn reserved.val) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.denied_path_allowed
  step with borrow_text_exact read.method methodFits as ⟨method, methodMeaning⟩
  simp only [lift, Array.to_slice, Array.make, bind_tc_ok]
  step with native_schema_byte_equality method (toStr "GET") as ⟨get, getMeaning⟩
  have originalGet : get = decide (textBytes read.method = getMethod) := by
    simpa [schemaSliceBytes, methodMeaning, getMethod] using getMeaning
  have suffix :
      (do
        let statuses ← AuthsNativeRecipe.recipe.validate.refused_statuses_valid
          (AuthsNativeRecipe.alloc.vec.Vec.deref read.refused_status)
        if statuses then
          let used ← AuthsNativeRecipe.recipe.validate.path_seen seen path
          if used then ok false else
            let occupied ← AuthsNativeRecipe.recipe.validate.path_seen reserved path
            ok (!occupied)
        else ok false) ⦃ actual =>
        actual = decide (RefusedStatuses (read.refused_status.val.map (·.val)) ∧
          path.val.map textBytes ∉ fixedPathColumn seen.val ∧
          path.val.map textBytes ∉ fixedPathColumn reserved.val) ⦄ := by
    step with native_guard_refused_statuses_exact (AuthsNativeRecipe.alloc.vec.Vec.deref read.refused_status)
      as ⟨statuses, statusMeaning⟩
    cases statuses with
    | false => simp [← statusMeaning, native_deref_contents]
    | true =>
        simp only [Bool.true_eq_true, ↓reduceIte]
        step with native_guard_path_seen_exact seen path seenFits pathFits as ⟨used, useMeaning⟩
        cases used with
        | true => simp [← statusMeaning, native_deref_contents, ← useMeaning]
        | false =>
            simp only [Bool.false_eq_true, ↓reduceIte]
            step with native_guard_path_seen_exact reserved path reservedFits pathFits as ⟨occupied, occupation⟩
            simp [← statusMeaning, native_deref_contents, ← useMeaning, ← occupation]
  cases get with
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      apply spec_mono suffix
      intro actual meaning
      simpa [← originalGet] using meaning
  | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, lift, Array.to_slice, Array.make, bind_tc_ok]
      step with native_schema_byte_equality method (toStr "HEAD") as ⟨head, headMeaning⟩
      have originalHead : head = decide (textBytes read.method = headMethod) := by
        simpa [schemaSliceBytes, methodMeaning, headMethod] using headMeaning
      cases head with
      | false => simp [← originalGet, ← originalHead]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          apply spec_mono suffix
          intro actual meaning
          simpa [← originalGet, ← originalHead] using meaning

end Auths.Product.NativeCompiler.Refinement
