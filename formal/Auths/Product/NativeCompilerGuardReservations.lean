import Auths.Product.NativeCompilerGuardPathIdentity

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def ruleGuardSourcePaths (source : NativeRecipeSource) : RecipeCredentialAdmission.SourcePaths := {
  write := planPath source.write.path
  observation := source.observation.map (fun read => planPath read.path)
  preEntry := source.pre_entry.map (fun read => planPath read.path)
  relativeCeiling := source.relative_ceiling.map (fun read => planPath read.path)
}

/-- Transparent first four stages of validate_guard_denied, calling the
unchanged native tag-copy function in the native reservation order. This is
a proof term for the source prefix, not a replacement production validator. -/
def guardSourceReservations (reserved : NativeVec (NativeVec String)) (source : NativeRecipeSource) :
    Result (NativeVec (NativeVec String)) := do
  let write ← AuthsNativeRecipe.recipe.validate.reserve_fixed_path reserved
    (AuthsNativeRecipe.alloc.vec.Vec.deref source.write.path)
  let observation ← match source.observation with
    | none => ok write
    | some read => AuthsNativeRecipe.recipe.validate.reserve_fixed_path write
        (AuthsNativeRecipe.alloc.vec.Vec.deref read.path)
  let preEntry ← match source.pre_entry with
    | none => ok observation
    | some read => AuthsNativeRecipe.recipe.validate.reserve_fixed_path observation
        (AuthsNativeRecipe.alloc.vec.Vec.deref read.path)
  match source.relative_ceiling with
  | none => ok preEntry
  | some read => AuthsNativeRecipe.recipe.validate.reserve_fixed_path preEntry
      (AuthsNativeRecipe.alloc.vec.Vec.deref read.path)

theorem original_guard_reservation_paths (source : NativeRecipeSource) (body : TemplateAst.Body) :
    ruleGuardSourcePaths source = RecipeRuleAdmission.paths (ruleSource source body) := by
  simpa [ruleGuardSourcePaths] using (rule_source_has_original_guard_paths source body).symm

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 18000000
set_option maxRecDepth 4096

/-- Reservation copies every all-fixed path, including an empty path or an
invalid fixed literal. It does not grant admission to that path: the enclosing
source validator owns its grammar and role. Non-fixed tags reserve nothing. -/
@[step] theorem native_guard_reserve_fixed_path_exact (reserved : NativeVec (NativeVec String))
    (path : Slice NativePathSource) (room : reserved.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.reserve_fixed_path reserved path ⦃ actual =>
      fixedPathColumn actual.val = fixedPathColumn reserved.val ++
        (fixedValues (path.val.map planPathSegment)).toList ∧
      actual.val.length ≤ reserved.val.length + 1 ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.reserve_fixed_path
  step with native_fixed_values_exact path as ⟨copied, original⟩
  cases copied with
  | none => simp_all
  | some values =>
      step with native_push_exact reserved values room as ⟨updated, appended⟩
      simp_all [fixedPathColumn, appended, List.map_append]

/-- At most four original source paths are added. Existing probe/account
reservations remain the prefix, and write/observation/pre-entry/relative paths
remain in the actual native order, without requiring source admission. -/
@[step] theorem native_guard_source_reservations_exact (reserved : NativeVec (NativeVec String))
    (source : NativeRecipeSource) (room : reserved.val.length + 4 ≤ Usize.max) :
    guardSourceReservations reserved source ⦃ actual =>
      fixedPathColumn actual.val = fixedPathColumn reserved.val ++ sourceReserved (ruleGuardSourcePaths source) ∧
      actual.val.length ≤ reserved.val.length + 4 ⦄ := by
  unfold guardSourceReservations
  step with native_guard_reserve_fixed_path_exact reserved
    (AuthsNativeRecipe.alloc.vec.Vec.deref source.write.path) (by omega)
    as ⟨write, writeMeaning, writeGrowth⟩
  have observationStage :
      (match source.observation with
      | none => ok write
      | some read => AuthsNativeRecipe.recipe.validate.reserve_fixed_path write
          (AuthsNativeRecipe.alloc.vec.Vec.deref read.path)) ⦃ actual =>
        fixedPathColumn actual.val = fixedPathColumn write.val ++
          optionalFixedPath (ruleGuardSourcePaths source).observation ∧
        actual.val.length ≤ reserved.val.length + 2 ⦄ := by
    cases present : source.observation with
    | none => simp [ruleGuardSourcePaths, present, optionalFixedPath]; omega
    | some read =>
        apply spec_mono (native_guard_reserve_fixed_path_exact write
          (AuthsNativeRecipe.alloc.vec.Vec.deref read.path) (by omega))
        intro actual meaning
        refine ⟨?_, by omega⟩
        simpa [ruleGuardSourcePaths, present, optionalFixedPath, planPath, native_deref_contents] using meaning.1
  step with observationStage as ⟨observation, observationMeaning, observationGrowth⟩
  have preEntryStage :
      (match source.pre_entry with
      | none => ok observation
      | some read => AuthsNativeRecipe.recipe.validate.reserve_fixed_path observation
          (AuthsNativeRecipe.alloc.vec.Vec.deref read.path)) ⦃ actual =>
        fixedPathColumn actual.val = fixedPathColumn observation.val ++
          optionalFixedPath (ruleGuardSourcePaths source).preEntry ∧
        actual.val.length ≤ reserved.val.length + 3 ⦄ := by
    cases present : source.pre_entry with
    | none => simp [ruleGuardSourcePaths, present, optionalFixedPath]; omega
    | some read =>
        apply spec_mono (native_guard_reserve_fixed_path_exact observation
          (AuthsNativeRecipe.alloc.vec.Vec.deref read.path) (by omega))
        intro actual meaning
        refine ⟨?_, by omega⟩
        simpa [ruleGuardSourcePaths, present, optionalFixedPath, planPath, native_deref_contents] using meaning.1
  step with preEntryStage as ⟨preEntry, preEntryMeaning, preEntryGrowth⟩
  cases present : source.relative_ceiling with
  | none =>
      simp [sourceReserved, ruleGuardSourcePaths, present, optionalFixedPath, planPath,
        native_deref_contents, preEntryMeaning, observationMeaning, writeMeaning, List.append_assoc]
      omega
  | some read =>
      step with native_guard_reserve_fixed_path_exact preEntry
        (AuthsNativeRecipe.alloc.vec.Vec.deref read.path) (by omega) as ⟨actual, meaning, growth⟩
      refine ⟨?_, by omega⟩
      simpa [sourceReserved, ruleGuardSourcePaths, present, optionalFixedPath, planPath,
        native_deref_contents, preEntryMeaning, observationMeaning, writeMeaning, List.append_assoc] using meaning

/-- The transparent prefix above is the actual caller prefix; no validator
callback or independently selected reserved set stands in for the Rust path. -/
theorem native_guard_denied_uses_source_reservations (reads : Slice NativeDeniedSource)
    (reserved : NativeVec (NativeVec String)) (source : NativeRecipeSource) :
    AuthsNativeRecipe.recipe.validate.validate_guard_denied reads reserved source =
      (do
        let final ← guardSourceReservations reserved source
        AuthsNativeRecipe.recipe.validate.validate_denied_reads reads
          (AuthsNativeRecipe.alloc.vec.Vec.deref final)) := by
  simp only [AuthsNativeRecipe.recipe.validate.validate_guard_denied, guardSourceReservations]
  simp [bind_assoc]

end Auths.Product.NativeCompiler.Refinement
