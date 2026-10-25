import Auths.Product.NativeCompilerGuardReservations
import Auths.Product.NativeCompilerDeniedReadSequence

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

/-- Only original Fixed payloads are borrowed after raw reservation. Source
role and grammar admission remain separate, actual constructor obligations. -/
structure GuardSourcePathsFit (source : NativeRecipeSource) : Prop where
  write : ∀ segment ∈ source.write.path.val, GuardPathFits segment
  observation : ∀ read, source.observation = some read → ∀ segment ∈ read.path.val, GuardPathFits segment
  preEntry : ∀ read, source.pre_entry = some read → ∀ segment ∈ read.path.val, GuardPathFits segment
  relative : ∀ read, source.relative_ceiling = some read → ∀ segment ∈ read.path.val, GuardPathFits segment

def FixedByteDomain (values : RecipeCredentialAdmission.FixedPath) : Prop :=
  ∀ value ∈ values, value.length ≤ Usize.max

theorem fixed_path_column_domain (paths : List (NativeVec String)) :
    FixedPathColumnFits paths ↔ ∀ values ∈ fixedPathColumn paths, FixedByteDomain values := by
  simp [FixedPathColumnFits, FixedPathTextsFit, fixedPathColumn, FixedByteDomain,
    List.forall_mem_map, TextFits, textBytes]

theorem original_fixed_values_domain (path : List NativePathSource)
    (fits : ∀ segment ∈ path, GuardPathFits segment) (values : RecipeCredentialAdmission.FixedPath)
    (copied : RecipeCredentialAdmission.fixedValues (path.map planPathSegment) = some values) :
    FixedByteDomain values := by
  induction path generalizing values with
  | nil =>
      have empty : values = [] := by simpa [RecipeCredentialAdmission.fixedValues] using copied.symm
      simp [empty, FixedByteDomain]
  | cons first rest ih =>
      have tailFits : ∀ segment ∈ rest, GuardPathFits segment := fun segment member => fits segment (by simp [member])
      have headFits := fits first (by simp)
      cases first with
      | Fixed text =>
          cases tail : RecipeCredentialAdmission.fixedValues (rest.map planPathSegment) with
          | none => simp [planPathSegment, RecipeCredentialAdmission.fixedValues, tail] at copied
          | some remaining =>
              have same : values = textBytes text :: remaining := by
                simpa [planPathSegment, RecipeCredentialAdmission.fixedValues, tail] using copied.symm
              have tailDomain := ih tailFits remaining tail
              subst values
              intro value member
              rcases List.mem_cons.mp member with rfl | later
              · simpa [TextFits, textBytes, GuardPathFits] using headFits
              · exact tailDomain value later
      | Field _ | ResponseField _ _ | Echo =>
          simp [planPathSegment, RecipeCredentialAdmission.fixedValues] at copied

theorem original_fixed_option_domain (path : List NativePathSource)
    (fits : ∀ segment ∈ path, GuardPathFits segment) :
    ∀ values ∈ (RecipeCredentialAdmission.fixedValues (path.map planPathSegment)).toList, FixedByteDomain values := by
  cases copied : RecipeCredentialAdmission.fixedValues (path.map planPathSegment) with
  | none => simp
  | some values => simpa using original_fixed_values_domain path fits values copied

theorem original_source_reservations_domain (source : NativeRecipeSource) (fits : GuardSourcePathsFit source) :
    ∀ values ∈ RecipeCredentialAdmission.sourceReserved (ruleGuardSourcePaths source), FixedByteDomain values := by
  have write := original_fixed_option_domain source.write.path.val fits.write
  have observation : ∀ values ∈ RecipeCredentialAdmission.optionalFixedPath (ruleGuardSourcePaths source).observation,
      FixedByteDomain values := by
    cases present : source.observation with
    | none => simp [ruleGuardSourcePaths, present, RecipeCredentialAdmission.optionalFixedPath]
    | some read =>
        simpa [ruleGuardSourcePaths, present, RecipeCredentialAdmission.optionalFixedPath, planPath] using
          original_fixed_option_domain read.path.val (fits.observation read present)
  have preEntry : ∀ values ∈ RecipeCredentialAdmission.optionalFixedPath (ruleGuardSourcePaths source).preEntry,
      FixedByteDomain values := by
    cases present : source.pre_entry with
    | none => simp [ruleGuardSourcePaths, present, RecipeCredentialAdmission.optionalFixedPath]
    | some read =>
        simpa [ruleGuardSourcePaths, present, RecipeCredentialAdmission.optionalFixedPath, planPath] using
          original_fixed_option_domain read.path.val (fits.preEntry read present)
  have relative : ∀ values ∈ RecipeCredentialAdmission.optionalFixedPath (ruleGuardSourcePaths source).relativeCeiling,
      FixedByteDomain values := by
    cases present : source.relative_ceiling with
    | none => simp [ruleGuardSourcePaths, present, RecipeCredentialAdmission.optionalFixedPath]
    | some read =>
        simpa [ruleGuardSourcePaths, present, RecipeCredentialAdmission.optionalFixedPath, planPath] using
          original_fixed_option_domain read.path.val (fits.relative read present)
  intro values member
  simp only [RecipeCredentialAdmission.sourceReserved, List.mem_append] at member
  rcases member with fromWrite | fromObservation | fromPreEntry | fromRelative
  · exact write values (by simpa [ruleGuardSourcePaths, planPath] using fromWrite)
  · exact observation values fromObservation
  · exact preEntry values fromPreEntry
  · exact relative values fromRelative

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeCredentialAdmission
set_option maxHeartbeats 22000000
set_option maxRecDepth 4096

@[step] theorem native_guard_source_reservations_with_domain (reserved : NativeVec (NativeVec String))
    (source : NativeRecipeSource) (room : reserved.val.length + 4 ≤ Usize.max)
    (reservedFits : FixedPathColumnFits reserved.val) (fits : GuardSourcePathsFit source) :
    guardSourceReservations reserved source ⦃ actual =>
      fixedPathColumn actual.val = fixedPathColumn reserved.val ++ sourceReserved (ruleGuardSourcePaths source) ∧
      actual.val.length ≤ reserved.val.length + 4 ∧ FixedPathColumnFits actual.val ⦄ := by
  apply spec_mono (native_guard_source_reservations_exact reserved source room)
  rintro actual ⟨original, growth⟩
  refine ⟨original, growth, (fixed_path_column_domain actual.val).mpr ?_⟩
  rw [original]
  intro values member
  rcases List.mem_append.mp member with earlier | added
  · exact (fixed_path_column_domain reserved.val).mp reservedFits values earlier
  · exact original_source_reservations_domain source fits values added

/-- The real denied caller earns its full reserved column and representation
domain from the actual four source calls, then invokes the actual bounded list
validator. All capacity is derived from the original prefix's four-slot room. -/
@[step] theorem native_guard_denied_original_source_exact (reads : Slice NativeDeniedSource)
    (reserved : NativeVec (NativeVec String)) (source : NativeRecipeSource)
    (fits : ∀ read ∈ reads.val, GuardDeniedReadFits read)
    (reservedFits : FixedPathColumnFits reserved.val) (sourceFits : GuardSourcePathsFit source)
    (room : reserved.val.length + 4 ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.validate_guard_denied reads reserved source ⦃ actual =>
      actual = guardUnitVerdict (deniedReadsResult (reads.val.map ruleGuardDeniedRead)
        (fixedPathColumn reserved.val ++ sourceReserved (ruleGuardSourcePaths source))) ⦄ := by
  rw [native_guard_denied_uses_source_reservations]
  step with native_guard_source_reservations_with_domain reserved source room reservedFits sourceFits
    as ⟨complete, column, growth, completeFits⟩
  apply spec_mono (native_guard_denied_reads_exact reads (AuthsNativeRecipe.alloc.vec.Vec.deref complete) fits completeFits)
  intro actual meaning
  simpa [native_deref_contents, column] using meaning

end Auths.Product.NativeCompiler.Refinement
