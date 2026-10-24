import Auths.Product.RecipeGuardPaths

namespace Auths.Product.RecipeCredentialAdmission
open RecipeAdmissionAtoms

def deniedReadStep (read : DeniedRead) (reserved seen : List FixedPath) :
    Except Unit Unit × List FixedPath :=
  match fixedPathResult read.path with
  | .error _ => (.error (), seen)
  | .ok path =>
      if (read.method = getMethod ∨ read.method = headMethod) ∧ RefusedStatuses read.refusedStatuses ∧
          path ∉ seen ∧ path ∉ reserved then (.ok (), seen ++ [path])
      else (.error (), seen)

theorem denied_read_step_refusal_retains_seen (read : DeniedRead) (reserved seen : List FixedPath)
    (refused : (deniedReadStep read reserved seen).1 = .error ()) :
    (deniedReadStep read reserved seen).2 = seen := by
  unfold deniedReadStep at *
  cases fixedPathResult read.path <;> simp_all
  split at refused <;> simp_all

theorem denied_read_step_success (read : DeniedRead) (reserved seen : List FixedPath) :
    (deniedReadStep read reserved seen).1 = .ok () ↔
      DeniedReadAdmitted read ∧ ∃ path, fixedValues read.path = some path ∧
        path ∉ seen ∧ path ∉ reserved ∧ (deniedReadStep read reserved seen).2 = seen ++ [path] := by
  unfold deniedReadStep
  cases selected : fixedPathResult read.path with
  | error error =>
      cases error
      have denied := (fixed_path_result_refuses read.path).mp selected
      simp [DeniedReadAdmitted, denied]
  | ok path =>
      obtain ⟨admitted, copied⟩ := (fixed_path_result_ok _ _).mp selected
      by_cases method : read.method = getMethod ∨ read.method = headMethod <;>
        by_cases statuses : RefusedStatuses read.refusedStatuses <;>
        by_cases fresh : path ∉ seen <;> by_cases separate : path ∉ reserved <;>
        simp_all [DeniedReadAdmitted, and_assoc]

theorem denied_read_step_storage (read : DeniedRead) (reserved seen : List FixedPath) :
    (deniedReadStep read reserved seen).2.length ≤ seen.length + 1 := by
  unfold deniedReadStep
  cases fixedPathResult read.path <;> simp
  split <;> simp

end Auths.Product.RecipeCredentialAdmission
