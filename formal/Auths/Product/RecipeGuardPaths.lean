import Auths.Product.RecipeCredentialAdmission

namespace Auths.Product.RecipeCredentialAdmission

/-- Original all-fixed prefix, stopping before the first non-fixed tag. The
flag says whether the entire original path was copied; no grammar is checked. -/
def fixedPrefix : Path → FixedPath × Bool
  | [] => ([], true)
  | .fixed value :: rest =>
      let tail := fixedPrefix rest
      (value :: tail.1, tail.2)
  | _ :: _ => ([], false)

def FixedSegments : Path → Prop
  | [] => True
  | .fixed value :: rest => PathCompiler.FixedValid value ∧ FixedSegments rest
  | _ :: _ => False
instance (path : Path) : Decidable (FixedSegments path) := by
  induction path with
  | nil => exact isTrue trivial
  | cons first rest ih => cases first <;> simp only [FixedSegments] <;> infer_instance

theorem fixed_prefix_length (path : Path) : (fixedPrefix path).1.length ≤ path.length := by
  induction path with
  | nil => simp [fixedPrefix]
  | cons first rest ih => cases first <;> simp_all [fixedPrefix]

theorem fixed_prefix_values (path : Path) :
    (if (fixedPrefix path).2 then some (fixedPrefix path).1 else none) = fixedValues path := by
  induction path with
  | nil => rfl
  | cons first rest ih =>
      cases first <;> simp only [fixedPrefix, fixedValues]
      · cases flag : (fixedPrefix rest).2 <;> simp_all

theorem fixed_segments_values (path : Path) :
    FixedSegments path ↔ ∃ values, fixedValues path = some values ∧
      ∀ value ∈ values, PathCompiler.FixedValid value := by
  induction path with
  | nil => simp [FixedSegments, fixedValues]
  | cons first rest ih =>
      cases first <;> simp only [FixedSegments, fixedValues]
      · cases copied : fixedValues rest with
        | none => simp_all
        | some values => simp_all [List.mem_cons, forall_eq_or_imp, and_assoc]
      · simp
      · simp
      · simp

theorem fixed_segments_copy_completes (path : Path) (valid : FixedSegments path) :
    (fixedPrefix path).2 = true := by
  obtain ⟨values, copied, _⟩ := (fixed_segments_values path).mp valid
  have exact := fixed_prefix_values path
  cases flag : (fixedPrefix path).2 <;> simp_all

/-- All guard path failures carry one error. Keeping the returned original
bytes in the model permits callers to prove reservation, rather than merely
equating two admission Booleans. -/
def fixedPathResult (path : Path) : Except Unit FixedPath :=
  if 0 < path.length ∧ path.length ≤ 16 ∧ FixedSegments path then
    match fixedValues path with
    | some values => .ok values
    | none => .error ()
  else .error ()

theorem fixed_path_result_ok (path : Path) (values : FixedPath) :
    fixedPathResult path = .ok values ↔
      FixedPathAdmitted path ∧ fixedValues path = some values := by
  unfold fixedPathResult FixedPathAdmitted
  rw [← fixed_segments_values]
  by_cases admitted : 0 < path.length ∧ path.length ≤ 16 ∧ FixedSegments path
  · obtain ⟨copied, selected, _⟩ := (fixed_segments_values path).mp admitted.2.2
    simp [admitted, selected]
  · simp [admitted]

theorem fixed_path_result_refuses (path : Path) :
    fixedPathResult path = .error () ↔ ¬FixedPathAdmitted path := by
  cases result : fixedPathResult path with
  | ok values =>
      have admitted := ((fixed_path_result_ok path values).mp result).1
      simp [admitted]
  | error error =>
      cases error
      simp only [true_iff]
      intro admitted
      obtain ⟨values, selected, _⟩ := admitted.2.2
      have accepted := (fixed_path_result_ok path values).mpr ⟨admitted, selected⟩
      simp [result] at accepted

def accountReadResult (read : Read) : Except Unit FixedPath := do
  let path ← fixedPathResult read.path
  if RecipeAdmissionAtoms.ResponsePointer read.pointer ∧
      RecipeAdmissionAtoms.ReadBound read.maximumResponseBytes then .ok path else .error ()

def probeResult (probe : Probe) : Except Unit FixedPath := do
  let path ← fixedPathResult probe.path
  if RecipeAdmissionAtoms.ResponsePointer probe.pointer ∧ ProbeLiteralAdmitted probe.equals ∧
      RecipeAdmissionAtoms.ReadBound probe.maximumResponseBytes then .ok path else .error ()

theorem account_read_result_ok (read : Read) (values : FixedPath) :
    accountReadResult read = .ok values ↔
      ReadAdmitted read ∧ fixedValues read.path = some values := by
  unfold accountReadResult ReadAdmitted
  cases result : fixedPathResult read.path with
  | error error =>
      cases error
      have refused := (fixed_path_result_refuses read.path).mp result
      simp [refused]
  | ok path =>
      obtain ⟨admitted, selected⟩ := (fixed_path_result_ok read.path path).mp result
      by_cases pointer : RecipeAdmissionAtoms.ResponsePointer read.pointer <;>
        by_cases bound : RecipeAdmissionAtoms.ReadBound read.maximumResponseBytes <;>
        simp_all [and_assoc]

theorem probe_result_ok (probe : Probe) (values : FixedPath) :
    probeResult probe = .ok values ↔
      ProbeAdmitted probe ∧ fixedValues probe.path = some values := by
  unfold probeResult ProbeAdmitted
  cases result : fixedPathResult probe.path with
  | error error =>
      cases error
      have refused := (fixed_path_result_refuses probe.path).mp result
      simp [refused]
  | ok path =>
      obtain ⟨admitted, selected⟩ := (fixed_path_result_ok probe.path path).mp result
      by_cases pointer : RecipeAdmissionAtoms.ResponsePointer probe.pointer <;>
        by_cases literal : ProbeLiteralAdmitted probe.equals <;>
        by_cases bound : RecipeAdmissionAtoms.ReadBound probe.maximumResponseBytes <;>
        simp_all [and_assoc]

end Auths.Product.RecipeCredentialAdmission
