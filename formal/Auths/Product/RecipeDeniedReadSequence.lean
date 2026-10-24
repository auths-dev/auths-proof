import Auths.Product.RecipeDeniedReadSteps

namespace Auths.Product.RecipeCredentialAdmission

def FreshPaths (reserved seen paths : List FixedPath) : Prop :=
  paths.Nodup ∧ ∀ path ∈ paths, path ∉ seen ∧ path ∉ reserved
instance (reserved seen paths : List FixedPath) : Decidable (FreshPaths reserved seen paths) := by
  unfold FreshPaths
  infer_instance

theorem fresh_paths_cons (reserved seen : List FixedPath) (first : FixedPath) (rest : List FixedPath) :
    FreshPaths reserved seen (first :: rest) ↔
      first ∉ seen ∧ first ∉ reserved ∧ FreshPaths reserved (seen ++ [first]) rest := by
  constructor
  · rintro ⟨unique, all⟩
    obtain ⟨fresh, separate⟩ := all first (by simp)
    refine ⟨fresh, separate, (List.nodup_cons.mp unique).2, ?_⟩
    intro path member
    obtain ⟨fresh, separate⟩ := all path (by simp [member])
    refine ⟨?_, separate⟩
    intro earlier
    rcases List.mem_append.mp earlier with seenBefore | current
    · exact fresh seenBefore
    · have same : path = first := List.mem_singleton.mp current
      exact (List.nodup_cons.mp unique).1 (same ▸ member)
  · rintro ⟨fresh, separate, unique, all⟩
    have absent : first ∉ rest := by
      intro member
      exact (all first member).1 (by simp)
    refine ⟨List.nodup_cons.mpr ⟨absent, unique⟩, ?_⟩
    intro path member
    rcases List.mem_cons.mp member with rfl | later
    · exact ⟨fresh, separate⟩
    · exact ⟨fun earlier => (all path later).1 (List.mem_append_left _ earlier), (all path later).2⟩

theorem denied_paths_cons (read : DeniedRead) (rest : List DeniedRead) :
    deniedPaths (read :: rest) = do
      let first ← fixedValues read.path
      let tail ← deniedPaths rest
      some (first :: tail) := by
  simp [deniedPaths, List.mapM_cons]

/-- The declarative suffix still excludes every earlier original path, as
well as every reserved source/probe/account path. No native result is input. -/
def DeniedSequenceMeaning (reads : List DeniedRead) (reserved seen : List FixedPath) : Prop :=
  (∀ read ∈ reads, DeniedReadAdmitted read) ∧
    ∃ paths, deniedPaths reads = some paths ∧ FreshPaths reserved seen paths
instance (reads : List DeniedRead) (reserved seen : List FixedPath) :
    Decidable (DeniedSequenceMeaning reads reserved seen) := by
  unfold DeniedSequenceMeaning
  cases deniedPaths reads <;> simp <;> infer_instance

theorem denied_sequence_meaning_nil (reserved seen : List FixedPath) :
    DeniedSequenceMeaning [] reserved seen := by
  simp [DeniedSequenceMeaning, deniedPaths, FreshPaths]

theorem denied_sequence_meaning_cons (read : DeniedRead) (rest : List DeniedRead)
    (reserved seen : List FixedPath) :
    DeniedSequenceMeaning (read :: rest) reserved seen ↔
      (deniedReadStep read reserved seen).1 = .ok () ∧
        DeniedSequenceMeaning rest reserved (deniedReadStep read reserved seen).2 := by
  cases selected : fixedPathResult read.path with
  | error error =>
      cases error
      have invalidPath := (fixed_path_result_refuses read.path).mp selected
      have invalidRead : ¬DeniedReadAdmitted read := fun allowed => invalidPath allowed.2.1
      simp [deniedReadStep, selected, DeniedSequenceMeaning, invalidRead]
  | ok first =>
      obtain ⟨validPath, copied⟩ := (fixed_path_result_ok _ _).mp selected
      cases tail : deniedPaths rest with
      | none =>
          simp [DeniedSequenceMeaning, denied_paths_cons, copied, tail, deniedReadStep, selected]
      | some paths =>
          by_cases method : read.method = getMethod ∨ read.method = headMethod <;>
            by_cases statuses : RecipeAdmissionAtoms.RefusedStatuses read.refusedStatuses <;>
            by_cases fresh : first ∉ seen <;> by_cases separate : first ∉ reserved <;>
            simp_all [DeniedSequenceMeaning, denied_paths_cons, fresh_paths_cons,
              deniedReadStep, DeniedReadAdmitted, List.nodup_cons, and_assoc, and_comm, and_left_comm]

/-- Ordered, first-refusal execution of the independent original-read steps. -/
def deniedReadSequence (reserved seen : List FixedPath) : List DeniedRead → Bool
  | [] => true
  | read :: rest =>
      let checked := deniedReadStep read reserved seen
      match checked.1 with
      | .error _ => false
      | .ok _ => deniedReadSequence reserved checked.2 rest

theorem denied_read_sequence_exact (reads : List DeniedRead) (reserved seen : List FixedPath) :
    deniedReadSequence reserved seen reads = true ↔ DeniedSequenceMeaning reads reserved seen := by
  induction reads generalizing seen with
  | nil => simp [deniedReadSequence, denied_sequence_meaning_nil]
  | cons read rest ih =>
      rw [denied_sequence_meaning_cons]
      cases checked : (deniedReadStep read reserved seen).1 <;>
        simp [deniedReadSequence, checked, ih]

def deniedReadsResult (reads : List DeniedRead) (reserved : List FixedPath) : Except Unit Unit :=
  if 0 < reads.length ∧ reads.length ≤ 4 then
    if deniedReadSequence reserved [] reads then .ok () else .error ()
  else .error ()

theorem denied_reads_result_admission (reads : List DeniedRead) (reserved : List FixedPath) :
    deniedReadsResult reads reserved = .ok () ↔ DeniedReadsAdmitted reads reserved := by
  simp [deniedReadsResult, denied_read_sequence_exact, DeniedReadsAdmitted,
    DeniedSequenceMeaning, FreshPaths, and_assoc]

theorem denied_reads_result_exact (reads : List DeniedRead) (reserved : List FixedPath) :
    deniedReadsResult reads reserved = if DeniedReadsAdmitted reads reserved then .ok () else .error () := by
  by_cases admitted : DeniedReadsAdmitted reads reserved
  · simp [admitted, (denied_reads_result_admission reads reserved).mpr admitted]
  · have refused : deniedReadsResult reads reserved ≠ .ok () :=
      fun accepted => admitted ((denied_reads_result_admission reads reserved).mp accepted)
    cases result : deniedReadsResult reads reserved <;> simp_all

end Auths.Product.RecipeCredentialAdmission
