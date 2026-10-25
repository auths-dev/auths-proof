import Auths.Product.RecipeDeniedReadSequence

namespace Auths.Product.RecipeCredentialAdmission

theorem account_read_result_refuses (read : Read) :
    accountReadResult read = .error () ↔ ¬ReadAdmitted read := by
  cases result : accountReadResult read with
  | ok values =>
      have admitted := ((account_read_result_ok read values).mp result).1
      simp [admitted]
  | error error =>
      cases error
      simp only [true_iff]
      intro admitted
      obtain ⟨values, selected, _⟩ := admitted.1.2.2
      have accepted := (account_read_result_ok read values).mpr ⟨admitted, selected⟩
      simp [result] at accepted

theorem probe_result_refuses (probe : Probe) :
    probeResult probe = .error () ↔ ¬ProbeAdmitted probe := by
  cases result : probeResult probe with
  | ok values =>
      have admitted := ((probe_result_ok probe values).mp result).1
      simp [admitted]
  | error error =>
      cases error
      simp only [true_iff]
      intro admitted
      obtain ⟨values, selected, _⟩ := admitted.1.2.2
      have accepted := (probe_result_ok probe values).mpr ⟨admitted, selected⟩
      simp [result] at accepted

def guardDeniedTailResult (denied : Option (List DeniedRead)) (reserved : List FixedPath)
    (source : SourcePaths) : Except Unit Unit :=
  match denied with
  | none => .ok ()
  | some reads => deniedReadsResult reads (reserved ++ sourceReserved source)

def guardAccountTailResult (account : Option Read) (denied : Option (List DeniedRead))
    (reserved : List FixedPath) (source : SourcePaths) : Except Unit Unit :=
  match account with
  | none => guardDeniedTailResult denied reserved source
  | some read => do
      let path ← accountReadResult read
      guardDeniedTailResult denied (reserved ++ [path]) source

def guardResult (guard : Guard) (source : SourcePaths) : Except Unit Unit :=
  if RecipeAdmissionAtoms.Prefixes guard.prefixes then
    match guard.probe with
    | none => guardAccountTailResult guard.account guard.denied [] source
    | some probe => do
        let path ← probeResult probe
        guardAccountTailResult guard.account guard.denied [path] source
  else .error ()

theorem guard_denied_tail_result_exact (denied : Option (List DeniedRead)) (reserved : List FixedPath)
    (source : SourcePaths) :
    guardDeniedTailResult denied reserved source =
      if OptionalAdmitted (fun reads => DeniedReadsAdmitted reads (reserved ++ sourceReserved source)) denied
      then .ok () else .error () := by
  cases denied with
  | none => rfl
  | some reads => simpa [guardDeniedTailResult, OptionalAdmitted] using denied_reads_result_exact reads _

theorem guard_account_tail_result_exact (account : Option Read) (denied : Option (List DeniedRead))
    (reserved : List FixedPath) (source : SourcePaths) :
    guardAccountTailResult account denied reserved source =
      if OptionalAdmitted ReadAdmitted account ∧
          OptionalAdmitted (fun reads => DeniedReadsAdmitted reads
            (reserved ++ (account.bind (fun read => fixedValues read.path)).toList ++ sourceReserved source)) denied
      then .ok () else .error () := by
  cases account with
  | none => simp [guardAccountTailResult, guard_denied_tail_result_exact, OptionalAdmitted]
  | some read =>
      cases selected : accountReadResult read with
      | error error =>
          cases error
          have refused := (account_read_result_refuses read).mp selected
          simp [guardAccountTailResult, selected, OptionalAdmitted, refused]
      | ok path =>
          obtain ⟨admitted, original⟩ := (account_read_result_ok read path).mp selected
          simp [guardAccountTailResult, selected, OptionalAdmitted, admitted, original,
            guard_denied_tail_result_exact]

theorem guard_result_exact (guard : Guard) (source : SourcePaths) :
    guardResult guard source = validateGuard () guard source := by
  by_cases prefixes : RecipeAdmissionAtoms.Prefixes guard.prefixes
  · cases probeAt : guard.probe with
    | none =>
        simp [guardResult, prefixes, probeAt, guard_account_tail_result_exact,
          validateGuard, GuardAdmitted, OptionalAdmitted, guardReserved]
    | some probe =>
        cases selected : probeResult probe with
        | error error =>
            cases error
            have refused := (probe_result_refuses probe).mp selected
            simp [guardResult, prefixes, probeAt, selected, validateGuard, GuardAdmitted,
              OptionalAdmitted, refused]
        | ok path =>
            obtain ⟨admitted, original⟩ := (probe_result_ok probe path).mp selected
            simp [guardResult, prefixes, probeAt, selected, guard_account_tail_result_exact,
              validateGuard, GuardAdmitted, OptionalAdmitted, guardReserved, admitted,
              original, List.append_assoc, and_assoc]
  · simp [guardResult, prefixes, validateGuard, GuardAdmitted]

end Auths.Product.RecipeCredentialAdmission
