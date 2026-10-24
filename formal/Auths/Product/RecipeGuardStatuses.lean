import Auths.Product.RecipeCredentialAdmission

namespace Auths.Product.RecipeAdmissionAtoms

def refusedStatusAt (statuses : List Nat) (position : Nat) : Bool :=
  match statuses[position]? with
  | none => false
  | some status => decide (RefusedStatus status ∧ status ∉ statuses.take position)

/-- A suffix remains accountable to every earlier original status, rather
than testing uniqueness only inside the remaining suffix. -/
def StatusSequence (prefix values : List Nat) : Prop :=
  values.Nodup ∧ ∀ value ∈ values, RefusedStatus value ∧ value ∉ prefix
instance (prefix values : List Nat) : Decidable (StatusSequence prefix values) := by
  unfold StatusSequence
  infer_instance

theorem status_sequence_cons (prefix : List Nat) (first : Nat) (rest : List Nat) :
    StatusSequence prefix (first :: rest) ↔
      RefusedStatus first ∧ first ∉ prefix ∧ StatusSequence (prefix ++ [first]) rest := by
  constructor
  · rintro ⟨unique, all⟩
    obtain ⟨valid, fresh⟩ := all first (by simp)
    refine ⟨valid, fresh, (List.nodup_cons.mp unique).2, ?_⟩
    intro value member
    obtain ⟨valid, fresh⟩ := all value (by simp [member])
    refine ⟨valid, ?_⟩
    intro used
    rcases List.mem_append.mp used with earlier | current
    · exact fresh earlier
    · have same : value = first := List.mem_singleton.mp current
      exact (List.nodup_cons.mp unique).1 (same ▸ member)
  · rintro ⟨valid, fresh, unique, all⟩
    have firstAbsent : first ∉ rest := by
      intro present
      exact (all first present).2 (by simp)
    refine ⟨List.nodup_cons.mpr ⟨firstAbsent, unique⟩, ?_⟩
    intro value member
    rcases List.mem_cons.mp member with rfl | later
    · exact ⟨valid, fresh⟩
    · exact ⟨(all value later).1, fun earlier => (all value later).2 (List.mem_append_left _ earlier)⟩

theorem status_sequence_original (statuses : List Nat) :
    StatusSequence [] statuses ↔ statuses.Nodup ∧ ∀ status ∈ statuses, RefusedStatus status := by
  simp [StatusSequence]

theorem refused_statuses_exclude_retryable (statuses : List Nat) (admitted : RefusedStatuses statuses) :
    408 ∉ statuses ∧ 429 ∉ statuses ∧ statuses.Nodup ∧
      ∀ status ∈ statuses, 400 ≤ status ∧ status ≤ 499 := by
  refine ⟨?_, ?_, admitted.2.2.1, ?_⟩
  · intro member
    exact (admitted.2.2.2 408 member).2.2.1 rfl
  · intro member
    exact (admitted.2.2.2 429 member).2.2.2 rfl
  · intro status member
    exact ⟨(admitted.2.2.2 status member).1, (admitted.2.2.2 status member).2.1⟩

end Auths.Product.RecipeAdmissionAtoms
