import Auths.Product.EntryDeadline

/-!
Independent complete entry-time meaning. Each original endpoint constrains
dispatch separately; this relation does not compute a minimum endpoint and
does not assume an earlier gate remains true. Clock/qualification acquisition,
native command provenance and physical HTTP invocation remain separate duties.
-/
namespace Auths.Product.EntryGate
open EntryDeadline

def maximumElapsedNanos : Nat := 60000000000

def Allows (evaluatedAt : Nat) (now : Option Nat) (authority prepared : Bound)
    (current : Option Bound) (elapsedNanos : Nat) : Prop :=
  match now, current with
  | some now, some current =>
      elapsedNanos ≤ maximumElapsedNanos ∧
      admits evaluatedAt authority now ∧
      admits evaluatedAt prepared now ∧
      admits evaluatedAt current now
  | _, _ => False

instance (evaluatedAt : Nat) (now : Option Nat) (authority prepared : Bound)
    (current : Option Bound) (elapsedNanos : Nat) :
    Decidable (Allows evaluatedAt now authority prepared current elapsedNanos) := by
  unfold Allows
  split <;> infer_instance

theorem original_bounds_iff_intersection (evaluatedAt now : Nat)
    (authority prepared current : Bound) (elapsedNanos : Nat) :
    Allows evaluatedAt (some now) authority prepared (some current) elapsedNanos ↔
      elapsedNanos ≤ maximumElapsedNanos ∧
        admits evaluatedAt (meet authority (meet prepared current)) now := by
  simp only [Allows, every_deadline_holds, and_assoc]

theorem requires_present_samples (evaluatedAt : Nat) (now : Option Nat)
    (authority prepared : Bound) (current : Option Bound) (elapsedNanos : Nat)
    (allowed : Allows evaluatedAt now authority prepared current elapsedNanos) :
    ∃ sampledNow checkedCurrent,
      now = some sampledNow ∧ current = some checkedCurrent ∧
      elapsedNanos ≤ maximumElapsedNanos ∧
      admits evaluatedAt authority sampledNow ∧
      admits evaluatedAt prepared sampledNow ∧
      admits evaluatedAt checkedCurrent sampledNow := by
  cases now with
  | none => exact False.elim allowed
  | some sampledNow =>
    cases current with
    | none => exact False.elim allowed
    | some checkedCurrent => exact ⟨sampledNow, checkedCurrent, rfl, rfl, allowed⟩

theorem missing_clock_refuses (evaluatedAt : Nat) (authority prepared : Bound)
    (current : Option Bound) (elapsedNanos : Nat) :
    ¬ Allows evaluatedAt none authority prepared current elapsedNanos := by
  cases current <;> simp [Allows]

theorem missing_qualification_refuses (evaluatedAt : Nat) (now : Option Nat)
    (authority prepared : Bound) (elapsedNanos : Nat) :
    ¬ Allows evaluatedAt now authority prepared none elapsedNanos := by
  cases now <;> simp [Allows]

theorem elapsed_timeout_refuses (evaluatedAt : Nat) (now : Option Nat)
    (authority prepared : Bound) (current : Option Bound) (elapsedNanos : Nat)
    (expired : maximumElapsedNanos < elapsedNanos) :
    ¬ Allows evaluatedAt now authority prepared current elapsedNanos := by
  intro allowed
  obtain ⟨_, _, _, _, elapsed, _⟩ := requires_present_samples _ _ _ _ _ _ allowed
  omega

theorem rollback_refuses (evaluatedAt now : Nat) (authority prepared : Bound)
    (current : Option Bound) (elapsedNanos : Nat) (rollback : now < evaluatedAt) :
    ¬ Allows evaluatedAt (some now) authority prepared current elapsedNanos := by
  cases current with
  | none => exact missing_qualification_refuses _ _ _ _ _
  | some current =>
    intro allowed
    have lower := allowed.2.1.1
    omega

theorem expired_authority_refuses (evaluatedAt now : Nat) (authority prepared : Bound)
    (current : Option Bound) (elapsedNanos : Nat) (expired : authority.deadline < now) :
    ¬ Allows evaluatedAt (some now) authority prepared current elapsedNanos := by
  cases current with
  | none => exact missing_qualification_refuses _ _ _ _ _
  | some current =>
    intro allowed
    rcases allowed.2.1.2 with before | ⟨equal, _⟩ <;> omega

theorem an_exclusive_original_endpoint_refuses (evaluatedAt now : Nat)
    (authority prepared current : Bound) (elapsedNanos : Nat)
    (exclusive : (authority = ⟨now, false⟩) ∨
      (prepared = ⟨now, false⟩) ∨ (current = ⟨now, false⟩)) :
    ¬ Allows evaluatedAt (some now) authority prepared (some current) elapsedNanos := by
  intro allowed
  rcases exclusive with rfl | rfl | rfl
  · exact exclusive_endpoint_refuses evaluatedAt now allowed.2.1
  · exact exclusive_endpoint_refuses evaluatedAt now allowed.2.2.1
  · exact exclusive_endpoint_refuses evaluatedAt now allowed.2.2.2

theorem useful_original_endpoints (evaluatedAt now elapsedNanos : Nat)
    (authority prepared current : Bound)
    (elapsed : elapsedNanos ≤ maximumElapsedNanos)
    (authorityAllows : admits evaluatedAt authority now)
    (preparedAllows : admits evaluatedAt prepared now)
    (currentAllows : admits evaluatedAt current now) :
    Allows evaluatedAt (some now) authority prepared (some current) elapsedNanos :=
  ⟨elapsed, authorityAllows, preparedAllows, currentAllows⟩

theorem useful_exact_elapsed_and_inclusive_endpoint (evaluatedAt endpoint : Nat)
    (ordered : evaluatedAt ≤ endpoint) :
    Allows evaluatedAt (some endpoint) ⟨endpoint, true⟩ ⟨endpoint, true⟩
      (some ⟨endpoint, true⟩) maximumElapsedNanos := by
  have accepted := inclusive_endpoint_admits evaluatedAt endpoint ordered
  exact useful_original_endpoints _ _ _ _ _ _ (Nat.le_refl _) accepted accepted accepted

end Auths.Product.EntryGate
