import Auths.Product.StrictJsonMembers

namespace Auths.Product.StrictJsonMembers
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

mutual
  theorem check_sound (value : Value) (accepted : check value = .ok ()) : Unique value := by
    cases value with
    | scalar => exact .scalar
    | array children => exact .array children (check_values_sound children accepted)
    | object members =>
        have complete := check_members_sound ∅ members accepted
        exact .object members complete.1 complete.2.2
  termination_by sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  theorem check_values_sound (children : List Value) (accepted : checkValues children = .ok ()) :
      ∀ child ∈ children, Unique child := by
    cases children with
    | nil => simp
    | cons child rest =>
        cases first : check child with
        | error reason => simp [checkValues, first] at accepted
        | ok unit =>
            cases unit
            have remaining : checkValues rest = .ok () := by simpa [checkValues, first] using accepted
            intro value member
            rcases List.mem_cons.mp member with rfl | later
            · exact check_sound child first
            · exact check_values_sound rest remaining value later
  termination_by sizeOf children
  decreasing_by all_goals simp_wf <;> omega

  theorem check_members_sound (seen : Finset String) (members : List (String × Value))
      (accepted : checkMembers seen members = .ok ()) : RemainingUnique seen members := by
    cases members with
    | nil => exact ⟨by simp, by simp, by simp⟩
    | cons member rest =>
        rcases member with ⟨name, child⟩
        by_cases repeated : name ∈ seen
        · simp [checkMembers, repeated] at accepted
        · cases first : check child with
          | error reason => simp [checkMembers, repeated, first] at accepted
          | ok unit =>
              cases unit
              have remaining : checkMembers (insert name seen) rest = .ok () := by
                simpa [checkMembers, repeated, first] using accepted
              exact (remaining_unique_cons seen name child rest).mpr
                ⟨repeated, check_sound child first, check_members_sound (insert name seen) rest remaining⟩
  termination_by sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

theorem check_values_complete (children : List Value) (each : ∀ child ∈ children, check child = .ok ()) :
    checkValues children = .ok () := by
  induction children with
  | nil => rfl
  | cons child rest ih =>
      simp [checkValues, each child (by simp), ih (fun value member => each value (List.mem_cons_of_mem _ member))]

theorem check_members_complete (seen : Finset String) (members : List (String × Value))
    (unique : RemainingUnique seen members) (each : ∀ member ∈ members, check member.2 = .ok ()) :
    checkMembers seen members = .ok () := by
  induction members generalizing seen with
  | nil => rfl
  | cons member rest ih =>
      rcases member with ⟨name, child⟩
      obtain ⟨fresh, _, remaining⟩ := (remaining_unique_cons seen name child rest).mp unique
      simp [checkMembers, fresh, each (name, child) (by simp),
        ih (insert name seen) remaining (fun member belongs => each member (List.mem_cons_of_mem _ belongs))]

/-- Every independently unique original decoded structure passes the closed
checker. Distinct objects may reuse names; only each object's own complete
prefix participates in its duplicate check. No checker success is supplied. -/
theorem check_complete (value : Value) (unique : Unique value) : check value = .ok () := by
  induction unique with
  | scalar => rfl
  | array children each ih => exact check_values_complete children ih
  | object members keys each ih => exact check_members_complete ∅ members ⟨keys, by simp, each⟩ ih

theorem check_acceptance_exact (value : Value) : check value = .ok () ↔ Unique value :=
  ⟨check_sound value, check_complete value⟩

theorem check_refusal_exact (value : Value) : check value = .error () ↔ ¬Unique value := by
  constructor
  · intro refused unique
    have accepted := check_complete value unique
    rw [refused] at accepted
    contradiction
  · intro invalid
    cases result : check value with
    | error unit => cases unit; rfl
    | ok unit => cases unit; exact False.elim (invalid (check_sound value result))

theorem check_members_acceptance_exact (seen : Finset String) (members : List (String × Value)) :
    checkMembers seen members = .ok () ↔ RemainingUnique seen members := by
  constructor
  · exact check_members_sound seen members
  · intro unique
    exact check_members_complete seen members unique (fun member belongs => check_complete member.2 (unique.2.2 member belongs))

theorem repeated_name_refuses_before_value (seen : Finset String) (name : String) (child : Value)
    (rest : List (String × Value)) (repeated : name ∈ seen) :
    checkMembers seen ((name, child) :: rest) = .error () := by simp [checkMembers, repeated]

end Auths.Product.StrictJsonMembers
