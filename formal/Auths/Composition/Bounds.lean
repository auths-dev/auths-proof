import Auths.Composition.Work
open Auths.Composition.PlanModel Auths.Composition.Work
namespace Auths.Composition.Bounds
mutual
  def depth {R : Type} : Plan R → Nat
    | .proof _ => 1
    | .allOf members | .anyOf members | .kOfN _ members => 1 + memberDepth members
  termination_by plan => sizeOf plan
  def memberDepth {R : Type} : List (Plan R) → Nat
    | [] => 0
    | head :: tail => max (depth head) (memberDepth tail)
  termination_by members => sizeOf members
end
mutual
  def proper {R : Type} : Plan R → Prop
    | .proof _ => True
    | .allOf members | .anyOf members | .kOfN _ members => members ≠ [] ∧ membersProper members
  termination_by plan => sizeOf plan
  def membersProper {R : Type} : List (Plan R) → Prop
    | [] => True
    | head :: tail => proper head ∧ membersProper tail
  termination_by members => sizeOf members
end

def NodeBound {R : Type} (plan : Plan R) : Prop :=
  proper plan → 1 ≤ (leaves plan).length ∧ nodes plan ≤ depth plan * (leaves plan).length

def MembersBound {R : Type} (members : List (Plan R)) : Prop :=
  membersProper members →
    memberNodes members ≤ memberDepth members * (memberLeaves members).length ∧
      (members ≠ [] → 1 ≤ (memberLeaves members).length)

theorem node_bound {R : Type} (plan : Plan R) : NodeBound plan := by
  refine Plan.rec
    (motive_1 := fun plan => NodeBound plan)
    (motive_2 := fun members => MembersBound members)
    ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro reference valid
    simp [leaves, nodes, depth]
  · intro members correct valid
    simp only [proper] at valid
    obtain ⟨nonempty, valid⟩ := valid
    obtain ⟨bound, positive⟩ := correct valid
    have positive := positive nonempty
    simp only [leaves, nodes, depth]
    exact ⟨positive, by nlinarith⟩
  · intro members correct valid
    simp only [proper] at valid
    obtain ⟨nonempty, valid⟩ := valid
    obtain ⟨bound, positive⟩ := correct valid
    have positive := positive nonempty
    simp only [leaves, nodes, depth]
    exact ⟨positive, by nlinarith⟩
  · intro required members correct valid
    simp only [proper] at valid
    obtain ⟨nonempty, valid⟩ := valid
    obtain ⟨bound, positive⟩ := correct valid
    have positive := positive nonempty
    simp only [leaves, nodes, depth]
    exact ⟨positive, by nlinarith⟩
  · intro valid
    simp [memberNodes, memberDepth, memberLeaves]
  · intro head tail headCorrect tailCorrect valid
    simp only [membersProper] at valid
    obtain ⟨headValid, tailValid⟩ := valid
    obtain ⟨headPositive, headBound⟩ := headCorrect headValid
    obtain ⟨tailBound, tailPositive⟩ := tailCorrect tailValid
    simp only [memberNodes, memberDepth, memberLeaves, List.length_append]
    constructor
    · have headMax := Nat.mul_le_mul_right (leaves head).length
        (Nat.le_max_left (depth head) (memberDepth tail))
      have tailMax := Nat.mul_le_mul_right (memberLeaves tail).length
        (Nat.le_max_right (depth head) (memberDepth tail))
      nlinarith
    · intro nonempty
      omega

theorem bounded_events {R : Type} (plan : Plan R)
    (valid : proper plan) (depthBound : depth plan ≤ 16) (leavesBound : (leaves plan).length ≤ 128) :
    nodes plan ≤ 2048 := by
  have bound := (node_bound plan valid).2
  nlinarith

open Aeneas Aeneas.Std auths_composition

theorem source_bounded_events {B : Type}
    (nativeBranch : core.ops.function.FnMut B auths_model.ProofRef BranchOutcome)
    (nativeObserver : core.ops.function.FnMut Nat EvaluationEvent Unit)
    (modelBranch : B → auths_model.ProofRef → BranchOutcome × B)
    (branchContract : ∀ state reference,
      nativeBranch.call_mut state reference = Result.ok (modelBranch state reference))
    (observerContract : ∀ count event,
      nativeObserver.call_mut count event = Result.ok ((), count + 1))
    (plan : auths_model.AuthorizationPlan) (state : B) (count : Nat)
    (valid : proper (viewPlan plan)) (depthBound : depth (viewPlan plan) ≤ 16)
    (leavesBound : (leaves (viewPlan plan)).length ≤ 128) :
    ∃ outcome next finalCount,
      evaluate_node nativeBranch nativeObserver plan state count = Result.ok (outcome, next, finalCount) ∧
      finalCount ≤ count + 2048 := by
  obtain ⟨outcome, next, exactCount⟩ := Auths.Composition.Work.source_event_count
    nativeBranch modelBranch branchContract nativeObserver observerContract plan state count
  refine ⟨outcome, next, count + nodes (viewPlan plan), exactCount, ?_⟩
  have bound := bounded_events (viewPlan plan) valid depthBound leavesBound
  omega

end Auths.Composition.Bounds
