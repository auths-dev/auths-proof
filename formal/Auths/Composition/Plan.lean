import Auths.Composition.Refinement
open Aeneas Aeneas.Std Result
open auths_composition
namespace Auths.Composition.PlanModel
open Auths.Composition.Model

inductive Plan (Reference : Type) where
  | proof (reference : Reference)
  | allOf (members : List (Plan Reference))
  | anyOf (members : List (Plan Reference))
  | kOfN (required : Nat) (members : List (Plan Reference))

inductive Event (Reference : Type) where
  | proof (reference : Reference) (outcome : BranchOutcome)
  | aggregate (children required authorized indeterminate : Nat) (outcome : BranchOutcome)

def eventView : EvaluationEvent → Event auths_model.ProofRef
  | .Proof reference outcome => .proof reference outcome
  | .Aggregate children required authorized indeterminate outcome =>
      .aggregate children.val required.val authorized.val indeterminate.val outcome

mutual
  def viewPlan (plan : auths_model.AuthorizationPlan) : Plan auths_model.ProofRef :=
    match plan with
    | .mk node => viewNode node
  termination_by sizeOf plan

  def viewNode (node : auths_model.AuthorizationPlanNode) : Plan auths_model.ProofRef :=
    match node with
    | .Proof reference => .proof reference
    | .AllOf members => .allOf (viewMembers members)
    | .AnyOf members => .anyOf (viewMembers members)
    | .KOfN required members => .kOfN required.val (viewMembers members)
  termination_by sizeOf node

  def viewMembers (members : auths_composition.alloc.vec.Vec auths_model.AuthorizationPlan) :
      List (Plan auths_model.ProofRef) :=
    match members with
    | .mk _ elements _ => viewElements elements
  termination_by sizeOf members

  def viewElements {n : Nat} (elements : auths_composition.alloc.vec.SizedList auths_model.AuthorizationPlan n) :
      List (Plan auths_model.ProofRef) :=
    match elements with
    | .nil => []
    | .cons head tail => viewPlan head :: viewElements tail
  termination_by sizeOf elements
end

mutual
  def evaluate {Reference B O : Type}
      (branch : B → Reference → BranchOutcome × B)
      (observe : O → Event Reference → O)
      (plan : Plan Reference) (state : B) (observer : O) : BranchOutcome × B × O :=
    match plan with
    | .proof reference =>
      let (outcome, next) := branch state reference
      (outcome, next, observe observer (.proof reference outcome))
    | .allOf members =>
      let (outcomes, next, observed) := evaluateChildren branch observe members state observer
      let summary := summarize outcomes
      let outcome := allOutcome summary
      (outcome, next, observe observed (.aggregate members.length (min 65535 members.length)
        summary.authorized summary.indeterminate outcome))
    | .anyOf members =>
      let (outcomes, next, observed) := evaluateChildren branch observe members state observer
      let summary := summarize outcomes
      let outcome := thresholdOutcome 1 summary
      (outcome, next, observe observed (.aggregate members.length 1
        summary.authorized summary.indeterminate outcome))
    | .kOfN required members =>
      let (outcomes, next, observed) := evaluateChildren branch observe members state observer
      let summary := summarize outcomes
      let outcome := thresholdOutcome required summary
      (outcome, next, observe observed (.aggregate members.length required
        summary.authorized summary.indeterminate outcome))
  termination_by sizeOf plan

  def evaluateChildren {Reference B O : Type}
      (branch : B → Reference → BranchOutcome × B)
      (observe : O → Event Reference → O)
      (members : List (Plan Reference)) (state : B) (observer : O) : List BranchOutcome × B × O :=
    match members with
    | [] => ([], state, observer)
    | first :: remaining =>
      let (outcome, next, observed) := evaluate branch observe first state observer
      let (outcomes, final, finalObserver) := evaluateChildren branch observe remaining next observed
      (outcome :: outcomes, final, finalObserver)
  termination_by sizeOf members
end

end Auths.Composition.PlanModel
