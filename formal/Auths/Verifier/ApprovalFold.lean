import Auths.Approval

/-!
The sequential approval stage omits ignored records and stops evaluating a
principal once one approval has counted. The independent approval relation
instead describes all supplied records and counts distinct principals. This
module proves those two aggregation semantics agree for every finite history,
including pending-before-counted, arbitrary duplicates and arbitrary ordering.

This is an independent adequacy lemma. The actual candidate filter, signature,
status, binding, cache and work-meter driver still require source refinement;
no expected source outcome is a premise of these statements.
-/

namespace Auths.Verifier.ApprovalFold
open Auths.Approval

def merge : Verdict → Verdict → Verdict
  | .counted, _ | _, .counted => .counted
  | .pending, _ | _, .pending => .pending
  | .ignored, .ignored => .ignored

theorem merge_assoc (first second third : Verdict) :
    merge (merge first second) third = merge first (merge second third) := by
  cases first <;> cases second <;> cases third <;> rfl

theorem merge_comm (first second : Verdict) : merge first second = merge second first := by
  cases first <;> cases second <;> rfl

@[simp] theorem merge_ignored (value : Verdict) : merge value .ignored = value := by
  cases value <;> rfl

@[simp] theorem merge_counted (value : Verdict) : merge .counted value = .counted := by
  cases value <;> rfl

theorem verdict_append (left right : List (String × Verdict)) (principal : String) :
    approverVerdict (left ++ right) principal =
      merge (approverVerdict left principal) (approverVerdict right principal) := by
  cases lc : left.any (fun outcome => decide (outcome.1 = principal) && decide (outcome.2 = .counted)) <;>
    cases lp : left.any (fun outcome => decide (outcome.1 = principal) && decide (outcome.2 = .pending)) <;>
    cases rc : right.any (fun outcome => decide (outcome.1 = principal) && decide (outcome.2 = .counted)) <;>
    cases rp : right.any (fun outcome => decide (outcome.1 = principal) && decide (outcome.2 = .pending)) <;>
    simp [approverVerdict, List.any_append, lc, lp, rc, rp, merge]

theorem verdict_single (outcome : String × Verdict) (principal : String) :
    approverVerdict [outcome] principal =
      if principal = outcome.1 then outcome.2 else .ignored := by
  rcases outcome with ⟨name, value⟩
  cases value <;> by_cases same : principal = name <;>
    simp_all [approverVerdict, eq_comm]

def SameVerdicts (left right : List (String × Verdict)) : Prop :=
  ∀ principal, approverVerdict left principal = approverVerdict right principal

theorem append_congr {left right : List (String × Verdict)}
    (same : SameVerdicts left right) (suffix : List (String × Verdict)) :
    SameVerdicts (left ++ suffix) (right ++ suffix) := by
  intro principal
  rw [verdict_append, verdict_append, same principal]

/-- The actual stage's aggregation rule, separated from the evidence checks
that determine an eligible candidate's verdict. -/
def retain (seen : List (String × Verdict)) (outcome : String × Verdict) : List (String × Verdict) :=
  if outcome.2 = .ignored ∨ approverVerdict seen outcome.1 = .counted
  then seen else seen ++ [outcome]

theorem retain_exact (seen : List (String × Verdict)) (outcome : String × Verdict) :
    SameVerdicts (retain seen outcome) (seen ++ [outcome]) := by
  unfold retain
  split
  · rename_i skip
    intro principal
    rw [verdict_append, verdict_single]
    rcases skip with ignored | counted
    · by_cases same : principal = outcome.1 <;> simp [same, ignored]
    · by_cases same : principal = outcome.1
      · simp [same, counted]
      · simp [same]
  · intro principal
    rfl

def accumulate (seen : List (String × Verdict)) : List (String × Verdict) → List (String × Verdict)
  | [] => seen
  | outcome :: rest => accumulate (retain seen outcome) rest

/-- A finite sequential scan has exactly the declarative per-principal
verdict, even though it omits ignored and superseded records. -/
theorem every_history_exact (seen events : List (String × Verdict)) :
    SameVerdicts (accumulate seen events) (seen ++ events) := by
  induction events generalizing seen with
  | nil => intro principal; simp [accumulate]
  | cons outcome rest ih =>
    intro principal
    rw [accumulate, ih (retain seen outcome) principal]
    have composed := append_congr (retain_exact seen outcome) rest principal
    simpa only [List.append_assoc, List.singleton_append] using composed

theorem counts_exact (approvers : List String) (events : List (String × Verdict)) :
    countedCount approvers (accumulate [] events) = countedCount approvers events ∧
    pendingCount approvers (accumulate [] events) = pendingCount approvers events := by
  have same : approverVerdict (accumulate [] events) = approverVerdict events := by
    funext principal
    simpa only [List.nil_append] using every_history_exact [] events principal
  constructor
  · unfold countedCount; rw [same]
  · unfold pendingCount; rw [same]

variable {Action : Type} [DecidableEq Action]

def decision (environment : Environment Action) (identifier : Nat) (requirement : Requirement)
    (approvals : List (ApprovalRecord Action)) : Truth :=
  decideCounts requirement.threshold requirement.approvers
    (accumulate [] (outcomes environment identifier requirement approvals))

/-- Completeness as well as soundness: the sequential aggregation cannot
authorize an insufficient quorum or reject a sufficient one. -/
theorem decision_exact (environment : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action)) :
    decision environment identifier requirement approvals =
      approvalDecision environment identifier requirement approvals := by
  obtain ⟨counted, pending⟩ := counts_exact requirement.approvers
    (outcomes environment identifier requirement approvals)
  simp only [decision, approvalDecision, decideCounts, counted, pending]

theorem authorized_iff_distinct_quorum (environment : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (distinct : requirement.approvers.Nodup) :
    decision environment identifier requirement approvals = .authorized ↔
      ∃ chosen : List String, chosen.Nodup ∧ chosen ⊆ requirement.approvers ∧
        requirement.threshold ≤ chosen.length ∧
        ∀ principal ∈ chosen, ∃ approval ∈ approvals, approval.approver = principal ∧
          verdict environment identifier requirement approval = .counted := by
  rw [decision_exact]
  exact approval_authorized_iff_distinct_quorum environment identifier requirement approvals distinct

private def exampleEnvironment : Environment Nat := ⟨7, 5, ["root"]⟩
private def exampleRequirement : Requirement := ⟨["alice", "bob", "carol"], 2⟩
private def authentic (principal : String) : ApprovalRecord Nat :=
  ⟨principal, 7, 11, 0, 10, .authorized⟩

example : decision exampleEnvironment 11 exampleRequirement [authentic "alice", authentic "bob"] = .authorized := by decide
example : decision exampleEnvironment 11 exampleRequirement [authentic "alice", authentic "carol"] = .authorized := by decide
example : decision exampleEnvironment 11 exampleRequirement [authentic "bob", authentic "carol"] = .authorized := by decide
example : decision exampleEnvironment 11 exampleRequirement [authentic "alice", authentic "alice"] = .denied := by decide

example : countedCount ["alice"] (accumulate [] [("alice", .pending), ("alice", .counted)]) = 1 ∧
    pendingCount ["alice"] (accumulate [] [("alice", .pending), ("alice", .counted)]) = 0 := by decide

end Auths.Verifier.ApprovalFold
