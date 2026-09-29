import Auths.Approval
import Auths.Refinement.Observation

/-!
# Translated approval predicates refine the abstract model

Each theorem states that one Aeneas-translated predicate from
`auths_model::approval` terminates with `ok` and returns exactly its
counterpart in `Auths.Approval`, under the representation-validity premise
that every compared principal fits the `u32` UTF-8 byte bound under which
`String::as_bytes` is translated. The abstraction maps `usize` and `u16` to
their natural-number values, slices and vectors to lists, and the translated
verdict, outcome, and requirement carriers to the model's.
-/

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Refinement.Approval

open Auths.Approval
open Auths.Refinement.Observation (string_equal_spec result_eq_ok_of_spec)

set_option maxHeartbeats 2000000

/-! ## Abstraction -/

def verdictOf : auths_model.approval.ApprovalVerdict → Verdict
  | .Counted => .counted
  | .Pending => .pending
  | .Ignored => .ignored

def outcomeOf (outcome : auths_model.approval.ApprovalOutcome) : String × Verdict :=
  (outcome.approver, verdictOf outcome.verdict)

def requirementOf (requirement : auths_model.approval.ApprovalRequirement) : Requirement :=
  ⟨requirement.approvers.val, requirement.threshold.val⟩

/-! ## Representation validity -/

def PrincipalsValid (principals : List auths_model.PrincipalId) : Prop :=
  ∀ principal ∈ principals, StringBounded principal

def OutcomesValid (outcomes : List auths_model.approval.ApprovalOutcome) : Prop :=
  ∀ outcome ∈ outcomes, StringBounded outcome.approver

def RequirementValid (requirement : auths_model.approval.ApprovalRequirement) : Prop :=
  PrincipalsValid requirement.approvers.val

instance (child parent : Requirement) : Decidable (covers child parent) := by
  unfold covers; infer_instance

instance (child parent : List Requirement) :
    Decidable (requirementsAttenuate child parent) := by
  unfold requirementsAttenuate; infer_instance

/-! ## Principal equality -/

@[step] theorem principal_equal_spec
    (left right : auths_model.PrincipalId)
    (leftBounded : StringBounded left) (rightBounded : StringBounded right) :
    auths_model.principal_id_equal left right
      ⦃ result => result = decide (left = right) ⦄ := by
  unfold auths_model.principal_id_equal
  exact string_equal_spec left right leftBounded rightBounded

/-! ## Distinct counting -/

/-- The verdict the remaining outcomes give an approver once earlier ones
have left `pending`. -/
def remainingVerdict (pending : Bool) (rest : List (String × Verdict)) (approver : String) :
    Verdict :=
  if rest.any (fun outcome => decide (outcome.1 = approver) && decide (outcome.2 = .counted))
  then .counted
  else if pending || rest.any
      (fun outcome => decide (outcome.1 = approver) && decide (outcome.2 = .pending))
  then .pending
  else .ignored

theorem approverVerdict_eq_remainingVerdict (outcomes : List (String × Verdict))
    (approver : String) :
    approverVerdict outcomes approver = remainingVerdict false outcomes approver := by
  simp [approverVerdict, remainingVerdict]

@[step] theorem approver_verdict_spec
    (outcomes : Slice auths_model.approval.ApprovalOutcome) (approver : auths_model.PrincipalId)
    (outcomesValid : OutcomesValid outcomes.val) (approverBounded : StringBounded approver) :
    auths_model.approval.approver_verdict outcomes approver
      ⦃ result => verdictOf result = approverVerdict (outcomes.val.map outcomeOf) approver ⦄ := by
  unfold auths_model.approval.approver_verdict auths_model.approval.approver_verdict_loop
  apply loop.spec_decr_nat
    (measure := fun state => outcomes.val.length - state.2.val)
    (inv := fun state =>
      state.2.val ≤ outcomes.val.length ∧
      approverVerdict (outcomes.val.map outcomeOf) approver =
        remainingVerdict state.1 ((outcomes.val.drop state.2.val).map outcomeOf) approver)
  · rintro ⟨pending, index⟩ ⟨indexBound, remaining⟩
    unfold auths_model.approval.approver_verdict_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < outcomes.val.length := by simpa using withinBounds
      step as ⟨outcome, outcomeEq⟩
      have outcomeBounded : StringBounded outcome.approver := by
        rw [outcomeEq]; exact outcomesValid _ (List.getElem_mem inBounds)
      step with principal_equal_spec as ⟨matched, matchedEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, ← outcomeEq] at remaining
      split <;> rename_i same
      · have sameApprover : outcome.approver = approver := by simpa [matchedEq] using same
        split <;> rename_i verdictIs
        · simp only [spec_ok]
          rw [remaining]
          simp [remainingVerdict, outcomeOf, verdictOf, verdictIs, sameApprover]
        · step as ⟨nextIndex, nextIndexPost⟩
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          rw [remaining, nextIndexPost]
          simp [remainingVerdict, outcomeOf, verdictOf, verdictIs, sameApprover]
        · step as ⟨nextIndex, nextIndexPost⟩
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          rw [remaining, nextIndexPost]
          simp [remainingVerdict, outcomeOf, verdictOf, verdictIs, sameApprover]
      · have otherApprover : outcome.approver ≠ approver := by simpa [matchedEq] using same
        step as ⟨nextIndex, nextIndexPost⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [remaining, nextIndexPost]
        simp [remainingVerdict, outcomeOf, otherApprover]
    · have atEnd : outcomes.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at remaining
      split <;> rename_i isPending
      · simp only [spec_ok]
        rw [remaining]
        simp [remainingVerdict, verdictOf, isPending]
      · simp only [spec_ok]
        rw [remaining]
        simp [remainingVerdict, verdictOf, isPending]
  · exact ⟨by simp, approverVerdict_eq_remainingVerdict _ _⟩

/-- The translated approver verdict is the model's `approverVerdict`. -/
theorem translated_approver_verdict_refines_model
    (outcomes : Slice auths_model.approval.ApprovalOutcome) (approver : auths_model.PrincipalId)
    (outcomesValid : OutcomesValid outcomes.val) (approverBounded : StringBounded approver) :
    ∃ result, auths_model.approval.approver_verdict outcomes approver = ok result ∧
      verdictOf result = approverVerdict (outcomes.val.map outcomeOf) approver := by
  obtain ⟨result, isOk, holds⟩ :=
    spec_imp_exists (approver_verdict_spec outcomes approver outcomesValid approverBounded)
  exact ⟨result, isOk, holds⟩

theorem countedCount_cons (head : String) (tail : List String)
    (outcomes : List (String × Verdict)) :
    countedCount (head :: tail) outcomes =
      (if approverVerdict outcomes head = .counted then 1 else 0) +
        countedCount tail outcomes := by
  unfold countedCount
  by_cases isCounted : approverVerdict outcomes head = .counted
  · simp [isCounted]
    omega
  · simp [isCounted]

theorem pendingCount_cons (head : String) (tail : List String)
    (outcomes : List (String × Verdict)) :
    pendingCount (head :: tail) outcomes =
      (if approverVerdict outcomes head = .pending then 1 else 0) +
        pendingCount tail outcomes := by
  unfold pendingCount
  by_cases isPending : approverVerdict outcomes head = .pending
  · simp [isPending]
    omega
  · simp [isPending]

@[step] theorem approval_counts_spec
    (approvers : Slice auths_model.PrincipalId)
    (outcomes : Slice auths_model.approval.ApprovalOutcome)
    (approversValid : PrincipalsValid approvers.val)
    (outcomesValid : OutcomesValid outcomes.val) :
    auths_model.approval.approval_counts approvers outcomes
      ⦃ counts =>
        counts.counted.val = countedCount approvers.val (outcomes.val.map outcomeOf) ∧
        counts.pending.val = pendingCount approvers.val (outcomes.val.map outcomeOf) ⦄ := by
  unfold auths_model.approval.approval_counts
  have loopSpec : auths_model.approval.approval_counts_loop approvers outcomes 0#usize 0#usize
      0#usize ⦃ result =>
        result.1.val = countedCount approvers.val (outcomes.val.map outcomeOf) ∧
        result.2.val = pendingCount approvers.val (outcomes.val.map outcomeOf) ⦄ := by
    unfold auths_model.approval.approval_counts_loop
    apply loop.spec_decr_nat
      (measure := fun state => approvers.val.length - state.2.2.val)
      (inv := fun state =>
        state.2.2.val ≤ approvers.val.length ∧
        state.1.val + state.2.1.val ≤ state.2.2.val ∧
        state.1.val + countedCount (approvers.val.drop state.2.2.val)
            (outcomes.val.map outcomeOf) =
          countedCount approvers.val (outcomes.val.map outcomeOf) ∧
        state.2.1.val + pendingCount (approvers.val.drop state.2.2.val)
            (outcomes.val.map outcomeOf) =
          pendingCount approvers.val (outcomes.val.map outcomeOf))
    · rintro ⟨counted, pending, index⟩ ⟨indexBound, countsBound, countedSum, pendingSum⟩
      unfold auths_model.approval.approval_counts_loop.body
      dsimp only at indexBound countsBound countedSum pendingSum ⊢
      split <;> rename_i withinBounds
      · have inBounds : index.val < approvers.val.length := by simpa using withinBounds
        step as ⟨approver, approverEq⟩
        have approverBounded : StringBounded approver := by
          rw [approverEq]; exact approversValid _ (List.getElem_mem inBounds)
        step with approver_verdict_spec as ⟨verdict, verdictEq⟩
        rw [List.drop_eq_getElem_cons inBounds, ← approverEq, countedCount_cons] at countedSum
        rw [List.drop_eq_getElem_cons inBounds, ← approverEq, pendingCount_cons] at pendingSum
        cases verdict <;> simp only [verdictOf] at verdictEq <;> dsimp only <;>
          rw [← verdictEq] at countedSum pendingSum <;> simp at countedSum pendingSum
        · step as ⟨nextCounted, nextCountedPost⟩
          step as ⟨nextIndex, nextIndexPost⟩
          split_ands <;> (try simp only [nextCountedPost, nextIndexPost]) <;>
            scalar_tac
        · step as ⟨nextPending, nextPendingPost⟩
          step as ⟨nextIndex, nextIndexPost⟩
          split_ands <;> (try simp only [nextPendingPost, nextIndexPost]) <;>
            scalar_tac
        · step as ⟨nextIndex, nextIndexPost⟩
          split_ands <;> (try simp only [nextIndexPost]) <;> scalar_tac
      · simp only [spec_ok]
        have atEnd : approvers.val.length ≤ index.val := by simpa using withinBounds
        rw [List.drop_eq_nil_of_le atEnd] at countedSum pendingSum
        simp [countedCount, pendingCount] at countedSum pendingSum
        exact ⟨countedSum, pendingSum⟩
    · refine ⟨by simp, by simp, ?_, ?_⟩ <;> simp
  step with loopSpec as ⟨counted, pending, countedPost, pendingPost⟩
  exact ⟨countedPost, pendingPost⟩

/-- The translated distinct counting is the model's: the counted and pending
approver counts, and so the requirement's decision `decideCounts`. -/
theorem translated_approval_counts_refines_model
    (approvers : Slice auths_model.PrincipalId)
    (outcomes : Slice auths_model.approval.ApprovalOutcome)
    (approversValid : PrincipalsValid approvers.val)
    (outcomesValid : OutcomesValid outcomes.val) (threshold : Std.U16) :
    ∃ counts, auths_model.approval.approval_counts approvers outcomes = ok counts ∧
      counts.counted.val = countedCount approvers.val (outcomes.val.map outcomeOf) ∧
      counts.pending.val = pendingCount approvers.val (outcomes.val.map outcomeOf) ∧
      thresholdCounts threshold.val counts.counted.val counts.pending.val =
        decideCounts threshold.val approvers.val (outcomes.val.map outcomeOf) := by
  obtain ⟨counts, isOk, countedEq, pendingEq⟩ :=
    spec_imp_exists (approval_counts_spec approvers outcomes approversValid outcomesValid)
  refine ⟨counts, isOk, countedEq, pendingEq, ?_⟩
  simp only [decideCounts, countedEq, pendingEq]

/-! ## The approval-requirement law -/

@[step] theorem principal_ids_contain_spec
    (principals : Slice auths_model.PrincipalId) (principal : auths_model.PrincipalId)
    (principalsValid : PrincipalsValid principals.val) (principalBounded : StringBounded principal) :
    auths_model.approval.principal_ids_contain principals principal
      ⦃ result => result = decide (principal ∈ principals.val) ⦄ := by
  unfold auths_model.approval.principal_ids_contain
    auths_model.approval.principal_ids_contain_loop
  apply loop.spec_decr_nat
    (measure := fun index => principals.val.length - index.val)
    (inv := fun index =>
      index.val ≤ principals.val.length ∧
      (principal ∈ principals.val ↔ principal ∈ principals.val.drop index.val))
  · rintro index ⟨indexBound, memberDrop⟩
    unfold auths_model.approval.principal_ids_contain_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < principals.val.length := by simpa using withinBounds
      step as ⟨candidate, candidateEq⟩
      have candidateBounded : StringBounded candidate := by
        rw [candidateEq]; exact principalsValid _ (List.getElem_mem inBounds)
      step with principal_equal_spec as ⟨same, sameEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.mem_cons, ← candidateEq] at memberDrop
      split <;> rename_i matched
      · simp only [spec_ok]
        have : candidate = principal := by simpa [sameEq] using matched
        exact (decide_eq_true (memberDrop.mpr (Or.inl this.symm))).symm
      · step as ⟨nextIndex, nextIndexPost⟩
        have : candidate ≠ principal := by simpa [sameEq] using matched
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [memberDrop, nextIndexPost]
        simp [Ne.symm this]
    · simp only [spec_ok]
      have atEnd : principals.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at memberDrop
      simp [memberDrop]
  · exact ⟨by simp, by simp⟩

/-- Principal-list membership is the model's list membership. -/
theorem translated_principal_ids_contain_refines_model
    (principals : Slice auths_model.PrincipalId) (principal : auths_model.PrincipalId)
    (principalsValid : PrincipalsValid principals.val) (principalBounded : StringBounded principal) :
    auths_model.approval.principal_ids_contain principals principal =
      ok (decide (principal ∈ principals.val)) :=
  result_eq_ok_of_spec
    (principal_ids_contain_spec principals principal principalsValid principalBounded)

@[step] theorem principal_ids_subset_spec
    (narrower wider : Slice auths_model.PrincipalId)
    (narrowerValid : PrincipalsValid narrower.val) (widerValid : PrincipalsValid wider.val) :
    auths_model.approval.principal_ids_subset narrower wider
      ⦃ result => result = decide (narrower.val ⊆ wider.val) ⦄ := by
  unfold auths_model.approval.principal_ids_subset
    auths_model.approval.principal_ids_subset_loop
  apply loop.spec_decr_nat
    (measure := fun index => narrower.val.length - index.val)
    (inv := fun index =>
      index.val ≤ narrower.val.length ∧
      (narrower.val ⊆ wider.val ↔ ∀ principal ∈ narrower.val.drop index.val,
        principal ∈ wider.val))
  · rintro index ⟨indexBound, subsetDrop⟩
    unfold auths_model.approval.principal_ids_subset_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < narrower.val.length := by simpa using withinBounds
      step as ⟨candidate, candidateEq⟩
      have candidateBounded : StringBounded candidate := by
        rw [candidateEq]; exact narrowerValid _ (List.getElem_mem inBounds)
      step with principal_ids_contain_spec as ⟨contained, containedEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.forall_mem_cons, ← candidateEq] at subsetDrop
      split <;> rename_i matched
      · step as ⟨nextIndex, nextIndexPost⟩
        have : candidate ∈ wider.val := by simpa [containedEq] using matched
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [subsetDrop, nextIndexPost]
        simp only [this, true_and]
      · simp only [spec_ok]
        have : candidate ∉ wider.val := by simpa [containedEq] using matched
        simp only [subsetDrop, this, false_and, decide_false]
    · simp only [spec_ok]
      have atEnd : narrower.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at subsetDrop
      simp only [subsetDrop, List.not_mem_nil, false_implies, implies_true, decide_true]
  · refine ⟨by simp, fun included principal member => included (by simpa using member),
      fun holds principal member => holds principal (by simpa using member)⟩

/-- Principal-list inclusion is the model's list subset. -/
theorem translated_principal_ids_subset_refines_model
    (narrower wider : Slice auths_model.PrincipalId)
    (narrowerValid : PrincipalsValid narrower.val) (widerValid : PrincipalsValid wider.val) :
    auths_model.approval.principal_ids_subset narrower wider =
      ok (decide (narrower.val ⊆ wider.val)) :=
  result_eq_ok_of_spec (principal_ids_subset_spec narrower wider narrowerValid widerValid)

@[step] theorem approval_requirement_covers_spec
    (child parent : auths_model.approval.ApprovalRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.approval.approval_requirement_covers child parent
      ⦃ result => result = decide (covers (requirementOf child) (requirementOf parent)) ⦄ := by
  unfold auths_model.approval.approval_requirement_covers
  step with principal_ids_subset_spec (alloc.vec.Vec.deref child.approvers)
    (alloc.vec.Vec.deref parent.approvers) (by exact childValid) (by exact parentValid)
    as ⟨subset, subsetEq⟩
  split <;> rename_i isSubset
  · simp only [spec_ok]
    have included : child.approvers.val ⊆ parent.approvers.val := by
      simpa [subsetEq, alloc.vec.Vec.deref] using isSubset
    by_cases higher : parent.threshold.val ≤ child.threshold.val
    · have : child.threshold >= parent.threshold := by scalar_tac
      simp [covers, requirementOf, included, higher, this]
    · have : ¬ child.threshold >= parent.threshold := by scalar_tac
      simp [covers, requirementOf, included, higher, this]
  · simp only [spec_ok]
    have notIncluded : ¬ child.approvers.val ⊆ parent.approvers.val := by
      simpa [subsetEq, alloc.vec.Vec.deref] using isSubset
    simp [covers, requirementOf, notIncluded]

/-- The translated cover check is the model's `covers`: approvers a subset
and a threshold no lower. -/
theorem translated_approval_requirement_covers_refines_model
    (child parent : auths_model.approval.ApprovalRequirement)
    (childValid : RequirementValid child) (parentValid : RequirementValid parent) :
    auths_model.approval.approval_requirement_covers child parent =
      ok (decide (covers (requirementOf child) (requirementOf parent))) :=
  result_eq_ok_of_spec (approval_requirement_covers_spec child parent childValid parentValid)

@[step] theorem approval_requirement_retained_spec
    (child : auths_model.approval.ApprovalRequirements)
    (parent : auths_model.approval.ApprovalRequirement)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : RequirementValid parent) :
    auths_model.approval.approval_requirement_retained child parent
      ⦃ result => result =
        decide (∃ candidate ∈ child.val.map requirementOf,
          covers candidate (requirementOf parent)) ⦄ := by
  unfold auths_model.approval.approval_requirement_retained
    auths_model.approval.approval_requirement_retained_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.1.val.length - state.2.val)
    (inv := fun state =>
      state.1 = child ∧ state.2.val ≤ child.val.length ∧
      ((∃ candidate ∈ child.val.map requirementOf,
          covers candidate (requirementOf parent)) ↔
        ∃ candidate ∈ (child.val.drop state.2.val).map requirementOf,
          covers candidate (requirementOf parent)))
  · rintro ⟨current, index⟩ ⟨rfl, indexBound, existsDrop⟩
    unfold auths_model.approval.approval_requirement_retained_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < current.val.length := by simpa using withinBounds
      step as ⟨candidate, candidateEq⟩
      have candidateValid : RequirementValid candidate := by
        rw [candidateEq]; exact childValid _ (List.getElem_mem inBounds)
      step with approval_requirement_covers_spec as ⟨covered, coveredEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.exists_mem_cons_iff,
        ← candidateEq] at existsDrop
      split <;> rename_i matched
      · simp only [spec_ok]
        have : covers (requirementOf candidate) (requirementOf parent) := by
          simpa [coveredEq] using matched
        exact (decide_eq_true (existsDrop.mpr (Or.inl this))).symm
      · step as ⟨nextIndex, nextIndexPost⟩
        have : ¬ covers (requirementOf candidate) (requirementOf parent) := by
          simpa [coveredEq] using matched
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [existsDrop, nextIndexPost]
        simp [this]
    · simp only [spec_ok]
      have atEnd : current.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at existsDrop
      simp only [existsDrop, List.map_nil, List.not_mem_nil, false_and, exists_false,
        decide_false]
  · exact ⟨rfl, by simp, by simp⟩

/-- Some child requirement covers the parent requirement, in the model's
sense. -/
theorem translated_approval_requirement_retained_refines_model
    (child : auths_model.approval.ApprovalRequirements)
    (parent : auths_model.approval.ApprovalRequirement)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : RequirementValid parent) :
    auths_model.approval.approval_requirement_retained child parent =
      ok (decide (∃ candidate ∈ child.val.map requirementOf,
        covers candidate (requirementOf parent))) :=
  result_eq_ok_of_spec
    (approval_requirement_retained_spec child parent childValid parentValid)

@[step] theorem approval_requirements_attenuate_spec
    (child parent : auths_model.approval.ApprovalRequirements)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : ∀ requirement ∈ parent.val, RequirementValid requirement) :
    auths_model.approval.approval_requirements_attenuate child parent
      ⦃ result => result =
        decide (requirementsAttenuate (child.val.map requirementOf)
          (parent.val.map requirementOf)) ⦄ := by
  unfold auths_model.approval.approval_requirements_attenuate
    auths_model.approval.approval_requirements_attenuate_loop
  unfold requirementsAttenuate
  apply loop.spec_decr_nat
    (measure := fun state => state.1.val.length - state.2.val)
    (inv := fun state =>
      state.1 = parent ∧ state.2.val ≤ parent.val.length ∧
      ((∀ requirement ∈ parent.val.map requirementOf,
          ∃ candidate ∈ child.val.map requirementOf, covers candidate requirement) ↔
        ∀ requirement ∈ (parent.val.drop state.2.val).map requirementOf,
          ∃ candidate ∈ child.val.map requirementOf, covers candidate requirement))
  · rintro ⟨current, index⟩ ⟨rfl, indexBound, allDrop⟩
    unfold auths_model.approval.approval_requirements_attenuate_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < current.val.length := by simpa using withinBounds
      step as ⟨requirement, requirementEq⟩
      have requirementValid : RequirementValid requirement := by
        rw [requirementEq]; exact parentValid _ (List.getElem_mem inBounds)
      step with approval_requirement_retained_spec as ⟨retained, retainedEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.forall_mem_cons,
        ← requirementEq] at allDrop
      split <;> rename_i matched
      · step as ⟨nextIndex, nextIndexPost⟩
        have : ∃ candidate ∈ child.val.map requirementOf,
            covers candidate (requirementOf requirement) := by
          simpa [retainedEq] using matched
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [allDrop, nextIndexPost]
        simp only [this, true_and]
      · simp only [spec_ok]
        have : ¬ ∃ candidate ∈ child.val.map requirementOf,
            covers candidate (requirementOf requirement) := by
          simpa [retainedEq] using matched
        simp only [allDrop, this, false_and, decide_false]
    · simp only [spec_ok]
      have atEnd : current.val.length ≤ index.val := by simpa using withinBounds
      rw [List.drop_eq_nil_of_le atEnd] at allDrop
      simp only [allDrop, List.map_nil, List.not_mem_nil, false_implies, implies_true,
        decide_true]
  · exact ⟨rfl, by simp, by simp⟩

/-- The translated `approval-requirement-v1` attenuation law is the model's
`requirementsAttenuate` on the abstracted lists. -/
theorem translated_approval_requirements_attenuate_refines_model
    (child parent : auths_model.approval.ApprovalRequirements)
    (childValid : ∀ requirement ∈ child.val, RequirementValid requirement)
    (parentValid : ∀ requirement ∈ parent.val, RequirementValid requirement) :
    auths_model.approval.approval_requirements_attenuate child parent =
      ok (decide (requirementsAttenuate (child.val.map requirementOf)
        (parent.val.map requirementOf))) :=
  result_eq_ok_of_spec
    (approval_requirements_attenuate_spec child parent childValid parentValid)

end Auths.Refinement.Approval
