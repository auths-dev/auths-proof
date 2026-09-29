import Mathlib.Tactic
import Auths.Composition
import Auths.ExtensionLaw

/-!
# Native K-of-N approvals

An abstract model of approval requirements. A requirement names a list of
approver principals and a threshold K. An approval record names its approver,
the exact action it approves, the requirement identifier it binds, its
validity window, and the truth of its verification (signature, approver
anchor, and principal status, which stay in the cryptographic and status
trust boundary).

Each approval gets a verdict for one requirement: counted, pending, or
ignored. Approvals are counted per distinct approver, and the requirement's
decision is the generated threshold function the plan evaluator runs:
`thresholdCounts K a i`, where `a` counts approvers with a counted approval
and `i` the remaining approvers with a pending one.

Unlike the count-level composition model, this one names principals, so
duplicate approvals, outsiders, approvals of another action, and approvals by
a principal of the authority chain are statable, and each is irrelevant to
the decision.

The last section models the `approval-requirement-v1` grant extension's
attenuation law and proves it a narrowing preorder, which discharges the
rich model's premise that delegation never widens authority.
-/

namespace Auths.Approval

/-! ## Distinct counting -/

/-- One approval's verdict for one requirement. -/
inductive Verdict where
  | counted
  | pending
  | ignored
  deriving DecidableEq, Repr

/-- The verdict of one approver over per-approval outcomes: counted when
some outcome for it is counted, pending when none is counted and some is
pending, and ignored otherwise. -/
def approverVerdict (outcomes : List (String × Verdict)) (approver : String) : Verdict :=
  if outcomes.any (fun outcome => decide (outcome.1 = approver) && decide (outcome.2 = .counted))
  then .counted
  else if outcomes.any
      (fun outcome => decide (outcome.1 = approver) && decide (outcome.2 = .pending))
  then .pending
  else .ignored

/-- The number of listed approvers with a counted approval. -/
def countedCount (approvers : List String) (outcomes : List (String × Verdict)) : Nat :=
  (approvers.filter fun approver => decide (approverVerdict outcomes approver = .counted)).length

/-- The number of listed approvers with a pending and no counted approval. -/
def pendingCount (approvers : List String) (outcomes : List (String × Verdict)) : Nat :=
  (approvers.filter fun approver => decide (approverVerdict outcomes approver = .pending)).length

/-- The threshold decision over distinct counts. -/
def decideCounts (threshold : Nat) (approvers : List String)
    (outcomes : List (String × Verdict)) : Truth :=
  thresholdCounts threshold (countedCount approvers outcomes) (pendingCount approvers outcomes)

/-! ## Approvals and requirements -/

/-- One signed approval as the verifier sees it. `verification` is the truth
of its signature under the approver anchor's accepted methods, the anchor's
window, and the approver's principal status. -/
structure ApprovalRecord (Action : Type) where
  approver : String
  action : Action
  requirement : Nat
  notBefore : Nat
  expiresAt : Nat
  verification : Truth

/-- "K of these N principals". -/
structure Requirement where
  approvers : List String
  threshold : Nat
  deriving DecidableEq

/-- The request under evaluation: the exact action, the evaluation time, and
the authority principals, none of whom may approve. -/
structure Environment (Action : Type) where
  action : Action
  evaluationTime : Nat
  authority : List String

variable {Action : Type} [DecidableEq Action]

/-- How a verification truth becomes a verdict: authentic approvals count,
unavailable ones are pending, and invalid ones are ignored. -/
def verificationVerdict : Truth → Verdict
  | .authorized => .counted
  | .indeterminate => .pending
  | .denied => .ignored

/-- An approval is eligible for the requirement named `identifier` when its
approver is listed and outside the authority chain, it binds that identifier
and the exact action, and its window contains the evaluation time. -/
def eligible (env : Environment Action) (identifier : Nat) (requirement : Requirement)
    (approval : ApprovalRecord Action) : Bool :=
  decide (approval.approver ∈ requirement.approvers) &&
  !decide (approval.approver ∈ env.authority) &&
  decide (approval.requirement = identifier) &&
  decide (approval.action = env.action) &&
  decide (approval.notBefore ≤ env.evaluationTime) &&
  decide (env.evaluationTime ≤ approval.expiresAt)

/-- One approval's verdict for one requirement. -/
def verdict (env : Environment Action) (identifier : Nat) (requirement : Requirement)
    (approval : ApprovalRecord Action) : Verdict :=
  if eligible env identifier requirement approval then
    verificationVerdict approval.verification
  else .ignored

/-- The per-approval outcomes the counting predicate consumes. -/
def outcomes (env : Environment Action) (identifier : Nat) (requirement : Requirement)
    (approvals : List (ApprovalRecord Action)) : List (String × Verdict) :=
  approvals.map fun approval => (approval.approver, verdict env identifier requirement approval)

/-- The requirement's decision. -/
def approvalDecision (env : Environment Action) (identifier : Nat) (requirement : Requirement)
    (approvals : List (ApprovalRecord Action)) : Truth :=
  decideCounts requirement.threshold requirement.approvers
    (outcomes env identifier requirement approvals)

/-! ## Counting lemmas -/

theorem approverVerdict_congr {left right : List (String × Verdict)}
    (same : ∀ outcome, outcome ∈ left ↔ outcome ∈ right) :
    approverVerdict left = approverVerdict right := by
  funext approver
  have anyCongr : ∀ predicate : String × Verdict → Bool,
      left.any predicate = right.any predicate := by
    intro predicate
    rw [Bool.eq_iff_iff]
    simp only [List.any_eq_true]
    constructor
    · rintro ⟨outcome, member, holds⟩
      exact ⟨outcome, (same outcome).mp member, holds⟩
    · rintro ⟨outcome, member, holds⟩
      exact ⟨outcome, (same outcome).mpr member, holds⟩
  simp only [approverVerdict, anyCongr]

theorem approverVerdict_cons_other {rest : List (String × Verdict)} {other approver : String}
    {value : Verdict} (distinct : other ≠ approver) :
    approverVerdict ((other, value) :: rest) approver = approverVerdict rest approver := by
  simp [approverVerdict, List.any_cons, distinct]

theorem approverVerdict_cons_ignored {rest : List (String × Verdict)} {other approver : String} :
    approverVerdict ((other, .ignored) :: rest) approver = approverVerdict rest approver := by
  simp [approverVerdict, List.any_cons]

theorem approverVerdict_counted_iff {outcomes : List (String × Verdict)} {approver : String} :
    approverVerdict outcomes approver = .counted ↔ (approver, Verdict.counted) ∈ outcomes := by
  unfold approverVerdict
  constructor
  · intro isCounted
    split at isCounted
    · rename_i found
      simp only [List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq] at found
      obtain ⟨⟨name, value⟩, member, rfl, rfl⟩ := found
      exact member
    · split at isCounted <;> cases isCounted
  · intro member
    have found : outcomes.any
        (fun outcome => decide (outcome.1 = approver) && decide (outcome.2 = .counted)) = true := by
      simp only [List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq]
      exact ⟨(approver, .counted), member, rfl, rfl⟩
    simp [found]

/-- Counted and pending approvers are disjoint, so together they are the
approvers that are not ignored. -/
theorem counted_add_pending (approvers : List String) (outcomes : List (String × Verdict)) :
    countedCount approvers outcomes + pendingCount approvers outcomes =
      (approvers.filter fun approver =>
        decide (approverVerdict outcomes approver ≠ .ignored)).length := by
  induction approvers with
  | nil => rfl
  | cons head tail tailHolds =>
      simp only [countedCount, pendingCount, ne_eq, decide_not] at tailHolds ⊢
      rcases showing : approverVerdict outcomes head with _ | _ | _ <;>
        simp [showing] <;> omega

theorem filter_length_mono {α : Type} {list : List α} {first second : α → Bool}
    (implies : ∀ element ∈ list, first element = true → second element = true) :
    (list.filter first).length ≤ (list.filter second).length := by
  induction list with
  | nil => simp
  | cons head tail tailHolds =>
      have tailBound := tailHolds fun element member =>
        implies element (List.mem_cons_of_mem head member)
      by_cases firstHolds : first head = true
      · have secondHolds := implies head (List.mem_cons_self) firstHolds
        simp [firstHolds, secondHolds]
        omega
      · by_cases secondHolds : second head = true
        · simp [firstHolds, secondHolds]
          omega
        · simp [firstHolds, secondHolds]
          omega

/-- The threshold decision is monotone in the counted approvers and in the
approvers that are not ignored. -/
theorem thresholdCounts_monotone_counts {threshold counted₁ pending₁ counted₂ pending₂ : Nat}
    (moreCounted : counted₁ ≤ counted₂)
    (moreReached : counted₁ + pending₁ ≤ counted₂ + pending₂) :
    Truth.le (thresholdCounts threshold counted₁ pending₁)
      (thresholdCounts threshold counted₂ pending₂) := by
  simp only [Truth.le, thresholdCounts, Generated.thresholdCounts]
  split <;> split <;> (try split) <;> (try split) <;> simp [Truth.rank] <;> omega

theorem approvalDecision_congr {env : Environment Action} {identifier : Nat}
    {requirement : Requirement} {left right : List (ApprovalRecord Action)}
    (same : ∀ approval, approval ∈ left ↔ approval ∈ right) :
    approvalDecision env identifier requirement left =
      approvalDecision env identifier requirement right := by
  have outcomesSame : ∀ outcome,
      outcome ∈ outcomes env identifier requirement left ↔
        outcome ∈ outcomes env identifier requirement right := by
    intro outcome
    simp only [outcomes, List.mem_map]
    constructor
    · rintro ⟨approval, member, rfl⟩
      exact ⟨approval, (same approval).mp member, rfl⟩
    · rintro ⟨approval, member, rfl⟩
      exact ⟨approval, (same approval).mpr member, rfl⟩
  simp only [approvalDecision, decideCounts, countedCount, pendingCount,
    approverVerdict_congr outcomesSame]

theorem outcomes_cons (env : Environment Action) (identifier : Nat) (requirement : Requirement)
    (approval : ApprovalRecord Action) (approvals : List (ApprovalRecord Action)) :
    outcomes env identifier requirement (approval :: approvals) =
      (approval.approver, verdict env identifier requirement approval) ::
        outcomes env identifier requirement approvals :=
  rfl

theorem approverVerdict_cons_ignored_fun {rest : List (String × Verdict)} {other : String} :
    approverVerdict ((other, .ignored) :: rest) = approverVerdict rest :=
  funext fun _ => approverVerdict_cons_ignored

/-- An approval whose verdict is ignored changes no decision. -/
theorem approvalDecision_cons_ignored {env : Environment Action} {identifier : Nat}
    {requirement : Requirement} {approvals : List (ApprovalRecord Action)}
    {approval : ApprovalRecord Action}
    (ignored : verdict env identifier requirement approval = .ignored) :
    approvalDecision env identifier requirement (approval :: approvals) =
      approvalDecision env identifier requirement approvals := by
  simp only [approvalDecision, decideCounts, countedCount, pendingCount, outcomes_cons, ignored,
    approverVerdict_cons_ignored_fun]

theorem verdict_ignored_of_not_eligible {env : Environment Action} {identifier : Nat}
    {requirement : Requirement} {approval : ApprovalRecord Action}
    (notEligible : eligible env identifier requirement approval = false) :
    verdict env identifier requirement approval = .ignored := by
  simp [verdict, notEligible]

/-! ## F1 theorems -/

/-- The decision is the generated threshold function over distinct counts. -/
theorem approval_decide_eq_threshold_counts (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action)) :
    approvalDecision env identifier requirement approvals =
      thresholdCounts requirement.threshold
        (countedCount requirement.approvers (outcomes env identifier requirement approvals))
        (pendingCount requirement.approvers (outcomes env identifier requirement approvals)) :=
  rfl

/-- A requirement is authorized exactly when at least K distinct listed
principals each have a counted approval. -/
theorem approval_authorized_iff_distinct_quorum (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (distinctApprovers : requirement.approvers.Nodup) :
    approvalDecision env identifier requirement approvals = .authorized ↔
      ∃ chosen : List String, chosen.Nodup ∧ chosen ⊆ requirement.approvers ∧
        requirement.threshold ≤ chosen.length ∧
        ∀ principal ∈ chosen, ∃ approval ∈ approvals, approval.approver = principal ∧
          verdict env identifier requirement approval = .counted := by
  have authorizedIff : approvalDecision env identifier requirement approvals = .authorized ↔
      requirement.threshold ≤
        countedCount requirement.approvers (outcomes env identifier requirement approvals) := by
    constructor
    · exact authorized_implies_threshold_met
    · intro enough
      simp only [approvalDecision, decideCounts, thresholdCounts, Generated.thresholdCounts]
      rw [if_pos enough]
  have countedMember : ∀ principal,
      approverVerdict (outcomes env identifier requirement approvals) principal = .counted ↔
        ∃ approval ∈ approvals, approval.approver = principal ∧
          verdict env identifier requirement approval = .counted := by
    intro principal
    rw [approverVerdict_counted_iff]
    simp only [outcomes, List.mem_map, Prod.mk.injEq]
  rw [authorizedIff]
  constructor
  · intro enough
    refine ⟨requirement.approvers.filter fun approver => decide
        (approverVerdict (outcomes env identifier requirement approvals) approver = .counted),
      distinctApprovers.filter _, fun _ member => (List.mem_filter.mp member).1, enough, ?_⟩
    intro principal member
    simp only [List.mem_filter, decide_eq_true_eq] at member
    exact (countedMember principal).mp member.2
  · rintro ⟨chosen, chosenDistinct, chosenListed, enough, chosenCounted⟩
    have chosenInFilter : chosen ⊆ requirement.approvers.filter fun approver => decide
        (approverVerdict (outcomes env identifier requirement approvals) approver = .counted) := by
      intro principal member
      simp only [List.mem_filter, decide_eq_true_eq]
      exact ⟨chosenListed member, (countedMember principal).mpr (chosenCounted principal member)⟩
    exact enough.trans (chosenDistinct.subperm chosenInFilter).length_le

/-- Presenting an approval twice changes nothing. -/
theorem approval_duplicate_irrelevant (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (approval : ApprovalRecord Action) (repeated : approval ∈ approvals) :
    approvalDecision env identifier requirement (approval :: approvals) =
      approvalDecision env identifier requirement approvals := by
  apply approvalDecision_congr
  intro candidate
  simp only [List.mem_cons]
  constructor
  · rintro (rfl | member)
    · exact repeated
    · exact member
  · exact Or.inr

/-- An approval by a principal the requirement does not list changes nothing. -/
theorem approval_outsider_irrelevant (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (approval : ApprovalRecord Action) (outsider : approval.approver ∉ requirement.approvers) :
    approvalDecision env identifier requirement (approval :: approvals) =
      approvalDecision env identifier requirement approvals := by
  have sameOnListed : ∀ principal ∈ requirement.approvers,
      approverVerdict (outcomes env identifier requirement (approval :: approvals)) principal =
        approverVerdict (outcomes env identifier requirement approvals) principal := by
    intro principal listed
    have distinct : approval.approver ≠ principal := fun same => outsider (same ▸ listed)
    simp only [outcomes, List.map_cons]
    exact approverVerdict_cons_other distinct
  have countedEq : (requirement.approvers.filter fun principal => decide
        (approverVerdict (outcomes env identifier requirement (approval :: approvals)) principal =
          .counted)) =
      requirement.approvers.filter fun principal => decide
        (approverVerdict (outcomes env identifier requirement approvals) principal = .counted) :=
    List.filter_congr fun principal listed => by rw [sameOnListed principal listed]
  have pendingEq : (requirement.approvers.filter fun principal => decide
        (approverVerdict (outcomes env identifier requirement (approval :: approvals)) principal =
          .pending)) =
      requirement.approvers.filter fun principal => decide
        (approverVerdict (outcomes env identifier requirement approvals) principal = .pending) :=
    List.filter_congr fun principal listed => by rw [sameOnListed principal listed]
  simp only [approvalDecision, decideCounts, countedCount, pendingCount, countedEq, pendingEq]

/-- An approval of another action changes nothing. -/
theorem approval_other_action_irrelevant (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (approval : ApprovalRecord Action) (other : approval.action ≠ env.action) :
    approvalDecision env identifier requirement (approval :: approvals) =
      approvalDecision env identifier requirement approvals :=
  approvalDecision_cons_ignored (verdict_ignored_of_not_eligible (by simp [eligible, other]))

/-- An approval by a principal of the authority chain changes nothing. -/
theorem approval_self_approval_irrelevant (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (approval : ApprovalRecord Action) (inChain : approval.approver ∈ env.authority) :
    approvalDecision env identifier requirement (approval :: approvals) =
      approvalDecision env identifier requirement approvals :=
  approvalDecision_cons_ignored (verdict_ignored_of_not_eligible (by simp [eligible, inChain]))

/-- An approval that binds another requirement changes nothing. -/
theorem approval_other_requirement_irrelevant (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (approval : ApprovalRecord Action) (other : approval.requirement ≠ identifier) :
    approvalDecision env identifier requirement (approval :: approvals) =
      approvalDecision env identifier requirement approvals :=
  approvalDecision_cons_ignored (verdict_ignored_of_not_eligible (by simp [eligible, other]))

/-- The decision does not depend on the order of approvals. -/
theorem approval_permutation_invariant (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) {left right : List (ApprovalRecord Action)}
    (permuted : left.Perm right) :
    approvalDecision env identifier requirement left =
      approvalDecision env identifier requirement right :=
  approvalDecision_congr fun _ => permuted.mem_iff

/-- Adding approvals never lowers the decision. -/
theorem approval_monotone_in_approvals (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals extra : List (ApprovalRecord Action)) :
    Truth.le (approvalDecision env identifier requirement approvals)
      (approvalDecision env identifier requirement (approvals ++ extra)) := by
  set before := outcomes env identifier requirement approvals
  set after := outcomes env identifier requirement (approvals ++ extra)
  have included : ∀ outcome, outcome ∈ before → outcome ∈ after := by
    intro outcome member
    simp only [before, after, outcomes, List.map_append, List.mem_append] at member ⊢
    exact Or.inl member
  have countedStays : ∀ principal, approverVerdict before principal = .counted →
      approverVerdict after principal = .counted := by
    intro principal isCounted
    rw [approverVerdict_counted_iff] at isCounted ⊢
    exact included _ isCounted
  have reachedStays : ∀ principal, approverVerdict before principal ≠ .ignored →
      approverVerdict after principal ≠ .ignored := by
    intro principal reached
    unfold approverVerdict at reached ⊢
    simp only [List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq] at reached ⊢
    split at reached
    · rename_i found
      obtain ⟨outcome, member, sameName, sameValue⟩ := found
      rw [if_pos ⟨outcome, included _ member, sameName, sameValue⟩]
      simp
    · split at reached
      · rename_i found
        obtain ⟨outcome, member, sameName, sameValue⟩ := found
        split
        · simp
        · rw [if_pos ⟨outcome, included _ member, sameName, sameValue⟩]
          simp
      · exact absurd rfl reached
  simp only [approvalDecision, decideCounts]
  apply thresholdCounts_monotone_counts
  · exact filter_length_mono fun principal _ holds => by
      simp only [decide_eq_true_eq] at holds ⊢
      exact countedStays principal holds
  · rw [counted_add_pending, counted_add_pending]
    exact filter_length_mono fun principal _ holds => by
      simp only [decide_eq_true_eq] at holds ⊢
      exact reachedStays principal holds

/-- Raising K never raises the decision. -/
theorem approval_antitone_in_threshold (env : Environment Action) (identifier : Nat)
    (approvers : List String) (approvals : List (ApprovalRecord Action)) {lower higher : Nat}
    (raised : lower ≤ higher) :
    Truth.le (approvalDecision env identifier ⟨approvers, higher⟩ approvals)
      (approvalDecision env identifier ⟨approvers, lower⟩ approvals) := by
  simp only [approvalDecision, decideCounts]
  have sameOutcomes : outcomes env identifier ⟨approvers, higher⟩ approvals =
      outcomes env identifier ⟨approvers, lower⟩ approvals := by
    simp [outcomes, verdict, eligible]
  rw [sameOutcomes]
  exact thresholdCounts_antitone_required raised

/-- Listing fewer approvers, with the same K, never raises the decision. -/
theorem approval_antitone_in_approvers (env : Environment Action) (identifier : Nat)
    (threshold : Nat) (approvals : List (ApprovalRecord Action)) {fewer more : List String}
    (subset : fewer ⊆ more) (fewerDistinct : fewer.Nodup) :
    Truth.le (approvalDecision env identifier ⟨fewer, threshold⟩ approvals)
      (approvalDecision env identifier ⟨more, threshold⟩ approvals) := by
  set small := outcomes env identifier ⟨fewer, threshold⟩ approvals
  set large := outcomes env identifier ⟨more, threshold⟩ approvals
  have sameOnFewer : ∀ principal ∈ fewer,
      approverVerdict small principal = approverVerdict large principal := by
    intro principal listed
    have outcomeFor : ∀ value, (principal, value) ∈ small ↔ (principal, value) ∈ large := by
      intro value
      simp only [small, large, outcomes, List.mem_map, Prod.mk.injEq]
      constructor
      · rintro ⟨approval, member, same, isValue⟩
        refine ⟨approval, member, same, ?_⟩
        rw [← isValue]
        simp only [verdict, eligible, same, listed, subset listed, decide_true, Bool.true_and]
      · rintro ⟨approval, member, same, isValue⟩
        refine ⟨approval, member, same, ?_⟩
        rw [← isValue]
        simp only [verdict, eligible, same, listed, subset listed, decide_true, Bool.true_and]
    unfold approverVerdict
    have anyFor : ∀ value : Verdict,
        small.any (fun outcome => decide (outcome.1 = principal) && decide (outcome.2 = value)) =
          large.any (fun outcome => decide (outcome.1 = principal) && decide (outcome.2 = value)) := by
      intro value
      rw [Bool.eq_iff_iff]
      simp only [List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq]
      constructor
      · rintro ⟨⟨name, current⟩, member, rfl, rfl⟩
        exact ⟨(name, current), (outcomeFor current).mp member, rfl, rfl⟩
      · rintro ⟨⟨name, current⟩, member, rfl, rfl⟩
        exact ⟨(name, current), (outcomeFor current).mpr member, rfl, rfl⟩
    rw [anyFor .counted, anyFor .pending]
  have countedSubset : (fewer.filter fun principal => decide (approverVerdict small principal = .counted)) ⊆
      (more.filter fun principal => decide (approverVerdict large principal = .counted)) := by
    intro principal member
    simp only [List.mem_filter, decide_eq_true_eq] at member ⊢
    exact ⟨subset member.1, sameOnFewer principal member.1 ▸ member.2⟩
  have reachedSubset : (fewer.filter fun principal => decide (approverVerdict small principal ≠ .ignored)) ⊆
      (more.filter fun principal => decide (approverVerdict large principal ≠ .ignored)) := by
    intro principal member
    simp only [List.mem_filter, decide_eq_true_eq] at member ⊢
    exact ⟨subset member.1, sameOnFewer principal member.1 ▸ member.2⟩
  simp only [approvalDecision, decideCounts]
  apply thresholdCounts_monotone_counts
  · exact ((fewerDistinct.filter _).subperm countedSubset).length_le
  · rw [counted_add_pending, counted_add_pending]
    exact ((fewerDistinct.filter _).subperm reachedSubset).length_le

/-! ## The `approval-requirement-v1` attenuation law -/

/-- The distinct listed principals among those who approved. -/
def approvingListed (approving : List String) (requirement : Requirement) : List String :=
  requirement.approvers.dedup.filter fun principal => decide (principal ∈ approving)

/-- A set of approving principals meets a requirement when at least K
distinct listed principals are in it. -/
def meets (approving : List String) (requirement : Requirement) : Prop :=
  requirement.threshold ≤ (approvingListed approving requirement).length

/-- A child requirement covers a parent requirement when its approvers are a
subset and its threshold is at least the parent's. -/
def covers (child parent : Requirement) : Prop :=
  child.approvers ⊆ parent.approvers ∧ parent.threshold ≤ child.threshold

/-- Every parent requirement is covered by some child requirement. -/
def requirementsAttenuate (child parent : List Requirement) : Prop :=
  ∀ requirement ∈ parent, ∃ candidate ∈ child, covers candidate requirement

theorem covers_refl (requirement : Requirement) : covers requirement requirement :=
  ⟨List.Subset.refl _, le_refl _⟩

theorem covers_trans {child middle parent : Requirement}
    (childMiddle : covers child middle) (middleParent : covers middle parent) :
    covers child parent :=
  ⟨childMiddle.1.trans middleParent.1, middleParent.2.trans childMiddle.2⟩

/-- Covering narrows: approvals that meet the child meet the parent. -/
theorem covers_monotone {approving : List String} {child parent : Requirement}
    (covered : covers child parent) (childMet : meets approving child) :
    meets approving parent := by
  have included : approvingListed approving child ⊆ approvingListed approving parent := by
    intro principal member
    simp only [approvingListed, List.mem_filter, List.mem_dedup] at member ⊢
    exact ⟨covered.1 member.1, member.2⟩
  have distinct : (approvingListed approving child).Nodup :=
    (List.nodup_dedup _).filter _
  exact covered.2.trans (childMet.trans (distinct.subperm included).length_le)

theorem approval_requirements_attenuate_refl (requirements : List Requirement) :
    requirementsAttenuate requirements requirements :=
  fun requirement member => ⟨requirement, member, covers_refl requirement⟩

theorem approval_requirements_attenuate_trans {child middle parent : List Requirement}
    (childMiddle : requirementsAttenuate child middle)
    (middleParent : requirementsAttenuate middle parent) :
    requirementsAttenuate child parent := by
  intro requirement member
  obtain ⟨middleRequirement, middleMember, middleCovers⟩ := middleParent requirement member
  obtain ⟨childRequirement, childMember, childCovers⟩ := childMiddle middleRequirement middleMember
  exact ⟨childRequirement, childMember, covers_trans childCovers middleCovers⟩

/-- A child list that attenuates its parent's authorizes a subset: every set
of approving principals that meets every child requirement meets every
parent requirement. -/
theorem approval_requirements_attenuate_monotone {approving : List String}
    {child parent : List Requirement} (attenuates : requirementsAttenuate child parent)
    (childMet : ∀ requirement ∈ child, meets approving requirement) :
    ∀ requirement ∈ parent, meets approving requirement := by
  intro requirement member
  obtain ⟨candidate, candidateMember, covered⟩ := attenuates requirement member
  exact covers_monotone covered (childMet candidate candidateMember)

/-- The `approval-requirement-v1` law over decoded requirement lists: the
child attenuates the parent when both carry the extension, adding the
extension is accepted, and a missing child payload is refused. A payload
admits the sets of approving principals that meet all its requirements. -/
def approvalRequirementLaw : NarrowingLaw (List Requirement) (List String) where
  attenuates child parent :=
    match child, parent with
    | some child, some parent => requirementsAttenuate child parent
    | some _, none => True
    | none, _ => False
  admits requirements approving := ∀ requirement ∈ requirements, meets approving requirement

/-- The approval-requirement law is a preorder that narrows. -/
theorem approval_requirement_law_lawful : approvalRequirementLaw.Lawful where
  refl requirements := approval_requirements_attenuate_refl requirements
  trans child middle parent childMiddle middleParent := by
    cases parent with
    | none => trivial
    | some parent => exact approval_requirements_attenuate_trans childMiddle middleParent
  narrows _ _ attenuates _ admitted :=
    approval_requirements_attenuate_monotone attenuates admitted

/-- Adding the extension where the parent has none is accepted. -/
theorem approval_requirement_law_accepts_addition (requirements : List Requirement) :
    approvalRequirementLaw.attenuates (some requirements) none :=
  trivial

/-- Dropping the extension where the parent has it is refused. -/
theorem approval_requirement_law_refuses_drop (requirements : List Requirement) :
    ¬ approvalRequirementLaw.attenuates none (some requirements) :=
  id

/-- An authorized decision meets its requirement: the principals with a
counted approval are an approving set that meets it. -/
theorem approval_authorized_meets (env : Environment Action) (identifier : Nat)
    (requirement : Requirement) (approvals : List (ApprovalRecord Action))
    (distinctApprovers : requirement.approvers.Nodup)
    (authorized : approvalDecision env identifier requirement approvals = .authorized) :
    meets ((approvals.filter fun approval =>
      decide (verdict env identifier requirement approval = .counted)).map
        ApprovalRecord.approver) requirement := by
  obtain ⟨chosen, chosenDistinct, chosenListed, enough, chosenCounted⟩ :=
    (approval_authorized_iff_distinct_quorum env identifier requirement approvals
      distinctApprovers).mp authorized
  have included : chosen ⊆ approvingListed ((approvals.filter fun approval =>
      decide (verdict env identifier requirement approval = .counted)).map
        ApprovalRecord.approver) requirement := by
    intro principal member
    obtain ⟨approval, approvalMember, same, isCounted⟩ := chosenCounted principal member
    simp only [approvingListed, List.mem_filter, List.mem_dedup, List.mem_map,
      decide_eq_true_eq]
    exact ⟨chosenListed member, approval, ⟨approvalMember, isCounted⟩, same⟩
  exact enough.trans (chosenDistinct.subperm included).length_le

end Auths.Approval
