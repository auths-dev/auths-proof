import Auths.Verifier.TemporalModel
import qualification.aeneas.generated.temporal_witness.Funs
import Auths.Composition.IteratorFacts
import Mathlib.Tactic

open Aeneas Aeneas.Std Result
open AuthsTemporalWitness
set_option maxHeartbeats 2000000

namespace Auths.TemporalWitness

def policyView (context : auths_model.TrustedContext) : List (Option Nat) :=
  context.assurance_policy.requirements.val.map (fun requirement =>
    requirement.maximum_age.map (fun age => age.val))

def witnessView (record : auths_model.AssuranceSatisfaction) : Witness :=
  ⟨record.requirement_index.val, record.claim.observed_at.map (fun observed => observed.val)⟩

def AssuranceRefines (expected : Except Unit Nat)
    (actual : core.result.Result auths_model.Timestamp VerificationFailure) : Prop :=
  match expected with
  | .error _ => actual = .Err (.Indeterminate .AssuranceRequirementNotMet)
  | .ok horizon => ∃ output, actual = .Ok output ∧ output.val = horizon

theorem timestamp_lt (left right : auths_model.Timestamp) :
    core.cmp.PartialOrd.lt.default
      auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp left right =
      ok (decide (left.val < right.val)) := by
  simp [AuthsTemporalWitness.core.cmp.PartialOrd.lt.default,
    Aeneas.Std.core.cmp.PartialOrd.lt.default, Aeneas.Std.core.cmp.PartialOrd.lt_body,
    auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp.partial_cmp,
    auths_model.Timestamp.Insts.CoreCmpOrd.cmp, core.cmp.impls.OrdU64.cmp, Nat.compare_eq_lt]

theorem status_horizon_exact (evaluation : auths_ports.StatusEvaluation)
    (evaluatedAt : auths_model.Timestamp) :
    status_horizon evaluation evaluatedAt =
      ok (if evaluatedAt.val ≤ evaluation.valid_through.val then
        .Ok evaluation.valid_through else .Err (.Indeterminate .StaleStatus)) := by
  simp only [status_horizon, auths_ports.StatusEvaluation.impl.valid_through,
    bind_tc_ok, timestamp_lt]
  split <;> rename_i comparison <;> simp_all

theorem status_horizon_accepts_iff (evaluation : auths_ports.StatusEvaluation)
    (evaluatedAt output : auths_model.Timestamp) :
    status_horizon evaluation evaluatedAt = ok (.Ok output) ↔
      output = evaluation.valid_through ∧ evaluatedAt.val ≤ output.val := by
  rw [status_horizon_exact]
  split
  · rename_i within
    constructor
    · intro accepted
      have same : evaluation.valid_through = output := by simpa using accepted
      subst output
      exact ⟨rfl, within⟩
    · rintro ⟨rfl, _⟩
      rfl
  · simp_all

theorem status_horizon_stale_refused (evaluation : auths_ports.StatusEvaluation)
    (evaluatedAt : auths_model.Timestamp)
    (stale : evaluation.valid_through.val < evaluatedAt.val) :
    status_horizon evaluation evaluatedAt = ok (.Err (.Indeterminate .StaleStatus)) := by
  rw [status_horizon_exact]
  simp [Nat.not_le_of_gt stale]

theorem status_decision_accepts_iff (decision : auths_ports.StatusDecision) (principal : Bool) :
    status_decision decision principal = ok (.Ok ()) ↔ decision = .Active := by
  cases decision <;> cases principal <;> simp [status_decision]

theorem timestamp_min_exact (left right : auths_model.Timestamp) :
    core.cmp.Ord.min.trait_default auths_model.Timestamp.Insts.CoreCmpOrd left right =
      ok (if left.val < right.val then left else right) := by
  simp [core.cmp.Ord.min.trait_default, core.cmp.Ord.min.default, core.cmp.Ord.min_body,
    Aeneas.Std.core.cmp.PartialOrd.lt.default, Aeneas.Std.core.cmp.PartialOrd.lt_body,
    auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp.partial_cmp,
    auths_model.Timestamp.Insts.CoreCmpOrd.cmp, core.cmp.impls.OrdU64.cmp, Nat.compare_eq_lt]
  split <;> rfl

theorem requirement_lookup (requirements : Slice auths_model.AssuranceRequirement)
    (index : Std.U16) :
    core.slice.Slice.get (core.slice.index.SliceIndexUsizeSlice auths_model.AssuranceRequirement)
      requirements (core.convert.num.FromUsizeU16.from index) =
      ok (requirements.val[index.val]?) := by
  simp [core.slice.Slice.get, core.convert.num.FromUsizeU16.from_val_eq]

theorem saturation_exact (left right : Std.U64) :
    (core.num.U64.saturating_add left right).val = min wordMaximum (left.val + right.val) := by
  change (min (UScalar.max .U64) (left.val + right.val)) % (2 ^ 64) = _
  rw [UScalar.max_UScalarTy_U64_eq, U64.max_eq]
  unfold wordMaximum
  apply Nat.mod_eq_of_lt
  have bounded := Nat.min_le_left (18446744073709551615 : Nat) (left.val + right.val)
  omega

end Auths.TemporalWitness
