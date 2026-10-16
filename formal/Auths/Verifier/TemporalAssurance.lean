import Auths.Verifier.TemporalNative
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsTemporalWitness
namespace Auths.TemporalWitness
set_option maxHeartbeats 2000000

theorem minimum_value (left right : Std.U64) :
    (if left.val < right.val then left else right).val = min left.val right.val := by
  split
  · rename_i ordered
    exact (Nat.min_eq_left (Nat.le_of_lt ordered)).symm
  · rename_i ordered
    exact (Nat.min_eq_right (Nat.le_of_not_gt ordered)).symm

theorem assurance_loop_refines (records : List auths_model.AssuranceSatisfaction)
    (iterator : core.slice.iter.Iter auths_model.AssuranceSatisfaction)
    (context : auths_model.TrustedContext) (initial : auths_model.Timestamp)
    (remaining : iterator.slice.val.drop iterator.i = records) :
    assurance_horizon_loop iterator context initial ⦃ actual =>
      AssuranceRefines (assuranceHorizon (policyView context) (records.map witnessView) initial.val) actual ⦄ := by
  induction records generalizing iterator initial with
  | nil =>
    rw [assurance_horizon_loop.eq_def,
      Auths.Composition.IteratorFacts.next_nil iterator remaining]
    simp [assuranceHorizon, AssuranceRefines]
  | cons record rest ih =>
    obtain ⟨next, advances, nextRemaining⟩ :=
      Auths.Composition.IteratorFacts.next_cons iterator record rest remaining
    rw [assurance_horizon_loop.eq_def, advances]
    simp only [bind_tc_ok,
      auths_model.TrustedContext.impl.assurance_policy,
      auths_model.AssurancePolicy.impl.requirements,
      auths_model.AssuranceSatisfaction.impl.requirement_index,
      lift, requirement_lookup, alloc.vec.Vec.deref]
    cases selected : context.assurance_policy.requirements.val[record.requirement_index.val]? with
    | none =>
      simp [selected, AuthsTemporalWitness.core.option.Option.ok_or,
        _root_.core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from,
        assuranceHorizon, policyView, witnessView, AssuranceRefines]
    | some requirement =>
      simp only [AuthsTemporalWitness.core.option.Option.ok_or,
        _root_.core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
        bind_tc_ok, auths_model.AssuranceRequirement.impl.maximum_age]
      cases age : requirement.maximum_age with
      | none =>
        simpa [age, assuranceHorizon, policyView, witnessView, selected] using
          ih next initial nextRemaining
      | some ageValue =>
        simp only [bind_tc_ok, auths_model.AssuranceSatisfaction.impl.claim,
          auths_model.AssuranceClaim.impl.observed_at]
        cases observed : record.claim.observed_at with
        | none =>
          simp [observed,

            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame.from,
            assuranceHorizon, policyView, witnessView, selected, age, AssuranceRefines]
        | some atTime =>
          simp only [

            bind_tc_ok, auths_model.Timestamp.get, auths_model.FreshnessLimit.get,
            auths_model.Timestamp.new, timestamp_min_exact]
          have nextProof :=
            ih next (if initial.val < (core.num.U64.saturating_add atTime ageValue).val then
              initial else core.num.U64.saturating_add atTime ageValue) nextRemaining
          rw [minimum_value] at nextProof
          simp only [saturation_exact] at nextProof
          simpa [assuranceHorizon, policyView, witnessView, selected, age, observed,
            saturation_exact] using nextProof

theorem assurance_entry_refines (records : Slice auths_model.AssuranceSatisfaction)
    (context : auths_model.TrustedContext) :
    assurance_horizon records context ⦃ actual =>
      AssuranceRefines (assuranceHorizon (policyView context) (records.val.map witnessView) wordMaximum) actual ⦄ := by
  have contract := assurance_loop_refines records.val ⟨records, 0⟩ context core.num.U64.MAX (by simp)
  simpa [assurance_horizon, auths_model.Timestamp.new,
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter,
    core.num.U64.MAX, UScalar.ofNat, UScalar.ofNatCore_val_eq, U64.rMax, wordMaximum] using contract

end Auths.TemporalWitness
