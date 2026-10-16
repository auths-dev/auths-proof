import Auths.Verifier.StatusPublic
import Auths.Verifier.StatusGrantLeaves
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection
set_option maxHeartbeats 4000000

def grantLoop (method : String) (age : Std.U64) (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (subject : AuthsStatusSelection.auths_model.GrantId) (now : Std.U64) (statements : Slice AuthsStatusSelection.auths_model.SignedGrantStatus)
    (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (state : NativeScan) (position : Std.Usize) :=
  select_grant_from_snapshot_loop method age snapshot subject .Approver now statements rules
    state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position

theorem grant_loop_refines (records : List AuthsStatusSelection.auths_model.SignedGrantStatus)
    (statements : Slice AuthsStatusSelection.auths_model.SignedGrantStatus) (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (method : String) (subject : AuthsStatusSelection.auths_model.GrantId) (age now : Std.U64) (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (state : NativeScan) (position : Std.Usize)
    (remaining : statements.val.drop position.val = records) :
    AuthsStatusSelection.select_grant_from_snapshot_loop method age snapshot subject .Approver now statements rules
      state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position ⦃ actual =>
      scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
        (rules.val.map ruleView) subject .approver (records.map grantView) (scanView state) ⦄ := by
  change Aeneas.Std.WP.spec (grantLoop method age snapshot subject now statements rules state position) _
  induction records generalizing state position with
  | nil =>
    have finished : ¬ position < statements.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    unfold grantLoop
    rw [select_grant_from_snapshot_loop.eq_def]
    simp [finished, Model.scan]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := indexed_head statements position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := indexed_next statements position head tail remaining
    rcases state with ⟨seen, methodSeen, rollback, maximum, stale, revoked, through⟩
    by_cases stopped : rollback = true
    ·
      unfold grantLoop
      rw [select_grant_from_snapshot_loop.eq_def]
      simp [guard, stopped, Model.scan, scanView]
    · have running : rollback = false := by simpa using stopped
      subst rollback
      have advance (nextSeen nextMethod nextRollback : Bool) (nextMaximum : Option Std.U64)
          (nextStale nextRevoked : Bool) (nextThrough : Std.U64)
          (meaning : scanView (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) = Model.record snapshot.valid_until.val age.val now.val method
            (rules.val.map ruleView) subject .approver (grantView head)
            (scanView (seen, methodSeen, false, maximum, stale, revoked, through))) :
          select_grant_from_snapshot_loop method age snapshot subject .Approver now statements rules
            nextSeen nextMethod nextRollback nextMaximum nextStale nextRevoked nextThrough next ⦃ actual =>
            scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
              (rules.val.map ruleView) subject .approver ((head :: tail).map grantView)
              (scanView (seen, methodSeen, false, maximum, stale, revoked, through)) ⦄ := by
        have contract := ih (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) next nextRemaining
        rw [meaning] at contract
        simpa only [grantLoop, List.map_cons, Model.scan, Bool.false_eq_true, ↓reduceIte, scanView] using contract
      unfold grantLoop
      rw [select_grant_from_snapshot_loop.eq_def]
      simp only [guard, ↓reduceIte, atHead, bind_tc_ok,
        AuthsStatusSelection.auths_model.SignedGrantStatus.impl.statement,
        AuthsStatusSelection.auths_model.GrantStatusStatement.impl.grant_id, grant_eq,
        AuthsStatusSelection.auths_model.GrantStatusStatement.impl.issuer, approver_visibility_exact,
        AuthsStatusSelection.auths_model.GrantStatusStatement.impl.method, method_eq,
        sequence_floor_exact, AuthsStatusSelection.auths_model.GrantStatusStatement.impl.sequence,
        AuthsStatusSelection.auths_model.GrantStatusSnapshot.impl.valid_until,
        AuthsStatusSelection.auths_model.GrantStatusStatement.impl.observed_at,
        AuthsStatusSelection.auths_model.GrantStatusStatement.impl.valid_until,
        freshness_exact, stale_test, AuthsStatusSelection.auths_model.GrantStatusStatement.impl.state,
        grant_not_active, timestamp_min_exact,
        AuthsStatusSelection.auths_model.Timestamp.get, AuthsStatusSelection.auths_model.FreshnessLimit.get,
        AuthsStatusSelection.auths_model.Timestamp.new, lift, step]
      cases subjectMatch : (head.statement.grant_id == subject) <;>
        cases visible : Model.visible (rules.val.map ruleView) head.statement.issuer .approver <;>
        cases methodMatch : (head.statement.method == method) <;>
        simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
      all_goals
        first
        | exact advance _ _ _ _ _ _ _ (by simp [Model.record, grantView, scanView, subjectMatch, visible, methodMatch])
        | skip
      all_goals
        cases floor : nativeFloor rules method head.statement.issuer <;>
          try simp only [bind_tc_ok]
      all_goals
        first
        | exact advance _ _ _ _ _ _ _ (by simp [Model.record, grantView, scanView, subjectMatch, visible, methodMatch,
            ← native_floor_view rules method head.statement.issuer, floor])
        | skip
      all_goals
        cases maximum <;> try simp only [bind_tc_ok]
      all_goals
        repeat' (split_ifs <;> try simp (config := { zeta := true, zetaHave := true }) only [bind_tc_ok])
      all_goals try simp only [result_ite, bind_tc_ok, boolean_or]
      all_goals
        exact advance _ _ _ _ _ _ _ (by
          clear ih advance
          simp only [scanView]
          repeat' rw [minimum_value]
          simp_all [Model.record, Model.contribute, grantView, Model.deadline,
            ← native_floor_view rules method head.statement.issuer,
            saturation_exact, UScalar.lt_equiv, UScalar.eq_equiv, Nat.min_assoc, beq_iff_eq] <;>
            (split_ifs <;> simp_all <;> omega))

theorem grant_selector_approver_refines
    (id : String) (policy : AuthsStatusSelection.auths_model.StatusPolicy) (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (subject : AuthsStatusSelection.auths_model.GrantId) (now : Std.U64) :
    select_grant_from_snapshot id policy snapshot subject .Approver now ⦃ actual =>
      evaluationView actual = Model.evaluateScan id (policyView policy) snapshot.observed_at.val
        snapshot.valid_until.val (snapshot.trust.val.map ruleView)
        (snapshot.statements.val.map grantView) subject .approver now.val ⦄ := by
  cases policyEquation : policy with
  | ExpiryOnly =>
    simp [select_grant_from_snapshot, AuthsStatusSelection.auths_model.Timestamp.new,
      AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, policyView,
      Model.evaluateScan, Model.wordMaximum, core.num.U64.MAX, UScalar.ofNat, UScalar.ofNatCore_val_eq,
      U64.rMax]
  | SnapshotRequired method age =>
    simp only [select_grant_from_snapshot, method_ne, bind_tc_ok,
      AuthsStatusSelection.auths_model.GrantStatusSnapshot.impl.observed_at, timestamp_gt,
      AuthsStatusSelection.auths_model.GrantStatusSnapshot.impl.valid_until, timestamp_lt,
      AuthsStatusSelection.auths_model.GrantStatusSnapshot.impl.statements,
      AuthsStatusSelection.auths_model.GrantStatusSnapshot.impl.trust, alloc.vec.Vec.deref]
    by_cases mismatch : (method != id) = true
    · simp [mismatch, AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.evaluateScan, policyView]
    · simp only [mismatch]
      by_cases future : snapshot.observed_at.val > now.val
      · simp [future, AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.evaluateScan, policyView, mismatch]
      · simp only [future, decide_false, Bool.false_eq_true, ↓reduceIte]
        by_cases expired : snapshot.valid_until.val < now.val
        · simp [expired, AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.evaluateScan, policyView, mismatch, future]
        · simp only [expired, decide_false, Bool.false_eq_true, ↓reduceIte]
          have loop := grant_loop_refines snapshot.statements.val snapshot.statements snapshot.trust
            method subject age now snapshot (false, false, false, none, false, false, snapshot.valid_until)
            0#usize (by simp)
          apply spec_bind loop
          intro actual meaning
          rcases actual with ⟨seen, matched, rollback, maximum, stale, revoked, through⟩
          change scanView (seen, matched, rollback, maximum, stale, revoked, through) =
            Model.scan snapshot.valid_until.val age.val now.val method (snapshot.trust.val.map ruleView)
              subject .approver (snapshot.statements.val.map grantView) (Model.initial snapshot.valid_until.val) at meaning
          simp only [Model.evaluateScan, policyView, mismatch, future, expired, decide_false,
            Bool.false_or, Bool.false_eq_true, ↓reduceIte]
          rw [← meaning]
          cases seenEquation : seen <;> cases matchedEquation : matched <;>
            cases rollbackEquation : rollback <;> cases maximumEquation : maximum <;>
            cases staleEquation : stale <;> cases revokedEquation : revoked <;>
            simp [AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.finish,
              scanView, core.option.Option.is_none]

theorem grant_method_approver_refines
    (implementation : ExactStatusMethod) (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot) (subject : AuthsStatusSelection.auths_model.GrantId) (now : Std.U64) :
    ExactStatusMethod.Insts.Auths_portsStatusMethod.grant implementation policy snapshot subject .Approver now
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
        Model.evaluateScan implementation.id (policyView policy) snapshot.observed_at.val snapshot.valid_until.val
          (snapshot.trust.val.map ruleView) (snapshot.statements.val.map grantView) subject .approver now.val ⦄ := by
  unfold ExactStatusMethod.Insts.Auths_portsStatusMethod.grant
  apply spec_bind (grant_selector_approver_refines implementation.id policy snapshot subject now)
  intro evaluation meaning
  simp only [spec_ok]
  exact ⟨evaluation, rfl, meaning⟩
end Auths.StatusSelection
