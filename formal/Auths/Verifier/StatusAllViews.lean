import Auths.Verifier.StatusAnchorVisibility
import Auths.Verifier.StatusIndependent
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection
set_option maxHeartbeats 4000000

def principalLoopAll (method : String) (age : Std.U64) (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (subject : String) (view : AuthsStatusSelection.auths_model.StatusView) (now : Std.U64) (statements : Slice AuthsStatusSelection.auths_model.SignedPrincipalStatus)
    (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (state : NativeScan) (position : Std.Usize) :=
  select_principal_from_snapshot_loop method age snapshot subject view now statements rules
    state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position

theorem principal_loop_all_views (records : List AuthsStatusSelection.auths_model.SignedPrincipalStatus)
    (statements : Slice AuthsStatusSelection.auths_model.SignedPrincipalStatus) (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (method subject : String) (age now : Std.U64) (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (view : AuthsStatusSelection.auths_model.StatusView) (ordered : rulesOrdered rules.val)
    (state : NativeScan) (position : Std.Usize)
    (remaining : statements.val.drop position.val = records) :
    AuthsStatusSelection.select_principal_from_snapshot_loop method age snapshot subject view now statements rules
      state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position ⦃ actual =>
      scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
        (rules.val.map ruleView) subject (viewView view) (records.map principalView) (scanView state) ⦄ := by
  change Aeneas.Std.WP.spec (principalLoopAll method age snapshot subject view now statements rules state position) _
  induction records generalizing state position with
  | nil =>
    have finished : ¬ position < statements.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    unfold principalLoopAll
    rw [select_principal_from_snapshot_loop.eq_def]
    simp [finished, Model.scan]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := indexed_head statements position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := indexed_next statements position head tail remaining
    rcases state with ⟨seen, methodSeen, rollback, maximum, stale, revoked, through⟩
    by_cases stopped : rollback = true
    ·
      unfold principalLoopAll
      rw [select_principal_from_snapshot_loop.eq_def]
      simp [guard, stopped, Model.scan, scanView]
    · have running : rollback = false := by simpa using stopped
      subst rollback
      have advance (nextSeen nextMethod nextRollback : Bool) (nextMaximum : Option Std.U64)
          (nextStale nextRevoked : Bool) (nextThrough : Std.U64)
          (meaning : scanView (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) = Model.record snapshot.valid_until.val age.val now.val method
            (rules.val.map ruleView) subject (viewView view) (principalView head)
            (scanView (seen, methodSeen, false, maximum, stale, revoked, through))) :
          select_principal_from_snapshot_loop method age snapshot subject view now statements rules
            nextSeen nextMethod nextRollback nextMaximum nextStale nextRevoked nextThrough next ⦃ actual =>
            scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
              (rules.val.map ruleView) subject (viewView view) ((head :: tail).map principalView)
              (scanView (seen, methodSeen, false, maximum, stale, revoked, through)) ⦄ := by
        have contract := ih (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) next nextRemaining
        rw [meaning] at contract
        simpa only [principalLoopAll, List.map_cons, Model.scan, Bool.false_eq_true, ↓reduceIte, scanView] using contract
      unfold principalLoopAll
      rw [select_principal_from_snapshot_loop.eq_def]
      simp only [guard, ↓reduceIte, atHead, bind_tc_ok,
        AuthsStatusSelection.auths_model.SignedPrincipalStatus.impl.statement,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.principal, principal_eq,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.issuer, visibility_exact _ _ _ ordered,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.method, method_eq,
        sequence_floor_exact, AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.sequence,
        AuthsStatusSelection.auths_model.PrincipalStatusSnapshot.impl.valid_until,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.observed_at,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.valid_until,
        freshness_exact, stale_test, AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.state,
        principal_not_active, timestamp_min_exact,
        AuthsStatusSelection.auths_model.Timestamp.get, AuthsStatusSelection.auths_model.FreshnessLimit.get,
        AuthsStatusSelection.auths_model.Timestamp.new, lift, step]
      cases subjectMatch : (head.statement.principal == subject) <;>
        cases visible : Model.visible (rules.val.map ruleView) head.statement.issuer (viewView view) <;>
        cases methodMatch : (head.statement.method == method) <;>
        simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
      all_goals
        first
        | exact advance _ _ _ _ _ _ _ (by simp [Model.record, principalView, scanView, subjectMatch, visible, methodMatch])
        | skip
      all_goals
        cases floor : nativeFloor rules method head.statement.issuer <;>
          try simp only [bind_tc_ok]
      all_goals
        first
        | exact advance _ _ _ _ _ _ _ (by simp [Model.record, principalView, scanView, subjectMatch, visible, methodMatch,
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
          simp_all [Model.record, Model.contribute, principalView, Model.deadline,
            ← native_floor_view rules method head.statement.issuer,
            saturation_exact, UScalar.lt_equiv, UScalar.eq_equiv, Nat.min_assoc, beq_iff_eq] <;>
            (split_ifs <;> simp_all <;> omega))

def grantLoopAll (method : String) (age : Std.U64) (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (subject : AuthsStatusSelection.auths_model.GrantId) (view : AuthsStatusSelection.auths_model.StatusView) (now : Std.U64) (statements : Slice AuthsStatusSelection.auths_model.SignedGrantStatus)
    (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (state : NativeScan) (position : Std.Usize) :=
  select_grant_from_snapshot_loop method age snapshot subject view now statements rules
    state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position

theorem grant_loop_all_views (records : List AuthsStatusSelection.auths_model.SignedGrantStatus)
    (statements : Slice AuthsStatusSelection.auths_model.SignedGrantStatus) (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (method : String) (subject : AuthsStatusSelection.auths_model.GrantId) (age now : Std.U64) (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (view : AuthsStatusSelection.auths_model.StatusView) (ordered : rulesOrdered rules.val)
    (state : NativeScan) (position : Std.Usize)
    (remaining : statements.val.drop position.val = records) :
    AuthsStatusSelection.select_grant_from_snapshot_loop method age snapshot subject view now statements rules
      state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position ⦃ actual =>
      scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
        (rules.val.map ruleView) subject (viewView view) (records.map grantView) (scanView state) ⦄ := by
  change Aeneas.Std.WP.spec (grantLoopAll method age snapshot subject view now statements rules state position) _
  induction records generalizing state position with
  | nil =>
    have finished : ¬ position < statements.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    unfold grantLoopAll
    rw [select_grant_from_snapshot_loop.eq_def]
    simp [finished, Model.scan]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := indexed_head statements position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := indexed_next statements position head tail remaining
    rcases state with ⟨seen, methodSeen, rollback, maximum, stale, revoked, through⟩
    by_cases stopped : rollback = true
    ·
      unfold grantLoopAll
      rw [select_grant_from_snapshot_loop.eq_def]
      simp [guard, stopped, Model.scan, scanView]
    · have running : rollback = false := by simpa using stopped
      subst rollback
      have advance (nextSeen nextMethod nextRollback : Bool) (nextMaximum : Option Std.U64)
          (nextStale nextRevoked : Bool) (nextThrough : Std.U64)
          (meaning : scanView (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) = Model.record snapshot.valid_until.val age.val now.val method
            (rules.val.map ruleView) subject (viewView view) (grantView head)
            (scanView (seen, methodSeen, false, maximum, stale, revoked, through))) :
          select_grant_from_snapshot_loop method age snapshot subject view now statements rules
            nextSeen nextMethod nextRollback nextMaximum nextStale nextRevoked nextThrough next ⦃ actual =>
            scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
              (rules.val.map ruleView) subject (viewView view) ((head :: tail).map grantView)
              (scanView (seen, methodSeen, false, maximum, stale, revoked, through)) ⦄ := by
        have contract := ih (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) next nextRemaining
        rw [meaning] at contract
        simpa only [grantLoopAll, List.map_cons, Model.scan, Bool.false_eq_true, ↓reduceIte, scanView] using contract
      unfold grantLoopAll
      rw [select_grant_from_snapshot_loop.eq_def]
      simp only [guard, ↓reduceIte, atHead, bind_tc_ok,
        AuthsStatusSelection.auths_model.SignedGrantStatus.impl.statement,
        AuthsStatusSelection.auths_model.GrantStatusStatement.impl.grant_id, grant_eq,
        AuthsStatusSelection.auths_model.GrantStatusStatement.impl.issuer, visibility_exact _ _ _ ordered,
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
        cases visible : Model.visible (rules.val.map ruleView) head.statement.issuer (viewView view) <;>
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

theorem principal_selector_all_views
    (id : String) (policy : AuthsStatusSelection.auths_model.StatusPolicy) (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (view : AuthsStatusSelection.auths_model.StatusView) (ordered : rulesOrdered snapshot.trust.val)
    (subject : String) (now : Std.U64) :
    select_principal_from_snapshot id policy snapshot subject view now ⦃ actual =>
      evaluationView actual = Model.evaluateScan id (policyView policy) snapshot.observed_at.val
        snapshot.valid_until.val (snapshot.trust.val.map ruleView)
        (snapshot.statements.val.map principalView) subject (viewView view) now.val ⦄ := by
  cases policyEquation : policy with
  | ExpiryOnly =>
    simp [select_principal_from_snapshot, AuthsStatusSelection.auths_model.Timestamp.new,
      AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, policyView,
      Model.evaluateScan, Model.wordMaximum, core.num.U64.MAX, UScalar.ofNat, UScalar.ofNatCore_val_eq,
      U64.rMax]
  | SnapshotRequired method age =>
    simp only [select_principal_from_snapshot, method_ne, bind_tc_ok,
      AuthsStatusSelection.auths_model.PrincipalStatusSnapshot.impl.observed_at, timestamp_gt,
      AuthsStatusSelection.auths_model.PrincipalStatusSnapshot.impl.valid_until, timestamp_lt,
      AuthsStatusSelection.auths_model.PrincipalStatusSnapshot.impl.statements,
      AuthsStatusSelection.auths_model.PrincipalStatusSnapshot.impl.trust, alloc.vec.Vec.deref]
    by_cases mismatch : (method != id) = true
    · simp [mismatch, AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.evaluateScan, policyView]
    · simp only [mismatch]
      by_cases future : snapshot.observed_at.val > now.val
      · simp [future, AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.evaluateScan, policyView, mismatch]
      · simp only [future, decide_false, Bool.false_eq_true, ↓reduceIte]
        by_cases expired : snapshot.valid_until.val < now.val
        · simp [expired, AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.evaluateScan, policyView, mismatch, future]
        · simp only [expired, decide_false, Bool.false_eq_true, ↓reduceIte]
          have loop := principal_loop_all_views snapshot.statements.val snapshot.statements snapshot.trust
            method subject age now snapshot view ordered (false, false, false, none, false, false, snapshot.valid_until)
            0#usize (by simp)
          apply spec_bind loop
          intro actual meaning
          rcases actual with ⟨seen, matched, rollback, maximum, stale, revoked, through⟩
          change scanView (seen, matched, rollback, maximum, stale, revoked, through) =
            Model.scan snapshot.valid_until.val age.val now.val method (snapshot.trust.val.map ruleView)
              subject (viewView view) (snapshot.statements.val.map principalView) (Model.initial snapshot.valid_until.val) at meaning
          simp only [Model.evaluateScan, policyView, mismatch, future, expired, decide_false,
            Bool.false_or, Bool.false_eq_true, ↓reduceIte]
          rw [← meaning]
          cases seenEquation : seen <;> cases matchedEquation : matched <;>
            cases rollbackEquation : rollback <;> cases maximumEquation : maximum <;>
            cases staleEquation : stale <;> cases revokedEquation : revoked <;>
            simp [AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.finish,
              scanView, core.option.Option.is_none]

theorem principal_method_all_views
    (implementation : ExactStatusMethod) (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (subject : String) (view : AuthsStatusSelection.auths_model.StatusView)
    (now : Std.U64) (ordered : rulesOrdered snapshot.trust.val) :
    ExactStatusMethod.Insts.Auths_portsStatusMethod.principal implementation policy snapshot subject view now
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
        Model.evaluate implementation.id (policyView policy) snapshot.observed_at.val snapshot.valid_until.val
          (snapshot.trust.val.map ruleView) (snapshot.statements.val.map principalView) subject (viewView view) now.val ⦄ := by
  unfold ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
  apply spec_bind (principal_selector_all_views implementation.id policy snapshot view ordered subject now)
  intro evaluation meaning
  simp only [spec_ok]
  exact ⟨evaluation, rfl, meaning.trans (Algebra.evaluateScan_eq_evaluate ..)⟩

theorem grant_selector_all_views
    (id : String) (policy : AuthsStatusSelection.auths_model.StatusPolicy) (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (view : AuthsStatusSelection.auths_model.StatusView) (ordered : rulesOrdered snapshot.trust.val)
    (subject : AuthsStatusSelection.auths_model.GrantId) (now : Std.U64) :
    select_grant_from_snapshot id policy snapshot subject view now ⦃ actual =>
      evaluationView actual = Model.evaluateScan id (policyView policy) snapshot.observed_at.val
        snapshot.valid_until.val (snapshot.trust.val.map ruleView)
        (snapshot.statements.val.map grantView) subject (viewView view) now.val ⦄ := by
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
          have loop := grant_loop_all_views snapshot.statements.val snapshot.statements snapshot.trust
            method subject age now snapshot view ordered (false, false, false, none, false, false, snapshot.valid_until)
            0#usize (by simp)
          apply spec_bind loop
          intro actual meaning
          rcases actual with ⟨seen, matched, rollback, maximum, stale, revoked, through⟩
          change scanView (seen, matched, rollback, maximum, stale, revoked, through) =
            Model.scan snapshot.valid_until.val age.val now.val method (snapshot.trust.val.map ruleView)
              subject (viewView view) (snapshot.statements.val.map grantView) (Model.initial snapshot.valid_until.val) at meaning
          simp only [Model.evaluateScan, policyView, mismatch, future, expired, decide_false,
            Bool.false_or, Bool.false_eq_true, ↓reduceIte]
          rw [← meaning]
          cases seenEquation : seen <;> cases matchedEquation : matched <;>
            cases rollbackEquation : rollback <;> cases maximumEquation : maximum <;>
            cases staleEquation : stale <;> cases revokedEquation : revoked <;>
            simp [AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.finish,
              scanView, core.option.Option.is_none]

theorem grant_method_all_views
    (implementation : ExactStatusMethod) (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (subject : AuthsStatusSelection.auths_model.GrantId) (view : AuthsStatusSelection.auths_model.StatusView)
    (now : Std.U64) (ordered : rulesOrdered snapshot.trust.val) :
    ExactStatusMethod.Insts.Auths_portsStatusMethod.grant implementation policy snapshot subject view now
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
        Model.evaluate implementation.id (policyView policy) snapshot.observed_at.val snapshot.valid_until.val
          (snapshot.trust.val.map ruleView) (snapshot.statements.val.map grantView) subject (viewView view) now.val ⦄ := by
  unfold ExactStatusMethod.Insts.Auths_portsStatusMethod.grant
  apply spec_bind (grant_selector_all_views implementation.id policy snapshot view ordered subject now)
  intro evaluation meaning
  simp only [spec_ok]
  exact ⟨evaluation, rfl, meaning.trans (Algebra.evaluateScan_eq_evaluate ..)⟩

end Auths.StatusSelection
