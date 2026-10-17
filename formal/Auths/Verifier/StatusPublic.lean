import Auths.Verifier.StatusSelection
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection
set_option maxHeartbeats 2000000

def policyView : AuthsStatusSelection.auths_model.StatusPolicy → Model.Policy
  | .ExpiryOnly => .expiryOnly
  | .SnapshotRequired method age => .required method age.val

def decisionView : AuthsStatusSelection.auths_ports.StatusDecision → Model.Decision
  | .Active => .active
  | .Revoked => .revoked
  | .Missing => .missing
  | .Stale => .stale
  | .Rollback => .rollback
  | .UntrustedIssuer => .untrusted
  | .WrongMethod => .wrongMethod

def evaluationView (evaluation : AuthsStatusSelection.auths_ports.StatusEvaluation) : Model.Evaluation :=
  ⟨decisionView evaluation.decision, evaluation.valid_through.val⟩

theorem method_ne (left right : String) :
    core.cmp.impls.PartialEqShared.ne AuthsStatusSelection.auths_model.StatusMethodId.Insts.CoreCmpPartialEqStatusMethodId left right =
      ok (left != right) := by
  simp [core.cmp.impls.PartialEqShared.ne,
    core.cmp.PartialEq.ne.default,
    method_eq, bne_eq]

theorem principal_selector_approver_refines
    (id : String) (policy : AuthsStatusSelection.auths_model.StatusPolicy) (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (subject : String) (now : Std.U64) :
    select_principal_from_snapshot id policy snapshot subject .Approver now ⦃ actual =>
      evaluationView actual = Model.evaluateScan id (policyView policy) snapshot.observed_at.val
        snapshot.valid_until.val (snapshot.trust.val.map ruleView)
        (snapshot.statements.val.map principalView) subject .approver now.val ⦄ := by
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
          have loop := principal_loop_refines snapshot.statements.val snapshot.statements snapshot.trust
            method subject age now snapshot (false, false, false, none, false, false, snapshot.valid_until)
            0#usize (by simp)
          apply spec_bind loop
          intro actual meaning
          rcases actual with ⟨seen, matched, rollback, maximum, stale, revoked, through⟩
          change scanView (seen, matched, rollback, maximum, stale, revoked, through) =
            Model.scan snapshot.valid_until.val age.val now.val method (snapshot.trust.val.map ruleView)
              subject .approver (snapshot.statements.val.map principalView) (Model.initial snapshot.valid_until.val) at meaning
          simp only [Model.evaluateScan, policyView, mismatch, future, expired, decide_false,
            Bool.false_or, Bool.false_eq_true, ↓reduceIte]
          rw [← meaning]
          cases seenEquation : seen <;> cases matchedEquation : matched <;>
            cases rollbackEquation : rollback <;> cases maximumEquation : maximum <;>
            cases staleEquation : stale <;> cases revokedEquation : revoked <;>
            simp [AuthsStatusSelection.auths_ports.StatusEvaluation.new, evaluationView, decisionView, Model.finish,
              scanView, core.option.Option.is_none]

theorem principal_method_approver_refines
    (implementation : ExactStatusMethod) (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot) (subject : String) (now : Std.U64) :
    ExactStatusMethod.Insts.Auths_portsStatusMethod.principal implementation policy snapshot subject .Approver now
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
        Model.evaluateScan implementation.id (policyView policy) snapshot.observed_at.val snapshot.valid_until.val
          (snapshot.trust.val.map ruleView) (snapshot.statements.val.map principalView) subject .approver now.val ⦄ := by
  unfold ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
  apply spec_bind (principal_selector_approver_refines implementation.id policy snapshot subject now)
  intro evaluation meaning
  simp only [spec_ok]
  exact ⟨evaluation, rfl, meaning⟩
end Auths.StatusSelection
