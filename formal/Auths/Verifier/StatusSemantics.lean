import Auths.Verifier.StatusIndependent
import Auths.Verifier.StatusGrant
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection

/-- Actual principal port result against the independent filter/max/tie-set
    specification. Evidence authentication remains a separate caller boundary. -/
theorem principal_method_approver_independent
    (implementation : ExactStatusMethod) (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot) (subject : String) (now : Std.U64) :
    ExactStatusMethod.Insts.Auths_portsStatusMethod.principal implementation policy snapshot subject .Approver now
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
        Model.evaluate implementation.id (policyView policy) snapshot.observed_at.val snapshot.valid_until.val
          (snapshot.trust.val.map ruleView) (snapshot.statements.val.map principalView) subject .approver now.val ⦄ := by
  simpa only [Algebra.evaluateScan_eq_evaluate] using
    principal_method_approver_refines implementation policy snapshot subject now

/-- Actual grant port result against the independent filter/max/tie-set
    specification, including the exact decision and inclusive horizon. -/
theorem grant_method_approver_independent
    (implementation : ExactStatusMethod) (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot) (subject : AuthsStatusSelection.auths_model.GrantId) (now : Std.U64) :
    ExactStatusMethod.Insts.Auths_portsStatusMethod.grant implementation policy snapshot subject .Approver now
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
        Model.evaluate implementation.id (policyView policy) snapshot.observed_at.val snapshot.valid_until.val
          (snapshot.trust.val.map ruleView) (snapshot.statements.val.map grantView) subject .approver now.val ⦄ := by
  simpa only [Algebra.evaluateScan_eq_evaluate] using
    grant_method_approver_refines implementation policy snapshot subject now

end Auths.StatusSelection
