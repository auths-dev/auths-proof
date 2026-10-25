import Auths.Codec.ScopeConsequences
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.ScopeConstructor
open Auths.StatusSelection

def listedRules (anchors : alloc.vec.Vec String)
    (rules : alloc.vec.Vec AuthsStatusSelection.auths_model.StatusTrustRule) :
    alloc.vec.Vec AuthsStatusSelection.auths_model.StatusTrustRule :=
  ⟨rules.val.map (fun rule => {rule with scope := .Anchors anchors}), by
    simpa only [List.length_map] using rules.property⟩

theorem listed_rules_ordered (anchors : alloc.vec.Vec String)
    (rules : alloc.vec.Vec AuthsStatusSelection.auths_model.StatusTrustRule)
    (ordered : Search.Ordered anchors.val) : rulesOrdered (listedRules anchors rules).val := by
  intro rule member
  obtain ⟨original, _, equal⟩ := List.mem_map.mp member
  subst rule
  exact ordered

/-- A successful actual constructor earns all ordering obligations for the
    actual principal port, for arbitrary rules, evidence and status views.
    This statement covers assigning the constructed list to every rule. -/
theorem constructed_principal_selection (values : alloc.vec.Vec String)
    (implementation : AuthsStatusSelection.ExactStatusMethod)
    (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (subject : String) (view : AuthsStatusSelection.auths_model.StatusView) (now : Std.U64) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new values ⦃ result =>
      match result with
      | .Ok output =>
        let constructed := {snapshot with trust := listedRules output snapshot.trust}
        AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
          implementation policy constructed subject view now ⦃ actual =>
            ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
              Model.evaluate implementation.id (policyView policy) constructed.observed_at.val
                constructed.valid_until.val (constructed.trust.val.map ruleView)
                (constructed.statements.val.map principalView) subject (viewView view) now.val ⦄
      | .Err error => error = .InvalidStatusSnapshot ⦄ := by
  apply spec_mono (constructor_validity values)
  intro result validity
  cases result with
  | Ok output =>
    exact principal_method_all_views implementation policy _ subject view now
      (listed_rules_ordered output snapshot.trust validity.2.1)
  | Err error => exact validity.1

/-- The analogous constructor-to-port result for grant status. -/
theorem constructed_grant_selection (values : alloc.vec.Vec String)
    (implementation : AuthsStatusSelection.ExactStatusMethod)
    (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (subject : AuthsStatusSelection.auths_model.GrantId)
    (view : AuthsStatusSelection.auths_model.StatusView) (now : Std.U64) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new values ⦃ result =>
      match result with
      | .Ok output =>
        let constructed := {snapshot with trust := listedRules output snapshot.trust}
        AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.grant
          implementation policy constructed subject view now ⦃ actual =>
            ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation =
              Model.evaluate implementation.id (policyView policy) constructed.observed_at.val
                constructed.valid_until.val (constructed.trust.val.map ruleView)
                (constructed.statements.val.map grantView) subject (viewView view) now.val ⦄
      | .Err error => error = .InvalidStatusSnapshot ⦄ := by
  apply spec_mono (constructor_validity values)
  intro result validity
  cases result with
  | Ok output =>
    exact grant_method_all_views implementation policy _ subject view now
      (listed_rules_ordered output snapshot.trust validity.2.1)
  | Err error => exact validity.1

end Auths.ScopeConstructor
