import Auths.Codec.ScopeTrustCollection
open Aeneas Aeneas.Std Result
namespace Auths.ScopeConstructor

def nativeRules (rules : alloc.vec.Vec AuthsScopeCodec.auths_model.StatusTrustRule) :
    alloc.vec.Vec AuthsStatusSelection.auths_model.StatusTrustRule :=
  ⟨rules.val.map nativeRule, by simpa only [List.length_map] using rules.property⟩

/-- The actual complete trust-field decoder supplies every rule's scope
    invariant to the actual principal status port. Remaining snapshot fields
    and all status views stay arbitrary. Evidence authenticity is separate. -/
theorem decoded_trust_principal
    (decoder : AuthsScopeCodec.cbor.Decoder) (limits : AuthsScopeCodec.auths_model.VerifierLimits)
    (rules : alloc.vec.Vec AuthsScopeCodec.auths_model.StatusTrustRule) (next : AuthsScopeCodec.cbor.Decoder)
    (implementation : AuthsStatusSelection.ExactStatusMethod)
    (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (subject : String) (view : AuthsStatusSelection.auths_model.StatusView) (now : Std.U64)
    (decoded : AuthsScopeCodec.decode.status_trust decoder limits = ok (.Ok rules, next)) :
    let constructed := {snapshot with trust := nativeRules rules}
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation policy constructed subject view now ⦃ actual =>
        ∃ evaluation, actual = .Ok evaluation ∧ Auths.StatusSelection.evaluationView evaluation =
          Auths.StatusSelection.Model.evaluate implementation.id (Auths.StatusSelection.policyView policy)
            constructed.observed_at.val constructed.valid_until.val
            (constructed.trust.val.map Auths.StatusSelection.ruleView)
            (constructed.statements.val.map Auths.StatusSelection.principalView)
            subject (Auths.StatusSelection.viewView view) now.val ⦄ :=
  Auths.StatusSelection.principal_method_all_views implementation policy _ subject view now
    (valid_trust_ordered rules.val (accepted_trust_valid decoder limits rules next decoded))

/-- The same decoder-earned rule invariants compose with the actual grant
    status port, preserving the complete decision and freshness horizon. -/
theorem decoded_trust_grant
    (decoder : AuthsScopeCodec.cbor.Decoder) (limits : AuthsScopeCodec.auths_model.VerifierLimits)
    (rules : alloc.vec.Vec AuthsScopeCodec.auths_model.StatusTrustRule) (next : AuthsScopeCodec.cbor.Decoder)
    (implementation : AuthsStatusSelection.ExactStatusMethod)
    (policy : AuthsStatusSelection.auths_model.StatusPolicy)
    (snapshot : AuthsStatusSelection.auths_model.GrantStatusSnapshot)
    (subject : AuthsStatusSelection.auths_model.GrantId)
    (view : AuthsStatusSelection.auths_model.StatusView) (now : Std.U64)
    (decoded : AuthsScopeCodec.decode.status_trust decoder limits = ok (.Ok rules, next)) :
    let constructed := {snapshot with trust := nativeRules rules}
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.grant
      implementation policy constructed subject view now ⦃ actual =>
        ∃ evaluation, actual = .Ok evaluation ∧ Auths.StatusSelection.evaluationView evaluation =
          Auths.StatusSelection.Model.evaluate implementation.id (Auths.StatusSelection.policyView policy)
            constructed.observed_at.val constructed.valid_until.val
            (constructed.trust.val.map Auths.StatusSelection.ruleView)
            (constructed.statements.val.map Auths.StatusSelection.grantView)
            subject (Auths.StatusSelection.viewView view) now.val ⦄ :=
  Auths.StatusSelection.grant_method_all_views implementation policy _ subject view now
    (valid_trust_ordered rules.val (accepted_trust_valid decoder limits rules next decoded))

end Auths.ScopeConstructor
