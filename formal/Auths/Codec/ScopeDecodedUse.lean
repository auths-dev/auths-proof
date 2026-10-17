import Auths.Codec.ScopeDecodeSafety
open Aeneas Aeneas.Std Result
namespace Auths.ScopeConstructor

/-- Fieldwise identity between two translations of the same Rust enum. The
    listed-vector carrier is identical; no collection or decision changes. -/
def nativeScope : AuthsScopeCodec.auths_model.StatusScope → AuthsStatusSelection.auths_model.StatusScope
  | .OwnAnchor => .OwnAnchor
  | .AnyAnchor => .AnyAnchor
  | .Anchors anchors => .Anchors anchors

theorem decoded_scope_ordered (decoder : AuthsScopeCodec.cbor.Decoder)
    (limits : AuthsScopeCodec.auths_model.VerifierLimits)
    (scope : AuthsScopeCodec.auths_model.StatusScope) (next : AuthsScopeCodec.cbor.Decoder)
    (accepted : AuthsScopeCodec.decode.status_scope decoder limits = ok (.Ok scope, next)) :
    Auths.StatusSelection.scopeOrdered (nativeScope scope) := by
  have valid := accepted_scope_valid decoder limits scope next accepted
  cases scope with
  | OwnAnchor => trivial
  | AnyAnchor => trivial
  | Anchors anchors => exact valid.2

/-- Actual successful decoding supplies the invariant required by the actual
    scope-coverage function. This is a success-path safety/composition theorem;
    it does not assume an authorization or coverage decision. -/
theorem decoded_scope_covers (decoder : AuthsScopeCodec.cbor.Decoder)
    (limits : AuthsScopeCodec.auths_model.VerifierLimits)
    (scope : AuthsScopeCodec.auths_model.StatusScope) (next : AuthsScopeCodec.cbor.Decoder)
    (issuer : String) (anchor : AuthsStatusSelection.auths_model.TrustAnchor)
    (accepted : AuthsScopeCodec.decode.status_scope decoder limits = ok (.Ok scope, next)) :
    AuthsStatusSelection.auths_model.StatusScope.covers (nativeScope scope) issuer anchor =
      ok (Auths.StatusSelection.Model.scopeCovers (Auths.StatusSelection.scopeView (nativeScope scope))
        issuer (.anchor anchor.id anchor.principal)) :=
  Auths.StatusSelection.scope_covers _ _ _ (decoded_scope_ordered decoder limits scope next accepted)

end Auths.ScopeConstructor
