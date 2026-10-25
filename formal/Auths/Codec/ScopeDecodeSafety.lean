import Auths.Codec.ScopeConsequences
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.ScopeConstructor
open AuthsScopeCodec
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

def scopeValid (scope : auths_model.StatusScope) : Prop :=
  match scope with
  | .OwnAnchor | .AnyAnchor => True
  | .Anchors anchors => Model.admitted anchors.val ∧ Auths.StatusSelection.Search.Ordered anchors.val

theorem constructed_scope_valid (values output : alloc.vec.Vec String)
    (accepted : AuthsScopeCodec.auths_model.StatusScopeAnchors.new values = ok (.Ok output)) :
    scopeValid (.Anchors output) := by
  have contract := constructor_validity values
  rw [accepted] at contract
  simp only [spec_ok] at contract
  rcases contract with ⟨admitted, ordered, permutation, bound⟩
  refine ⟨⟨?_, bound, permutation.nodup_iff.mpr admitted.2.2⟩, ordered⟩
  intro empty
  have same := permutation.length_eq
  have original : values.val = [] := List.length_eq_zero_iff.mp (by simpa [empty] using same.symm)
  exact admitted.1 original

theorem accepted_scope_valid (decoder : cbor.Decoder) (limits : auths_model.VerifierLimits)
    (scope : auths_model.StatusScope) (next : cbor.Decoder)
    (accepted : decode.status_scope decoder limits = ok (.Ok scope, next)) : scopeValid scope := by
  unfold decode.status_scope at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | casesm* _ ∧ _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, error.CodecError.Insts.CoreConvertFromModelError.from,         Result.ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals
    repeat' first
      | casesm* core.result.Result core.convert.Infallible _
      | casesm* core.convert.Infallible
      | simp_all (failIfUnchanged := true) only [Result.ok.injEq, reduceCtorEq]
  all_goals subst scope
  all_goals try trivial
  all_goals
    casesm* core.result.Result auths_model.StatusScopeAnchors auths_model.ModelError
  all_goals simp_all only [Result.ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals apply constructed_scope_valid
  all_goals assumption

end Auths.ScopeConstructor
