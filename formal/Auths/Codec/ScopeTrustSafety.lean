import Auths.Codec.ScopeDecodedUse
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
namespace Auths.ScopeConstructor
open AuthsScopeCodec
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

def trustValid (rules : List auths_model.StatusTrustRule) : Prop :=
  ∀ rule ∈ rules, scopeValid rule.scope

private theorem decodedScopeResult (d : cbor.Decoder) (l : auths_model.VerifierLimits)
    (r : core.result.Result auths_model.StatusScope error.CodecError) (n : cbor.Decoder)
    (h : decode.status_scope d l = ok (r, n)) :
    match r with | .Ok scope => scopeValid scope | .Err _ => True := by
  cases r with
  | Ok scope => exact accepted_scope_valid d l scope n h
  | Err _ => trivial

/-- Every actual successfully decoded trust rule carries a constructor-valid
    scope. This is a structural safety fact, not evidence authentication. -/
theorem accepted_rule_valid (decoder : cbor.Decoder) (limits : auths_model.VerifierLimits)
    (rule : auths_model.StatusTrustRule) (next : cbor.Decoder)
    (accepted : decode.status_trust_rule decoder limits = ok (.Ok rule, next)) :
    scopeValid rule.scope := by
  unfold decode.status_trust_rule auths_model.StatusTrustRule.new at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | casesm* _ ∧ _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, Result.ok.injEq, core.result.Result.Ok.injEq,
        Prod.mk.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals try have scopeSafety := decodedScopeResult _ _ _ _ (by assumption)
  all_goals
    repeat' first
      | casesm* core.result.Result core.convert.Infallible _
      | casesm* core.convert.Infallible
      | casesm* core.result.Result auths_model.StatusScope error.CodecError
      | simp_all (failIfUnchanged := true) only [Result.ok.injEq, core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals subst rule
  all_goals simpa only using scopeSafety

/-- A fieldwise identity between the same Rust trust-rule representation in
    two extraction contexts. Scope, issuer, method and sequence are preserved. -/
def nativeRule (rule : auths_model.StatusTrustRule) : AuthsStatusSelection.auths_model.StatusTrustRule :=
  {method := rule.method, issuer := rule.issuer, sequence_floor := rule.sequence_floor,
    scope := nativeScope rule.scope}

theorem valid_rule_ordered (rule : auths_model.StatusTrustRule) (valid : scopeValid rule.scope) :
    Auths.StatusSelection.scopeOrdered (nativeRule rule).scope := by
  cases scope : rule.scope <;> simp_all [nativeRule, nativeScope, scopeValid, Auths.StatusSelection.scopeOrdered]

theorem valid_trust_ordered (rules : List auths_model.StatusTrustRule) (valid : trustValid rules) :
    Auths.StatusSelection.rulesOrdered (rules.map nativeRule) := by
  intro rule member
  obtain ⟨original, included, rfl⟩ := List.mem_map.mp member
  exact valid_rule_ordered original (valid original included)

theorem pushed_values (rules : alloc.vec.Vec auths_model.StatusTrustRule)
    (rule : auths_model.StatusTrustRule) (output : alloc.vec.Vec auths_model.StatusTrustRule)
    (pushed : alloc.vec.Vec.push rules rule = ok output) : output.val = rules.val ++ [rule] := by
  unfold alloc.vec.Vec.push at pushed
  dsimp only at pushed
  split at pushed
  · cases pushed
    simp
  · contradiction

theorem valid_push (rules : alloc.vec.Vec auths_model.StatusTrustRule)
    (rule : auths_model.StatusTrustRule) (valid : trustValid rules.val) (nextValid : scopeValid rule.scope)
    (output : alloc.vec.Vec auths_model.StatusTrustRule)
    (pushed : alloc.vec.Vec.push rules rule = ok output) : trustValid output.val := by
  rw [pushed_values rules rule output pushed]
  intro item included
  rcases List.mem_append.mp included with previous | added
  · exact valid item previous
  · simp only [List.mem_singleton] at added
    simpa only [added] using nextValid

end Auths.ScopeConstructor
