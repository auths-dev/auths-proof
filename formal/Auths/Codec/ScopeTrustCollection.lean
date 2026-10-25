import Auths.Codec.ScopeTrustSafety
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.ScopeConstructor
open AuthsScopeCodec
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

theorem failed_trust_loop (decoder : cbor.Decoder) (limits : auths_model.VerifierLimits)
    (length : Std.Usize) (rules : alloc.vec.Vec auths_model.StatusTrustRule)
    (position : Std.Usize) (error : error.CodecError) :
    decode.status_trust_loop decoder limits length rules position (some error) =
      ok (decoder.input, decoder.position, rules, some error) := by
  rw [decode.status_trust_loop.eq_def]
  by_cases guard : position < length <;> simp [guard, core.option.Option.is_none]

/-- Every successful finite collection loop retains valid accumulated scopes;
    errors cannot turn a partially decoded collection into successful output. -/
theorem trust_loop_valid (remaining : Nat) (decoder : cbor.Decoder)
    (limits : auths_model.VerifierLimits) (length position : Std.Usize)
    (rules output : alloc.vec.Vec auths_model.StatusTrustRule)
    (input : Slice Std.U8) (cursor : Std.Usize)
    (measure : length.val - position.val = remaining) (valid : trustValid rules.val)
    (returned : decode.status_trust_loop decoder limits length rules position none =
      ok (input, cursor, output, none)) : trustValid output.val := by
  induction remaining using Nat.strong_induction_on generalizing decoder position rules with
  | h remaining ih =>
    rw [decode.status_trust_loop.eq_def] at returned
    by_cases guard : position < length
    · simp only [guard, ↓reduceIte, core.option.Option.is_none, Option.isNone] at returned
      have fits : position.val + 1 ≤ Usize.max := by
        have bound : length.val ≤ Usize.max := by scalar_tac
        have before : position.val < length.val := by simpa only [UScalar.lt_equiv] using guard
        omega
      obtain ⟨next, addition, nextValue⟩ := spec_imp_exists
        (Usize.add_spec (x := position) (y := 1#usize) (by simpa using fits))
      have decreases : length.val - next.val < remaining := by
        have before : position.val < length.val := by simpa only [UScalar.lt_equiv] using guard
        simp only [UScalar.ofNatCore_val_eq] at nextValue
        omega
      cases parsed : decode.status_trust_rule decoder limits with
      | fail error => simp [parsed, bind_tc_fail] at returned
      | div => simp [parsed, bind_tc_div] at returned
      | ok result =>
        rcases result with ⟨result, nextDecoder⟩
        cases result with
        | Err error =>
          simp [parsed, bind_tc_ok, addition, failed_trust_loop] at returned
        | Ok rule =>
          have ruleValid := accepted_rule_valid decoder limits rule nextDecoder parsed
          cases pushed : alloc.vec.Vec.push rules rule with
          | fail error => simp [parsed, pushed, bind_tc_ok, bind_tc_fail] at returned
          | div => simp [parsed, pushed, bind_tc_ok, bind_tc_div] at returned
          | ok accumulated =>
            apply ih (length.val - next.val) decreases nextDecoder next accumulated rfl
              (valid_push rules rule valid ruleValid accumulated pushed)
            simpa [parsed, pushed, addition] using returned
    · simp only [guard, ↓reduceIte, Result.ok.injEq, Prod.mk.injEq] at returned
      rcases returned with ⟨_, _, same, _⟩
      simpa only [← same] using valid

/-- Every successful actual status-trust decode returns rules whose listed
    scopes satisfy the actual status selector's ordering invariant. -/
theorem accepted_trust_valid (decoder : cbor.Decoder) (limits : auths_model.VerifierLimits)
    (rules : alloc.vec.Vec auths_model.StatusTrustRule) (next : cbor.Decoder)
    (accepted : decode.status_trust decoder limits = ok (.Ok rules, next)) : trustValid rules.val := by
  unfold decode.status_trust at accepted
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
  all_goals
    repeat' first
      | casesm* core.result.Result core.convert.Infallible _
      | casesm* core.convert.Infallible
      | simp_all (failIfUnchanged := true) only [Result.ok.injEq, reduceCtorEq]
  all_goals subst rules
  all_goals
    have emptyValid : ∀ (capacity : Std.Usize), trustValid (alloc.vec.Vec.with_capacity auths_model.StatusTrustRule capacity).val := by
      intro capacity rule included
      simp [alloc.vec.Vec.with_capacity] at included
    exact trust_loop_valid _ _ _ _ _ _ _ _ _ rfl (emptyValid _) (by assumption)

end Auths.ScopeConstructor
