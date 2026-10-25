import Auths.Product.NativeCompilerBindConsumption
import Auths.Product.NativeCompilerBodyAdmissionState
import Auths.Product.NativeCompilerPathRules
import Auths.Product.NativeCompilerBoundRules

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def RelativeFits (source : AuthsNativeRecipe.recipe.source.RelativeCeilingSource) : Prop :=
  TextFits source.argument ∧ TextFits source.json_pointer ∧
    (∀ pointer, source.subtract_pointer = some pointer → TextFits pointer) ∧
    (∀ binds, source.bind = some binds → ∀ bind ∈ binds.val, BindFits bind) ∧
    (∀ segment ∈ source.path.val, RulePathFits segment)

/-- Transparent abbreviation of the unchanged bind/path suffix appearing
twice in the actual relative_ceiling body. It invokes the real source
validator, path rule, try branch and bind consumer; it supplies no decision,
compiled plan or foreign Auths implementation. -/
def nativeRelativePathStage (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.RelativeCeilingSource) (argument : Str) :
    Result (core.result.Result Unit AuthsNativeRecipe.recipe.GatewayRecipeError ×
      AuthsNativeRecipe.recipe.validate.Rules) := do
  match source.bind with
  | none =>
      let (result, next) ← AuthsNativeRecipe.recipe.validate.Rules.path input
        (AuthsNativeRecipe.alloc.vec.Vec.deref source.path) .RelativeCeiling
      let branch ← core.result.Result.Insts.CoreOpsTry.branch result
      match branch with
      | .Continue _ => ok (.Ok (), next)
      | .Break residual =>
          let result ← core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
          ok (result, next)
  | some binds =>
      let valid ← AuthsNativeRecipe.recipe.validate.relative_binds_valid input.fields
        (AuthsNativeRecipe.alloc.vec.Vec.deref binds) argument
      if valid then
        let (result, next) ← AuthsNativeRecipe.recipe.validate.Rules.path input
          (AuthsNativeRecipe.alloc.vec.Vec.deref source.path) .RelativeCeiling
        let branch ← core.result.Result.Insts.CoreOpsTry.branch result
        match branch with
        | .Continue _ =>
            let final ← AuthsNativeRecipe.recipe.validate.Rules.consume_binds next
              (AuthsNativeRecipe.alloc.vec.Vec.deref binds)
            ok (.Ok (), final)
        | .Break residual =>
            let result ← core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
              Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
            ok (result, next)
      else ok (.Err .InvalidRelativeCeiling, input)

def relativePathStageModel (fields : RecipeRuleAdmission.Fields)
    (source : RecipeRuleAdmission.RelativeCeiling) (state : RecipeConsumption.State) : RecipeConsumption.Outcome :=
  if source.binds.any (fun binds => !decide (RecipeRuleAdmission.RelativeBindsAdmitted fields source.argument binds)) then
    RecipeRuleAdmission.refused .invalidRelativeCeiling state
  else RecipeRuleAdmission.andThen (RecipeRuleAdmission.path fields .relativeCeiling source.path state)
    (fun next => RecipeRuleAdmission.accepted (RecipeRuleAdmission.consumeBinds (source.binds.getD []) next))

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 20000000
set_option maxRecDepth 4096

/-- The original schema count and field containment earn path insertion room;
oversized paths still refuse without a machine-room premise. -/
@[step] theorem native_path_on_rule_domain (input : AuthsNativeRecipe.recipe.validate.Rules)
    (path : Slice NativePathSource) (role : AuthsNativeRecipe.recipe.validate.PathRole)
    (fits : ∀ segment ∈ path.val, RulePathFits segment) (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.path input path role ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.path (nativeRuleMapMeaning input.fields)
        (rulePathRole role) (path.val.map ruleSegment) (consumptionState input.consumed)) actual ∧
      RuleStateDomain actual.2 ∧ actual.2.consumed.body = input.consumed.body ∧
      actual.2.consumed.binds = input.consumed.binds ⦄ := by
  obtain ⟨allBound, bodyBound, bindBound⟩ := rule_state_storage input domain
  apply spec_mono (native_path_rules_exact input path role fits domain.fieldNames domain.ordered
    (by intro pathBound; scalar_tac))
  rintro actual ⟨meaning, growth, body, binds⟩
  have known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields) (consumptionState actual.2.consumed) := by
    rw [meaning.2.1]
    exact RecipeRuleAdmission.path_well_formed _ _ _ _ domain.known
  exact ⟨meaning, rule_state_transfer input actual.2 domain meaning.2.2.1 meaning.2.2.2 known, body, binds⟩

@[step] theorem native_relative_basis_points_exact (value : Std.U64) :
    (do
      let range ← core.ops.range.RangeInclusive.new 1#u64 AuthsNativeRecipe.recipe.validate.MAX_BASIS_POINTS
      AuthsNativeRecipe.core.ops.range.RangeInclusive.contains core.cmp.PartialOrdU64
        core.cmp.PartialOrdU64 core.cmp.PartialOrdU64 range value) ⦃ actual =>
      actual = decide (1 ≤ value.val ∧ value.val ≤ 10000) ⦄ := by
  simp [AuthsNativeRecipe.recipe.validate.MAX_BASIS_POINTS, core.ops.range.RangeInclusive.new,
    AuthsNativeRecipe.core.ops.range.RangeInclusive.contains, UScalar.le_equiv, spec_ok]

private theorem native_relative_path_without_binds (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.RelativeCeilingSource) (domain : RuleStateDomain input)
    (pathFits : ∀ segment ∈ source.path.val, RulePathFits segment) :
    (do
      let (result, next) ← AuthsNativeRecipe.recipe.validate.Rules.path input
        (AuthsNativeRecipe.alloc.vec.Vec.deref source.path) .RelativeCeiling
      let branch ← core.result.Result.Insts.CoreOpsTry.branch result
      match branch with
      | .Continue _ => ok (.Ok (), next)
      | .Break residual =>
          let result ← core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            Unit (core.convert.FromSame AuthsNativeRecipe.recipe.GatewayRecipeError) residual
          ok (result, next)) ⦃ actual =>
      BodyMeaning input (RecipeRuleAdmission.path (nativeRuleMapMeaning input.fields) .relativeCeiling
        (source.path.val.map ruleSegment) (consumptionState input.consumed)) actual ∧
      actual.2.consumed.body = input.consumed.body ⦄ := by
  step with native_path_on_rule_domain input (AuthsNativeRecipe.alloc.vec.Vec.deref source.path)
    .RelativeCeiling pathFits domain as ⟨walked, meaning, nextDomain, sameBody, sameBinds⟩
  cases result : walked.1 <;>
    simp only [result, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok]
  all_goals simpa [BodyMeaning, rulePathRole, result] using
    And.intro (And.intro meaning (And.intro nextDomain sameBinds)) sameBody

/-- Complete bind/path source suffix. Bind mutations occur only after every
bind is admitted and the full path succeeds. A failed path retains its actual
consumed prefix and never adds binding names. -/
@[step] theorem native_relative_path_stage_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.RelativeCeilingSource) (fits : RelativeFits source)
    (domain : RuleStateDomain input) :
    nativeRelativePathStage input source (nativeTextView source.argument fits.1) ⦃ actual =>
      ClaimMeaning input (relativePathStageModel (nativeRuleMapMeaning input.fields)
        (ruleRelativeCeiling source) (consumptionState input.consumed)) actual ∧
      RuleStateDomain actual.2 ∧ actual.2.consumed.body = input.consumed.body ⦄ := by
  unfold nativeRelativePathStage
  cases bindsAt : source.bind with
  | none =>
      apply spec_mono (native_relative_path_without_binds input source domain fits.2.2.2.2)
      rintro actual ⟨meaning, body⟩
      exact ⟨by simpa [relativePathStageModel, ruleRelativeCeiling, bindsAt,
        RecipeRuleAdmission.consumeBinds, RecipeRuleAdmission.and_then_identity] using meaning.1,
        meaning.2.1, body⟩
  | some binds =>
      step with native_relative_binds_exact input.fields (AuthsNativeRecipe.alloc.vec.Vec.deref binds)
        source.argument fits.1 (fits.2.2.2.1 binds bindsAt) domain.fieldNames as ⟨valid, validity⟩
      cases valid with
      | false =>
          simp [relativePathStageModel, ruleRelativeCeiling, bindsAt, ← validity,
            ClaimMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
      | true =>
          have admitted : RecipeRuleAdmission.RelativeBindsAdmitted (nativeRuleMapMeaning input.fields)
              source.argument (binds.val.map ruleBind) := by simpa using validity.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_path_on_rule_domain input (AuthsNativeRecipe.alloc.vec.Vec.deref source.path)
            .RelativeCeiling fits.2.2.2.2 domain as ⟨walked, pathMeaning, nextDomain, sameBody, sameBinds⟩
          let pathModel := RecipeRuleAdmission.path (nativeRuleMapMeaning input.fields) .relativeCeiling
            (source.path.val.map ruleSegment) (consumptionState input.consumed)
          have sameFields : walked.2.fields = input.fields := pathMeaning.2.2.1
          have sameState : consumptionState walked.2.consumed = pathModel.2 := pathMeaning.2.1
          cases verdict : pathModel.1 with
          | error error =>
              have refused : walked.1 = .Err (consumptionError error) := by
                simpa [pathModel, rulePathRole, verdict, consumptionVerdict] using pathMeaning.1
              simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                core.convert.FromSame, core.convert.FromSame.from, relativePathStageModel,
                ruleRelativeCeiling, bindsAt, admitted, RecipeRuleAdmission.andThen, ← pathModel,
                verdict, ClaimMeaning, consumptionVerdict, sameState, sameFields, nextDomain, nextDomain.ordered, sameBody]
          | ok unit =>
              cases unit
              have accepted : walked.1 = .Ok () := by
                simpa [pathModel, rulePathRole, verdict, consumptionVerdict] using pathMeaning.1
              simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              have known : ∀ bind ∈ binds.val, RecipeConsumption.fieldTest RecipeConsumption.formSchema
                  (nativeRuleMapMeaning walked.2.fields) bind.field = true := by
                intro bind present
                rw [sameFields]
                exact (admitted.2.2 (ruleBind bind) (List.mem_map.mpr ⟨bind, present, rfl⟩)).2.1
              step with native_consume_binds_exact walked.2 (AuthsNativeRecipe.alloc.vec.Vec.deref binds)
                nextDomain (fun bind present => (fits.2.2.2.1 binds bindsAt bind present).2) known
                as ⟨final, finalFields, finalState, finalDomain, finalBody⟩
              refine ⟨⟨?_, ?_, finalFields.trans sameFields, finalDomain.ordered⟩, finalDomain, finalBody.trans sameBody⟩
              · simp [relativePathStageModel, ruleRelativeCeiling, bindsAt, admitted,
                  RecipeRuleAdmission.andThen, ← pathModel, verdict, RecipeRuleAdmission.accepted, consumptionVerdict]
              · simpa [relativePathStageModel, ruleRelativeCeiling, bindsAt, admitted,
                  RecipeRuleAdmission.andThen, ← pathModel, verdict, RecipeRuleAdmission.accepted, sameState] using finalState

/-- Complete original relative-ceiling admission. Every success and refusal
is derived through the actual integer-body, ratio, response, subtraction,
bind and path checks. In particular, checking a ratio never changes an
unrendered integer into a body field or bypasses the shared original ledger. -/
@[step] theorem native_relative_ceiling_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.RelativeCeilingSource) (fits : RelativeFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.relative_ceiling input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.relativeCeiling (nativeRuleMapMeaning input.fields)
        (ruleRelativeCeiling source) (consumptionState input.consumed)) actual ∧
      RuleStateDomain actual.2 ∧ actual.2.consumed.body = input.consumed.body ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.relative_ceiling
  step with native_deref_view_exact source.argument fits.1 as ⟨argument, argumentView⟩
  subst argument
  step with native_integer_body_field_exact input source.argument fits.1 domain.fieldNames
    (rule_state_names_fit input domain).2.1 as ⟨integer, integerMeaning⟩
  cases integer with
  | false =>
      simp [RecipeRuleAdmission.relativeCeiling, ruleRelativeCeiling, ← integerMeaning,
        ClaimMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_relative_basis_points_exact source.basis_points as ⟨ratio, ratioMeaning⟩
      cases ratio with
      | false =>
          simp [RecipeRuleAdmission.relativeCeiling, ruleRelativeCeiling, ← ratioMeaning,
            ClaimMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
      | true =>
          have ratioValid : 1 ≤ source.basis_points.val ∧ source.basis_points.val ≤ 10000 := by simpa using ratioMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_read_bound_exact source.maximum_response_bytes as ⟨readBound, readMeaning⟩
          cases readBound with
          | false =>
              simp [RecipeRuleAdmission.relativeCeiling, ruleRelativeCeiling, ← readMeaning,
                ClaimMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
          | true =>
              have readValid : ReadBound source.maximum_response_bytes.val := by simpa using readMeaning.symm
              simp only [Bool.true_eq_true, ↓reduceIte]
              step with native_deref_view_exact source.json_pointer fits.2.1 as ⟨pointer, pointerView⟩
              subst pointer
              step with native_response_pointer_exact (nativeTextView source.json_pointer fits.2.1)
                as ⟨pointerValid, pointerMeaning⟩
              cases pointerValid with
              | false =>
                  have invalid : ¬ResponsePointer (textBytes source.json_pointer) := by
                    simpa [responsePointer, native_text_view_bytes] using pointerMeaning.symm
                  simp [RecipeRuleAdmission.relativeCeiling, ruleRelativeCeiling, invalid,
                    ClaimMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
              | true =>
                  have pointerAdmitted : ResponsePointer (textBytes source.json_pointer) := by
                    simpa [responsePointer, native_text_view_bytes] using pointerMeaning.symm
                  have head : RecipeConsumption.integerBodyField (nativeRuleMapMeaning input.fields)
                      (consumptionState input.consumed) source.argument = true := integerMeaning.symm
                  have finish (subtractAllowed : (source.subtract_pointer.map textBytes).any
                        (fun value => !responsePointer value || decide (value = textBytes source.json_pointer)) = false) :
                      nativeRelativePathStage input source (nativeTextView source.argument fits.1) ⦃ actual =>
                        ClaimMeaning input (RecipeRuleAdmission.relativeCeiling (nativeRuleMapMeaning input.fields)
                          (ruleRelativeCeiling source) (consumptionState input.consumed)) actual ∧
                        RuleStateDomain actual.2 ∧ actual.2.consumed.body = input.consumed.body ⦄ := by
                    apply spec_mono (native_relative_path_stage_exact input source fits domain)
                    intro actual meaning
                    simpa [RecipeRuleAdmission.relativeCeiling, ruleRelativeCeiling, head, ratioValid,
                      readValid, pointerAdmitted, subtractAllowed, relativePathStageModel] using meaning
                  simp only [Bool.true_eq_true, ↓reduceIte]
                  cases subtractAt : source.subtract_pointer with
                  | none =>
                      change nativeRelativePathStage input source (nativeTextView source.argument fits.1) ⦃ _ ⦄
                      exact finish (by simp [subtractAt])
                  | some subtract =>
                      have subtractFits := fits.2.2.1 subtract subtractAt
                      step with native_deref_view_exact subtract subtractFits as ⟨subtractView, subtractViewMeaning⟩
                      subst subtractView
                      step with native_response_pointer_exact (nativeTextView subtract subtractFits)
                        as ⟨valid, validity⟩
                      cases valid with
                      | false =>
                          have invalid : ¬ResponsePointer (textBytes subtract) := by
                            simpa [responsePointer, native_text_view_bytes] using validity.symm
                          simp [RecipeRuleAdmission.relativeCeiling, ruleRelativeCeiling, head, ratioValid,
                            readValid, pointerAdmitted, subtractAt, responsePointer, invalid,
                            ClaimMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
                      | true =>
                          have subtractValid : ResponsePointer (textBytes subtract) := by
                            simpa [responsePointer, native_text_view_bytes] using validity.symm
                          simp only [Bool.true_eq_true, ↓reduceIte]
                          step as ⟨same, sameMeaning⟩
                          cases same with
                          | true =>
                              have equal : subtract = source.json_pointer := by simpa using sameMeaning.symm
                              simp [RecipeRuleAdmission.relativeCeiling, ruleRelativeCeiling, head, ratioValid,
                                readValid, pointerAdmitted, subtractAt, equal,
                                ClaimMeaning, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
                          | false =>
                              have different : subtract ≠ source.json_pointer := by simpa using sameMeaning.symm
                              change nativeRelativePathStage input source (nativeTextView source.argument fits.1) ⦃ _ ⦄
                              exact finish (by simp [subtractAt, responsePointer, subtractValid, text_bytes_injective.eq_iff, different])

theorem native_relative_ceiling_storage (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.RelativeCeilingSource) (fits : RelativeFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.relative_ceiling input source ⦃ actual =>
      actual.2.fields = input.fields ∧ actual.2.consumed.body = input.consumed.body ∧
      actual.2.consumed.all.elements.val.length ≤ 32 ∧ actual.2.consumed.body.elements.val.length ≤ 32 ∧
      actual.2.consumed.binds.elements.val.length ≤ 32 ⦄ := by
  apply spec_mono (native_relative_ceiling_exact input source fits domain)
  rintro actual ⟨meaning, nextDomain, body⟩
  exact ⟨meaning.2.2.1, body, rule_state_storage actual.2 nextDomain⟩

end Auths.Product.NativeCompiler.Refinement
