import Auths.Product.NativeCompilerReadAdmission
import Auths.Product.NativeCompilerPreconditions
import Auths.Product.NativeCompilerRelativeAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def ObservationAdmissionFits (source : AuthsNativeRecipe.recipe.source.ObservationSource) : Prop :=
  (∀ segment ∈ source.path.val, RulePathFits segment) ∧
    TextFits source.json_pointer ∧ TextFits source.expected_field

def PreEntryAdmissionFits (source : AuthsNativeRecipe.recipe.source.PreEntrySource) : Prop :=
  (∀ segment ∈ source.path.val, RulePathFits segment) ∧ ∀ pointer ∈ source.pointers.val, TextFits pointer

def PreconditionsAdmissionFits (source : AuthsNativeRecipe.recipe.source.PreconditionSource) : Prop :=
  (∀ subject, source.read_back_subject = some subject → TextFits subject) ∧
    ∀ name ∈ source.verified.val, TextFits name

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 22000000
set_option maxRecDepth 4096

@[step] theorem native_observation_on_rule_domain (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.ObservationSource) (fits : ObservationAdmissionFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.observation input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.observation (nativeRuleMapMeaning input.fields)
        (ruleObservation source) (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  obtain ⟨allBound, bodyBound, bindBound⟩ := rule_state_storage input domain
  apply spec_mono (native_observation_admission_exact input source fits.1 fits.2.1 fits.2.2
    domain.fieldNames domain.ordered (by intro pathBound; scalar_tac))
  rintro actual ⟨meaning, growth, body, binds⟩
  have known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields) (consumptionState actual.2.consumed) := by
    rw [meaning.2.1]
    exact RecipeRuleAdmission.observation_well_formed _ _ _ domain.known
  exact ⟨meaning, rule_state_transfer input actual.2 domain meaning.2.2.1 meaning.2.2.2 known, body, binds⟩

@[step] theorem native_pre_entry_on_rule_domain (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.PreEntrySource) (fits : PreEntryAdmissionFits source)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.pre_entry input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.preEntry (nativeRuleMapMeaning input.fields)
        (rulePreEntry source) (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  obtain ⟨allBound, bodyBound, bindBound⟩ := rule_state_storage input domain
  apply spec_mono (native_pre_entry_admission_exact input source fits.1 fits.2
    domain.fieldNames domain.ordered (by intro pathBound; scalar_tac))
  rintro actual ⟨meaning, growth, body, binds⟩
  have known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields) (consumptionState actual.2.consumed) := by
    rw [meaning.2.1]
    exact RecipeRuleAdmission.pre_entry_well_formed _ _ _ domain.known
  exact ⟨meaning, rule_state_transfer input actual.2 domain meaning.2.2.1 meaning.2.2.2 known, body, binds⟩

/-- Oversized verified lists refuse before any insertion. Only the accepted
1..8-list branch needs room, which the original 32-field domain earns. This
wrapper therefore covers arbitrary represented source list lengths. -/
@[step] theorem native_preconditions_on_rule_domain (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.PreconditionSource)
    (read : Option AuthsNativeRecipe.recipe.source.ObservationSource)
    (fits : PreconditionsAdmissionFits source) (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.preconditions input source read ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.preconditions (nativeRuleMapMeaning input.fields)
        (rulePreconditions source) (read.map ruleObservation) (consumptionState input.consumed)) actual ∧
      RuleStateDomain actual.2 ⦄ := by
  by_cases oversized : 8 < source.verified.val.length
  · have nativeOversized : AuthsNativeRecipe.alloc.vec.Vec.len source.verified >
        AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS := by
      simp [AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS]; scalar_tac
    have nonempty : source.verified.val ≠ [] := by intro empty; simp [empty] at oversized
    unfold AuthsNativeRecipe.recipe.validate.Rules.preconditions
    cases subjectAt : source.read_back_subject <;>
      simp [subjectAt, core.option.Option.is_none, AuthsNativeRecipe.alloc.vec.Vec.is_empty,
        List.isEmpty_eq_false.mpr nonempty, nativeOversized, ClaimMeaning,
        RecipeRuleAdmission.preconditions, rulePreconditions, RecipeRuleAdmission.refused,
        oversized, consumptionVerdict, consumptionError, domain, domain.ordered]
  · obtain ⟨allBound, bodyBound, bindBound⟩ := rule_state_storage input domain
    apply spec_mono (native_preconditions_exact input source read fits.1 fits.2
      domain.fieldNames domain.ordered (by scalar_tac))
    intro actual meaning
    have known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields) (consumptionState actual.2.consumed) := by
      rw [meaning.2.1]
      exact RecipeRuleAdmission.preconditions_well_formed _ _ _ _ domain.known
    exact ⟨meaning, rule_state_transfer input actual.2 domain meaning.2.2.1 meaning.2.2.2 known⟩

@[step] theorem native_bound_group_on_rule_domain (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (model : TemplateAst.Body)
    (scopeFits : ∀ scope, source.account_scope = some scope → TextFits scope.header ∧ TextFits scope.field)
    (boundFits : ∀ bounds, source.bounds = some bounds → BoundFieldsFit bounds)
    (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.validate_bound_rules input source ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.boundRules (nativeRuleMapMeaning input.fields)
        (ruleSource source model) (consumptionState input.consumed)) actual ∧ RuleStateDomain actual.2 ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  obtain ⟨allBound, bodyBound, bindBound⟩ := rule_state_storage input domain
  have names := rule_state_names_fit input domain
  apply spec_mono (native_bound_group_exact input source model scopeFits boundFits domain.fieldNames
    names.2.1 names.2.2 domain.ordered (by scalar_tac))
  rintro actual ⟨meaning, body, binds⟩
  have known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields) (consumptionState actual.2.consumed) := by
    rw [meaning.2.1]
    exact RecipeRuleAdmission.bound_rules_well_formed _ _ _ domain.known
  exact ⟨meaning, rule_state_transfer input actual.2 domain meaning.2.2.1 meaning.2.2.2 known, body, binds⟩

end Auths.Product.NativeCompiler.Refinement
