import Auths.Product.NativeCompilerConsumption
import Auths.Product.NativeCompilerRuleSource
import Auths.Product.NativeCompilerHeaderGrammar
import Auths.Product.RecipeRuleProperties

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def ScopeFieldFits (scope : Option AuthsNativeRecipe.recipe.source.AccountScopeSource) : Prop :=
  ∀ source, scope = some source → TextFits source.field

def BoundFieldsFit (source : AuthsNativeRecipe.recipe.source.BoundsSource) : Prop :=
  ∀ sum, source.sum = some sum → TextFits sum.argument ∧
    ∀ partition, sum.partition = some partition → TextFits partition

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 14000000
set_option maxRecDepth 4096

@[step] theorem native_string_field_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (name : String) (nameFits : TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.Rules.string_field input (nativeTextView name nameFits) ⦃ actual =>
      actual = RecipeConsumption.fieldTest RecipeConsumption.pathSchema (nativeRuleMapMeaning input.fields) name ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.string_field
  step with native_rule_map_lookup input.fields name nameFits fieldFits as ⟨selected, meaning⟩
  cases selected with
  | none => simp [RecipeConsumption.fieldTest, ← meaning]
  | some schema =>
      cases schema <;> simp [RecipeConsumption.fieldTest, ← meaning,
        RecipeConsumption.pathSchema, nativeScalarMeaning]

@[step] theorem native_integer_body_field_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (name : String) (nameFits : TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (bodyFits : ∀ field ∈ input.consumed.body.elements.val, TextFits field) :
    AuthsNativeRecipe.recipe.validate.Rules.integer_body_field input (nativeTextView name nameFits) ⦃ actual =>
      actual = RecipeConsumption.integerBodyField (nativeRuleMapMeaning input.fields)
        (consumptionState input.consumed) name ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.integer_body_field
  step with native_integer_field_exact input name nameFits fieldFits as ⟨integer, integerMeaning⟩
  cases integer with
  | false => simp [RecipeConsumption.integerBodyField, ← integerMeaning]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      apply spec_mono (native_name_set_contains_borrowed input.consumed.body name nameFits bodyFits)
      intro actual meaning
      simpa [RecipeConsumption.integerBodyField, ← integerMeaning, consumptionState] using meaning

@[step] theorem native_account_scope_header_exact (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.header_compiler.account_scope_header_name name ⦃ actual =>
      actual = decide (schemaSliceBytes name = HeaderCompiler.stripeAccountName) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.header_compiler.account_scope_header_name
  step with native_header_index_exact name as ⟨index, meaning⟩
  cases index with
  | none =>
      have absent : schemaSliceBytes name ≠ HeaderCompiler.stripeAccountName := by
        intro same
        have required := HeaderCompiler.header_index_two_iff.mpr same
        simp [required] at meaning
      simp [absent]
  | some index =>
      by_cases selected : index.val = 2
      · have nativeSelected : index = 2#usize := by scalar_tac
        have named : schemaSliceBytes name = HeaderCompiler.stripeAccountName :=
          HeaderCompiler.header_index_two_iff.mp (by simpa [selected] using meaning.symm)
        simp [nativeSelected, named]
      · have nativeOther : index ≠ 2#usize := by scalar_tac
        have notNamed : schemaSliceBytes name ≠ HeaderCompiler.stripeAccountName := by
          intro named
          have required := HeaderCompiler.header_index_two_iff.mpr named
          simp [required] at meaning
          omega
        simp [nativeOther, notNamed]

@[step] theorem native_account_scope_uses_exact
    (scope : Option AuthsNativeRecipe.recipe.source.AccountScopeSource)
    (name : String) (nameFits : TextFits name) (scopeFits : ScopeFieldFits scope) :
    AuthsNativeRecipe.recipe.validate.account_scope_uses_field scope (nativeTextView name nameFits) ⦃ actual =>
      actual = decide (scope.map (·.field) = some name) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.account_scope_uses_field
  cases scope with
  | none => simp
  | some scope =>
      step with borrow_text_exact scope.field (scopeFits scope rfl) as ⟨field, fieldMeaning⟩
      simp only [AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
      apply spec_mono (native_schema_byte_equality field (nativeTextView name nameFits))
      intro actual meaning
      simpa [schemaSliceBytes, fieldMeaning, native_text_view_bytes,
        text_bytes_injective.eq_iff] using meaning

@[step] theorem native_partition_bound_exact (input : AuthsNativeRecipe.recipe.validate.Consumption)
    (scope : Option AuthsNativeRecipe.recipe.source.AccountScopeSource)
    (name : String) (nameFits : TextFits name) (scopeFits : ScopeFieldFits scope)
    (bodyFits : ∀ field ∈ input.body.elements.val, TextFits field)
    (bindFits : ∀ field ∈ input.binds.elements.val, TextFits field) :
    AuthsNativeRecipe.recipe.validate.partition_bound input scope (nativeTextView name nameFits) ⦃ actual =>
      actual = RecipeConsumption.partitionBound (consumptionState input) (scope.map (·.field)) name ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.partition_bound
  step with native_name_set_contains_borrowed input.body name nameFits bodyFits as ⟨body, bodyMeaning⟩
  cases body with
  | true => simp [RecipeConsumption.partitionBound, consumptionState, ← bodyMeaning]
  | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      step with native_account_scope_uses_exact scope name nameFits scopeFits as ⟨account, accountMeaning⟩
      cases account with
      | true =>
          cases scope <;> simp_all [RecipeConsumption.partitionBound, consumptionState]
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          apply spec_mono (native_name_set_contains_borrowed input.binds name nameFits bindFits)
          intro actual meaning
          cases scope <;> simpa [RecipeConsumption.partitionBound, consumptionState,
            ← bodyMeaning, ← accountMeaning] using meaning

/-- Complete account-scope admission, including unchanged body/bind carriers.
An accepted field is fresh, original, string-like and carried by the exact
registered header. Scope presence alone grants none of these properties. -/
@[step] theorem native_account_scope_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.AccountScopeSource)
    (headerFits : TextFits source.header) (nameFits : TextFits source.field)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (room : input.consumed.all.elements.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.account_scope input source ⦃ actual =>
      ClaimMeaning input
        (RecipeRuleAdmission.accountScope (nativeRuleMapMeaning input.fields)
          (ruleScope source) (consumptionState input.consumed)) actual ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.account_scope
  step with borrow_text_exact source.header headerFits as ⟨header, originalHeader⟩
  step with native_account_scope_header_exact header as ⟨registered, registeredMeaning⟩
  have named : registered = decide (textBytes source.header = HeaderCompiler.stripeAccountName) := by
    simpa [schemaSliceBytes, originalHeader] using registeredMeaning
  cases registered with
  | false =>
      simp [ClaimMeaning, RecipeRuleAdmission.accountScope, ruleScope, ← named,
        RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step with native_deref_view_exact source.field nameFits as ⟨name, sameView⟩
      subst name
      step with native_string_field_exact input source.field nameFits fieldFits as ⟨string, stringMeaning⟩
      cases string with
      | false =>
          simp [ClaimMeaning, RecipeRuleAdmission.accountScope, ruleScope, ← stringMeaning,
            RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          step with native_binding_field_name_exact source.field nameFits as ⟨binding, bindingMeaning⟩
          cases binding with
          | true =>
              simp [ClaimMeaning, RecipeRuleAdmission.accountScope, ruleScope, ← bindingMeaning,
                RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
          | false =>
              simp only [Bool.false_eq_true, ↓reduceIte]
              step with native_name_set_contains_owned input.consumed.all source.field as ⟨used, usedMeaning⟩
              cases used with
              | true =>
                  simp [ClaimMeaning, RecipeRuleAdmission.accountScope, ruleScope,
                    RecipeRuleAdmission.refused, consumptionVerdict, consumptionError,
                    consumptionState, ← usedMeaning, ordered]
              | false =>
                  simp only [Bool.false_eq_true, ↓reduceIte]
                  step with native_consume_exact input source.field nameFits ordered room
                    as ⟨next, nextMeaning, sameFields, nextOrdered, growth, sameBody, sameBinds⟩
                  have headerAllowed : textBytes source.header = HeaderCompiler.stripeAccountName := by simpa using named.symm
                  have fresh : source.field ∉ (consumptionState input.consumed).all := by
                    simpa [consumptionState] using usedMeaning.symm
                  simp [ClaimMeaning, RecipeRuleAdmission.accountScope, RecipeRuleAdmission.accepted,
                    ruleScope, headerAllowed, ← stringMeaning, ← bindingMeaning, fresh,
                    consumptionVerdict, nextMeaning, sameFields, nextOrdered, sameBody, sameBinds]

@[step] theorem native_bounds_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.BoundsSource)
    (scope : Option AuthsNativeRecipe.recipe.source.AccountScopeSource)
    (sourceFits : BoundFieldsFit source) (scopeFits : ScopeFieldFits scope)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (bodyFits : ∀ field ∈ input.consumed.body.elements.val, TextFits field)
    (bindFits : ∀ field ∈ input.consumed.binds.elements.val, TextFits field) :
    AuthsNativeRecipe.recipe.validate.Rules.bounds input source scope ⦃ actual =>
      actual = consumptionVerdict
        (RecipeRuleAdmission.bounds (nativeRuleMapMeaning input.fields) (ruleBounds source)
          (scope.map ruleScope) (consumptionState input.consumed)).1 ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.bounds
  cases sumAt : source.sum with
  | none =>
      simp [core.option.Option.as_ref, core.option.Option.ok_or, sumAt,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, ruleBounds,
        RecipeRuleAdmission.bounds, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError]
  | some sum =>
      simp only [core.option.Option.as_ref, sumAt, core.option.Option.ok_or,
        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      have argumentFits := (sourceFits sum sumAt).1
      step with native_deref_view_exact sum.argument argumentFits as ⟨argument, argumentView⟩
      subst argument
      step with native_integer_body_field_exact input sum.argument argumentFits fieldFits bodyFits
        as ⟨integer, integerMeaning⟩
      cases integer with
      | false =>
          simp [RecipeRuleAdmission.bounds, ruleBounds, sumAt, ← integerMeaning,
            RecipeRuleAdmission.refused, consumptionVerdict, consumptionError]
      | true =>
          simp only [Bool.true_eq_true, ↓reduceIte]
          cases partitionAt : sum.partition with
          | none =>
              simp [RecipeRuleAdmission.bounds, ruleBounds, sumAt, partitionAt, ← integerMeaning,
                RecipeRuleAdmission.accepted, consumptionVerdict]
          | some partition =>
              simp only [partitionAt]
              have partitionFits := (sourceFits sum sumAt).2 partition partitionAt
              step as ⟨same, sameMeaning⟩
              cases same with
              | true =>
                  simp_all [RecipeRuleAdmission.bounds, ruleBounds, RecipeRuleAdmission.refused,
                    consumptionVerdict, consumptionError]
              | false =>
                  simp only [Bool.false_eq_true, ↓reduceIte]
                  step with native_deref_view_exact partition partitionFits as ⟨name, nameView⟩
                  subst name
                  step with native_string_field_exact input partition partitionFits fieldFits as ⟨string, stringMeaning⟩
                  cases string with
                  | false =>
                      simp [RecipeRuleAdmission.bounds, ruleBounds, sumAt, partitionAt,
                        ← integerMeaning, ← stringMeaning, RecipeRuleAdmission.refused,
                        consumptionVerdict, consumptionError]
                  | true =>
                      simp only [Bool.true_eq_true, ↓reduceIte]
                      step with native_binding_field_name_exact partition partitionFits as ⟨binding, bindingMeaning⟩
                      cases binding with
                      | true =>
                          simp [RecipeRuleAdmission.bounds, ruleBounds, sumAt, partitionAt,
                            ← integerMeaning, ← bindingMeaning, RecipeRuleAdmission.refused,
                            consumptionVerdict, consumptionError]
                      | false =>
                          simp only [Bool.false_eq_true, ↓reduceIte]
                          step with native_partition_bound_exact input.consumed scope partition partitionFits
                            scopeFits bodyFits bindFits as ⟨bound, boundMeaning⟩
                          cases bound <;>
                            simp_all [RecipeRuleAdmission.bounds, ruleBounds, ruleScope,
                              RecipeRuleAdmission.refused, RecipeRuleAdmission.accepted,
                              consumptionVerdict, consumptionError, Option.map_map, Function.comp_def]

/-- The actual fifth rule-group caller, including optional scope, optional
sum bounds, first-error order and the ledger returned after a later refusal.
No earlier-group success is assumed. Those groups must earn this group's
representability/ordering/room domain when it is composed into the constructor.
The body argument is irrelevant to this group and grants no body admission. -/
@[step] theorem native_bound_group_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : NativeRecipeSource) (body : TemplateAst.Body)
    (scopeFits : ∀ scope, source.account_scope = some scope → TextFits scope.header ∧ TextFits scope.field)
    (boundFits : ∀ bounds, source.bounds = some bounds → BoundFieldsFit bounds)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (bodyFits : ∀ field ∈ input.consumed.body.elements.val, TextFits field)
    (bindFits : ∀ field ∈ input.consumed.binds.elements.val, TextFits field)
    (ordered : ConsumptionOrdered input.consumed)
    (room : input.consumed.all.elements.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.validate.validate_bound_rules input source ⦃ actual =>
      ClaimMeaning input
        (RecipeRuleAdmission.boundRules (nativeRuleMapMeaning input.fields)
          (ruleSource source body) (consumptionState input.consumed)) actual ∧
      actual.2.consumed.body = input.consumed.body ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_bound_rules
  cases scopeAt : source.account_scope with
  | none =>
      simp only [scopeAt]
      cases boundsAt : source.bounds with
      | none =>
          simp [boundsAt, ClaimMeaning, RecipeRuleAdmission.boundRules, ruleSource, scopeAt,
            RecipeRuleAdmission.accepted, RecipeRuleAdmission.andThen, consumptionVerdict, ordered]
      | some bounds =>
          simp only [boundsAt, core.option.Option.as_ref, scopeAt, bind_tc_ok]
          step with native_bounds_exact input bounds none (boundFits bounds boundsAt)
            (by intro scope impossible; contradiction) fieldFits bodyFits bindFits as ⟨result, meaning⟩
          have sameState := RecipeRuleAdmission.bounds_preserve_state
            (nativeRuleMapMeaning input.fields) (ruleBounds bounds) none (consumptionState input.consumed)
          cases result <;>
            simp_all [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame, core.convert.FromSame.from,
              ClaimMeaning, RecipeRuleAdmission.boundRules, ruleSource, RecipeRuleAdmission.accepted,
              RecipeRuleAdmission.andThen]
  | some scope =>
      simp only [scopeAt]
      step with native_account_scope_exact input scope (scopeFits scope scopeAt).1
        (scopeFits scope scopeAt).2 fieldFits ordered room
        as ⟨scoped, scopedMeaning, sameBody, sameBinds⟩
      let scopedModel := RecipeRuleAdmission.accountScope (nativeRuleMapMeaning input.fields)
        (ruleScope scope) (consumptionState input.consumed)
      have sameFields : scoped.2.fields = input.fields := scopedMeaning.2.2.1
      have sameState : consumptionState scoped.2.consumed = scopedModel.2 := scopedMeaning.2.1
      have nextOrdered : ConsumptionOrdered scoped.2.consumed := scopedMeaning.2.2.2
      have nextFieldFits : ∀ entry ∈ scoped.2.fields.entries.val, TextFits entry.1 := by
        simpa only [sameFields] using fieldFits
      have nextBodyFits : ∀ field ∈ scoped.2.consumed.body.elements.val, TextFits field := by
        simpa only [sameBody] using bodyFits
      have nextBindFits : ∀ field ∈ scoped.2.consumed.binds.elements.val, TextFits field := by
        simpa only [sameBinds] using bindFits
      cases verdict : scopedModel.1 with
      | error error =>
          have refused : scoped.1 = .Err (consumptionError error) := by
            simpa only [verdict, consumptionVerdict] using scopedMeaning.1
          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from,
            ClaimMeaning, RecipeRuleAdmission.boundRules, ruleSource, scopeAt,
            RecipeRuleAdmission.andThen, ← scopedModel, verdict, sameState,
            sameFields, nextOrdered, sameBody, sameBinds, consumptionVerdict]
      | ok unit =>
          cases unit
          have accepted : scoped.1 = .Ok () := by
            simpa only [verdict, consumptionVerdict] using scopedMeaning.1
          simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          cases boundsAt : source.bounds with
          | none =>
              simp [boundsAt, ClaimMeaning, RecipeRuleAdmission.boundRules, ruleSource,
                scopeAt, RecipeRuleAdmission.andThen, RecipeRuleAdmission.accepted,
                ← scopedModel, verdict, sameState, sameFields, nextOrdered,
                sameBody, sameBinds, consumptionVerdict]
          | some bounds =>
              simp only [boundsAt, core.option.Option.as_ref, scopeAt, bind_tc_ok]
              have borrowedScope : ScopeFieldFits (some scope) := by
                intro selected same
                cases Option.some.inj same
                exact (scopeFits scope scopeAt).2
              step with native_bounds_exact scoped.2 bounds (some scope) (boundFits bounds boundsAt)
                borrowedScope nextFieldFits nextBodyFits nextBindFits as ⟨result, meaning⟩
              have statePreserved := RecipeRuleAdmission.bounds_preserve_state
                (nativeRuleMapMeaning input.fields) (ruleBounds bounds) (some (ruleScope scope)) scopedModel.2
              cases result <;>
                simp_all [core.result.Result.Insts.CoreOpsTry.branch,
                  core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                  core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
                  RecipeRuleAdmission.boundRules, ruleSource, RecipeRuleAdmission.andThen,
                  RecipeRuleAdmission.accepted]

end Auths.Product.NativeCompiler.Refinement
