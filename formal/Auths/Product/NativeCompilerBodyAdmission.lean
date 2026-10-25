import Auths.Product.NativeCompilerValueAdmission

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 20000000
set_option maxRecDepth 4096

@[step] theorem native_form_json_shape_exact (source : SourceAst) (model : TemplateAst.Value)
    (original : AstSourceMeaning source model) :
    AuthsNativeRecipe.recipe.validate.form_json_shape source ⦃ actual =>
      actual = RecipeRuleAdmission.formJsonShape model ⦄ := by
  cases original <;> simp [AuthsNativeRecipe.recipe.validate.form_json_shape, RecipeRuleAdmission.formJsonShape]
  rename_i values models related
  have sameCount := body_source_values_count related
  simp [sameCount, UScalar.eq_equiv]

private theorem native_form_echo_tag (source : SourceForm) (model : TemplateAst.FormValue)
    (original : FormSourceMeaning source model) :
    (match source with
    | .String _ | .Field _ | .Json _ => ok false
    | .Echo => ok true) ⦃ actual => actual = decide (model = .authorEcho) ⦄ := by
  cases original <;> rfl

private theorem native_form_admission_loop
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceForm)
    (input : AuthsNativeRecipe.recipe.validate.Rules) (nodes : Std.Usize)
    (models : List (List Nat × TemplateAst.FormValue))
    (paired : List.Forall₂ SourceFormMemberMeaning iterator.val models)
    (names : ∀ member ∈ iterator.val, TextFits member.1)
    (bounded : ∀ member ∈ iterator.val, FormBounds member.2) (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.body_loop iterator input nodes ⦃ actual =>
      BodyMeaning input (RecipeRuleAdmission.foldNodes (RecipeRuleAdmission.formMember (nativeRuleMapMeaning input.fields))
        models nodes.val (consumptionState input.consumed)).1 actual ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator input nodes models with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.body_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          rw [original] at paired
          cases paired
          simp [ended, BodyMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes,
            RecipeRuleAdmission.accepted, consumptionVerdict, domain, domain.ordered]
      | cons member rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some member ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [headAt]
          rw [original] at paired
          cases models with
          | nil => cases paired
          | cons model models =>
              cases paired with
              | cons head tail =>
                  rcases model with ⟨modelKey, modelValue⟩
                  have originalKey : modelKey = textBytes member.1 := head.1
                  have originalValue : FormSourceMeaning member.2 modelValue := head.2
                  have present : member ∈ iterator.val := by simp [original]
                  have nameFits := names member present
                  have valueBound := bounded member present
                  have smaller : next.2.val.length < count := by simp [original, tailAt] at *; omega
                  have nextNames : ∀ member ∈ next.2.val, TextFits member.1 := by
                    intro other belongs
                    exact names other (by simp only [original, List.mem_cons]; exact Or.inr (by simpa [tailAt] using belongs))
                  have nextBounds : ∀ member ∈ next.2.val, FormBounds member.2 := by
                    intro other belongs
                    exact bounded other (by simp only [original, List.mem_cons]; exact Or.inr (by simpa [tailAt] using belongs))
                  have recurse (before : AuthsNativeRecipe.recipe.validate.Rules) (count : Std.Usize)
                      (beforeDomain : RuleStateDomain before) :
                      AuthsNativeRecipe.recipe.validate.Rules.body_loop next.2 before count ⦃ actual =>
                        BodyMeaning before
                          (RecipeRuleAdmission.foldNodes (RecipeRuleAdmission.formMember (nativeRuleMapMeaning before.fields))
                            models count.val (consumptionState before.consumed)).1 actual ⦄ :=
                    ih _ smaller next.2 before count models (by simpa [tailAt] using tail)
                      nextNames nextBounds beforeDomain rfl
                  step with native_form_echo_tag member.2 modelValue originalValue as ⟨echo, echoMeaning⟩
                  cases echo with
                  | true =>
                      have authorEcho : modelValue = .authorEcho := by simpa using echoMeaning.symm
                      simp [BodyMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember,
                        authorEcho, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
                  | false =>
                      have notEcho : modelValue ≠ .authorEcho := by simpa using echoMeaning.symm
                      simp only [Bool.false_eq_true, ↓reduceIte]
                      step with native_deref_view_exact member.1 nameFits as ⟨key, keyView⟩
                      subst key
                      step with native_recipe_field_name_exact (nativeTextView member.1 nameFits) as ⟨valid, validity⟩
                      cases valid with
                      | false =>
                          simp [BodyMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember,
                            notEcho, originalKey, native_text_view_bytes, ← validity,
                            RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
                      | true =>
                          simp only [Bool.true_eq_true, ↓reduceIte]
                          cases originalValue with
                          | text text =>
                              cases valueBound with
                              | text text fits =>
                                  step with native_text_size_exact text fits as ⟨size, sizeMeaning⟩
                                  by_cases within : (textBytes text).length ≤ 1024
                                  · have nativeWithin : size <= AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES := by
                                      simp only [AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES]
                                      scalar_tac
                                    simp only [nativeWithin, ↓reduceIte]
                                    apply spec_mono (recurse input nodes domain)
                                    intro actual meaning
                                    simpa [RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember, originalKey,
                                      notEcho, native_text_view_bytes, ← validity, within,
                                      RecipeRuleAdmission.accepted] using meaning
                                  · have nativeLarge : ¬size <= AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES := by
                                      simp only [AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES]
                                      scalar_tac
                                    simp [nativeLarge, BodyMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes,
                                      RecipeRuleAdmission.formMember, originalKey, notEcho, native_text_view_bytes,
                                      ← validity, within, RecipeRuleAdmission.refused,
                                      consumptionVerdict, consumptionError, domain, domain.ordered]
                          | field name =>
                              cases valueBound with
                              | field name fits =>
                                  step with native_deref_view_exact name fits as ⟨nameView, nameViewMeaning⟩
                                  subst nameView
                                  step with native_form_field_exact input name fits domain.fieldNames as ⟨scalar, scalarMeaning⟩
                                  cases scalar with
                                  | false =>
                                      simp [BodyMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes,
                                        RecipeRuleAdmission.formMember, originalKey, notEcho,
                                        native_text_name_decode name fits, ← scalarMeaning,
                                        native_text_view_bytes, ← validity, RecipeRuleAdmission.refused,
                                        consumptionVerdict, consumptionError, domain, domain.ordered]
                                  | true =>
                                      simp only [Bool.true_eq_true, ↓reduceIte]
                                      step with native_body_field_ref_on_domain input name fits domain
                                        as ⟨visited, visitMeaning, visitDomain, visitBinds⟩
                                      let visitModel := RecipeRuleAdmission.fieldRef (nativeRuleMapMeaning input.fields)
                                        (textBytes name) (consumptionState input.consumed)
                                      have sameFields : visited.2.fields = input.fields := visitMeaning.2.2.1
                                      have sameState : consumptionState visited.2.consumed = visitModel.2 := visitMeaning.2.1
                                      cases verdict : visitModel.1 with
                                      | error error =>
                                          have refused : visited.1 = .Err (consumptionError error) := by
                                            simpa [verdict, consumptionVerdict] using visitMeaning.1
                                          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                                            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                            core.convert.FromSame, core.convert.FromSame.from, BodyMeaning, ClaimMeaning,
                                            RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember, originalKey,
                                            notEcho, native_text_view_bytes, ← validity, native_text_name_decode name fits,
                                            ← scalarMeaning, ← visitModel, verdict, sameState, sameFields,
                                            visitDomain, visitDomain.ordered, visitBinds, consumptionVerdict]
                                      | ok unit =>
                                          cases unit
                                          have accepted : visited.1 = .Ok () := by
                                            simpa [verdict, consumptionVerdict] using visitMeaning.1
                                          simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                          apply spec_mono (recurse visited.2 nodes visitDomain)
                                          rintro actual ⟨meaning, finalDomain, finalBinds⟩
                                          refine ⟨⟨?_, ?_, meaning.2.2.1.trans sameFields, finalDomain.ordered⟩,
                                            finalDomain, finalBinds.trans visitBinds⟩
                                          · simpa [RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember,
                                              originalKey, notEcho, native_text_view_bytes, ← validity,
                                              native_text_name_decode name fits, ← scalarMeaning, ← visitModel,
                                              verdict, sameState, sameFields] using meaning.1
                                          · simpa [RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember,
                                              originalKey, notEcho, native_text_view_bytes, ← validity,
                                              native_text_name_decode name fits, ← scalarMeaning, ← visitModel,
                                              verdict, sameState, sameFields] using meaning.2.1
                          | @json value modelValue originalJson =>
                              cases valueBound with
                              | json value bounds =>
                                  step with native_form_json_shape_exact value modelValue originalJson as ⟨shape, shapeMeaning⟩
                                  cases shape with
                                  | false =>
                                      simp [BodyMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes,
                                        RecipeRuleAdmission.formMember, originalKey, notEcho,
                                        native_text_view_bytes, ← validity, ← shapeMeaning,
                                        RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
                                  | true =>
                                      simp only [Bool.true_eq_true, ↓reduceIte]
                                      step with native_value_expr_admission_exact 7 input value modelValue 0#usize nodes
                                        (by simp) bounds originalJson domain
                                        as ⟨visited, visitMeaning, visitNodes, visitDomain, visitBinds⟩
                                      let visitModel := RecipeRuleAdmission.value 7 modelValue 0 nodes.val
                                        (consumptionState input.consumed) (nativeRuleMapMeaning input.fields)
                                      have sameFields : visited.2.1.fields = input.fields := visitMeaning.2.2.1
                                      have sameState : consumptionState visited.2.1.consumed = visitModel.1.2 := visitMeaning.2.1
                                      have sameNodes : visited.2.2.val = visitModel.2 := visitNodes
                                      cases verdict : visitModel.1.1 with
                                      | error error =>
                                          have refused : visited.1 = .Err (consumptionError error) := by
                                            simpa [verdict, consumptionVerdict] using visitMeaning.1
                                          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                                            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                            core.convert.FromSame, core.convert.FromSame.from, BodyMeaning, ClaimMeaning,
                                            RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember, originalKey,
                                            notEcho, native_text_view_bytes, ← validity, ← shapeMeaning,
                                            ← visitModel, verdict, sameState, sameFields,
                                            visitDomain, visitDomain.ordered, visitBinds, consumptionVerdict]
                                      | ok unit =>
                                          cases unit
                                          have accepted : visited.1 = .Ok () := by
                                            simpa [verdict, consumptionVerdict] using visitMeaning.1
                                          simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                          apply spec_mono (recurse visited.2.1 visited.2.2 visitDomain)
                                          rintro actual ⟨meaning, finalDomain, finalBinds⟩
                                          refine ⟨⟨?_, ?_, meaning.2.2.1.trans sameFields, finalDomain.ordered⟩,
                                            finalDomain, finalBinds.trans visitBinds⟩
                                          · simpa [RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember,
                                              originalKey, notEcho, native_text_view_bytes, ← validity,
                                              ← shapeMeaning, ← visitModel, verdict,
                                              sameState, sameFields, sameNodes] using meaning.1
                                          · simpa [RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.formMember,
                                              originalKey, notEcho, native_text_view_bytes, ← validity,
                                              ← shapeMeaning, ← visitModel, verdict,
                                              sameState, sameFields, sameNodes] using meaning.2.1
                          | echo => exact False.elim (notEcho rfl)

/-- The complete native body caller, with one shared JSON-node budget across
all form members. Public source bounds/meaning cover the entire original AST,
including malformed shapes; no successful child or lowered plan is assumed. -/
@[step] theorem native_body_admission_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : SourceBody) (model : TemplateAst.Body) (bounded : BodyBounds source)
    (original : BodySourceMeaning source model) (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.body input source ⦃ actual =>
      BodyMeaning input (RecipeRuleAdmission.body (nativeRuleMapMeaning input.fields)
        model (consumptionState input.consumed)) actual ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.body
  cases original with
  | json originalJson =>
      cases bounded with
      | json value bounds =>
          step with native_value_expr_admission_exact 7 input value _ 0#usize 0#usize (by simp)
            bounds originalJson domain as ⟨result, meaning, count, nextDomain, binds⟩
          exact ⟨by simpa [RecipeRuleAdmission.body, RecipeRuleAdmission.bodyWithNodes] using meaning,
            nextDomain, binds⟩
  | @form members models paired =>
      cases bounded with
      | form members names childBounds =>
          have countSame : members.entries.val.length = models.length := paired.length_eq
          simp only [AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.is_empty, bind_tc_ok]
          by_cases empty : members.entries.val = []
          · have noModels : models = [] := List.eq_nil_of_length_eq_zero (by simpa [empty] using countSame.symm)
            simp [empty, noModels, BodyMeaning, ClaimMeaning, RecipeRuleAdmission.body,
              RecipeRuleAdmission.bodyWithNodes, RecipeRuleAdmission.refused,
              consumptionVerdict, consumptionError, domain, domain.ordered]
          · have nonempty : 0 < models.length := by have nativePositive := List.length_pos.mpr empty; omega
            simp only [List.isEmpty_eq_false.mpr empty, Bool.false_eq_true, ↓reduceIte]
            step as ⟨size, sizeMeaning⟩
            by_cases large : 16 < members.entries.val.length
            · have nativeLarge : size > AuthsNativeRecipe.recipe.MAX_FORM_FIELDS := by
                simp only [AuthsNativeRecipe.recipe.MAX_FORM_FIELDS]; scalar_tac
              have modelLarge : ¬models.length ≤ 16 := by omega
              simp [nativeLarge, BodyMeaning, ClaimMeaning, RecipeRuleAdmission.body,
                RecipeRuleAdmission.bodyWithNodes, modelLarge, RecipeRuleAdmission.refused,
                consumptionVerdict, consumptionError, domain, domain.ordered]
            · have nativeWithin : ¬size > AuthsNativeRecipe.recipe.MAX_FORM_FIELDS := by
                simp only [AuthsNativeRecipe.recipe.MAX_FORM_FIELDS]; scalar_tac
              have within : models.length ≤ 16 := by omega
              simp only [nativeWithin, ↓reduceIte,
                AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter,
                bind_tc_ok]
              apply spec_mono (native_form_admission_loop members.entries input 0#usize models paired names childBounds domain)
              intro actual meaning
              simpa [RecipeRuleAdmission.body, RecipeRuleAdmission.bodyWithNodes, nonempty, within] using meaning

/-- Every actual body outcome retains finite original-field storage. This is
a native element-count consequence, not a total heap or B-tree-work bound. -/
theorem native_body_preserves_original_field_bound (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : SourceBody) (model : TemplateAst.Body) (bounded : BodyBounds source)
    (original : BodySourceMeaning source model) (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.body input source ⦃ actual =>
      actual.2.fields = input.fields ∧
      actual.2.consumed.all.elements.val.length ≤ 32 ∧ actual.2.consumed.body.elements.val.length ≤ 32 ∧
      actual.2.consumed.binds.elements.val.length ≤ 32 ∧ actual.2.consumed.binds = input.consumed.binds ⦄ := by
  apply spec_mono (native_body_admission_exact input source model bounded original domain)
  rintro actual ⟨meaning, nextDomain, binds⟩
  obtain ⟨all, body, bindCount⟩ := rule_state_storage actual.2 nextDomain
  exact ⟨meaning.2.2.1, all, body, bindCount, binds⟩

end Auths.Product.NativeCompiler.Refinement
