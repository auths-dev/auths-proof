import Auths.Product.NativeCompilerBodyAdmissionState

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 20000000
set_option maxRecDepth 4096

/- These private child specifications are structural-induction hypotheses.
The public value theorem below earns every one from the original AST and
smaller depth fuel; no Auths validator is supplied as an opaque callback. -/
private theorem native_value_array_admission_loop (fuel : Nat)
    (iterator : core.slice.iter.Iter SourceAst) (input : AuthsNativeRecipe.recipe.validate.Rules)
    (depth nodes : Std.Usize) (models : List TemplateAst.Value)
    (paired : AstSourceValuesMeaning (iterator.slice.val.drop iterator.i) models)
    (within : depth.val ≤ 6) (domain : RuleStateDomain input)
    (children : ∀ child ∈ iterator.slice.val, ∀ model, AstSourceMeaning child model →
      ∀ before : AuthsNativeRecipe.recipe.validate.Rules, ∀ childDepth count : Std.Usize,
      childDepth.val = depth.val + 1 → RuleStateDomain before →
      AuthsNativeRecipe.recipe.validate.Rules.value_expr before child childDepth count ⦃ actual =>
        NodeMeaning before (RecipeRuleAdmission.value fuel model childDepth.val count.val
          (consumptionState before.consumed) (nativeRuleMapMeaning before.fields)) actual ⦄) :
    AuthsNativeRecipe.recipe.validate.Rules.value_expr_loop1 iterator input depth nodes ⦃ actual =>
      NodeMeaning input (RecipeRuleAdmission.foldNodes
        (fun model count state => RecipeRuleAdmission.value fuel model (depth.val + 1) count state
          (nativeRuleMapMeaning input.fields)) models nodes.val (consumptionState input.consumed)) actual ⦄ := by
  generalize remaining : iterator.slice.val.length - iterator.i = count
  induction count using Nat.strong_induction_on generalizing iterator input nodes models with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.value_expr_loop1
      by_cases inside : iterator.i < iterator.slice.val.length
      · simp only [core.slice.iter.IteratorSliceIter.next, dif_pos inside, bind_tc_ok]
        let child := iterator.slice.val[iterator.i]
        let next : core.slice.iter.Iter SourceAst := { iterator with i := iterator.i + 1 }
        have suffix : iterator.slice.val.drop iterator.i = child :: iterator.slice.val.drop next.i := by
          simpa [child, next] using List.drop_eq_getElem_cons inside
        rw [suffix] at paired
        cases models with
        | nil => cases paired
        | cons model rest =>
            cases paired with
            | cons head tail =>
                step as ⟨childDepth, childDepthValue⟩
                step with children child (List.getElem_mem inside) model head input childDepth nodes childDepthValue domain
                  as ⟨visited, visitMeaning, visitNodes, visitDomain, visitBinds⟩
                let visitModel := RecipeRuleAdmission.value fuel model childDepth.val nodes.val
                  (consumptionState input.consumed) (nativeRuleMapMeaning input.fields)
                have sameFields : visited.2.1.fields = input.fields := visitMeaning.2.2.1
                have sameState : consumptionState visited.2.1.consumed = visitModel.1.2 := visitMeaning.2.1
                have sameNodes : visited.2.2.val = visitModel.2 := visitNodes
                cases verdict : visitModel.1.1 with
                | error error =>
                    have refused : visited.1 = .Err (consumptionError error) := by
                      simpa only [verdict, consumptionVerdict] using visitMeaning.1
                    simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                      core.convert.FromSame, core.convert.FromSame.from, NodeMeaning, ClaimMeaning,
                      RecipeRuleAdmission.foldNodes, ← visitModel, verdict, childDepthValue,
                      sameState, sameNodes, sameFields, visitDomain, visitDomain.ordered,
                      visitBinds, consumptionVerdict]
                | ok unit =>
                    cases unit
                    have accepted : visited.1 = .Ok () := by
                      simpa only [verdict, consumptionVerdict] using visitMeaning.1
                    simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                    have smaller : next.slice.val.length - next.i < count := by simp [next] at *; omega
                    have nextChildren : ∀ child ∈ next.slice.val, ∀ model, AstSourceMeaning child model →
                        ∀ before : AuthsNativeRecipe.recipe.validate.Rules, ∀ d n : Std.Usize,
                        d.val = depth.val + 1 → RuleStateDomain before →
                        AuthsNativeRecipe.recipe.validate.Rules.value_expr before child d n ⦃ actual =>
                          NodeMeaning before (RecipeRuleAdmission.value fuel model d.val n.val
                            (consumptionState before.consumed) (nativeRuleMapMeaning before.fields)) actual ⦄ := by
                      simpa [next] using children
                    apply spec_mono (ih _ smaller next visited.2.1 visited.2.2 rest tail visitDomain nextChildren rfl)
                    rintro actual ⟨finalMeaning, finalNodes, finalDomain, finalBinds⟩
                    refine ⟨⟨?_, ?_, finalMeaning.2.2.1.trans sameFields, finalDomain.ordered⟩,
                      ?_, finalDomain, finalBinds.trans visitBinds⟩
                    · simpa [RecipeRuleAdmission.foldNodes, ← visitModel, verdict, childDepthValue,
                        sameFields, sameState, sameNodes] using finalMeaning.1
                    · simpa [RecipeRuleAdmission.foldNodes, ← visitModel, verdict, childDepthValue,
                        sameFields, sameState, sameNodes] using finalMeaning.2.1
                    · simpa [RecipeRuleAdmission.foldNodes, ← visitModel, verdict, childDepthValue,
                        sameFields, sameState, sameNodes] using finalNodes
      · have ended : iterator.slice.val.length ≤ iterator.i := by omega
        have empty : iterator.slice.val.drop iterator.i = [] := List.drop_eq_nil_of_le ended
        rw [empty] at paired
        cases paired
        simp [core.slice.iter.IteratorSliceIter.next, dif_neg inside, NodeMeaning, ClaimMeaning,
          RecipeRuleAdmission.foldNodes, RecipeRuleAdmission.accepted, consumptionVerdict,
          domain, domain.ordered]

private theorem native_value_object_admission_loop (fuel : Nat)
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceAst)
    (input : AuthsNativeRecipe.recipe.validate.Rules) (depth nodes : Std.Usize)
    (models : List (List Nat × TemplateAst.Value))
    (paired : AstSourceMembersMeaning iterator.val models)
    (names : ∀ member ∈ iterator.val, TextFits member.1)
    (within : depth.val ≤ 6) (domain : RuleStateDomain input)
    (children : ∀ member ∈ iterator.val, ∀ model, AstSourceMeaning member.2 model →
      ∀ before : AuthsNativeRecipe.recipe.validate.Rules, ∀ childDepth count : Std.Usize,
      childDepth.val = depth.val + 1 → RuleStateDomain before →
      AuthsNativeRecipe.recipe.validate.Rules.value_expr before member.2 childDepth count ⦃ actual =>
        NodeMeaning before (RecipeRuleAdmission.value fuel model childDepth.val count.val
          (consumptionState before.consumed) (nativeRuleMapMeaning before.fields)) actual ⦄) :
    AuthsNativeRecipe.recipe.validate.Rules.value_expr_loop0 iterator input depth nodes ⦃ actual =>
      NodeMeaning input (RecipeRuleAdmission.foldNodes
        (fun member count state => if OperationIdentity.validToken member.1 64 then
          RecipeRuleAdmission.value fuel member.2 (depth.val + 1) count state (nativeRuleMapMeaning input.fields)
          else (RecipeRuleAdmission.refused .unsafeTemplate state, count))
        models nodes.val (consumptionState input.consumed)) actual ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator input nodes models with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.value_expr_loop0
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          rw [original] at paired
          cases paired
          simp [ended, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes,
            RecipeRuleAdmission.accepted, consumptionVerdict, domain, domain.ordered]
      | cons member rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some member ∧ next.2.val = rest := by
            simpa [original] using nextMeaning
          simp only [headAt]
          rw [original] at paired
          cases paired with
          | cons head tail =>
              have memberPresent : member ∈ iterator.val := by simp [original]
              have nameFits := names member memberPresent
              step with native_deref_view_exact member.1 nameFits as ⟨key, keyView⟩
              subst key
              step with native_recipe_field_name_exact (nativeTextView member.1 nameFits) as ⟨valid, validity⟩
              cases valid with
              | false =>
                  simp [NodeMeaning, ClaimMeaning, RecipeRuleAdmission.foldNodes,
                    native_text_view_bytes, ← validity, RecipeRuleAdmission.refused,
                    consumptionVerdict, consumptionError, domain, domain.ordered]
              | true =>
                  simp only [Bool.true_eq_true, ↓reduceIte]
                  step as ⟨childDepth, childDepthValue⟩
                  step with children member memberPresent _ head input childDepth nodes childDepthValue domain
                    as ⟨visited, visitMeaning, visitNodes, visitDomain, visitBinds⟩
                  let visitModel := RecipeRuleAdmission.value fuel _ childDepth.val nodes.val
                    (consumptionState input.consumed) (nativeRuleMapMeaning input.fields)
                  have sameFields : visited.2.1.fields = input.fields := visitMeaning.2.2.1
                  have sameState : consumptionState visited.2.1.consumed = visitModel.1.2 := visitMeaning.2.1
                  have sameNodes : visited.2.2.val = visitModel.2 := visitNodes
                  cases verdict : visitModel.1.1 with
                  | error error =>
                      have refused : visited.1 = .Err (consumptionError error) := by
                        simpa only [verdict, consumptionVerdict] using visitMeaning.1
                      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                        core.convert.FromSame, core.convert.FromSame.from, NodeMeaning, ClaimMeaning,
                        RecipeRuleAdmission.foldNodes, native_text_view_bytes, ← validity,
                        ← visitModel, verdict, childDepthValue, sameState, sameNodes, sameFields,
                        visitDomain, visitDomain.ordered, visitBinds, consumptionVerdict]
                  | ok unit =>
                      cases unit
                      have accepted : visited.1 = .Ok () := by
                        simpa only [verdict, consumptionVerdict] using visitMeaning.1
                      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                      have smaller : next.2.val.length < count := by simp [tailAt, original] at *; omega
                      have nextNames : ∀ member ∈ next.2.val, TextFits member.1 := by
                        intro other present
                        exact names other (by simp only [original, List.mem_cons]; exact Or.inr (by simpa [tailAt] using present))
                      have nextChildren : ∀ member ∈ next.2.val, ∀ model, AstSourceMeaning member.2 model →
                          ∀ before : AuthsNativeRecipe.recipe.validate.Rules, ∀ d n : Std.Usize,
                          d.val = depth.val + 1 → RuleStateDomain before →
                          AuthsNativeRecipe.recipe.validate.Rules.value_expr before member.2 d n ⦃ actual =>
                            NodeMeaning before (RecipeRuleAdmission.value fuel model d.val n.val
                              (consumptionState before.consumed) (nativeRuleMapMeaning before.fields)) actual ⦄ := by
                        intro other present
                        exact children other (by simp only [original, List.mem_cons]; exact Or.inr (by simpa [tailAt] using present))
                      apply spec_mono (ih _ smaller next.2 visited.2.1 visited.2.2 _
                        (by simpa [tailAt] using tail) nextNames visitDomain nextChildren rfl)
                      rintro actual ⟨finalMeaning, finalNodes, finalDomain, finalBinds⟩
                      refine ⟨⟨?_, ?_, finalMeaning.2.2.1.trans sameFields, finalDomain.ordered⟩,
                        ?_, finalDomain, finalBinds.trans visitBinds⟩
                      · simpa [RecipeRuleAdmission.foldNodes, native_text_view_bytes, ← validity,
                          ← visitModel, verdict, childDepthValue, sameFields, sameState, sameNodes] using finalMeaning.1
                      · simpa [RecipeRuleAdmission.foldNodes, native_text_view_bytes, ← validity,
                          ← visitModel, verdict, childDepthValue, sameFields, sameState, sameNodes] using finalMeaning.2.1
                      · simpa [RecipeRuleAdmission.foldNodes, native_text_view_bytes, ← validity,
                          ← visitModel, verdict, childDepthValue, sameFields, sameState, sameNodes] using finalNodes

/-- Complete actual JSON-value admission, including every returned mutation
and node counter on refusal. Fuel is earned from native depth, not used to
truncate an accepted original tree. String representability and original AST
meaning contain no schema/source-admission or expected-lowering premise. -/
@[step] theorem native_value_expr_admission_exact (fuel : Nat)
    (input : AuthsNativeRecipe.recipe.validate.Rules) (source : SourceAst) (model : TemplateAst.Value)
    (depth nodes : Std.Usize) (depthFuel : depth.val + fuel = 7)
    (bounded : AstBounds source) (original : AstSourceMeaning source model) (domain : RuleStateDomain input) :
    AuthsNativeRecipe.recipe.validate.Rules.value_expr input source depth nodes ⦃ actual =>
      NodeMeaning input (RecipeRuleAdmission.value fuel model depth.val nodes.val
        (consumptionState input.consumed) (nativeRuleMapMeaning input.fields)) actual ⦄ := by
  induction fuel generalizing input source model depth nodes with
  | zero =>
      have tooDeep : 6 < depth.val := by omega
      unfold AuthsNativeRecipe.recipe.validate.Rules.value_expr
      step with native_node_charge_exact nodes depth as ⟨charged, chargeMeaning⟩
      cases charged with
      | Ok value => simp [nativeTemplateResult, TemplateAst.chargeNode, Nat.not_le.mpr tooDeep] at chargeMeaning
      | Err error =>
          simp [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
            AuthsNativeRecipe.recipe.validate.Rules.value_expr.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError,
            AuthsNativeRecipe.recipe.validate.Rules.value_expr.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError.call_once,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, NodeMeaning, ClaimMeaning,
            RecipeRuleAdmission.value, RecipeRuleAdmission.refused, consumptionVerdict,
            consumptionError, domain, domain.ordered]
  | succ fuel ih =>
      unfold AuthsNativeRecipe.recipe.validate.Rules.value_expr
      step with native_node_charge_exact nodes depth as ⟨charged, chargeMeaning⟩
      cases charged with
      | Err error =>
          have exhausted : ¬(nodes.val < 64 ∧ depth.val ≤ 6) := by
            intro room
            simp [nativeTemplateResult, TemplateAst.chargeNode, room] at chargeMeaning
          simp [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
            AuthsNativeRecipe.recipe.validate.Rules.value_expr.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError,
            AuthsNativeRecipe.recipe.validate.Rules.value_expr.closure.Insts.CoreOpsFunctionFnOnceTupleTemplateErrorGatewayRecipeError.call_once,
            core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, NodeMeaning, ClaimMeaning,
            RecipeRuleAdmission.value, exhausted, RecipeRuleAdmission.refused,
            consumptionVerdict, consumptionError, domain, domain.ordered]
      | Ok charged =>
          have room : nodes.val < 64 ∧ depth.val ≤ 6 := by
            by_contra invalid
            simp [nativeTemplateResult, TemplateAst.chargeNode, invalid] at chargeMeaning
          have chargedValue : charged.val = nodes.val + 1 := by
            simpa [nativeTemplateResult, TemplateAst.chargeNode, room] using chargeMeaning
          simp only [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
            core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          cases original with
          | text text =>
              cases bounded with
              | text text fits =>
                  step with native_text_size_exact text fits as ⟨size, sizeMeaning⟩
                  by_cases within : (textBytes text).length ≤ 1024
                  · have nativeWithin : size <= AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES := by
                      simp only [AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES]
                      scalar_tac
                    simp [nativeWithin, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room,
                      within, chargedValue, RecipeRuleAdmission.accepted, consumptionVerdict, domain, domain.ordered]
                  · have nativeLarge : ¬size <= AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES := by
                      simp only [AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_LITERAL_BYTES]
                      scalar_tac
                    simp [nativeLarge, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room,
                      within, chargedValue, RecipeRuleAdmission.refused, consumptionVerdict,
                      consumptionError, domain, domain.ordered]
          | integer value =>
              step with native_body_unsigned_abs_exact value as ⟨magnitude, magnitudeMeaning⟩
              step with native_safe_integer_constant_exact as ⟨maximum, maximumMeaning⟩
              by_cases safe : value.val.natAbs ≤ 9007199254740991
              · have nativeSafe : magnitude <= maximum := by scalar_tac
                simp [nativeSafe, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room, safe,
                  chargedValue, RecipeRuleAdmission.accepted, consumptionVerdict, domain, domain.ordered]
              · have nativeUnsafe : ¬magnitude <= maximum := by scalar_tac
                simp [nativeUnsafe, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room, safe,
                  chargedValue, RecipeRuleAdmission.refused, consumptionVerdict,
                  consumptionError, domain, domain.ordered]
          | boolean value =>
              simp [NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room, chargedValue,
                RecipeRuleAdmission.accepted, consumptionVerdict, domain, domain.ordered]
          | field name =>
              cases bounded with
              | field name fits =>
                  step with native_deref_view_exact name fits as ⟨nameView, viewMeaning⟩
                  subst nameView
                  step with native_body_field_ref_on_domain input name fits domain
                    as ⟨result, meaning, nextDomain, sameBinds⟩
                  exact ⟨by simpa [RecipeRuleAdmission.value, room] using meaning,
                    by simpa [RecipeRuleAdmission.value, room] using chargedValue, nextDomain, sameBinds⟩
          | echo =>
              simp [NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room, chargedValue,
                RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, domain, domain.ordered]
          | @array values models paired =>
              cases bounded with
              | array values childBounds =>
                  have countSame := body_source_values_count paired
                  simp only [AuthsNativeRecipe.alloc.vec.Vec.is_empty, bind_tc_ok]
                  by_cases empty : values.val = []
                  · have noModels : models = [] := by
                      have length : models.length = 0 := by simpa [empty] using countSame.symm
                      exact List.eq_nil_of_length_eq_zero length
                    simp [empty, noModels, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value,
                      room, chargedValue, RecipeRuleAdmission.refused, consumptionVerdict,
                      consumptionError, domain, domain.ordered]
                  · have nonempty : 0 < models.length := by
                      have nativePositive := List.length_pos.mpr empty
                      omega
                    simp only [List.isEmpty_eq_false.mpr empty, Bool.false_eq_true, ↓reduceIte]
                    by_cases large : 16 < values.val.length
                    · have nativeLarge : ¬AuthsNativeRecipe.alloc.vec.Vec.len values <= 16#usize := by scalar_tac
                      have modelLarge : ¬models.length ≤ 16 := by omega
                      simp [nativeLarge, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room,
                        modelLarge, chargedValue, RecipeRuleAdmission.refused, consumptionVerdict,
                        consumptionError, domain, domain.ordered]
                    · have nativeWithin : AuthsNativeRecipe.alloc.vec.Vec.len values <= 16#usize := by scalar_tac
                      have within : models.length ≤ 16 := by omega
                      simp only [nativeWithin, ↓reduceIte,
                        AuthsNativeRecipe.SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
                        bind_tc_ok]
                      have visits : ∀ child ∈ (AuthsNativeRecipe.alloc.vec.Vec.deref values).val,
                          ∀ model, AstSourceMeaning child model →
                          ∀ before : AuthsNativeRecipe.recipe.validate.Rules, ∀ d n : Std.Usize,
                          d.val = depth.val + 1 → RuleStateDomain before →
                          AuthsNativeRecipe.recipe.validate.Rules.value_expr before child d n ⦃ actual =>
                            NodeMeaning before (RecipeRuleAdmission.value fuel model d.val n.val
                              (consumptionState before.consumed) (nativeRuleMapMeaning before.fields)) actual ⦄ := by
                        intro child present model original before d n nextDepth nextDomain
                        exact ih before child model d n (by omega) (childBounds child present) original nextDomain
                      apply spec_mono (native_value_array_admission_loop fuel
                        ⟨AuthsNativeRecipe.alloc.vec.Vec.deref values, 0⟩ input depth charged models
                        (by simpa using paired) room.2 domain visits)
                      intro actual meaning
                      simpa [RecipeRuleAdmission.value, room, nonempty, within, chargedValue] using meaning
          | @object members models paired =>
              cases bounded with
              | object members names childBounds =>
                  have countSame := body_source_members_count paired
                  simp only [AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.is_empty, bind_tc_ok]
                  by_cases empty : members.entries.val = []
                  · have noModels : models = [] := by
                      have length : models.length = 0 := by simpa [empty] using countSame.symm
                      exact List.eq_nil_of_length_eq_zero length
                    simp [empty, noModels, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value,
                      room, chargedValue, RecipeRuleAdmission.refused, consumptionVerdict,
                      consumptionError, domain, domain.ordered]
                  · have nonempty : 0 < models.length := by
                      have nativePositive := List.length_pos.mpr empty
                      omega
                    simp only [List.isEmpty_eq_false.mpr empty, Bool.false_eq_true, ↓reduceIte]
                    step as ⟨size, sizeMeaning⟩
                    by_cases large : 32 < members.entries.val.length
                    · have nativeLarge : ¬size <= 32#usize := by scalar_tac
                      have modelLarge : ¬models.length ≤ 32 := by omega
                      simp [nativeLarge, NodeMeaning, ClaimMeaning, RecipeRuleAdmission.value, room,
                        modelLarge, chargedValue, RecipeRuleAdmission.refused, consumptionVerdict,
                        consumptionError, domain, domain.ordered]
                    · have nativeWithin : size <= 32#usize := by scalar_tac
                      have within : models.length ≤ 32 := by omega
                      simp only [nativeWithin, ↓reduceIte,
                        AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter,
                        bind_tc_ok]
                      have visits : ∀ member ∈ members.entries.val, ∀ model, AstSourceMeaning member.2 model →
                          ∀ before : AuthsNativeRecipe.recipe.validate.Rules, ∀ d n : Std.Usize,
                          d.val = depth.val + 1 → RuleStateDomain before →
                          AuthsNativeRecipe.recipe.validate.Rules.value_expr before member.2 d n ⦃ actual =>
                            NodeMeaning before (RecipeRuleAdmission.value fuel model d.val n.val
                              (consumptionState before.consumed) (nativeRuleMapMeaning before.fields)) actual ⦄ := by
                        intro member present model original before d n nextDepth nextDomain
                        exact ih before member.2 model d n (by omega) (childBounds member present) original nextDomain
                      apply spec_mono (native_value_object_admission_loop fuel members.entries input depth charged models
                        paired names room.2 domain visits)
                      intro actual meaning
                      simpa [RecipeRuleAdmission.value, room, nonempty, within, chargedValue] using meaning

end Auths.Product.NativeCompiler.Refinement
