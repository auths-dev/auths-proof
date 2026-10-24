import Auths.Product.NativeCompilerEchoPointers
import Auths.Product.NativeCompilerMemberTargets
import Auths.Product.RecipeEchoProperties

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def jsonEchoAt (value : TemplateAst.Value) (pointer : List Nat) : Except RecipeConsumption.Error Unit :=
  match EchoPointer.decode pointer with
  | .error _ => .error .echoConflict
  | .ok tokens => RecipeRuleAdmission.jsonEchoTokens value tokens

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 26000000
set_option maxRecDepth 4096

/-- The actual recursive validator follows the complete original object
members. All native target/UTF-8/map/range results are earned at their callers;
neither admitted tokens nor a selected original child is supplied as a leaf. -/
@[step] theorem native_validate_json_echo_tokens_exact (source : SourceAst) (model : TemplateAst.Value)
    (bounds : AstBounds source) (original : AstSourceMeaning source model)
    (tokens : Slice (NativeVec Std.U8)) :
    AuthsNativeRecipe.recipe.validate.validate_json_echo_tokens source tokens ⦃ actual =>
      actual = consumptionVerdict (RecipeRuleAdmission.jsonEchoTokens model (nativeTokens tokens)) ⦄ := by
  generalize remaining : tokens.val.length = count
  induction count using Nat.strong_induction_on generalizing source model tokens with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.validate_json_echo_tokens
      cases original with
      | text text => rfl
      | integer integer => rfl
      | boolean boolean => rfl
      | field name => rfl
      | array children => rfl
      | echo => rfl
      | @object members models meaning =>
          cases bounds with
          | object members names children =>
              have originalNames := source_ast_member_names _ _ meaning
              have countSame : members.entries.val.length = models.length := body_source_members_count meaning
              simp only [AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.is_empty, bind_tc_ok]
              by_cases empty : members.entries.val = []
              · have noModels : models = [] := List.eq_nil_of_length_eq_zero (by simpa [empty] using countSame.symm)
                simp [empty, noModels, RecipeRuleAdmission.json_echo_bad_count _ _ (Or.inl rfl), consumptionVerdict, consumptionError]
              · have nonempty : 0 < models.length := by have positive := List.length_pos.mpr empty; omega
                simp only [List.isEmpty_eq_false.mpr empty, Bool.false_eq_true, ↓reduceIte]
                step as ⟨size, sizeMeaning⟩
                by_cases large : 32 < members.entries.val.length
                · have nativeLarge : size > 32#usize := by scalar_tac
                  have modelLarge : 32 < models.length := by omega
                  simp [nativeLarge, RecipeRuleAdmission.json_echo_bad_count _ _ (Or.inr modelLarge), consumptionVerdict, consumptionError]
                · have nativeWithin : ¬size > 32#usize := by scalar_tac
                  simp only [nativeWithin, ↓reduceIte]
                  step with native_json_member_names_exact members names as ⟨valid, validity⟩
                  have originalValidity : valid = decide (∀ member ∈ models, OperationIdentity.validToken member.1 64 = true) := by
                    simpa [← originalNames, List.forall_mem_map] using validity
                  cases valid with
                  | false =>
                      have invalid : ¬∀ member ∈ models, OperationIdentity.validToken member.1 64 = true := by
                        simpa using originalValidity.symm
                      simp [RecipeRuleAdmission.json_echo_bad_names models _ invalid, consumptionVerdict, consumptionError]
                  | true =>
                      have validNames : models.all (fun member => OperationIdentity.validToken member.1 64) = true := by
                        simpa [List.all_eq_true] using originalValidity.symm
                      simp only [Bool.true_eq_true, ↓reduceIte]
                      step with native_json_member_keys_exact members names as ⟨keys, keyNames, keyCount⟩
                      have originalKeys : nativeKeyColumn (AuthsNativeRecipe.alloc.vec.Vec.deref keys) = models.map Prod.fst := by
                        simpa [native_key_column_deref, originalNames] using keyNames
                      step with native_json_echo_target_exact (AuthsNativeRecipe.alloc.vec.Vec.deref keys) tokens
                        as ⟨target, targetMeaning⟩
                      rw [originalKeys] at targetMeaning
                      cases target with
                      | Err error =>
                          simp [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
                            AuthsNativeRecipe.recipe.validate.validate_json_echo_tokens.closure.Insts.CoreOpsFunctionFnOnceTupleMemberErrorGatewayRecipeError,
                            AuthsNativeRecipe.recipe.validate.validate_json_echo_tokens.closure.Insts.CoreOpsFunctionFnOnceTupleMemberErrorGatewayRecipeError.call_once,
                            core.result.Result.Insts.CoreOpsTry.branch,
                            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                            core.convert.FromSame, core.convert.FromSame.from,
                            RecipeRuleAdmission.jsonEchoTokens, validNames, ← targetMeaning,
                            nativeMemberResult, consumptionVerdict, consumptionError]
                      | Ok target =>
                          simp only [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
                            core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                          cases target with
                          | Insert =>
                              simp [RecipeRuleAdmission.jsonEchoTokens, validNames, ← targetMeaning,
                                nativeMemberResult, nativeTarget, consumptionVerdict]
                          | Descend index =>
                              have targetRun : TemplateMembers.jsonEchoTarget (models.map Prod.fst) (nativeTokens tokens) = .ok (.descend index.val) := by
                                simpa [nativeMemberResult, nativeTarget] using targetMeaning.symm
                              have pointer := (TemplateMembers.target_success_retains_pointer _ _ _ targetRun).2
                              have longer := (TemplateMembers.target_descends_to_original_name _ _ _ targetRun).1
                              have positive : 0 < tokens.val.length := by simpa [nativeTokens] using pointer.1
                              cases tokenAt : tokens.val with
                              | nil => simp [tokenAt] at positive
                              | cons first rest =>
                                  have headValid : OperationIdentity.validToken (bytes first) 64 = true := by
                                    exact pointer.2.2.1 (bytes first) (by simp [nativeTokens, tokenAt])
                                  simp only [AuthsNativeRecipe.core.slice.Slice.first, tokenAt, List.head?_cons,
                                    AuthsNativeRecipe.core.option.Option.ok_or, core.option.Option.ok_or,
                                    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                  step with native_ascii_token_utf8_exact (AuthsNativeRecipe.alloc.vec.Vec.deref first)
                                    (by simpa [bytes, schemaSliceBytes, native_deref_contents] using headValid)
                                    as ⟨converted, conversion⟩
                                  simp only [conversion, AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
                                    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                  step with native_original_map_lookup
                                    (fun source model => AstBounds source ∧ AstSourceMeaning source model)
                                    members models (AuthsNativeRecipe.alloc.vec.Vec.deref first)
                                    (original_ast_members_bounded _ _ meaning children) names as ⟨selected, selectedMeaning⟩
                                  have originalToken : schemaSliceBytes (AuthsNativeRecipe.alloc.vec.Vec.deref first) = bytes first := by rfl
                                  rw [originalToken] at selectedMeaning
                                  cases selectedMeaning with
                                  | none =>
                                      simp_all [AuthsNativeRecipe.core.option.Option.ok_or, core.option.Option.ok_or,
                                        core.result.Result.Insts.CoreOpsTry.branch,
                                        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                                        core.convert.FromSame, core.convert.FromSame.from,
                                        RecipeRuleAdmission.jsonEchoTokens, validNames, targetRun,
                                        nativeTokens, tokenAt, consumptionVerdict, consumptionError]
                                  | @some child childModel childMeaning =>
                                      simp only [AuthsNativeRecipe.core.option.Option.ok_or, core.option.Option.ok_or,
                                        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                      let tail : Slice (NativeVec Std.U8) := ⟨rest, by
                                        have bound := tokens.property
                                        simp [tokenAt] at bound; omega⟩
                                      have rangeBound : (1#usize).val ≤ tokens.val.length := by omega
                                      simp only [AuthsNativeRecipe.core.slice.Slice.get, core.slice.Slice.get,
                                        core.slice.index.SliceIndexRangeFromUsizeSlice,
                                        core.slice.index.SliceIndexRangeFromUsizeSlice.get, rangeBound,
                                        AuthsNativeRecipe.core.option.Option.ok_or, core.option.Option.ok_or,
                                        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                                      apply spec_mono (ih _ (by simp [tokenAt] at remaining; simp [tail]; omega)
                                        child childModel childMeaning.1 childMeaning.2 tail rfl)
                                      intro actual exactChild
                                      simpa [RecipeRuleAdmission.jsonEchoTokens, validNames, targetRun,
                                        nativeTokens, tokenAt, tail] using exactChild

/-- Pointer tokenization is the actual bounded kernel tokenizer. Its errors
are mapped by the real source closure; successful tokens then enter the actual
recursive source validator above. -/
@[step] theorem native_validate_json_echo_exact (pointer : Str) (source : SourceAst) (model : TemplateAst.Value)
    (bounds : AstBounds source) (original : AstSourceMeaning source model) :
    AuthsNativeRecipe.recipe.validate.validate_json_echo pointer source ⦃ actual =>
      actual = consumptionVerdict (jsonEchoAt model (schemaSliceBytes pointer)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_json_echo
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  step with native_echo_pointer_exact pointer as ⟨decoded, decodedMeaning⟩
  cases decoded with
  | Err error =>
      simp [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
        AuthsNativeRecipe.recipe.validate.validate_json_echo.closure.Insts.CoreOpsFunctionFnOnceTupleMemberErrorGatewayRecipeError,
        AuthsNativeRecipe.recipe.validate.validate_json_echo.closure.Insts.CoreOpsFunctionFnOnceTupleMemberErrorGatewayRecipeError.call_once,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, jsonEchoAt, ← decodedMeaning,
        nativeTokenResult, consumptionVerdict, consumptionError]
  | Ok tokens =>
      simp only [AuthsNativeRecipe.core.result.Result.map_err, _root_.core.result.Result.map_err,
        core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      apply spec_mono (native_validate_json_echo_tokens_exact source model bounds original
        (AuthsNativeRecipe.alloc.vec.Vec.deref tokens))
      intro actual exactTokens
      simpa [jsonEchoAt, ← decodedMeaning, nativeTokenResult, nativeTokenNames, nativeTokens] using exactTokens

end Auths.Product.NativeCompiler.Refinement
