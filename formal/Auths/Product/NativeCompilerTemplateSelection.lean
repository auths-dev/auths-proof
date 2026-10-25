import Auths.Product.NativeCompilerOriginalLookup
import Auths.Product.RecipeTemplateSelection

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev SelectedOriginalAst := OriginalOption
  (fun source model => AstBounds source ∧ AstSourceMeaning source model)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

private theorem native_template_token_selection (source : SourceAst) (model : TemplateAst.Value)
    (bounds : AstBounds source) (original : AstSourceMeaning source model)
    (pointer : String) (fits : TextFits pointer) (start : Std.Usize)
    (within : start.val ≤ (textBytes pointer).length)
    (boundary : (String.Pos.Raw.mk start.val).IsValid pointer) :
    AuthsNativeRecipe.recipe.validate.template_at_token source (nativeTextView pointer fits) start ⦃ actual =>
      SelectedOriginalAst actual (RecipeRuleAdmission.selectPointerFrom model (textBytes pointer) start.val) ⦄ := by
  generalize remaining : (textBytes pointer).length - start.val = count
  induction count using Nat.strong_induction_on generalizing source model start with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.template_at_token
      simp only [AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
      step with native_pointer_token_end_exact (nativeTextView pointer fits) start
        (by simpa [nativeTextView, native_text_length, textBytes] using within)
        as ⟨end1, endMeaning⟩
      have endValue : end1.val = pointerTokenEnd (textBytes pointer) start.val := by
        simpa [native_text_view_bytes] using endMeaning
      step with native_original_pointer_span pointer fits start end1 within boundary endValue
        as ⟨selectedSpan, token, spanSome, tokenBytes⟩
      simp only [spanSome, AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitTry.branch,
        bind_tc_ok]
      have continuation (child : SourceAst) (childModel : TemplateAst.Value)
          (childBounds : AstBounds child) (childOriginal : AstSourceMeaning child childModel) :
          (if end1 = (nativeTextView pointer fits).len then ok (some child)
          else do
            let next ← end1 + 1#usize
            AuthsNativeRecipe.recipe.validate.template_at_token child (nativeTextView pointer fits) next) ⦃ actual =>
            SelectedOriginalAst actual
              (if pointerTokenEnd (textBytes pointer) start.val = (textBytes pointer).length then some childModel
              else RecipeRuleAdmission.selectPointerFrom childModel (textBytes pointer)
                (pointerTokenEnd (textBytes pointer) start.val + 1)) ⦄ := by
        by_cases ended : pointerTokenEnd (textBytes pointer) start.val = (textBytes pointer).length
        · have nativeEnded : end1 = (nativeTextView pointer fits).len := by
            simp [nativeTextView, native_text_length, textBytes] at *; scalar_tac
          simp only [nativeEnded, ended, ↓reduceIte, spec_ok]
          exact .some ⟨childBounds, childOriginal⟩
        · have endBounds := pointer_token_end_bounds (textBytes pointer) start.val within
          have endInside : pointerTokenEnd (textBytes pointer) start.val < (textBytes pointer).length := by omega
          have delimiter : (textBytes pointer)[pointerTokenEnd (textBytes pointer) start.val] = 47 := by
            rcases pointer_token_end_delimiter (textBytes pointer) start.val within with done | ⟨inside, slash⟩
            · exact False.elim (ended done)
            · exact slash
          have nextBoundary := original_after_slash_boundary pointer _ endInside delimiter
          have nativeOther : end1 ≠ (nativeTextView pointer fits).len := by
            simp [nativeTextView, native_text_length, textBytes] at *; scalar_tac
          simp only [nativeOther, ↓reduceIte]
          step as ⟨next, nextValue⟩
          apply spec_mono (ih _ (by omega) child childModel childBounds childOriginal next
            (by omega) (by simpa [nextValue, endValue] using nextBoundary) rfl)
          intro actual meaning
          simpa [ended, nextValue, endValue] using meaning
      cases original with
      | text text =>
          simp [RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild]
          exact .none
      | integer integer =>
          simp [RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild]
          exact .none
      | boolean boolean =>
          simp [RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild]
          exact .none
      | field name =>
          simp [RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild]
          exact .none
      | echo =>
          simp [RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild]
          exact .none
      | @object members models memberMeaning =>
          cases bounds with
          | object members names children =>
              step with native_original_map_lookup
                (fun source model => AstBounds source ∧ AstSourceMeaning source model)
                members models token (original_ast_members_bounded _ _ memberMeaning children) names
                as ⟨selected, selectedMeaning⟩
              rw [tokenBytes] at selectedMeaning
              cases selectedMeaning with
              | none =>
                  simp [AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitTry.branch,
                    AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual,
                    RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild]
                  exact .none
              | @some child childModel childMeaning =>
                  simp only [AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitTry.branch, bind_tc_ok]
                  apply spec_mono (continuation child childModel childMeaning.1 childMeaning.2)
                  intro actual meaning
                  simpa [RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild] using meaning
      | @array values models childMeaning =>
          cases bounds with
          | array values children =>
              simp only [AuthsNativeRecipe.core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
              step with native_array_index_exact token as ⟨position, positionMeaning⟩
              rw [tokenBytes] at positionMeaning
              cases position with
              | none =>
                  have absent : arrayIndex Usize.max (pointerToken (textBytes pointer) start.val) = none := positionMeaning.symm
                  simp [AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitTry.branch,
                    AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual,
                    RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild, absent]
                  exact .none
              | some position =>
                  have parsed : arrayIndex Usize.max (pointerToken (textBytes pointer) start.val) = some position.val := positionMeaning.symm
                  simp only [AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitTry.branch, bind_tc_ok,
                    AuthsNativeRecipe.core.slice.Slice.get, core.slice.Slice.get, core.slice.index.SliceIndexUsizeSlice,
                    core.slice.index.Usize.get, Slice.getElem?_Usize_eq]
                  have selectedMeaning := original_ast_array_at values.val models childMeaning children position.val
                  cases selectedMeaning with
                  | none =>
                      simp [AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitTry.branch,
                        AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual,
                        RecipeRuleAdmission.selectPointerFrom, within, RecipeRuleAdmission.selectTemplateChild, parsed]
                      exact .none
                  | @some child childModel childOriginal =>
                      simp only [AuthsNativeRecipe.core.option.Option.Insts.CoreOpsTry_traitTry.branch, bind_tc_ok]
                      apply spec_mono (continuation child childModel childOriginal.1 childOriginal.2)
                      intro actual meaning
                      simpa [RecipeRuleAdmission.selectPointerFrom, within,
                        RecipeRuleAdmission.selectTemplateChild, parsed] using meaning

/-- The actual selector examines original pointer bytes and original AST
members. It rejects every tilde, independently of the more permissive response
pointer grammar; it does not RFC-unescape names. Checked UTF-8 spans, exact
word parsing and absent/out-of-range children all participate in the result. -/
@[step] theorem native_template_at_exact (source : SourceAst) (model : TemplateAst.Value)
    (bounds : AstBounds source) (original : AstSourceMeaning source model)
    (pointer : String) (fits : TextFits pointer) :
    AuthsNativeRecipe.recipe.validate.template_at source (nativeTextView pointer fits) ⦃ actual =>
      SelectedOriginalAst actual (RecipeRuleAdmission.templateAt model (textBytes pointer)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.template_at
  step with native_response_pointer_exact (nativeTextView pointer fits) as ⟨valid, validity⟩
  cases valid with
  | false =>
      have invalid : ¬ResponsePointer (textBytes pointer) := by
        simpa [responsePointer, native_text_view_bytes] using validity.symm
      simp only [Bool.false_eq_true, ↓reduceIte, spec_ok]
      simpa [RecipeRuleAdmission.templateAt, invalid] using (OriginalOption.none : SelectedOriginalAst none none)
  | true =>
      have admitted : ResponsePointer (textBytes pointer) := by
        simpa [responsePointer, native_text_view_bytes] using validity.symm
      simp only [Bool.true_eq_true, ↓reduceIte, AuthsNativeRecipe.core.str.Str.as_bytes,
        _root_.core.str.Str.as_bytes, bind_tc_ok]
      step with native_byte_contains_exact (nativeTextView pointer fits) 126#u8 as ⟨tilde, tildeMeaning⟩
      cases tilde with
      | true =>
          have contains : 126 ∈ textBytes pointer := by simpa [native_text_view_bytes] using tildeMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte, spec_ok]
          simpa [RecipeRuleAdmission.templateAt, contains] using (OriginalOption.none : SelectedOriginalAst none none)
      | false =>
          have noTilde : 126 ∉ textBytes pointer := by simpa [native_text_view_bytes] using tildeMeaning.symm
          have nonempty : textBytes pointer ≠ [] := fun empty => by simp [ResponsePointer, empty] at admitted
          have firstInside : 0 < (textBytes pointer).length := List.length_pos.mpr nonempty
          have firstSlash : (textBytes pointer)[0] = 47 := by simpa using admitted.1
          have startBoundary := original_after_slash_boundary pointer 0 firstInside firstSlash
          simp only [Bool.false_eq_true, ↓reduceIte]
          apply spec_mono (native_template_token_selection source model bounds original pointer fits 1#usize
            (by omega) (by simpa using startBoundary))
          intro actual meaning
          simpa [RecipeRuleAdmission.template_at_original_pointer, admitted, noTilde] using meaning

@[step] theorem native_is_operation_id_exact (source : SourceAst) (model : TemplateAst.Value)
    (bounds : AstBounds source) (original : AstSourceMeaning source model) :
    AuthsNativeRecipe.recipe.validate.is_operation_id source ⦃ actual =>
      actual = RecipeRuleAdmission.isOperationId model ⦄ := by
  cases original <;> unfold AuthsNativeRecipe.recipe.validate.is_operation_id
  all_goals first | rfl | skip
  rename_i name
  cases bounds with
  | field name fits =>
      step with borrow_text_exact name fits as ⟨nameBytes, nameBytesMeaning⟩
      subst nameBytes
      step with native_schema_byte_equality as ⟨same, equality⟩
      simpa [RecipeRuleAdmission.isOperationId, FieldProjection.operationName,
        native_text_view_bytes, schemaSliceBytes] using equality

@[step] theorem native_template_is_operation_id_exact (source : SourceAst) (model : TemplateAst.Value)
    (bounds : AstBounds source) (original : AstSourceMeaning source model)
    (pointer : String) (fits : TextFits pointer) :
    AuthsNativeRecipe.recipe.validate.template_is_operation_id source (nativeTextView pointer fits) ⦃ actual =>
      actual = RecipeRuleAdmission.templateIsOperationId model (textBytes pointer) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.template_is_operation_id
  step with native_template_at_exact source model bounds original pointer fits as ⟨selected, selectedMeaning⟩
  cases selectedMeaning with
  | none => simp_all [RecipeRuleAdmission.templateIsOperationId]
  | @some source model meaning =>
      apply spec_mono (native_is_operation_id_exact source model meaning.1 meaning.2)
      intro actual exactTag
      simpa [RecipeRuleAdmission.templateIsOperationId] using exactTag

end Auths.Product.NativeCompiler.Refinement
