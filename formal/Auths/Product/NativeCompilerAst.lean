import Auths.Product.NativeCompilerAstMeaning
import Auths.Product.NativeCompilerContainers
import qualification.aeneas.generated.native_recipe.Funs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/- Private recursive-loop specifications consume child refinements only to
perform structural induction. Public refinements discharge those premises from
the original typed source; no compiled output or admission result is assumed. -/
private theorem ast_array_suffix
    (items : Slice SourceAst) (position : Std.Usize) (output : NativeVec KernelAst)
    (copies : ∀ item ∈ items.val,
      AuthsNativeRecipe.recipe.lower.source_value item ⦃ actual => SameAst item actual ⦄)
    (positionBound : position.val ≤ items.val.length)
    (room : output.val.length + (items.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.lower.source_values_loop items output position ⦃ actual =>
      ∃ suffix, actual.val = output.val ++ suffix ∧
        List.Forall₂ SameAst (items.val.drop position.val) suffix ⦄ := by
  generalize remaining : items.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.lower.source_values_loop
    split <;> rename_i within
    · have inside : position.val < items.val.length := by simpa using within
      step with Slice.index_usize_spec items position inside as ⟨item, itemAt⟩
      have member : item ∈ items.val := by
        rw [itemAt]
        exact List.getElem_mem inside
      step with copies item member as ⟨copied, copiedMeaning⟩
      have capacity : output.val.length < Usize.max := by omega
      step with native_push_exact output copied capacity as ⟨updated, appended⟩
      have updatedLength : updated.val.length = output.val.length + 1 := by
        simp only [appended, List.length_append, List.length_singleton]
      step as ⟨next, nextValue⟩
      have nextBound : next.val ≤ items.val.length := by omega
      have nextRoom : updated.val.length + (items.val.length - next.val) ≤ Usize.max := by omega
      have smaller : items.val.length - next.val < count := by omega
      apply spec_mono (ih _ smaller next updated nextBound nextRoom rfl)
      rintro actual ⟨suffix, exactSuffix, suffixCopy⟩
      refine ⟨copied :: suffix, ?_, ?_⟩
      · simpa only [appended, List.append_assoc, List.singleton_append] using exactSuffix
      · have original : items.val.drop position.val = item :: items.val.drop next.val := by
          simpa only [nextValue, itemAt] using List.drop_eq_getElem_cons inside
        rw [original]
        exact .cons copiedMeaning suffixCopy
    · have done : position.val = items.val.length := by
        have ended : items.val.length ≤ position.val := by simpa using within
        omega
      simp only [spec_ok]
      exact ⟨[], by simp, by simpa only [done, List.drop_length] using (List.Forall₂.nil : List.Forall₂ SameAst [] [])⟩

private theorem ast_member_suffix
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceAst)
    (output : NativeVec KernelMember)
    (names : ∀ pair ∈ iterator.val, TextFits pair.1)
    (copies : ∀ pair ∈ iterator.val,
      AuthsNativeRecipe.recipe.lower.source_value pair.2 ⦃ actual => SameAst pair.2 actual ⦄)
    (room : output.val.length + iterator.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.lower.source_members_loop iterator output ⦃ actual =>
      ∃ suffix, actual.val = output.val ++ suffix ∧
        List.Forall₂ SameAstMember iterator.val suffix ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.lower.source_members_loop
    simp only [AuthsNativeRecipe.alloc.collections.btree.map.Iter.Insts.CoreIterTraitsIteratorIteratorPairSharedAKSharedAV.next]
    step with next_pair_exact iterator as ⟨next, nextMeaning⟩
    cases original : iterator.val with
    | nil =>
        have ended : next.1 = none := (by simpa only [original] using nextMeaning).1
        simp only [ended, spec_ok]
        exact ⟨[], by simp, by simpa only [original] using (List.Forall₂.nil : List.Forall₂ SameAstMember [] [])⟩
    | cons pair rest =>
        obtain ⟨headAt, tailAt⟩ : next.1 = some pair ∧ next.2.val = rest := by
          simpa only [original] using nextMeaning
        simp only [headAt]
        have headMember : pair ∈ iterator.val := by simp only [original, List.mem_cons]; exact Or.inl rfl
        step with borrow_text_exact pair.1 (names pair headMember) as ⟨rawName, rawMeaning⟩
        step with copy_u8_exact rawName as ⟨copiedName, copiedNameMeaning⟩
        step with copies pair headMember as ⟨copiedValue, copiedValueMeaning⟩
        let member : KernelMember := .mk copiedName copiedValue
        have capacity : output.val.length < Usize.max := by
          simp only [original, List.length_cons] at room
          omega
        step with native_push_exact output member capacity as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by
          simp only [appended, List.length_append, List.length_singleton]
        have nextNames : ∀ pair ∈ next.2.val, TextFits pair.1 := by
          intro other belongs
          apply names other
          simp only [original, List.mem_cons]
          exact Or.inr (by simpa only [tailAt] using belongs)
        have nextCopies : ∀ pair ∈ next.2.val,
            AuthsNativeRecipe.recipe.lower.source_value pair.2 ⦃ actual => SameAst pair.2 actual ⦄ := by
          intro other belongs
          apply copies other
          simp only [original, List.mem_cons]
          exact Or.inr (by simpa only [tailAt] using belongs)
        have nextRoom : updated.val.length + next.2.val.length ≤ Usize.max := by
          simp only [original, List.length_cons] at room
          simp only [tailAt]
          omega
        have smaller : next.2.val.length < count := by
          simp only [tailAt, original, List.length_cons] at *
          omega
        apply spec_mono (ih _ smaller next.2 updated nextNames nextCopies nextRoom rfl)
        rintro actual ⟨suffix, exactSuffix, suffixCopy⟩
        refine ⟨member :: suffix, ?_, ?_⟩
        · simpa only [appended, List.append_assoc, List.singleton_append] using exactSuffix
        · rw [original]
          exact .cons ⟨copiedNameMeaning.trans rawMeaning, copiedValueMeaning⟩
            (by simpa only [tailAt] using suffixCopy)

/-- Actual native body-AST lowering preserves the independent meaning of every
original constructor and every complete child/member sequence. Field names are
copied as UTF-8; they are neither resolved nor replaced by caller-chosen indices. -/
@[step] theorem native_ast_has_original_meaning (input : SourceAst) (bounded : AstBounds input) :
    AuthsNativeRecipe.recipe.lower.source_value input ⦃ actual => SameAst input actual ⦄ := by
  induction bounded with
  | text value fits =>
      unfold AuthsNativeRecipe.recipe.lower.source_value
      step with borrow_text_exact value fits as ⟨raw, rawMeaning⟩
      step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
      refine ⟨_, .text value, ?_⟩
      simpa only [copiedMeaning.trans rawMeaning] using AstKernelMeaning.text copied
  | integer value =>
      simp only [AuthsNativeRecipe.recipe.lower.source_value, spec_ok]
      exact ⟨_, .integer value, .integer value⟩
  | boolean value =>
      simp only [AuthsNativeRecipe.recipe.lower.source_value, spec_ok]
      exact ⟨_, .boolean value, .boolean value⟩
  | field name fits =>
      unfold AuthsNativeRecipe.recipe.lower.source_value
      step with borrow_text_exact name fits as ⟨raw, rawMeaning⟩
      step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
      refine ⟨_, .field name, ?_⟩
      simpa only [copiedMeaning.trans rawMeaning] using AstKernelMeaning.field copied
  | array values children ih =>
      unfold AuthsNativeRecipe.recipe.lower.source_value AuthsNativeRecipe.recipe.lower.source_values
      have childCopies : ∀ value ∈ (AuthsNativeRecipe.alloc.vec.Vec.deref values).val,
          AuthsNativeRecipe.recipe.lower.source_value value ⦃ actual => SameAst value actual ⦄ := by
        simpa only [native_deref_contents] using ih
      step with ast_array_suffix (AuthsNativeRecipe.alloc.vec.Vec.deref values) 0#usize
        (AuthsNativeRecipe.alloc.vec.Vec.new KernelAst) childCopies
        (by simp) (by simpa using values.property) as ⟨output, suffix, exactOutput, copied⟩
      have outputIsSuffix : output.val = suffix := by
        simpa only [native_empty_contents, List.nil_append] using exactOutput
      have originalCopies : List.Forall₂ SameAst values.val output.val := by
        simpa only [native_deref_contents, List.drop_zero, ← outputIsSuffix] using copied
      obtain ⟨meanings, original, target⟩ := ast_values_have_original_meaning originalCopies
      exact ⟨_, .array original, .array target⟩
  | object members names children ih =>
      unfold AuthsNativeRecipe.recipe.lower.source_value AuthsNativeRecipe.recipe.lower.source_members
      simp only [AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter,
        bind_tc_ok]
      step with ast_member_suffix members.entries (AuthsNativeRecipe.alloc.vec.Vec.new KernelMember)
        names ih (by simpa using members.entries.property) as ⟨output, suffix, exactOutput, copied⟩
      have outputIsSuffix : output.val = suffix := by
        simpa only [native_empty_contents, List.nil_append] using exactOutput
      have originalCopies : List.Forall₂ SameAstMember members.entries.val output.val := by
        simpa only [← outputIsSuffix] using copied
      obtain ⟨meanings, original, target⟩ := ast_members_have_original_meaning originalCopies
      exact ⟨_, .object original, .object target⟩
  | echo =>
      simp only [AuthsNativeRecipe.recipe.lower.source_value, spec_ok]
      exact ⟨_, .echo, .echo⟩

@[step] theorem native_form_has_original_meaning (input : SourceForm) (bounded : FormBounds input) :
    AuthsNativeRecipe.recipe.lower.source_form_value input ⦃ actual => SameForm input actual ⦄ := by
  cases bounded with
  | text value fits =>
      unfold AuthsNativeRecipe.recipe.lower.source_form_value
      step with borrow_text_exact value fits as ⟨raw, rawMeaning⟩
      step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
      refine ⟨_, .text value, ?_⟩
      simpa only [copiedMeaning.trans rawMeaning] using FormKernelMeaning.text copied
  | field name fits =>
      unfold AuthsNativeRecipe.recipe.lower.source_form_value
      step with borrow_text_exact name fits as ⟨raw, rawMeaning⟩
      step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
      refine ⟨_, .field name, ?_⟩
      simpa only [copiedMeaning.trans rawMeaning] using FormKernelMeaning.field copied
  | json value bounded =>
      unfold AuthsNativeRecipe.recipe.lower.source_form_value
      step with native_ast_has_original_meaning value bounded as ⟨copied, meaning, source, target⟩
      exact ⟨_, .json source, .json target⟩
  | echo =>
      simp only [AuthsNativeRecipe.recipe.lower.source_form_value, spec_ok]
      exact ⟨_, .echo, .echo⟩

private theorem form_member_suffix
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceForm)
    (output : NativeVec KernelFormMember)
    (names : ∀ pair ∈ iterator.val, TextFits pair.1)
    (children : ∀ pair ∈ iterator.val, FormBounds pair.2)
    (room : output.val.length + iterator.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.lower.source_form_members_loop iterator output ⦃ actual =>
      ∃ suffix, actual.val = output.val ++ suffix ∧
        List.Forall₂ SameFormMember iterator.val suffix ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.lower.source_form_members_loop
    simp only [AuthsNativeRecipe.alloc.collections.btree.map.Iter.Insts.CoreIterTraitsIteratorIteratorPairSharedAKSharedAV.next]
    step with next_pair_exact iterator as ⟨next, nextMeaning⟩
    cases original : iterator.val with
    | nil =>
        have ended : next.1 = none := (by simpa only [original] using nextMeaning).1
        simp only [ended, spec_ok]
        exact ⟨[], by simp, by simpa only [original] using (List.Forall₂.nil : List.Forall₂ SameFormMember [] [])⟩
    | cons pair rest =>
        obtain ⟨headAt, tailAt⟩ : next.1 = some pair ∧ next.2.val = rest := by
          simpa only [original] using nextMeaning
        simp only [headAt]
        have headMember : pair ∈ iterator.val := by simp only [original, List.mem_cons]; exact Or.inl rfl
        step with borrow_text_exact pair.1 (names pair headMember) as ⟨rawName, rawMeaning⟩
        step with copy_u8_exact rawName as ⟨copiedName, copiedNameMeaning⟩
        step with native_form_has_original_meaning pair.2 (children pair headMember) as ⟨copiedValue, copiedValueMeaning⟩
        let member : KernelFormMember := ⟨copiedName, copiedValue⟩
        have capacity : output.val.length < Usize.max := by
          simp only [original, List.length_cons] at room
          omega
        step with native_push_exact output member capacity as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by
          simp only [appended, List.length_append, List.length_singleton]
        have nextNames : ∀ pair ∈ next.2.val, TextFits pair.1 := by
          intro other belongs
          apply names other
          simp only [original, List.mem_cons]
          exact Or.inr (by simpa only [tailAt] using belongs)
        have nextChildren : ∀ pair ∈ next.2.val, FormBounds pair.2 := by
          intro other belongs
          apply children other
          simp only [original, List.mem_cons]
          exact Or.inr (by simpa only [tailAt] using belongs)
        have nextRoom : updated.val.length + next.2.val.length ≤ Usize.max := by
          simp only [original, List.length_cons] at room
          simp only [tailAt]
          omega
        have smaller : next.2.val.length < count := by
          simp only [tailAt, original, List.length_cons] at *
          omega
        apply spec_mono (ih _ smaller next.2 updated nextNames nextChildren nextRoom rfl)
        rintro actual ⟨suffix, exactSuffix, suffixCopy⟩
        refine ⟨member :: suffix, ?_, ?_⟩
        · simpa only [appended, List.append_assoc, List.singleton_append] using exactSuffix
        · rw [original]
          exact .cons ⟨copiedNameMeaning.trans rawMeaning, copiedValueMeaning⟩
            (by simpa only [tailAt] using suffixCopy)

@[step] theorem native_form_members_copy (members : SourceMap SourceForm)
    (names : ∀ pair ∈ members.entries.val, TextFits pair.1)
    (children : ∀ pair ∈ members.entries.val, FormBounds pair.2) :
    AuthsNativeRecipe.recipe.lower.source_form_members members ⦃ actual =>
      List.Forall₂ SameFormMember members.entries.val actual.val ⦄ := by
  unfold AuthsNativeRecipe.recipe.lower.source_form_members
  simp only [AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter,
    bind_tc_ok]
  step with form_member_suffix members.entries (AuthsNativeRecipe.alloc.vec.Vec.new KernelFormMember)
    names children (by simpa using members.entries.property) as ⟨output, suffix, exactOutput, copied⟩
  have outputIsSuffix : output.val = suffix := by
    simpa only [native_empty_contents, List.nil_append] using exactOutput
  simpa only [← outputIsSuffix] using copied

/-- Actual native JSON and form body adapters earn a complete original-source
meaning and the same meaning of their actual kernel result. The input domain is
representability only, not accepted grammar, a chosen field layout or compiled
request success. Kernel admission and request emission remain separate claims. -/
@[step] theorem native_body_has_original_meaning (input : SourceBody) (bounded : BodyBounds input) :
    AuthsNativeRecipe.recipe.lower.source_body input ⦃ actual => SameBody input actual ⦄ := by
  cases bounded with
  | json value bounded =>
      unfold AuthsNativeRecipe.recipe.lower.source_body
      step with native_ast_has_original_meaning value bounded as ⟨copied, meaning, original, target⟩
      exact ⟨_, .json original, .json target⟩
  | form members names children =>
      unfold AuthsNativeRecipe.recipe.lower.source_body
      step with native_form_members_copy members names children as ⟨copied, copiedMeaning⟩
      obtain ⟨meanings, original, target⟩ := form_members_have_original_meaning copiedMeaning
      exact ⟨_, .form original, .form target⟩

theorem native_form_member_names_and_count (members : SourceMap SourceForm)
    (names : ∀ pair ∈ members.entries.val, TextFits pair.1)
    (children : ∀ pair ∈ members.entries.val, FormBounds pair.2) :
    AuthsNativeRecipe.recipe.lower.source_form_members members ⦃ actual =>
      actual.val.length = members.entries.val.length ∧
      actual.val.map (fun member => bytes member.name) =
        members.entries.val.map (fun pair => textBytes pair.1) ⦄ := by
  apply spec_mono (native_form_members_copy members names children)
  intro actual copied
  exact ⟨copied.length_eq.symm, form_member_names_preserved copied⟩

theorem native_body_earns_original_meaning (input : SourceBody) (bounded : BodyBounds input) :
    ∃ actual meaning, AuthsNativeRecipe.recipe.lower.source_body input = ok actual ∧
      BodySourceMeaning input meaning ∧ BodyKernelMeaning actual meaning := by
  obtain ⟨actual, evaluates, meaning, original, target⟩ :=
    spec_imp_exists (native_body_has_original_meaning input bounded)
  exact ⟨actual, meaning, evaluates, original, target⟩

/-- A separately stated original-body meaning fixes the actual native result's
meaning. The source relation is over the original body, with no lowered result,
field index, rendering or successful compiler/admission in its premises. -/
theorem native_body_preserves_original_meaning (input : SourceBody) (bounded : BodyBounds input)
    (meaning : TemplateAst.Body) (original : BodySourceMeaning input meaning) :
    AuthsNativeRecipe.recipe.lower.source_body input ⦃ actual => BodyKernelMeaning actual meaning ⦄ := by
  apply spec_mono (native_body_has_original_meaning input bounded)
  rintro actual ⟨earned, source, target⟩
  have same : earned = meaning := body_source_meaning_unique source original
  simpa only [same] using target

end Auths.Product.NativeCompiler.Refinement
