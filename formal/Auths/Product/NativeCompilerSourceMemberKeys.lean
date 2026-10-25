import Auths.Product.NativeCompilerBodyAdmissionState
import Auths.Product.NativeCompilerMembers
import Auths.Product.NativeCompilerOriginalLookup

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def sourceMemberNames {T : Type} (members : List (String × T)) : List (List Nat) :=
  members.map fun member => textBytes member.1

theorem source_ast_member_names (members : List (String × SourceAst))
    (models : List (List Nat × TemplateAst.Value)) (original : AstSourceMembersMeaning members models) :
    models.map Prod.fst = sourceMemberNames members := by
  induction original <;> simp_all [sourceMemberNames]

theorem source_form_member_names (members : List (String × SourceForm))
    (models : List (List Nat × TemplateAst.FormValue))
    (original : List.Forall₂ SourceFormMemberMeaning members models) :
    models.map Prod.fst = sourceMemberNames members := by
  induction original with
  | nil => rfl
  | cons head tail ih => simp [sourceMemberNames, head.1, ih]

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

private theorem native_json_source_names_loop
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceAst)
    (fits : ∀ member ∈ iterator.val, TextFits member.1) :
    AuthsNativeRecipe.recipe.validate.json_member_names_valid_loop iterator ⦃ actual =>
      actual = decide (∀ name ∈ sourceMemberNames iterator.val, OperationIdentity.validToken name 64 = true) ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.json_member_names_valid_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          simp [ended, sourceMemberNames, original]
      | cons member rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some member ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [headAt]
          have nameFits := fits member (by simp [original])
          step with native_deref_view_exact member.1 nameFits as ⟨view, viewMeaning⟩
          subst view
          step with native_recipe_field_name_exact (nativeTextView member.1 nameFits) as ⟨valid, validity⟩
          cases valid with
          | false => simp [sourceMemberNames, original, ← validity, native_text_view_bytes]
          | true =>
              simp only [Bool.true_eq_true, ↓reduceIte]
              apply spec_mono (ih _ (by simp [original, tailAt] at *; omega) next.2
                (fun other present => fits other (by simp [original, tailAt] at present ⊢; exact Or.inr present)) rfl)
              intro actual meaning
              simpa [sourceMemberNames, original, tailAt, ← validity, native_text_view_bytes] using meaning

@[step] theorem native_json_member_names_exact (members : SourceMap SourceAst)
    (fits : ∀ member ∈ members.entries.val, TextFits member.1) :
    AuthsNativeRecipe.recipe.validate.json_member_names_valid members ⦃ actual =>
      actual = decide (∀ name ∈ sourceMemberNames members.entries.val, OperationIdentity.validToken name 64 = true) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.json_member_names_valid
    AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
  simp only [bind_tc_ok]
  exact native_json_source_names_loop members.entries fits

private theorem native_json_source_keys_loop
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceAst) (keys : NativeVec NativeKey)
    (fits : ∀ member ∈ iterator.val, TextFits member.1)
    (room : keys.val.length + iterator.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.json_member_keys_loop iterator keys ⦃ actual =>
      nativeKeys actual = nativeKeys keys ++ sourceMemberNames iterator.val ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator keys with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.json_member_keys_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          simp [ended, sourceMemberNames, original]
      | cons member rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some member ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [headAt]
          have nameFits := fits member (by simp [original])
          step with borrow_text_exact member.1 nameFits as ⟨view, viewMeaning⟩
          step with copy_u8_exact view as ⟨copied, copiedMeaning⟩
          have capacity : keys.val.length < Usize.max := by simp [original] at room; omega
          step with native_push_exact keys (⟨copied⟩ : NativeKey) capacity as ⟨updated, appended⟩
          have nextRoom : updated.val.length + next.2.val.length ≤ Usize.max := by
            simp [appended, original, tailAt] at *; omega
          apply spec_mono (ih _ (by simp [original, tailAt] at *; omega) next.2 updated
            (fun other present => fits other (by simp [original, tailAt] at present ⊢; exact Or.inr present)) nextRoom rfl)
          intro actual meaning
          simpa [nativeKeys, appended, sourceMemberNames, original, tailAt,
            copiedMeaning, viewMeaning, List.append_assoc] using meaning

/-- Every original key is copied with complete bytes and order. The original
map storage bound earns room for the whole output; there is no truncation or
assumed admitted member list. -/
@[step] theorem native_json_member_keys_exact (members : SourceMap SourceAst)
    (fits : ∀ member ∈ members.entries.val, TextFits member.1) :
    AuthsNativeRecipe.recipe.validate.json_member_keys members ⦃ actual =>
      nativeKeys actual = sourceMemberNames members.entries.val ∧ actual.val.length = members.entries.val.length ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.json_member_keys
    AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_json_source_keys_loop members.entries (AuthsNativeRecipe.alloc.vec.Vec.new NativeKey)
    fits (by simpa [native_empty_contents] using members.entries.toBase.property))
  intro actual meaning
  have original : nativeKeys actual = sourceMemberNames members.entries.val := by
    simpa [nativeKeys, native_empty_contents] using meaning
  exact ⟨original, by simpa [nativeKeys, sourceMemberNames] using congrArg List.length original⟩

private theorem native_form_source_names_loop
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceForm)
    (fits : ∀ member ∈ iterator.val, TextFits member.1) :
    AuthsNativeRecipe.recipe.validate.form_member_names_valid_loop iterator ⦃ actual =>
      actual = decide (∀ name ∈ sourceMemberNames iterator.val, OperationIdentity.validToken name 64 = true) ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.form_member_names_valid_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          simp [ended, sourceMemberNames, original]
      | cons member rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some member ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [headAt]
          have nameFits := fits member (by simp [original])
          step with native_deref_view_exact member.1 nameFits as ⟨view, viewMeaning⟩
          subst view
          step with native_recipe_field_name_exact (nativeTextView member.1 nameFits) as ⟨valid, validity⟩
          cases valid with
          | false => simp [sourceMemberNames, original, ← validity, native_text_view_bytes]
          | true =>
              simp only [Bool.true_eq_true, ↓reduceIte]
              apply spec_mono (ih _ (by simp [original, tailAt] at *; omega) next.2
                (fun other present => fits other (by simp [original, tailAt] at present ⊢; exact Or.inr present)) rfl)
              intro actual meaning
              simpa [sourceMemberNames, original, tailAt, ← validity, native_text_view_bytes] using meaning

@[step] theorem native_form_member_names_exact (members : SourceMap SourceForm)
    (fits : ∀ member ∈ members.entries.val, TextFits member.1) :
    AuthsNativeRecipe.recipe.validate.form_member_names_valid members ⦃ actual =>
      actual = decide (∀ name ∈ sourceMemberNames members.entries.val, OperationIdentity.validToken name 64 = true) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.form_member_names_valid
    AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
  simp only [bind_tc_ok]
  exact native_form_source_names_loop members.entries fits

private theorem native_form_source_keys_loop
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter String SourceForm) (keys : NativeVec NativeKey)
    (fits : ∀ member ∈ iterator.val, TextFits member.1)
    (room : keys.val.length + iterator.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.form_member_keys_loop iterator keys ⦃ actual =>
      nativeKeys actual = nativeKeys keys ++ sourceMemberNames iterator.val ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator keys with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.form_member_keys_loop
      step with next_pair_exact iterator as ⟨next, nextMeaning⟩
      cases original : iterator.val with
      | nil =>
          have ended : next.1 = none := (by simpa [original] using nextMeaning).1
          simp [ended, sourceMemberNames, original]
      | cons member rest =>
          obtain ⟨headAt, tailAt⟩ : next.1 = some member ∧ next.2.val = rest := by simpa [original] using nextMeaning
          simp only [headAt]
          have nameFits := fits member (by simp [original])
          step with borrow_text_exact member.1 nameFits as ⟨view, viewMeaning⟩
          step with copy_u8_exact view as ⟨copied, copiedMeaning⟩
          have capacity : keys.val.length < Usize.max := by simp [original] at room; omega
          step with native_push_exact keys (⟨copied⟩ : NativeKey) capacity as ⟨updated, appended⟩
          have nextRoom : updated.val.length + next.2.val.length ≤ Usize.max := by
            simp [appended, original, tailAt] at *; omega
          apply spec_mono (ih _ (by simp [original, tailAt] at *; omega) next.2 updated
            (fun other present => fits other (by simp [original, tailAt] at present ⊢; exact Or.inr present)) nextRoom rfl)
          intro actual meaning
          simpa [nativeKeys, appended, sourceMemberNames, original, tailAt,
            copiedMeaning, viewMeaning, List.append_assoc] using meaning

/-- Every original key is copied with complete bytes and order. The original
map storage bound earns room for the whole output; there is no truncation or
assumed admitted member list. -/
@[step] theorem native_form_member_keys_exact (members : SourceMap SourceForm)
    (fits : ∀ member ∈ members.entries.val, TextFits member.1) :
    AuthsNativeRecipe.recipe.validate.form_member_keys members ⦃ actual =>
      nativeKeys actual = sourceMemberNames members.entries.val ∧ actual.val.length = members.entries.val.length ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.form_member_keys
    AuthsNativeRecipe.SharedABTreeMap.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAKSharedAVIter.into_iter
  simp only [bind_tc_ok]
  apply spec_mono (native_form_source_keys_loop members.entries (AuthsNativeRecipe.alloc.vec.Vec.new NativeKey)
    fits (by simpa [native_empty_contents] using members.entries.toBase.property))
  intro actual meaning
  have original : nativeKeys actual = sourceMemberNames members.entries.val := by
    simpa [nativeKeys, native_empty_contents] using meaning
  exact ⟨original, by simpa [nativeKeys, sourceMemberNames] using congrArg List.length original⟩

end Auths.Product.NativeCompiler.Refinement
