import Auths.Product.NativeCompilerPointerSpans
import Auths.Product.NativeCompilerAstMeaning

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

inductive OriginalOption {A B : Type} (meaning : A → B → Prop) : Option A → Option B → Prop where
  | none : OriginalOption meaning none none
  | some {source : A} {model : B} (original : meaning source model) :
      OriginalOption meaning (some source) (some model)

def OriginalMember {A B : Type} (meaning : A → B → Prop)
    (source : String × A) (model : List Nat × B) : Prop :=
  model.1 = textBytes source.1 ∧ meaning source.2 model.2

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.StdModel

theorem native_borrowed_bytes_comparison (query : Str) (key : String) (fits : TextFits key) :
    AuthsNativeRecipe.NativeModel.byteOrdering query.val (nativeTextView key fits).val = .eq ↔
      schemaSliceBytes query = textBytes key := by
  simp [AuthsNativeRecipe.NativeModel.byteOrdering, Std.compare_eq_iff_eq,
    ← schemaSliceBytes, native_text_view_bytes]

private theorem borrowed_original_lookup {A B : Type} (meaning : A → B → Prop)
    (sources : List (String × A)) (models : List (List Nat × B)) (query : Str)
    (original : List.Forall₂ (OriginalMember meaning) sources models)
    (fits : ∀ source ∈ sources, TextFits source.1) :
    AuthsNativeRecipe.NativeModel.lookupBorrowed AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr
      AuthsNativeRecipe.Str.Insts.CoreCmpOrd query sources ⦃ actual =>
        OriginalOption meaning actual (RecipeRuleAdmission.findMember (schemaSliceBytes query) models) ⦄ := by
  induction original with
  | nil => exact OriginalOption.none
  | @cons source model sources models head tail ih =>
      have headFits := fits source (by simp)
      have borrow : AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr.borrow source.1 =
          ok (nativeTextView source.1 headFits) := by
        simp [AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr.borrow,
          AuthsNativeRecipe.alloc.string.String.as_bytes, nativeTextView, TextFits,
          native_text_length, headFits]
      unfold AuthsNativeRecipe.NativeModel.lookupBorrowed
      rw [borrow]
      simp only [bind_tc_ok, AuthsNativeRecipe.Str.Insts.CoreCmpOrd.cmp]
      by_cases same : schemaSliceBytes query = textBytes source.1
      · have equal := (native_borrowed_bytes_comparison query source.1 headFits).mpr same
        simpa [equal, RecipeRuleAdmission.findMember, head.1, same] using OriginalOption.some head.2
      · have different : AuthsNativeRecipe.NativeModel.byteOrdering query.val
            (nativeTextView source.1 headFits).val ≠ .eq :=
          fun equal => same ((native_borrowed_bytes_comparison query source.1 headFits).mp equal)
        simpa [different, RecipeRuleAdmission.findMember, head.1, Ne.symm same] using
          ih (fun member present => fits member (by simp [present]))

private theorem owned_original_lookup {A B : Type} (meaning : A → B → Prop)
    (sources : List (String × A)) (models : List (List Nat × B)) (query : String)
    (original : List.Forall₂ (OriginalMember meaning) sources models) :
    AuthsNativeRecipe.NativeModel.lookupBorrowed (AuthsNativeRecipe.core.borrow.Borrow.Blanket String)
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd query sources ⦃ actual =>
        OriginalOption meaning actual (RecipeRuleAdmission.findMember (textBytes query) models) ⦄ := by
  induction original with
  | nil => exact OriginalOption.none
  | @cons source model sources models head tail ih =>
      simp only [AuthsNativeRecipe.NativeModel.lookupBorrowed,
        AuthsNativeRecipe.core.borrow.Borrow.Blanket.borrow, bind_tc_ok, native_string_order_exact]
      by_cases same : query = source.1
      · simpa [same, RecipeRuleAdmission.findMember, head.1] using OriginalOption.some head.2
      · have different : compare query source.1 ≠ .eq := by simpa [Std.compare_eq_iff_eq] using same
        simpa [different, RecipeRuleAdmission.findMember, head.1, text_bytes_injective.eq_iff, Ne.symm same] using ih

/-- This is an ordinary complete map-lookup interface: every original pair is
related, and absence is covered as well as presence. The generic relation is
instantiated with the complete original AST/form relation at Auths callers;
it is not a validator result or a callback implementation. -/
@[step] theorem native_original_map_lookup {A B : Type} (meaning : A → B → Prop)
    (sources : SourceMap A) (models : List (List Nat × B)) (query : Str)
    (original : List.Forall₂ (OriginalMember meaning) sources.entries.val models)
    (fits : ∀ source ∈ sources.entries.val, TextFits source.1) :
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.get core.core.clone.CloneGlobal
      AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd AuthsNativeRecipe.Str.Insts.CoreCmpOrd
      sources query ⦃ actual =>
        OriginalOption meaning actual (RecipeRuleAdmission.findMember (schemaSliceBytes query) models) ⦄ := by
  exact borrowed_original_lookup meaning sources.entries.val models query original fits

@[step] theorem native_original_map_lookup_owned {A B : Type} (meaning : A → B → Prop)
    (sources : SourceMap A) (models : List (List Nat × B)) (query : String)
    (original : List.Forall₂ (OriginalMember meaning) sources.entries.val models) :
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.get core.core.clone.CloneGlobal
      (AuthsNativeRecipe.core.borrow.Borrow.Blanket String)
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd
      sources query ⦃ actual =>
        OriginalOption meaning actual (RecipeRuleAdmission.findMember (textBytes query) models) ⦄ := by
  exact owned_original_lookup meaning sources.entries.val models query original

theorem original_ast_members_bounded (sources : List (String × SourceAst))
    (models : List (List Nat × TemplateAst.Value)) (original : AstSourceMembersMeaning sources models)
    (bounds : ∀ source ∈ sources, AstBounds source.2) :
    List.Forall₂ (OriginalMember (fun source model => AstBounds source ∧ AstSourceMeaning source model)) sources models := by
  induction original with
  | nil => exact .nil
  | @cons name source model rest models head tail ih =>
      exact .cons ⟨rfl, bounds _ (by simp), head⟩ (ih (fun source present => bounds source (by simp [present])))

theorem original_form_members_bounded (sources : List (String × SourceForm))
    (models : List (List Nat × TemplateAst.FormValue))
    (original : List.Forall₂ SourceFormMemberMeaning sources models)
    (bounds : ∀ source ∈ sources, FormBounds source.2) :
    List.Forall₂ (OriginalMember (fun source model => FormBounds source ∧ FormSourceMeaning source model)) sources models := by
  induction original with
  | nil => exact .nil
  | @cons source model sources models head tail ih =>
      exact .cons ⟨head.1, bounds _ (by simp), head.2⟩
        (ih (fun source present => bounds source (by simp [present])))

theorem original_ast_array_at (sources : List SourceAst) (models : List TemplateAst.Value)
    (original : AstSourceValuesMeaning sources models) (bounds : ∀ source ∈ sources, AstBounds source)
    (position : Nat) :
    OriginalOption (fun source model => AstBounds source ∧ AstSourceMeaning source model)
      sources[position]? models[position]? := by
  induction original generalizing position with
  | nil => exact .none
  | @cons source model sources models head tail ih =>
      cases position with
      | zero => exact .some ⟨bounds _ (by simp), head⟩
      | succ position => exact ih (fun source present => bounds source (by simp [present])) position

end Auths.Product.NativeCompiler.StdModel
