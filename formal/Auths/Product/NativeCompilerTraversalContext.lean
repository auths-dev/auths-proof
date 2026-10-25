import Auths.Product.NativeCompilerDecimal
import Auths.Product.NativeCompilerMembers
import Auths.Product.TemplateAstTraversal
import Auths.Product.TemplateAstKeyTraversal

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

theorem kernel_values_full_relation {inputs : List KernelAst} {meanings : List TemplateAst.Value}
    (original : AstKernelValuesMeaning inputs meanings) : List.Forall₂ AstKernelMeaning inputs meanings := by
  induction original with
  | nil => exact .nil
  | cons head tail ih => exact .cons head ih

def KernelMemberMeaning (input : KernelMember) (meaning : List Nat × TemplateAst.Value) : Prop :=
  meaning.1 = bytes input.name ∧ AstKernelMeaning input.value meaning.2

theorem kernel_members_full_relation {inputs : List KernelMember} {meanings : List (List Nat × TemplateAst.Value)}
    (original : AstKernelMembersMeaning inputs meanings) : List.Forall₂ KernelMemberMeaning inputs meanings := by
  induction original with
  | nil => exact .nil
  | cons head tail ih => exact .cons ⟨rfl, head⟩ ih

theorem kernel_members_original_names {inputs : List KernelMember} {meanings : List (List Nat × TemplateAst.Value)}
    (original : AstKernelMembersMeaning inputs meanings) : meanings.map Prod.fst = inputs.map (fun field => bytes field.name) := by
  induction original with
  | nil => rfl
  | cons head tail ih => simp [ih]

theorem original_relation_lookup {A B : Type} {relation : A → B → Prop}
    {inputs : List A} {meanings : List B} (original : List.Forall₂ relation inputs meanings)
    (index : Nat) :
    match inputs[index]?, meanings[index]? with
    | none, none => True
    | some input, some meaning => relation input meaning
    | _, _ => False := by
  induction original generalizing index with
  | nil => simp
  | cons head tail ih => cases index <;> simp_all

theorem original_relation_selected {A B : Type} {relation : A → B → Prop}
    {inputs : List A} {meanings : List B} (original : List.Forall₂ relation inputs meanings)
    (index : Nat) (input : A) (selected : inputs[index]? = some input) :
    ∃ meaning, meanings[index]? = some meaning ∧ relation input meaning := by
  have atPosition := original_relation_lookup original index
  cases atMeaning : meanings[index]? with
  | none => simp [selected, atMeaning] at atPosition
  | some meaning => exact ⟨meaning, atMeaning, by simpa [selected, atMeaning] using atPosition⟩

namespace EmitterInternal

/-- Internal induction motive only. Public emitter statements must discharge
this from decreasing source depth; callers cannot supply a successful child
result, accepted AST or chosen emitted template. -/
def JsonChildren (depth : Nat) : Prop :=
  ∀ (value : KernelAst) (meaning : TemplateAst.Value), AstKernelMeaning value meaning →
    ∀ (echo : Option (Slice (NativeVec Std.U8))) (childDepth : Std.Usize) (output : NativeJsonBuild),
      childDepth.val = depth + 1 →
      AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_value value echo childDepth output ⦃ actual =>
        nativeJsonEffect actual = TemplateAst.emitJson 7 meaning (nativeEchoTokens echo)
          childDepth.val (nativeJsonBuild output) ⦄

end EmitterInternal
end Auths.Product.NativeCompiler
