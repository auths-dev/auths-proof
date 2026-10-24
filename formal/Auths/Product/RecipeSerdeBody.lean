import Auths.Product.NativeCompilerAstMeaning
import Auths.Product.NativeFullJsonMeaning

/-!
Independent complete typed-body serialization specification. This describes
the declared serde shapes in recipe/source.rs, BEFORE canonical key sorting or
numeric formatting. No derived Rust Serialize implementation is assumed here.
All original children participate; no depth fuel or admitted-template subset
is used, including author-placed Echo variants that validation later refuses.
-/
namespace Auths.Product.RecipeSerde
open NativeCompiler

abbrev Json := FullJsonValue.Value

def tagged (kind : String) (members : List (String × Json)) : Json :=
  .object (("kind", .text kind) :: members)

mutual
  inductive AstEncoding : SourceAst → Json → Prop where
    | text (value : String) : AstEncoding (.String value) (tagged "string" [("value", .text value)])
    | integer (value : Aeneas.Std.I64) :
        AstEncoding (.Integer value) (tagged "integer" [("value", .number (.signed value.val))])
    | boolean (value : Bool) : AstEncoding (.Boolean value) (tagged "boolean" [("value", .boolean value)])
    | field (name : String) : AstEncoding (.Field name) (tagged "field" [("name", .text name)])
    | object {members : SourceMap SourceAst} {output : List (String × Json)}
        (children : AstMemberEncodings members.entries.val output) :
        AstEncoding (.Object members) (tagged "object" [("fields", .object output)])
    | array {values : NativeVec SourceAst} {output : List Json}
        (children : AstEncodings values.val output) :
        AstEncoding (.Array values) (tagged "array" [("items", .array output)])
    | echo : AstEncoding .Echo (tagged "echo" [])

  inductive AstEncodings : List SourceAst → List Json → Prop where
    | nil : AstEncodings [] []
    | cons {input : SourceAst} {output : Json} {rest : List SourceAst} {outputs : List Json}
        (head : AstEncoding input output) (tail : AstEncodings rest outputs) :
        AstEncodings (input :: rest) (output :: outputs)

  inductive AstMemberEncodings : List (String × SourceAst) → List (String × Json) → Prop where
    | nil : AstMemberEncodings [] []
    | cons {name : String} {input : SourceAst} {output : Json}
        {rest : List (String × SourceAst)} {outputs : List (String × Json)}
        (head : AstEncoding input output) (tail : AstMemberEncodings rest outputs) :
        AstMemberEncodings ((name, input) :: rest) ((name, output) :: outputs)
end

private theorem collect_values (inputs : List SourceAst)
    (children : ∀ value ∈ inputs, ∃ output, AstEncoding value output) :
    ∃ outputs, AstEncodings inputs outputs := by
  revert children
  induction inputs with
  | nil => intro _; exact ⟨[], .nil⟩
  | cons value rest ih =>
      intro children
      obtain ⟨output, head⟩ := children value (by simp)
      obtain ⟨outputs, tail⟩ := ih (fun child member => children child (by simp [member]))
      exact ⟨_, .cons head tail⟩

private theorem collect_members (inputs : List (String × SourceAst))
    (children : ∀ pair ∈ inputs, ∃ output, AstEncoding pair.2 output) :
    ∃ outputs, AstMemberEncodings inputs outputs := by
  revert children
  induction inputs with
  | nil => intro _; exact ⟨[], .nil⟩
  | cons pair rest ih =>
      intro children
      obtain ⟨output, head⟩ := children pair (by simp)
      obtain ⟨outputs, tail⟩ := ih (fun child member => children child (by simp [member]))
      cases pair
      exact ⟨_, .cons head tail⟩

theorem ast_encoding_exists (input : SourceAst) (bounded : AstBounds input) :
    ∃ output, AstEncoding input output := by
  induction bounded with
  | text value _ => exact ⟨_, .text value⟩
  | integer value => exact ⟨_, .integer value⟩
  | boolean value => exact ⟨_, .boolean value⟩
  | field name _ => exact ⟨_, .field name⟩
  | object members _ _ ih =>
      obtain ⟨output, children⟩ := collect_members members.entries.val ih
      exact ⟨_, .object children⟩
  | array values _ ih =>
      obtain ⟨output, children⟩ := collect_values values.val ih
      exact ⟨_, .array children⟩
  | echo => exact ⟨_, .echo⟩

mutual
  theorem ast_encoding_unique {input : SourceAst} {first second : Json}
      (left : AstEncoding input first) (right : AstEncoding input second) : first = second := by
    cases left with
    | text value => cases right; rfl
    | integer value => cases right; rfl
    | boolean value => cases right; rfl
    | field name => cases right; rfl
    | object children =>
        cases right with
        | object other => rw [ast_members_encoding_unique children other]
    | array children =>
        cases right with
        | array other => rw [ast_values_encoding_unique children other]
    | echo => cases right; rfl
  termination_by structural left

  theorem ast_values_encoding_unique {inputs : List SourceAst} {first second : List Json}
      (left : AstEncodings inputs first) (right : AstEncodings inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [ast_encoding_unique head otherHead, ast_values_encoding_unique tail otherTail]
  termination_by structural left

  theorem ast_members_encoding_unique {inputs : List (String × SourceAst)} {first second : List (String × Json)}
      (left : AstMemberEncodings inputs first) (right : AstMemberEncodings inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [ast_encoding_unique head otherHead, ast_members_encoding_unique tail otherTail]
  termination_by structural left
end

inductive FormEncoding : SourceForm → Json → Prop where
  | text (value : String) : FormEncoding (.String value) (tagged "string" [("value", .text value)])
  | field (name : String) : FormEncoding (.Field name) (tagged "field" [("name", .text name)])
  | json {input : SourceAst} {output : Json} (value : AstEncoding input output) :
      FormEncoding (.Json input) (tagged "json" [("value", output)])
  | echo : FormEncoding .Echo (tagged "echo" [])

def FormMemberEncoding (input : String × SourceForm) (output : String × Json) : Prop :=
  input.1 = output.1 ∧ FormEncoding input.2 output.2

inductive BodyEncoding : SourceBody → Json → Prop where
  | json {input : SourceAst} {output : Json} (value : AstEncoding input output) :
      BodyEncoding (.Json input) (tagged "json" [("value", output)])
  | form {input : SourceMap SourceForm} {output : List (String × Json)}
      (fields : List.Forall₂ FormMemberEncoding input.entries.val output) :
      BodyEncoding (.Form input) (tagged "form" [("fields", .object output)])

theorem form_encoding_exists (input : SourceForm) (bounded : FormBounds input) :
    ∃ output, FormEncoding input output := by
  cases bounded with
  | text value _ => exact ⟨_, .text value⟩
  | field name _ => exact ⟨_, .field name⟩
  | json value bounded =>
      obtain ⟨output, original⟩ := ast_encoding_exists value bounded
      exact ⟨_, .json original⟩
  | echo => exact ⟨_, .echo⟩

private theorem collect_form_members (inputs : List (String × SourceForm))
    (children : ∀ pair ∈ inputs, FormBounds pair.2) :
    ∃ outputs, List.Forall₂ FormMemberEncoding inputs outputs := by
  revert children
  induction inputs with
  | nil => intro _; exact ⟨[], .nil⟩
  | cons pair rest ih =>
      intro children
      obtain ⟨output, original⟩ := form_encoding_exists pair.2 (children pair (by simp))
      obtain ⟨outputs, tail⟩ := ih (fun child member => children child (by simp [member]))
      exact ⟨(pair.1, output) :: outputs, .cons ⟨rfl, original⟩ tail⟩

theorem body_encoding_exists (input : SourceBody) (bounded : BodyBounds input) :
    ∃ output, BodyEncoding input output := by
  cases bounded with
  | json value bounded =>
      obtain ⟨output, original⟩ := ast_encoding_exists value bounded
      exact ⟨_, .json original⟩
  | form members _ children =>
      obtain ⟨outputs, originals⟩ := collect_form_members members.entries.val children
      exact ⟨_, .form originals⟩

theorem form_encoding_unique {input : SourceForm} {first second : Json}
    (left : FormEncoding input first) (right : FormEncoding input second) : first = second := by
  cases left with
  | text value => cases right; rfl
  | field name => cases right; rfl
  | json value =>
      cases right with
      | json other => rw [ast_encoding_unique value other]
  | echo => cases right; rfl

private theorem form_member_unique {input : String × SourceForm} {first second : String × Json}
    (left : FormMemberEncoding input first) (right : FormMemberEncoding input second) : first = second := by
  exact Prod.ext (left.1.symm.trans right.1) (form_encoding_unique left.2 right.2)

private theorem form_members_unique {inputs : List (String × SourceForm)} {first second : List (String × Json)}
    (left : List.Forall₂ FormMemberEncoding inputs first) (right : List.Forall₂ FormMemberEncoding inputs second) :
    first = second := by
  induction left generalizing second with
  | nil => cases right; rfl
  | cons head tail ih =>
      cases right with
      | cons otherHead otherTail => rw [form_member_unique head otherHead, ih otherTail]

theorem body_encoding_unique {input : SourceBody} {first second : Json}
    (left : BodyEncoding input first) (right : BodyEncoding input second) : first = second := by
  cases left with
  | json value =>
      cases right with
      | json other => rw [ast_encoding_unique value other]
  | form fields =>
      cases right with
      | form other => rw [form_members_unique fields other]

end Auths.Product.RecipeSerde
