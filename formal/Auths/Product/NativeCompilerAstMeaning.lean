import Auths.Product.NativeCompilerValues
import Auths.Product.TemplateAst

/-!
Meaning of the original typed recipe body and the native kernel's body carrier.
Names remain names; no field index, compiled plan, desired rendered output or
successful admission is an input to these relations. Every original member and
child participates in the complete ordered sequence.
-/
open Aeneas Aeneas.Std

namespace Auths.Product.NativeCompiler

abbrev SourceAst := AuthsNativeRecipe.recipe.source.ValueExpr
abbrev SourceForm := AuthsNativeRecipe.recipe.source.FormExpr
abbrev SourceBody := AuthsNativeRecipe.recipe.source.BodySource
abbrev SourceMap (T : Type) := AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap String T Global
abbrev KernelAst := AuthsNativeRecipe.auths_gateway_kernel.template_ast.Value
abbrev KernelMember := AuthsNativeRecipe.auths_gateway_kernel.template_ast.JsonMember
abbrev KernelForm := AuthsNativeRecipe.auths_gateway_kernel.template_ast.FormValue
abbrev KernelFormMember := AuthsNativeRecipe.auths_gateway_kernel.template_ast.FormMember
abbrev KernelBody := AuthsNativeRecipe.auths_gateway_kernel.template_ast.Body

/-- Representability only. Invalid, oversized and unbound template shapes are
still included; native admission must independently earn its stronger bounds. -/
inductive AstBounds : SourceAst → Prop where
  | text (value : String) (fits : TextFits value) : AstBounds (.String value)
  | integer (value : Std.I64) : AstBounds (.Integer value)
  | boolean (value : Bool) : AstBounds (.Boolean value)
  | field (name : String) (fits : TextFits name) : AstBounds (.Field name)
  | object (members : SourceMap SourceAst)
      (names : ∀ pair ∈ members.entries.val, TextFits pair.1)
      (children : ∀ pair ∈ members.entries.val, AstBounds pair.2) : AstBounds (.Object members)
  | array (values : NativeVec SourceAst)
      (children : ∀ value ∈ values.val, AstBounds value) : AstBounds (.Array values)
  | echo : AstBounds .Echo

inductive FormBounds : SourceForm → Prop where
  | text (value : String) (fits : TextFits value) : FormBounds (.String value)
  | field (name : String) (fits : TextFits name) : FormBounds (.Field name)
  | json (value : SourceAst) (bounded : AstBounds value) : FormBounds (.Json value)
  | echo : FormBounds .Echo

inductive BodyBounds : SourceBody → Prop where
  | json (value : SourceAst) (bounded : AstBounds value) : BodyBounds (.Json value)
  | form (members : SourceMap SourceForm)
      (names : ∀ pair ∈ members.entries.val, TextFits pair.1)
      (children : ∀ pair ∈ members.entries.val, FormBounds pair.2) : BodyBounds (.Form members)

mutual
  inductive AstSourceMeaning : SourceAst → TemplateAst.Value → Prop where
    | text (value : String) : AstSourceMeaning (.String value) (.text (textBytes value))
    | integer (value : Std.I64) : AstSourceMeaning (.Integer value) (.integer value.val)
    | boolean (value : Bool) : AstSourceMeaning (.Boolean value) (.boolean value)
    | field (name : String) : AstSourceMeaning (.Field name) (.field (textBytes name))
    | object {members : SourceMap SourceAst} {meaning : List (List Nat × TemplateAst.Value)}
        (children : AstSourceMembersMeaning members.entries.val meaning) :
        AstSourceMeaning (.Object members) (.object meaning)
    | array {values : NativeVec SourceAst} {meaning : List TemplateAst.Value}
        (children : AstSourceValuesMeaning values.val meaning) :
        AstSourceMeaning (.Array values) (.array meaning)
    | echo : AstSourceMeaning .Echo .authorEcho

  inductive AstSourceValuesMeaning : List SourceAst → List TemplateAst.Value → Prop where
    | nil : AstSourceValuesMeaning [] []
    | cons {input : SourceAst} {meaning : TemplateAst.Value}
        {rest : List SourceAst} {meanings : List TemplateAst.Value}
        (head : AstSourceMeaning input meaning) (tail : AstSourceValuesMeaning rest meanings) :
        AstSourceValuesMeaning (input :: rest) (meaning :: meanings)

  inductive AstSourceMembersMeaning : List (String × SourceAst) → List (List Nat × TemplateAst.Value) → Prop where
    | nil : AstSourceMembersMeaning [] []
    | cons {name : String} {input : SourceAst} {meaning : TemplateAst.Value}
        {rest : List (String × SourceAst)} {meanings : List (List Nat × TemplateAst.Value)}
        (head : AstSourceMeaning input meaning) (tail : AstSourceMembersMeaning rest meanings) :
        AstSourceMembersMeaning ((name, input) :: rest) ((textBytes name, meaning) :: meanings)
end

mutual
  inductive AstKernelMeaning : KernelAst → TemplateAst.Value → Prop where
    | text (value : NativeVec Std.U8) : AstKernelMeaning (.String value) (.text (bytes value))
    | integer (value : Std.I64) : AstKernelMeaning (.Integer value) (.integer value.val)
    | boolean (value : Bool) : AstKernelMeaning (.Boolean value) (.boolean value)
    | field (name : NativeVec Std.U8) : AstKernelMeaning (.Field name) (.field (bytes name))
    | object {members : NativeVec KernelMember} {meaning : List (List Nat × TemplateAst.Value)}
        (children : AstKernelMembersMeaning members.val meaning) :
        AstKernelMeaning (.Object members) (.object meaning)
    | array {values : NativeVec KernelAst} {meaning : List TemplateAst.Value}
        (children : AstKernelValuesMeaning values.val meaning) :
        AstKernelMeaning (.Array values) (.array meaning)
    | echo : AstKernelMeaning .AuthorEcho .authorEcho

  inductive AstKernelValuesMeaning : List KernelAst → List TemplateAst.Value → Prop where
    | nil : AstKernelValuesMeaning [] []
    | cons {input : KernelAst} {meaning : TemplateAst.Value}
        {rest : List KernelAst} {meanings : List TemplateAst.Value}
        (head : AstKernelMeaning input meaning) (tail : AstKernelValuesMeaning rest meanings) :
        AstKernelValuesMeaning (input :: rest) (meaning :: meanings)

  inductive AstKernelMembersMeaning : List KernelMember → List (List Nat × TemplateAst.Value) → Prop where
    | nil : AstKernelMembersMeaning [] []
    | cons {input : KernelMember} {meaning : TemplateAst.Value}
        {rest : List KernelMember} {meanings : List (List Nat × TemplateAst.Value)}
        (head : AstKernelMeaning input.value meaning) (tail : AstKernelMembersMeaning rest meanings) :
        AstKernelMembersMeaning (input :: rest) ((bytes input.name, meaning) :: meanings)
end

def SameAst (input : SourceAst) (output : KernelAst) : Prop :=
  ∃ meaning, AstSourceMeaning input meaning ∧ AstKernelMeaning output meaning

def SameAstMember (input : String × SourceAst) (output : KernelMember) : Prop :=
  bytes output.name = textBytes input.1 ∧ SameAst input.2 output.value

inductive FormSourceMeaning : SourceForm → TemplateAst.FormValue → Prop where
  | text (value : String) : FormSourceMeaning (.String value) (.text (textBytes value))
  | field (name : String) : FormSourceMeaning (.Field name) (.field (textBytes name))
  | json {value : SourceAst} {meaning : TemplateAst.Value} (same : AstSourceMeaning value meaning) :
      FormSourceMeaning (.Json value) (.json meaning)
  | echo : FormSourceMeaning .Echo .authorEcho

inductive FormKernelMeaning : KernelForm → TemplateAst.FormValue → Prop where
  | text (value : NativeVec Std.U8) : FormKernelMeaning (.String value) (.text (bytes value))
  | field (name : NativeVec Std.U8) : FormKernelMeaning (.Field name) (.field (bytes name))
  | json {value : KernelAst} {meaning : TemplateAst.Value} (same : AstKernelMeaning value meaning) :
      FormKernelMeaning (.Json value) (.json meaning)
  | echo : FormKernelMeaning .AuthorEcho .authorEcho

def SameForm (input : SourceForm) (output : KernelForm) : Prop :=
  ∃ meaning, FormSourceMeaning input meaning ∧ FormKernelMeaning output meaning

def SameFormMember (input : String × SourceForm) (output : KernelFormMember) : Prop :=
  bytes output.name = textBytes input.1 ∧ SameForm input.2 output.value

def SourceFormMemberMeaning (input : String × SourceForm) (meaning : List Nat × TemplateAst.FormValue) : Prop :=
  meaning.1 = textBytes input.1 ∧ FormSourceMeaning input.2 meaning.2

def KernelFormMemberMeaning (input : KernelFormMember) (meaning : List Nat × TemplateAst.FormValue) : Prop :=
  meaning.1 = bytes input.name ∧ FormKernelMeaning input.value meaning.2

inductive BodySourceMeaning : SourceBody → TemplateAst.Body → Prop where
  | json {input : SourceAst} {meaning : TemplateAst.Value} (same : AstSourceMeaning input meaning) :
      BodySourceMeaning (.Json input) (.json meaning)
  | form {members : SourceMap SourceForm} {meaning : List (List Nat × TemplateAst.FormValue)}
      (same : List.Forall₂ SourceFormMemberMeaning members.entries.val meaning) :
      BodySourceMeaning (.Form members) (.form meaning)

inductive BodyKernelMeaning : KernelBody → TemplateAst.Body → Prop where
  | json {input : KernelAst} {meaning : TemplateAst.Value} (same : AstKernelMeaning input meaning) :
      BodyKernelMeaning (.Json input) (.json meaning)
  | form {members : NativeVec KernelFormMember} {meaning : List (List Nat × TemplateAst.FormValue)}
      (same : List.Forall₂ KernelFormMemberMeaning members.val meaning) :
      BodyKernelMeaning (.Form members) (.form meaning)

def SameBody (input : SourceBody) (output : KernelBody) : Prop :=
  ∃ meaning, BodySourceMeaning input meaning ∧ BodyKernelMeaning output meaning

theorem ast_values_have_original_meaning {inputs : List SourceAst} {outputs : List KernelAst}
    (copied : List.Forall₂ SameAst inputs outputs) :
    ∃ meanings, AstSourceValuesMeaning inputs meanings ∧ AstKernelValuesMeaning outputs meanings := by
  induction copied with
  | nil => exact ⟨[], .nil, .nil⟩
  | cons head tail ih =>
      obtain ⟨meaning, source, target⟩ := head
      obtain ⟨meanings, sources, targets⟩ := ih
      exact ⟨meaning :: meanings, .cons source sources, .cons target targets⟩

theorem ast_members_have_original_meaning {inputs : List (String × SourceAst)} {outputs : List KernelMember}
    (copied : List.Forall₂ SameAstMember inputs outputs) :
    ∃ meanings, AstSourceMembersMeaning inputs meanings ∧ AstKernelMembersMeaning outputs meanings := by
  induction copied with
  | nil => exact ⟨[], .nil, .nil⟩
  | cons head tail ih =>
      obtain ⟨sameName, meaning, source, target⟩ := head
      obtain ⟨meanings, sources, targets⟩ := ih
      refine ⟨_, .cons source sources, ?_⟩
      simpa only [sameName] using AstKernelMembersMeaning.cons target targets

theorem form_members_have_original_meaning {inputs : List (String × SourceForm)} {outputs : List KernelFormMember}
    (copied : List.Forall₂ SameFormMember inputs outputs) :
    ∃ meanings, List.Forall₂ SourceFormMemberMeaning inputs meanings ∧
      List.Forall₂ KernelFormMemberMeaning outputs meanings := by
  induction copied with
  | nil => exact ⟨[], .nil, .nil⟩
  | cons head tail ih =>
      obtain ⟨sameName, meaning, source, target⟩ := head
      obtain ⟨meanings, sources, targets⟩ := ih
      exact ⟨_ :: meanings, .cons ⟨rfl, source⟩ sources, .cons ⟨sameName.symm, target⟩ targets⟩

theorem ast_member_names_preserved {inputs : List (String × SourceAst)} {outputs : List KernelMember}
    (copied : List.Forall₂ SameAstMember inputs outputs) :
    outputs.map (fun member => bytes member.name) = inputs.map (fun pair => textBytes pair.1) := by
  induction copied with
  | nil => rfl
  | cons head tail ih => simp only [List.map_cons, head.1, ih]

theorem form_member_names_preserved {inputs : List (String × SourceForm)} {outputs : List KernelFormMember}
    (copied : List.Forall₂ SameFormMember inputs outputs) :
    outputs.map (fun member => bytes member.name) = inputs.map (fun pair => textBytes pair.1) := by
  induction copied with
  | nil => rfl
  | cons head tail ih => simp only [List.map_cons, head.1, ih]

mutual
  /-- Original meaning is determined by the original constructor and complete
  source sequence. An existential model witness cannot choose new field names,
  drop children or change literal bytes. -/
  theorem ast_source_meaning_unique {input : SourceAst} {first second : TemplateAst.Value}
      (left : AstSourceMeaning input first) (right : AstSourceMeaning input second) : first = second := by
    cases left with
    | text value => cases right; rfl
    | integer value => cases right; rfl
    | boolean value => cases right; rfl
    | field name => cases right; rfl
    | object children =>
        cases right with
        | object other => exact congrArg TemplateAst.Value.object (ast_source_members_meaning_unique children other)
    | array children =>
        cases right with
        | array other => exact congrArg TemplateAst.Value.array (ast_source_values_meaning_unique children other)
    | echo => cases right; rfl
  termination_by structural left

  theorem ast_source_values_meaning_unique {inputs : List SourceAst} {first second : List TemplateAst.Value}
      (left : AstSourceValuesMeaning inputs first) (right : AstSourceValuesMeaning inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [ast_source_meaning_unique head otherHead, ast_source_values_meaning_unique tail otherTail]
  termination_by structural left

  theorem ast_source_members_meaning_unique {inputs : List (String × SourceAst)}
      {first second : List (List Nat × TemplateAst.Value)}
      (left : AstSourceMembersMeaning inputs first) (right : AstSourceMembersMeaning inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [ast_source_meaning_unique head otherHead, ast_source_members_meaning_unique tail otherTail]
  termination_by structural left
end

theorem form_source_meaning_unique {input : SourceForm} {first second : TemplateAst.FormValue}
    (left : FormSourceMeaning input first) (right : FormSourceMeaning input second) : first = second := by
  cases left with
  | text value => cases right; rfl
  | field name => cases right; rfl
  | json same =>
      cases right with
      | json other => exact congrArg TemplateAst.FormValue.json (ast_source_meaning_unique same other)
  | echo => cases right; rfl

theorem form_source_members_meaning_unique {inputs : List (String × SourceForm)}
    {first second : List (List Nat × TemplateAst.FormValue)}
    (left : List.Forall₂ SourceFormMemberMeaning inputs first)
    (right : List.Forall₂ SourceFormMemberMeaning inputs second) : first = second := by
  induction left generalizing second with
  | nil => cases right; rfl
  | cons head tail ih =>
      cases right with
      | cons otherHead otherTail =>
          have sameHead : _ := Prod.ext (head.1.trans otherHead.1.symm)
            (form_source_meaning_unique head.2 otherHead.2)
          rw [sameHead, ih otherTail]

theorem body_source_meaning_unique {input : SourceBody} {first second : TemplateAst.Body}
    (left : BodySourceMeaning input first) (right : BodySourceMeaning input second) : first = second := by
  cases left with
  | json same =>
      cases right with
      | json other => exact congrArg TemplateAst.Body.json (ast_source_meaning_unique same other)
  | form same =>
      cases right with
      | form other => exact congrArg TemplateAst.Body.form (form_source_members_meaning_unique same other)

end Auths.Product.NativeCompiler
