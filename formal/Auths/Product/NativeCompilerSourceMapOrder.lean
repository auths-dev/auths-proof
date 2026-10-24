import Auths.Product.NativeCompilerSourceMemberKeys
import Auths.Product.RecipeBodyStructure

namespace Auths.Product.NativeCompiler

/-- Complete original native map representation, stated in the byte order
consumed by the body compiler. This is neither source admission nor an opaque
validator flag. The public serde/BTreeMap and ordinary String-order relation
must earn it; arbitrary foreign list carriers are intentionally not admitted. -/
inductive NativeAstMapOrder : SourceAst → Prop where
  | text (value : String) : NativeAstMapOrder (.String value)
  | integer (value : Aeneas.Std.I64) : NativeAstMapOrder (.Integer value)
  | boolean (value : Bool) : NativeAstMapOrder (.Boolean value)
  | field (name : String) : NativeAstMapOrder (.Field name)
  | echo : NativeAstMapOrder .Echo
  | array (values : NativeVec SourceAst)
      (children : ∀ value ∈ values.val, NativeAstMapOrder value) : NativeAstMapOrder (.Array values)
  | object (members : SourceMap SourceAst)
      (ordered : (sourceMemberNames members.entries.val).Pairwise (· < ·))
      (children : ∀ member ∈ members.entries.val, NativeAstMapOrder member.2) : NativeAstMapOrder (.Object members)

def NativeFormMapOrder : SourceForm → Prop
  | .Json value => NativeAstMapOrder value
  | .String _ | .Field _ | .Echo => True

def NativeBodyMapOrder : SourceBody → Prop
  | .Json value => NativeAstMapOrder value
  | .Form members => (sourceMemberNames members.entries.val).Pairwise (· < ·) ∧
      ∀ member ∈ members.entries.val, NativeFormMapOrder member.2

mutual
  theorem original_ast_map_order (input : SourceAst) (model : TemplateAst.Value)
      (original : AstSourceMeaning input model) (ordered : NativeAstMapOrder input) :
      RecipeRuleAdmission.JsonMemberOrder model := by
    cases original with
    | text value => exact .text _
    | integer value => exact .integer _
    | boolean value => exact .boolean _
    | field name => exact .field _
    | echo => exact .authorEcho
    | array children =>
        cases ordered with
        | array values each => exact .array _ (original_values_map_order _ _ children each)
    | object children =>
        cases ordered with
        | object members order each =>
            exact .object _ (by simpa only [source_ast_member_names _ _ children] using order)
              (original_members_map_order _ _ children each)
  termination_by structural original

  theorem original_values_map_order (inputs : List SourceAst) (models : List TemplateAst.Value)
      (original : AstSourceValuesMeaning inputs models) (ordered : ∀ input ∈ inputs, NativeAstMapOrder input) :
      ∀ model ∈ models, RecipeRuleAdmission.JsonMemberOrder model := by
    cases original with
    | nil => simp
    | cons head tail =>
        intro model member
        rcases List.mem_cons.mp member with same | later
        · subst model
          exact original_ast_map_order _ _ head (ordered _ (by simp))
        · exact original_values_map_order _ _ tail
            (fun input present => ordered input (List.mem_cons_of_mem _ present)) model later
  termination_by structural original

  theorem original_members_map_order (inputs : List (String × SourceAst))
      (models : List (List Nat × TemplateAst.Value)) (original : AstSourceMembersMeaning inputs models)
      (ordered : ∀ input ∈ inputs, NativeAstMapOrder input.2) :
      ∀ model ∈ models, RecipeRuleAdmission.JsonMemberOrder model.2 := by
    cases original with
    | nil => simp
    | cons head tail =>
        intro model member
        rcases List.mem_cons.mp member with same | later
        · subst model
          exact original_ast_map_order _ _ head (ordered _ (by simp))
        · exact original_members_map_order _ _ tail
            (fun input present => ordered input (List.mem_cons_of_mem _ present)) model later
  termination_by structural original
end

theorem original_form_map_order (input : SourceForm) (model : TemplateAst.FormValue)
    (original : FormSourceMeaning input model) (ordered : NativeFormMapOrder input) : RecipeRuleAdmission.FormMemberOrder model := by
  cases original with
  | text value => trivial
  | field name => trivial
  | echo => trivial
  | json same => exact original_ast_map_order _ _ same ordered

theorem original_form_members_map_order (inputs : List (String × SourceForm))
    (models : List (List Nat × TemplateAst.FormValue)) (original : List.Forall₂ SourceFormMemberMeaning inputs models)
    (ordered : ∀ input ∈ inputs, NativeFormMapOrder input.2) :
    ∀ model ∈ models, RecipeRuleAdmission.FormMemberOrder model.2 := by
  induction original with
  | nil => simp
  | cons head tail ih =>
      intro model member
      rcases List.mem_cons.mp member with same | later
      · subst model
        exact original_form_map_order _ _ head.2 (ordered _ (by simp))
      · exact ih (fun input present => ordered input (List.mem_cons_of_mem _ present)) model later

/-- Original native representation order transfers through the complete body
relation, including all nested objects and form JSON. An unrelated abstract
AST cannot earn order by supplying a different native map or dropping a child. -/
theorem original_body_map_order (input : SourceBody) (model : TemplateAst.Body)
    (original : BodySourceMeaning input model) (ordered : NativeBodyMapOrder input) : RecipeRuleAdmission.BodyMemberOrder model := by
  cases original with
  | json same => exact original_ast_map_order _ _ same ordered
  | form same =>
      exact ⟨by simpa only [source_form_member_names _ _ same] using ordered.1,
        original_form_members_map_order _ _ same ordered.2⟩

end Auths.Product.NativeCompiler
