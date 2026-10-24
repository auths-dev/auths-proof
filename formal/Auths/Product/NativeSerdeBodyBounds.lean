import Auths.Product.NativeSerdeBounds

/-!
The compiler's existing body representation domains follow from complete
decoded carrier bounds. Invalid/unbound/oversized templates and author Echo
remain represented; none of these theorems grants recipe admission.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std

mutual
  theorem ast_bounds_from_carrier (input : SourceAst) (bounded : CarrierBounds (.internal .value) input) :
      AstBounds input := by
    cases bounded with
    | internal name input fields =>
      cases input with
      | String value =>
          cases fields with
          | cons head tail =>
              cases head with
              | text value fits => exact .text value fits
      | Integer value => exact .integer value
      | Boolean value => exact .boolean value
      | Field name =>
          cases fields with
          | cons head tail =>
              cases head with
              | text name fits => exact .field name fits
      | Object members =>
          cases fields with
          | cons head tail =>
              cases head with
              | map value children ordered =>
                  have each := ast_members_bounds_from_carrier children
                  exact .object members (fun pair member => (each pair member).1)
                    (fun pair member => (each pair member).2)
      | Array values =>
          cases fields with
          | cons head tail =>
              cases head with
              | vector value children => exact .array values (ast_values_bounds_from_carrier children)
      | Echo => exact .echo
  termination_by structural bounded

  theorem ast_values_bounds_from_carrier {values : List SourceAst}
      (bounded : ElementsBounded (.internal .value) values) : ∀ value ∈ values, AstBounds value := by
    cases bounded with
    | nil => simp
    | cons head tail =>
        intro value member
        rcases List.mem_cons.mp member with rfl | later
        · exact ast_bounds_from_carrier _ head
        · exact ast_values_bounds_from_carrier tail value later
  termination_by structural bounded

  theorem ast_members_bounds_from_carrier {members : List (String × SourceAst)}
      (bounded : MembersBounded (.internal .value) members) :
      ∀ pair ∈ members, TextFits pair.1 ∧ AstBounds pair.2 := by
    cases bounded with
    | nil => simp
    | cons fits head tail =>
        intro pair member
        rcases List.mem_cons.mp member with rfl | later
        · exact ⟨fits, ast_bounds_from_carrier _ head⟩
        · exact ast_members_bounds_from_carrier tail pair later
  termination_by structural bounded
end

theorem form_bounds_from_carrier (input : SourceForm) (bounded : CarrierBounds (.internal .form) input) :
    FormBounds input := by
  cases bounded with
  | internal name input fields =>
    cases input with
    | String value =>
        cases fields with
        | cons head tail =>
            cases head with
            | text value fits => exact .text value fits
    | Field name =>
        cases fields with
        | cons head tail =>
            cases head with
            | text name fits => exact .field name fits
    | Json value =>
        cases fields with
        | cons head tail => exact .json value (ast_bounds_from_carrier value head)
    | Echo => exact .echo

theorem form_members_bounds_from_carrier {members : List (String × SourceForm)}
    (bounded : MembersBounded (.internal .form) members) :
    ∀ pair ∈ members, TextFits pair.1 ∧ FormBounds pair.2 := by
  induction bounded with
  | nil => simp
  | cons fits head tail ih =>
      intro pair member
      rcases List.mem_cons.mp member with rfl | later
      · exact ⟨fits, form_bounds_from_carrier _ head⟩
      · exact ih pair later

theorem body_bounds_from_carrier (input : SourceBody) (bounded : CarrierBounds (.internal .body) input) :
    BodyBounds input := by
  cases bounded with
  | internal name input fields =>
    cases input with
    | Json value =>
        cases fields with
        | cons head tail => exact .json value (ast_bounds_from_carrier value head)
    | Form members =>
        cases fields with
        | cons head tail =>
            cases head with
            | map value children ordered =>
                have each := form_members_bounds_from_carrier children
                exact .form members (fun pair member => (each pair member).1)
                  (fun pair member => (each pair member).2)

theorem decoded_ast_earns_representation_bounds {mode : SerdeFieldLayout.Mode} {raw : RawJson} (input : SourceAst)
    (original : Decode mode (.internal .value) raw input) : AstBounds input :=
  ast_bounds_from_carrier input (native_decode_earns_carrier_bounds original)

theorem decoded_body_earns_representation_bounds {mode : SerdeFieldLayout.Mode} {raw : RawJson} (input : SourceBody)
    (original : Decode mode (.internal .body) raw input) : BodyBounds input :=
  body_bounds_from_carrier input (native_decode_earns_carrier_bounds original)

end Auths.Product.NativeSerde
