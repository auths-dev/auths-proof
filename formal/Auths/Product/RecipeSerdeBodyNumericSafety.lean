import Auths.Product.NativeRecipeNumericDomains
import Auths.Product.RecipeSerdeBody
import Auths.Product.FullJsonNumericSafety

/-!
Full typed-body serialization retains the admitted original integer domain.
All arrays/maps and same-native-value probe literals participate. No target
canonical bytes, serializer success flag or unrelated schema/body is supplied.
RecipeSerdeSourceNumericSafety composes this through every source field.
Native Serialize/cast/ryu adequacy remains outer work.
-/
namespace Auths.Product.RecipeSerde
open NativeCompiler

private theorem tagged_safe (kind : String) (members : List (String × Json))
    (each : ∀ member ∈ members, FullJsonNumericSafety.SafeNumbers member.2) :
    FullJsonNumericSafety.SafeNumbers (tagged kind members) := by
  apply FullJsonNumericSafety.SafeNumbers.object
  intro member present
  rcases List.mem_cons.mp present with rfl | later
  · exact .text kind
  · exact each member later

mutual
  theorem ast_encoding_keeps_numeric_safety {input : SourceAst} {output : Json}
      (encoded : AstEncoding input output) (safe : AstIntegersSafe input) : FullJsonNumericSafety.SafeNumbers output := by
    cases encoded with
    | text value => exact tagged_safe _ _ (by simp; exact .text value)
    | integer value =>
        cases safe with
        | integer value bounded =>
            exact tagged_safe _ _ (by simp; exact .signed value.val (RecipeNumericRounding.signed_absolute_safe_range _ bounded))
    | boolean value => exact tagged_safe _ _ (by simp; exact .boolean value)
    | field name => exact tagged_safe _ _ (by simp; exact .text name)
    | echo => cases safe
    | array children =>
        cases safe with
        | array values each =>
            apply tagged_safe
            simp only [List.mem_singleton, forall_eq]
            exact .array _ (ast_values_encoding_keeps_numeric_safety children each)
    | object children =>
        cases safe with
        | object members each =>
            apply tagged_safe
            simp only [List.mem_singleton, forall_eq]
            exact .object _ (ast_members_encoding_keeps_numeric_safety children each)
  termination_by structural encoded

  theorem ast_values_encoding_keeps_numeric_safety {inputs : List SourceAst} {outputs : List Json}
      (encoded : AstEncodings inputs outputs) (safe : ∀ input ∈ inputs, AstIntegersSafe input) :
      ∀ output ∈ outputs, FullJsonNumericSafety.SafeNumbers output := by
    cases encoded with
    | nil => simp
    | cons head tail =>
        intro output present
        rcases List.mem_cons.mp present with rfl | later
        · exact ast_encoding_keeps_numeric_safety head (safe _ (by simp))
        · exact ast_values_encoding_keeps_numeric_safety tail
            (fun input member => safe input (List.mem_cons_of_mem _ member)) output later
  termination_by structural encoded

  theorem ast_members_encoding_keeps_numeric_safety {inputs : List (String × SourceAst)}
      {outputs : List (String × Json)} (encoded : AstMemberEncodings inputs outputs)
      (safe : ∀ input ∈ inputs, AstIntegersSafe input.2) :
      ∀ output ∈ outputs, FullJsonNumericSafety.SafeNumbers output.2 := by
    cases encoded with
    | nil => simp
    | cons head tail =>
        intro output present
        rcases List.mem_cons.mp present with rfl | later
        · exact ast_encoding_keeps_numeric_safety head (safe _ (by simp))
        · exact ast_members_encoding_keeps_numeric_safety tail
            (fun input member => safe input (List.mem_cons_of_mem _ member)) output later
  termination_by structural encoded
end

theorem form_encoding_keeps_numeric_safety {input : SourceForm} {output : Json}
    (encoded : FormEncoding input output) (safe : NativeCompiler.FormIntegersSafe input) : FullJsonNumericSafety.SafeNumbers output := by
  cases encoded with
  | text value => exact tagged_safe _ _ (by simp; exact .text value)
  | field name => exact tagged_safe _ _ (by simp; exact .text name)
  | echo => exact False.elim safe
  | json child =>
      apply tagged_safe
      simp only [List.mem_singleton, forall_eq]
      exact ast_encoding_keeps_numeric_safety child safe

theorem form_members_encoding_keeps_numeric_safety {inputs : List (String × SourceForm)}
    {outputs : List (String × Json)} (encoded : List.Forall₂ FormMemberEncoding inputs outputs)
    (safe : ∀ input ∈ inputs, NativeCompiler.FormIntegersSafe input.2) :
    ∀ output ∈ outputs, FullJsonNumericSafety.SafeNumbers output.2 := by
  revert safe
  induction encoded with
  | nil => intro _; simp
  | cons head tail ih =>
      intro safe output present
      rcases List.mem_cons.mp present with rfl | later
      · exact form_encoding_keeps_numeric_safety head.2 (safe _ (by simp))
      · exact ih (fun input member => safe input (List.mem_cons_of_mem _ member)) output later

theorem body_encoding_keeps_numeric_safety {input : SourceBody} {output : Json}
    (encoded : BodyEncoding input output) (safe : NativeCompiler.BodyIntegersSafe input) : FullJsonNumericSafety.SafeNumbers output := by
  cases encoded with
  | json child =>
      apply tagged_safe
      simp only [List.mem_singleton, forall_eq]
      exact ast_encoding_keeps_numeric_safety child safe
  | form children =>
      apply tagged_safe
      simp only [List.mem_singleton, forall_eq]
      exact .object _ (form_members_encoding_keeps_numeric_safety children safe)

/-- The admitted probe's complete original generic JSON value is safe. Float
bits (including integral-looking values and signed zero) never become integers
through the schema view or canonical formatting. -/
theorem original_probe_literal_keeps_numeric_safety (input : NativeCompiler.Json) (full : Json)
    (original : FullJsonMeaning input full)
    (admitted : RecipeCredentialAdmission.ProbeLiteralAdmitted (ruleProbeLiteral input)) :
    FullJsonNumericSafety.SafeNumbers full := by
  cases original with
  | null => simp [ruleProbeLiteral, RecipeCredentialAdmission.ProbeLiteralAdmitted] at admitted
  | boolean value => exact .boolean value
  | text value => exact .text value
  | array _ | object _ => simp [ruleProbeLiteral, RecipeCredentialAdmission.ProbeLiteralAdmitted] at admitted
  | number value =>
      cases value with
      | Float bits => simp [ruleProbeLiteral, RecipeCredentialAdmission.ProbeLiteralAdmitted] at admitted
      | PosInt value =>
          change value.val ≤ 9007199254740991 at admitted
          exact .unsigned value.val admitted
      | NegInt value =>
          exact .signed value.val (RecipeNumericRounding.signed_absolute_safe_range value.val admitted)

end Auths.Product.RecipeSerde
