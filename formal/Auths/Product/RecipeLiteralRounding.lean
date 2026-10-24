import Auths.Product.JcsIntegerRounding
import Auths.Product.TemplateAstShapeCoverage

/-!
The existing admitted literal range earns exact integer-to-binary64 rounding.
This covers source literals, including nested JSON in forms. It says nothing
about all recipe counters, command-schema annotations, float rendering or the
verified argument values substituted for field references.
-/
namespace Auths.Product.RecipeLiteralRounding
open TemplateAst

inductive JsonLiteralsExact : Value → Prop where
  | text (value : RequestConstruction.Bytes) : JsonLiteralsExact (.text value)
  | integer (value : Int) (exact : JcsIntegerRounding.integer value = value) : JsonLiteralsExact (.integer value)
  | boolean (value : Bool) : JsonLiteralsExact (.boolean value)
  | field (name : RequestConstruction.Bytes) : JsonLiteralsExact (.field name)
  | authorEcho : JsonLiteralsExact .authorEcho
  | array (values : List Value) (children : ∀ value ∈ values, JsonLiteralsExact value) : JsonLiteralsExact (.array values)
  | object (members : List (RequestConstruction.Bytes × Value))
      (children : ∀ member ∈ members, JsonLiteralsExact member.2) : JsonLiteralsExact (.object members)

def FormLiteralsExact : FormValue → Prop
  | .json value => JsonLiteralsExact value
  | .text _ | .field _ | .authorEcho => True

def BodyLiteralsExact : Body → Prop
  | .json value => JsonLiteralsExact value
  | .form members => ∀ member ∈ members, FormLiteralsExact member.2

theorem admitted_leaf_has_exact_literals (value : Value) (admitted : LeafAdmission value) : JsonLiteralsExact value := by
  cases admitted with
  | text value _ => exact .text value
  | integer value safe => exact .integer value (JcsIntegerRounding.integer_exact_in_safe_range value safe)
  | boolean value => exact .boolean value
  | field name _ => exact .field name

theorem admitted_json_shape_has_exact_literals (depth : Nat) (value : Value)
    (echo : Option (List RequestConstruction.Bytes)) (shape : JsonShape depth value echo) : JsonLiteralsExact value := by
  induction shape with
  | leaf depth value within admitted => exact admitted_leaf_has_exact_literals value admitted
  | array depth values within count children ih => exact .array values ih
  | object depth members echo route within keys routeMeaning children ih => exact .object members ih

theorem admitted_form_shape_has_exact_literals (value : FormValue) (shape : FormShape value) : FormLiteralsExact value := by
  cases shape with
  | text _ _ | field _ _ => trivial
  | json value allowed shape => exact admitted_json_shape_has_exact_literals _ _ _ shape

theorem admitted_body_shape_has_exact_literals (body : Body) (echo : Option Echo)
    (shape : BodyShape body echo) : BodyLiteralsExact body := by
  cases shape with
  | json value pointer shape => exact admitted_json_shape_has_exact_literals _ _ _ shape
  | form members insertion keys echo children =>
      intro member present
      exact admitted_form_shape_has_exact_literals member.2 (children member present)

end Auths.Product.RecipeLiteralRounding
