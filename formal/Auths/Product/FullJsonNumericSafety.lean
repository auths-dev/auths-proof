import Auths.Product.FullJsonSchemaView
import Auths.Product.ProfileSchemaNumericSafety

/-!
Lift admitted schema-number bounds to the same FULL original JSON value.
The schema view is used only to earn admission consequences; it is never a
canonical preimage. Every original array/object child and number is retained.
Floating numbers are outside this safe-integer property, including ±0.0.
-/
namespace Auths.Product.FullJsonNumericSafety
open FullJsonValue

inductive SafeNumbers : Value → Prop where
  | null : SafeNumbers .null
  | boolean (value : Bool) : SafeNumbers (.boolean value)
  | text (value : String) : SafeNumbers (.text value)
  | signed (value : Int) (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991) :
      SafeNumbers (.number (.signed value))
  | unsigned (value : Nat) (safe : value ≤ 9007199254740991) : SafeNumbers (.number (.unsigned value))
  | array (values : List Value) (children : ∀ value ∈ values, SafeNumbers value) : SafeNumbers (.array values)
  | object (members : List (String × Value)) (children : ∀ member ∈ members, SafeNumbers member.2) :
      SafeNumbers (.object members)

theorem schema_number_safety_keeps_original_number (number : Number)
    (safe : ProfileSchemaNumericSafety.SafeNumbers (schemaNumber number)) : SafeNumbers (.number number) := by
  cases number with
  | signed value =>
      cases safe with
      | signed value bounded => exact .signed value bounded
  | unsigned value =>
      by_cases small : value ≤ 9223372036854775807
      · simp only [schemaNumber, if_pos small] at safe
        cases safe with
        | signed original bounded => exact .unsigned value (by omega)
      · simp only [schemaNumber, if_neg small] at safe
        cases safe with
        | unsigned original bounded => exact .unsigned value bounded
  | floating bits => cases safe

mutual
  theorem schema_safety_keeps_full_original (source : Value)
      (safe : ProfileSchemaNumericSafety.SafeNumbers (schemaView source)) : SafeNumbers source := by
    cases source with
    | null => cases safe
    | boolean value => cases safe
    | number value => exact schema_number_safety_keeps_original_number value safe
    | text value => exact .text value
    | array values =>
        cases safe with
        | array projected each => exact .array values (schema_values_safety_keeps_original values each)
    | object members =>
        cases safe with
        | object projected each => exact .object members (schema_members_safety_keeps_original members each)
  termination_by sizeOf source
  decreasing_by all_goals simp_wf <;> omega

  theorem schema_values_safety_keeps_original (values : List Value)
      (safe : ∀ projected ∈ schemaValues values, ProfileSchemaNumericSafety.SafeNumbers projected) :
      ∀ original ∈ values, SafeNumbers original := by
    cases values with
    | nil => simp
    | cons first rest =>
        intro original present
        rcases List.mem_cons.mp present with rfl | later
        · exact schema_safety_keeps_full_original first (safe _ (by simp [schemaValues]))
        · exact schema_values_safety_keeps_original rest
            (fun value member => safe value (by simp [schemaValues, member])) original later
  termination_by sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  theorem schema_members_safety_keeps_original (members : List (String × Value))
      (safe : ∀ projected ∈ schemaMembers members, ProfileSchemaNumericSafety.SafeNumbers projected.2) :
      ∀ original ∈ members, SafeNumbers original.2 := by
    cases members with
    | nil => simp
    | cons first rest =>
        intro original present
        rcases List.mem_cons.mp present with rfl | later
        · exact schema_safety_keeps_full_original first.2 (safe _ (by cases first; simp [schemaMembers]))
        · exact schema_members_safety_keeps_original rest
            (fun value member => safe value (by cases first; simp [schemaMembers, member])) original later
  termination_by sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

theorem parsed_full_schema_has_safe_numbers (source : Value) (fields : List FieldProjection.Field)
    (parsed : ProfileSchema.parseRoot (schemaView source) = some fields) : SafeNumbers source :=
  schema_safety_keeps_full_original source
    (ProfileSchemaNumericSafety.parsed_root_has_safe_numbers _ fields parsed)

theorem native_schema_from_same_original_is_safe (source : NativeCompiler.Json) (full : Value)
    (view : ProfileSchema.Value) (fields : List FieldProjection.Field)
    (original : NativeCompiler.FullJsonMeaning source full) (sameSource : NativeCompiler.JsonMeaning source view)
    (parsed : ProfileSchema.parseRoot view = some fields) : SafeNumbers full := by
  have same := NativeCompiler.full_json_schema_view_agrees original sameSource
  rw [same] at parsed
  exact parsed_full_schema_has_safe_numbers full fields parsed

inductive NumberIn (number : Number) : Value → Prop where
  | here : NumberIn number (.number number)
  | array {values : List Value} {child : Value} (present : child ∈ values) (inside : NumberIn number child) :
      NumberIn number (.array values)
  | object {members : List (String × Value)} {child : String × Value}
      (present : child ∈ members) (inside : NumberIn number child.2) : NumberIn number (.object members)

def RoundingExact : Number → Prop
  | .signed value => JcsIntegerRounding.integer value = value
  | .unsigned value => JcsIntegerRounding.magnitude value = value
  | .floating _ => False

theorem every_original_number_rounds_exactly (source : Value) (safe : SafeNumbers source) (number : Number)
    (inside : NumberIn number source) : RoundingExact number := by
  revert safe
  induction inside with
  | here =>
      intro safe
      cases safe with
      | signed value bounded => exact JcsIntegerRounding.integer_exact_in_safe_range value bounded
      | unsigned value bounded => exact RecipeNumericRounding.unsigned_safe_rounding value bounded
  | array present inside ih =>
      intro safe
      cases safe with
      | array values each => exact ih (each _ present)
  | object present inside ih =>
      intro safe
      cases safe with
      | object members each => exact ih (each _ present)

theorem parsed_schema_every_number_rounds_exactly (source : Value) (fields : List FieldProjection.Field)
    (parsed : ProfileSchema.parseRoot (schemaView source) = some fields) :
    ∀ number, NumberIn number source → RoundingExact number :=
  every_original_number_rounds_exactly source (parsed_full_schema_has_safe_numbers source fields parsed)

end Auths.Product.FullJsonNumericSafety
