import Auths.Product.NativeFullJsonMeaning

/-!
The independent schema-validation view is a projection of the full original
JSON data. It is intentionally lossy and must not be used for canonical bytes.
The native compatibility proofs below connect both relations on the SAME
original native value, so an unrelated schema witness cannot be substituted.
-/
namespace Auths.Product.FullJsonValue
open NativeCompiler

def schemaNumber : Number → ProfileSchema.Value
  | .unsigned value =>
      if value ≤ 9223372036854775807 then .signed (Int.ofNat value) else .unsigned value
  | .signed value => .signed value
  | .floating _ => .unsupported

mutual
  def schemaView : Value → ProfileSchema.Value
    | .null | .boolean _ => .unsupported
    | .number value => schemaNumber value
    | .text value => .text (textBytes value)
    | .array values => .array (schemaValues values)
    | .object members => .object (schemaMembers members)
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def schemaValues : List Value → List ProfileSchema.Value
    | [] => []
    | value :: rest => schemaView value :: schemaValues rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def schemaMembers : List (String × Value) → List (List Nat × ProfileSchema.Value)
    | [] => []
    | (name, value) :: rest => (textBytes name, schemaView value) :: schemaMembers rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

end Auths.Product.FullJsonValue

namespace Auths.Product.NativeCompiler

mutual
  theorem full_json_earns_schema_view {input : Json} {meaning : FullJsonValue.Value}
      (original : FullJsonMeaning input meaning) : JsonMeaning input (FullJsonValue.schemaView meaning) := by
    cases original with
    | null => exact .null
    | boolean value => exact .boolean value
    | number value =>
        cases value with
        | Float bits => exact .float bits
        | NegInt value => exact .negative value
        | PosInt value =>
            by_cases small : value.val ≤ 9223372036854775807
            · simpa only [FullJsonValue.schemaView, fullNumber, FullJsonValue.schemaNumber, if_pos small]
                using JsonMeaning.smallPositive value small
            · simpa only [FullJsonValue.schemaView, fullNumber, FullJsonValue.schemaNumber, if_neg small]
                using JsonMeaning.largePositive value (by omega)
    | text value => exact .text value
    | array children => exact .array (full_json_values_earn_schema_view children)
    | object children => exact .object (full_json_members_earn_schema_view children)
  termination_by structural original

  theorem full_json_values_earn_schema_view {inputs : List Json} {meanings : List FullJsonValue.Value}
      (original : FullJsonMeanings inputs meanings) : JsonMeanings inputs (FullJsonValue.schemaValues meanings) := by
    cases original with
    | nil => exact .nil
    | cons head tail => exact .cons (full_json_earns_schema_view head) (full_json_values_earn_schema_view tail)
  termination_by structural original

  theorem full_json_members_earn_schema_view {inputs : List (String × Json)}
      {meanings : List (String × FullJsonValue.Value)} (original : FullJsonMemberMeanings inputs meanings) :
      MemberMeanings inputs (FullJsonValue.schemaMembers meanings) := by
    cases original with
    | nil => exact .nil
    | cons head tail => exact .cons (full_json_earns_schema_view head) (full_json_members_earn_schema_view tail)
  termination_by structural original
end

/-- Existing independent schema meaning and the full-data projection agree
only because both originate at exactly this native JSON value. -/
theorem full_json_schema_view_agrees {input : Json} {full : FullJsonValue.Value} {schema : ProfileSchema.Value}
    (original : FullJsonMeaning input full) (schemaOriginal : JsonMeaning input schema) :
    schema = FullJsonValue.schemaView full :=
  json_meaning_unique schemaOriginal (full_json_earns_schema_view original)

end Auths.Product.NativeCompiler
