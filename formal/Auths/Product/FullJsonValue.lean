import Auths.Product.StrictJsonMemberCorrectness

/-!
Complete decoded JSON data for parser/serializer provenance. Unlike the
uniqueness skeleton, this preserves every scalar, complete String key/value,
number representation and original member/array order. Floating payloads are
the original IEEE-754 bits; interpreting/formatting them is a separate pinned
ordinary-library obligation. No canonical bytes or parser success is assumed.
-/
namespace Auths.Product.FullJsonValue

inductive Number where
  | unsigned (value : Nat)
  | signed (value : Int)
  | floating (bits : Nat)
  deriving DecidableEq

inductive Value where
  | null
  | boolean (value : Bool)
  | number (value : Number)
  | text (value : String)
  | array (children : List Value)
  | object (members : List (String × Value))
  deriving DecidableEq

mutual
  def memberShape : Value → StrictJsonMembers.Value
    | .null | .boolean _ | .number _ | .text _ => .scalar
    | .array children => .array (valueShapes children)
    | .object members => .object (memberShapes members)
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def valueShapes : List Value → List StrictJsonMembers.Value
    | [] => []
    | value :: rest => memberShape value :: valueShapes rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def memberShapes : List (String × Value) → List (String × StrictJsonMembers.Value)
    | [] => []
    | (name, value) :: rest => (name, memberShape value) :: memberShapes rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

theorem member_shape_keeps_complete_keys (members : List (String × Value)) :
    (memberShapes members).map Prod.fst = members.map Prod.fst := by
  induction members with
  | nil => rfl
  | cons member rest ih => cases member; simp [memberShapes, ih]

theorem value_shapes_keep_count (values : List Value) : (valueShapes values).length = values.length := by
  induction values <;> simp_all [valueShapes]

theorem member_shapes_keep_count (members : List (String × Value)) : (memberShapes members).length = members.length := by
  induction members with
  | nil => rfl
  | cons member rest ih => cases member; simp [memberShapes, ih]

/-- Only uniqueness consumes the scalar-erasing view. All later typed serde,
canonicalization and commitment claims must use the full original value. -/
def checkMembers (value : Value) : Except Unit Unit := StrictJsonMembers.check (memberShape value)

theorem uniqueness_check_exact (value : Value) :
    checkMembers value = .ok () ↔ StrictJsonMembers.Unique (memberShape value) :=
  StrictJsonMembers.check_acceptance_exact _

end Auths.Product.FullJsonValue
