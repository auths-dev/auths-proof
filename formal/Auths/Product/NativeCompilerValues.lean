import qualification.aeneas.generated.native_recipe.Types
import Auths.Product.ProfileSchema

/-!
Original decoded JSON meaning and exact native copying relations. Every name,
array child and object pair is represented; there is no truncating fuel, selected
field index, parser-success premise or expected lowered plan in these relations.
The only adapter domain below is native string representability. Source byte
limits/parser contracts must earn that domain at the eventual public entry.
-/
open Aeneas Aeneas.Std

namespace Auths.Product.NativeCompiler

abbrev Json := AuthsNativeRecipe.serde_json.value.Value
abbrev JsonNumber := AuthsNativeRecipe.serde_json.number.Number
abbrev NativeVec := AuthsNativeRecipe.alloc.vec.Vec
abbrev SchemaNode := AuthsNativeRecipe.auths_gateway_kernel.profile_schema.SchemaValue
abbrev SchemaMember := AuthsNativeRecipe.auths_gateway_kernel.profile_schema.SchemaMember
abbrev JsonMap := AuthsNativeRecipe.serde_json.map.Map String Json

def textBytes (text : String) : List Nat := text.toByteArray.toList.map UInt8.toNat
def bytes (value : NativeVec Std.U8) : List Nat := value.val.map (·.val)
def TextFits (text : String) : Prop := text.toByteArray.size ≤ Usize.max

/-- All finite original JSON shapes remain in the adapter's domain, including
malformed schema shapes, floats, nulls, booleans and arbitrary object order.
Schema acceptance is a later, independently specified operation. -/
inductive JsonBounds : Json → Prop where
  | null : JsonBounds .Null
  | boolean (value : Bool) : JsonBounds (.Bool value)
  | number (value : JsonNumber) : JsonBounds (.Number value)
  | text (value : String) (fits : TextFits value) : JsonBounds (.String value)
  | array (values : NativeVec Json)
      (children : ∀ value ∈ values.val, JsonBounds value) : JsonBounds (.Array values)
  | object (members : JsonMap)
      (names : ∀ pair ∈ members.entries.val, TextFits pair.1)
      (children : ∀ pair ∈ members.entries.val, JsonBounds pair.2) : JsonBounds (.Object members)

mutual
  /-- Exact copying from original JSON into the native kernel's schema AST. -/
  inductive JsonCopy : Json → SchemaNode → Prop where
    | null : JsonCopy .Null .Unsupported
    | boolean (value : Bool) : JsonCopy (.Bool value) .Unsupported
    | float (bits : Std.U64) : JsonCopy (.Number (.Float bits)) .Unsupported
    | negative (value : Std.I64) : JsonCopy (.Number (.NegInt value)) (.Signed value)
    | smallPositive (value : Std.U64) (signed : Std.I64)
        (fits : value.val ≤ 9223372036854775807)
        (same : signed.val = Int.ofNat value.val) :
        JsonCopy (.Number (.PosInt value)) (.Signed signed)
    | largePositive (value : Std.U64) (large : 9223372036854775807 < value.val) :
        JsonCopy (.Number (.PosInt value)) (.Unsigned value)
    | text (value : String) (output : NativeVec Std.U8)
        (same : bytes output = textBytes value) : JsonCopy (.String value) (.Text output)
    | array (values : NativeVec Json) (output : NativeVec SchemaNode)
        (children : JsonCopies values.val output.val) : JsonCopy (.Array values) (.Array output)
    | object (members : JsonMap) (output : NativeVec SchemaMember)
        (children : MemberCopies members.entries.val output.val) :
        JsonCopy (.Object members) (.Object output)

  inductive JsonCopies : List Json → List SchemaNode → Prop where
    | nil : JsonCopies [] []
    | cons {value : Json} {output : SchemaNode} {rest : List Json} {outputs : List SchemaNode} (head : JsonCopy value output)
        (tail : JsonCopies rest outputs) : JsonCopies (value :: rest) (output :: outputs)

  inductive MemberCopies : List (String × Json) → List SchemaMember → Prop where
    | nil : MemberCopies [] []
    | cons {name : String} {value : Json} {rest : List (String × Json)} {output : SchemaMember} {outputs : List SchemaMember}
        (sameName : bytes output.name = textBytes name)
        (head : JsonCopy value output.value) (tail : MemberCopies rest outputs) :
        MemberCopies ((name, value) :: rest) (output :: outputs)
end

mutual
  /-- Meaning of the original decoded source, independent of kernel outputs. -/
  inductive JsonMeaning : Json → ProfileSchema.Value → Prop where
    | null : JsonMeaning .Null .unsupported
    | boolean (value : Bool) : JsonMeaning (.Bool value) .unsupported
    | float (bits : Std.U64) : JsonMeaning (.Number (.Float bits)) .unsupported
    | negative (value : Std.I64) : JsonMeaning (.Number (.NegInt value)) (.signed value.val)
    | smallPositive (value : Std.U64) (fits : value.val ≤ 9223372036854775807) :
        JsonMeaning (.Number (.PosInt value)) (.signed (Int.ofNat value.val))
    | largePositive (value : Std.U64) (large : 9223372036854775807 < value.val) :
        JsonMeaning (.Number (.PosInt value)) (.unsigned value.val)
    | text (value : String) : JsonMeaning (.String value) (.text (textBytes value))
    | array {values : NativeVec Json} {output : List ProfileSchema.Value} (children : JsonMeanings values.val output) :
        JsonMeaning (.Array values) (.array output)
    | object {members : JsonMap} {output : List (List Nat × ProfileSchema.Value)} (children : MemberMeanings members.entries.val output) :
        JsonMeaning (.Object members) (.object output)

  inductive JsonMeanings : List Json → List ProfileSchema.Value → Prop where
    | nil : JsonMeanings [] []
    | cons {value : Json} {meaning : ProfileSchema.Value} {rest : List Json} {meanings : List ProfileSchema.Value} (head : JsonMeaning value meaning)
        (tail : JsonMeanings rest meanings) : JsonMeanings (value :: rest) (meaning :: meanings)

  inductive MemberMeanings : List (String × Json) → List (List Nat × ProfileSchema.Value) → Prop where
    | nil : MemberMeanings [] []
    | cons {name : String} {value : Json} {meaning : ProfileSchema.Value} {rest : List (String × Json)} {meanings : List (List Nat × ProfileSchema.Value)} (head : JsonMeaning value meaning)
        (tail : MemberMeanings rest meanings) :
        MemberMeanings ((name, value) :: rest) ((textBytes name, meaning) :: meanings)
end

mutual
  /-- Meaning of the copied kernel AST in the existing independent schema model. -/
  inductive SchemaMeaning : SchemaNode → ProfileSchema.Value → Prop where
    | unsupported : SchemaMeaning .Unsupported .unsupported
    | signed (value : Std.I64) : SchemaMeaning (.Signed value) (.signed value.val)
    | unsigned (value : Std.U64) : SchemaMeaning (.Unsigned value) (.unsigned value.val)
    | text (value : NativeVec Std.U8) : SchemaMeaning (.Text value) (.text (bytes value))
    | array {values : NativeVec SchemaNode} {output : List ProfileSchema.Value} (children : SchemaMeanings values.val output) :
        SchemaMeaning (.Array values) (.array output)
    | object {members : NativeVec SchemaMember} {output : List (List Nat × ProfileSchema.Value)} (children : SchemaMemberMeanings members.val output) :
        SchemaMeaning (.Object members) (.object output)

  inductive SchemaMeanings : List SchemaNode → List ProfileSchema.Value → Prop where
    | nil : SchemaMeanings [] []
    | cons {value : SchemaNode} {meaning : ProfileSchema.Value} {rest : List SchemaNode} {meanings : List ProfileSchema.Value} (head : SchemaMeaning value meaning)
        (tail : SchemaMeanings rest meanings) : SchemaMeanings (value :: rest) (meaning :: meanings)

  inductive SchemaMemberMeanings : List SchemaMember → List (List Nat × ProfileSchema.Value) → Prop where
    | nil : SchemaMemberMeanings [] []
    | cons {value : SchemaMember} {meaning : ProfileSchema.Value} {rest : List SchemaMember} {meanings : List (List Nat × ProfileSchema.Value)} (head : SchemaMeaning value.value meaning)
        (tail : SchemaMemberMeanings rest meanings) :
        SchemaMemberMeanings (value :: rest) ((bytes value.name, meaning) :: meanings)
end

mutual
  theorem copy_has_original_meaning {input : Json} {output : SchemaNode}
      (copied : JsonCopy input output) :
      ∃ meaning, JsonMeaning input meaning ∧ SchemaMeaning output meaning := by
    cases copied with
    | null => exact ⟨_, .null, .unsupported⟩
    | boolean value => exact ⟨_, .boolean value, .unsupported⟩
    | float bits => exact ⟨_, .float bits, .unsupported⟩
    | negative value => exact ⟨_, .negative value, .signed value⟩
    | smallPositive value signed fits same =>
        exact ⟨_, .smallPositive value fits, by simpa only [same] using SchemaMeaning.signed signed⟩
    | largePositive value large => exact ⟨_, .largePositive value large, .unsigned value⟩
    | text value output same =>
        exact ⟨_, .text value, by simpa only [same] using SchemaMeaning.text output⟩
    | array values output children =>
        obtain ⟨meanings, original, target⟩ := copies_have_original_meanings children
        exact ⟨_, .array original, .array target⟩
    | object members output children =>
        obtain ⟨meanings, original, target⟩ := members_have_original_meanings children
        exact ⟨_, .object original, .object target⟩
  termination_by structural copied

  theorem copies_have_original_meanings {inputs : List Json} {outputs : List SchemaNode}
      (copied : JsonCopies inputs outputs) :
      ∃ meanings, JsonMeanings inputs meanings ∧ SchemaMeanings outputs meanings := by
    cases copied with
    | nil => exact ⟨[], .nil, .nil⟩
    | cons head tail =>
        obtain ⟨meaning, original, target⟩ := copy_has_original_meaning head
        obtain ⟨meanings, originals, targets⟩ := copies_have_original_meanings tail
        exact ⟨meaning :: meanings, .cons original originals, .cons target targets⟩
  termination_by structural copied

  theorem members_have_original_meanings {inputs : List (String × Json)} {outputs : List SchemaMember}
      (copied : MemberCopies inputs outputs) :
      ∃ meanings, MemberMeanings inputs meanings ∧ SchemaMemberMeanings outputs meanings := by
    cases copied with
    | nil => exact ⟨[], .nil, .nil⟩
    | cons sameName head tail =>
        obtain ⟨meaning, original, target⟩ := copy_has_original_meaning head
        obtain ⟨meanings, originals, targets⟩ := members_have_original_meanings tail
        exact ⟨_, .cons original originals, by simpa only [sameName] using SchemaMemberMeanings.cons target targets⟩
  termination_by structural copied
end

theorem copied_array_count {inputs : List Json} {outputs : List SchemaNode}
    (copied : JsonCopies inputs outputs) : outputs.length = inputs.length := by
  induction copied with
  | nil => rfl
  | cons _ _ ih => simpa only [List.length_cons] using congrArg Nat.succ ih

theorem copied_member_names {inputs : List (String × Json)} {outputs : List SchemaMember}
    (copied : MemberCopies inputs outputs) :
    outputs.map (fun member => bytes member.name) = inputs.map (fun pair => textBytes pair.1) := by
  induction copied with
  | nil => rfl
  | cons sameName _ _ ih => simp only [List.map_cons, sameName, ih]

theorem copied_member_count {inputs : List (String × Json)} {outputs : List SchemaMember}
    (copied : MemberCopies inputs outputs) : outputs.length = inputs.length := by
  induction copied with
  | nil => rfl
  | cons _ _ _ ih => simpa only [List.length_cons] using congrArg Nat.succ ih

mutual
  theorem json_meaning_unique {input : Json} {first second : ProfileSchema.Value}
      (left : JsonMeaning input first) (right : JsonMeaning input second) : first = second := by
    cases left with
    | null => cases right; rfl
    | boolean value => cases right; rfl
    | float bits => cases right; rfl
    | negative value => cases right; rfl
    | smallPositive value fits =>
        cases right with
        | smallPositive _ _ => rfl
        | largePositive _ large => omega
    | largePositive value large =>
        cases right with
        | smallPositive _ fits => omega
        | largePositive _ _ => rfl
    | text value => cases right; rfl
    | array children =>
        cases right with
        | array other => exact congrArg ProfileSchema.Value.array (json_values_meaning_unique children other)
    | object children =>
        cases right with
        | object other => exact congrArg ProfileSchema.Value.object (json_members_meaning_unique children other)
  termination_by structural left

  theorem json_values_meaning_unique {inputs : List Json} {first second : List ProfileSchema.Value}
      (left : JsonMeanings inputs first) (right : JsonMeanings inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [json_meaning_unique head otherHead, json_values_meaning_unique tail otherTail]
  termination_by structural left

  theorem json_members_meaning_unique {inputs : List (String × Json)}
      {first second : List (List Nat × ProfileSchema.Value)}
      (left : MemberMeanings inputs first) (right : MemberMeanings inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [json_meaning_unique head otherHead, json_members_meaning_unique tail otherTail]
  termination_by structural left
end

end Auths.Product.NativeCompiler
