import Auths.Product.FullJsonValue
import Auths.Product.NativeCompilerValues

/-!
Lossless meaning of the complete native serde_json value carrier. This is a
representation relation, not a lexer/serde contract: a post-decoding map cannot
witness the original occurrence list before duplicate keys were collapsed.
In particular, this relation never substitutes the schema converter's erased
unsupported values for original booleans, nulls or floating-point bit patterns.
-/
namespace Auths.Product.NativeCompiler

def fullNumber (number : JsonNumber) : FullJsonValue.Number :=
  match number with
  | .PosInt value => .unsigned value.val
  | .NegInt value => .signed value.val
  | .Float bits => .floating bits.val

mutual
  inductive FullJsonMeaning : Json → FullJsonValue.Value → Prop where
    | null : FullJsonMeaning .Null .null
    | boolean (value : Bool) : FullJsonMeaning (.Bool value) (.boolean value)
    | number (value : JsonNumber) : FullJsonMeaning (.Number value) (.number (fullNumber value))
    | text (value : String) : FullJsonMeaning (.String value) (.text value)
    | array {values : NativeVec Json} {output : List FullJsonValue.Value}
        (children : FullJsonMeanings values.val output) :
        FullJsonMeaning (.Array values) (.array output)
    | object {members : JsonMap} {output : List (String × FullJsonValue.Value)}
        (children : FullJsonMemberMeanings members.entries.val output) :
        FullJsonMeaning (.Object members) (.object output)

  inductive FullJsonMeanings : List Json → List FullJsonValue.Value → Prop where
    | nil : FullJsonMeanings [] []
    | cons {value : Json} {meaning : FullJsonValue.Value}
        {rest : List Json} {meanings : List FullJsonValue.Value}
        (head : FullJsonMeaning value meaning) (tail : FullJsonMeanings rest meanings) :
        FullJsonMeanings (value :: rest) (meaning :: meanings)

  inductive FullJsonMemberMeanings : List (String × Json) → List (String × FullJsonValue.Value) → Prop where
    | nil : FullJsonMemberMeanings [] []
    | cons {name : String} {value : Json} {meaning : FullJsonValue.Value}
        {rest : List (String × Json)} {meanings : List (String × FullJsonValue.Value)}
        (head : FullJsonMeaning value meaning) (tail : FullJsonMemberMeanings rest meanings) :
        FullJsonMemberMeanings ((name, value) :: rest) ((name, meaning) :: meanings)
end

private theorem collect_full_values (inputs : List Json)
    (children : ∀ value ∈ inputs, ∃ meaning, FullJsonMeaning value meaning) :
    ∃ meanings, FullJsonMeanings inputs meanings := by
  revert children
  induction inputs with
  | nil => intro _; exact ⟨[], .nil⟩
  | cons value rest ih =>
      intro children
      obtain ⟨meaning, head⟩ := children value (by simp)
      obtain ⟨meanings, tail⟩ := ih (fun child member => children child (by simp [member]))
      exact ⟨meaning :: meanings, .cons head tail⟩

private theorem collect_full_members (inputs : List (String × Json))
    (children : ∀ pair ∈ inputs, ∃ meaning, FullJsonMeaning pair.2 meaning) :
    ∃ meanings, FullJsonMemberMeanings inputs meanings := by
  revert children
  induction inputs with
  | nil => intro _; exact ⟨[], .nil⟩
  | cons pair rest ih =>
      intro children
      obtain ⟨meaning, head⟩ := children pair (by simp)
      obtain ⟨meanings, tail⟩ := ih (fun child member => children child (by simp [member]))
      cases pair
      exact ⟨_, .cons head tail⟩

/-- Native representability suffices to construct a full meaning; no parser,
canonicalizer, schema acceptance or desired output is assumed. -/
theorem full_json_meaning_exists (input : Json) (bounded : JsonBounds input) :
    ∃ meaning, FullJsonMeaning input meaning := by
  induction bounded with
  | null => exact ⟨.null, .null⟩
  | boolean value => exact ⟨.boolean value, .boolean value⟩
  | number value => exact ⟨.number (fullNumber value), .number value⟩
  | text value _ => exact ⟨.text value, .text value⟩
  | array values _ ih =>
      obtain ⟨meanings, children⟩ := collect_full_values values.val ih
      exact ⟨.array meanings, .array children⟩
  | object members _ _ ih =>
      obtain ⟨meanings, children⟩ := collect_full_members members.entries.val ih
      exact ⟨.object meanings, .object children⟩

mutual
  theorem full_json_meaning_unique {input : Json} {first second : FullJsonValue.Value}
      (left : FullJsonMeaning input first) (right : FullJsonMeaning input second) : first = second := by
    cases left with
    | null => cases right; rfl
    | boolean value => cases right; rfl
    | number value => cases right; rfl
    | text value => cases right; rfl
    | array children =>
        cases right with
        | array other => exact congrArg FullJsonValue.Value.array (full_json_values_unique children other)
    | object children =>
        cases right with
        | object other => exact congrArg FullJsonValue.Value.object (full_json_members_unique children other)
  termination_by structural left

  theorem full_json_values_unique {inputs : List Json} {first second : List FullJsonValue.Value}
      (left : FullJsonMeanings inputs first) (right : FullJsonMeanings inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [full_json_meaning_unique head otherHead, full_json_values_unique tail otherTail]
  termination_by structural left

  theorem full_json_members_unique {inputs : List (String × Json)} {first second : List (String × FullJsonValue.Value)}
      (left : FullJsonMemberMeanings inputs first) (right : FullJsonMemberMeanings inputs second) : first = second := by
    cases left with
    | nil => cases right; rfl
    | cons head tail =>
        cases right with
        | cons otherHead otherTail =>
            rw [full_json_meaning_unique head otherHead, full_json_members_unique tail otherTail]
  termination_by structural left
end

theorem full_json_values_keep_count {inputs : List Json} {outputs : List FullJsonValue.Value}
    (meaning : FullJsonMeanings inputs outputs) : outputs.length = inputs.length := by
  induction meaning with
  | nil => rfl
  | cons _ _ ih => simp only [List.length_cons, ih]

theorem full_json_members_keep_names {inputs : List (String × Json)} {outputs : List (String × FullJsonValue.Value)}
    (meaning : FullJsonMemberMeanings inputs outputs) : outputs.map Prod.fst = inputs.map Prod.fst := by
  induction meaning with
  | nil => rfl
  | cons _ _ ih => simp only [List.map_cons, ih]

theorem full_json_members_keep_count {inputs : List (String × Json)} {outputs : List (String × FullJsonValue.Value)}
    (meaning : FullJsonMemberMeanings inputs outputs) : outputs.length = inputs.length := by
  induction meaning with
  | nil => rfl
  | cons _ _ ih => simp only [List.length_cons, ih]

theorem full_json_float_keeps_bits (bits : Aeneas.Std.U64) (meaning : FullJsonValue.Value)
    (original : FullJsonMeaning (.Number (.Float bits)) meaning) :
    meaning = .number (.floating bits.val) := by
  cases original
  rfl

end Auths.Product.NativeCompiler
