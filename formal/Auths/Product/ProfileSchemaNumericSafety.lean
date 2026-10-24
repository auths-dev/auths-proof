import Auths.Product.ProfileSchemaCorrectness
import Auths.Product.RecipeNumericRounding

/-!
Every numeric occurrence of a completely admitted closed command schema is
in the safe integer domain. Exact key multiplicities and original members
prevent an unsupported/unsafe value from hiding in an ignored annotation.
This is a model/parser consequence, not native serde or ryu adequacy.
-/
namespace Auths.Product.ProfileSchemaNumericSafety
open ProfileSchema ScalarProjection FieldProjection RequestConstruction

inductive SafeNumbers : Value → Prop where
  | text (value : Bytes) : SafeNumbers (.text value)
  | signed (value : Int) (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991) : SafeNumbers (.signed value)
  | unsigned (value : Nat) (safe : value ≤ 9007199254740991) : SafeNumbers (.unsigned value)
  | array (values : List Value) (children : ∀ value ∈ values, SafeNumbers value) : SafeNumbers (.array values)
  | object (members : List (Bytes × Value)) (children : ∀ member ∈ members, SafeNumbers member.2) : SafeNumbers (.object members)

theorem numeric_safe_from_original_value (source : Value) (number : Int) (original : Numeric source number)
    (safe : -9007199254740991 ≤ number ∧ number ≤ 9007199254740991) : SafeNumbers source := by
  cases source with
  | signed value =>
      change value = number at original
      subst number
      exact .signed value safe
  | unsigned value =>
      change (value : Int) = number at original
      exact .unsigned value (by omega)
  | text _ | array _ | object _ | unsupported => simp [Numeric] at original

/-- Every actual member, not just a selected lookup, is accounted for by an
exact unique key declaration and that declaration's original value. -/
theorem exact_members_are_safe (members : List (Bytes × Value)) (expected : List Bytes)
    (keys : ExactKeys members expected) (unique : expected.Nodup)
    (known : ∀ name ∈ expected, ∃ value, member name members = some value ∧ SafeNumbers value) :
    ∀ original ∈ members, SafeNumbers original.2 := by
  have names := exact_keys_unique members expected keys unique
  intro original present
  have declared : original.1 ∈ expected := keys.mem_iff.mp (List.mem_map.mpr ⟨original, present, rfl⟩)
  obtain ⟨value, found, safe⟩ := known original.1 declared
  have originalValue := member_some_is_original members original.1 value found
  have same : original = (original.1, value) :=
    List.inj_on_of_nodup_map names present originalValue rfl
  have valueSame : original.2 = value := congrArg Prod.snd same
  simpa only [valueSame] using safe

private theorem enum_values_are_text (values : List Value) (variants : List Bytes)
    (paired : List.Forall₂ (fun value bytes => value = .text bytes) values variants) :
    ∀ value ∈ values, SafeNumbers value := by
  induction paired with
  | nil => simp
  | cons same tail ih =>
      intro value present
      rcases List.mem_cons.mp present with rfl | later
      · rw [same]; exact .text _
      · exact ih value later

theorem scalar_meaning_has_safe_numbers (source : Value) (schema : Schema)
    (meaning : ScalarMeaning source schema) : SafeNumbers source := by
  cases meaning with
  | string members minimum maximum low high keys kind lowAt highAt lowValue highValue bounds =>
      have lowSafe : -9007199254740991 ≤ (minimum : Int) ∧ (minimum : Int) ≤ 9007199254740991 := by
        unfold StringSchema at bounds
        omega
      have highSafe : -9007199254740991 ≤ (maximum : Int) ∧ (maximum : Int) ≤ 9007199254740991 := by
        unfold StringSchema at bounds
        omega
      apply SafeNumbers.object
      apply exact_members_are_safe members [kindKey, minimumKey, maximumKey] keys (by decide)
      intro name declared
      simp only [List.mem_cons, List.mem_singleton] at declared
      rcases declared with rfl | rfl | rfl
      · exact ⟨_, kind, .text _⟩
      · exact ⟨low, lowAt, numeric_safe_from_original_value low _ lowValue lowSafe⟩
      · exact ⟨high, highAt, numeric_safe_from_original_value high _ highValue highSafe⟩
  | integer members minimum maximum low high keys kind lowAt highAt lowValue highValue bounds =>
      have lowSafe : -9007199254740991 ≤ minimum ∧ minimum ≤ 9007199254740991 := by
        unfold IntegerSchema at bounds
        omega
      have highSafe : -9007199254740991 ≤ maximum ∧ maximum ≤ 9007199254740991 := by
        unfold IntegerSchema at bounds
        omega
      apply SafeNumbers.object
      apply exact_members_are_safe members [kindKey, minimumKey, maximumKey] keys (by decide)
      intro name declared
      simp only [List.mem_cons, List.mem_singleton] at declared
      rcases declared with rfl | rfl | rfl
      · exact ⟨_, kind, .text _⟩
      · exact ⟨low, lowAt, numeric_safe_from_original_value low _ lowValue lowSafe⟩
      · exact ⟨high, highAt, numeric_safe_from_original_value high _ highValue highSafe⟩
  | enumeration members values variants keys kind valuesAt paired valid =>
      apply SafeNumbers.object
      apply exact_members_are_safe members [typeKey, variantsKey] keys (by decide)
      intro name declared
      simp only [List.mem_cons, List.mem_singleton] at declared
      rcases declared with rfl | rfl
      · exact ⟨_, kind, .text _⟩
      · exact ⟨_, valuesAt, .array values (enum_values_are_text values variants paired)⟩
  | boolean members keys kind =>
      apply SafeNumbers.object
      apply exact_members_are_safe members [kindKey] keys (by decide)
      intro name declared
      have same : name = kindKey := by simpa using declared
      subst name
      exact ⟨_, kind, .text _⟩

theorem parsed_scalar_has_safe_numbers (source : Value) (schema : Schema) (parsed : parseScalar source = some schema) :
    SafeNumbers source := scalar_meaning_has_safe_numbers source schema (scalar_parse_sound source schema parsed)

theorem original_fields_have_safe_numbers (members : List (Bytes × Value)) (fields : List Field)
    (paired : List.Forall₂ FieldMeaning members fields) : ∀ original ∈ members, SafeNumbers original.2 := by
  induction paired with
  | nil => simp
  | cons head tail ih =>
      intro original present
      rcases List.mem_cons.mp present with rfl | later
      · exact scalar_meaning_has_safe_numbers _ _ head.2
      · exact ih original later

theorem root_meaning_has_safe_numbers (source : Value) (fields : List Field)
    (meaning : RootMeaning source fields) : SafeNumbers source := by
  obtain ⟨root, members, rfl, keys, kind, fieldsAt, nonempty, layout, paired⟩ := meaning
  apply SafeNumbers.object
  apply exact_members_are_safe root [kindKey, fieldsKey] keys (by decide)
  intro name declared
  simp only [List.mem_cons, List.mem_singleton] at declared
  rcases declared with rfl | rfl
  · exact ⟨_, kind, .text _⟩
  · exact ⟨_, fieldsAt, .object members (original_fields_have_safe_numbers members fields paired)⟩

theorem parsed_root_has_safe_numbers (source : Value) (fields : List Field) (parsed : parseRoot source = some fields) :
    SafeNumbers source := root_meaning_has_safe_numbers source fields ((root_parse_exact source fields).mp parsed)

end Auths.Product.ProfileSchemaNumericSafety
