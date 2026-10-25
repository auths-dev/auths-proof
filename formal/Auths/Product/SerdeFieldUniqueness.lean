import Auths.Product.SerdeFieldLayout
import Auths.Product.FullJsonUniqueness

/-!
Original recursive uniqueness survives field selection, actual missing-field
defaults, map/positional normalization and internal-tag content extraction in
the independent serde language. No decoding or serialization success is an
argument. Native derive adequacy must still establish this field language.
-/
namespace Auths.Product.SerdeFieldLayout
open FullJsonValue (Unique)

theorem lookup_keeps_unique_value (name : String) (members : List (String × Json))
    (each : ∀ member ∈ members, Unique member.2) (value : Json)
    (found : lookup name members = some value) : Unique value := by
  revert each found
  induction members with
  | nil => intro each found; simp [lookup] at found
  | cons first rest ih =>
      intro each found
      by_cases same : first.1 = name
      · simp [lookup, same] at found
        subst value
        exact each first (by simp)
      · exact ih (fun member present => each member (List.mem_cons_of_mem _ present))
          (by simpa [lookup, same] using found)

theorem missing_value_is_unique (missing : Missing) (value : Json)
    (found : missing.value = .ok value) : Unique value := by
  cases missing <;> simp [Missing.value] at found
  all_goals subst value; simp

theorem fill_map_keeps_unique_values {K : Type} (fields : List (Field K))
    (members : List (String × Json)) (each : ∀ member ∈ members, Unique member.2)
    (values : List Json) (filled : fillMap fields members = .ok values) :
    ∀ value ∈ values, Unique value := by
  have assigned := fill_map_preserves_original_values fields members values filled
  induction assigned with
  | nil => simp
  | cons assignment tail ih =>
      intro value present
      rcases List.mem_cons.mp present with rfl | later
      · rcases assignment with found | ⟨_, default⟩
        · exact lookup_keeps_unique_value _ members each _ found
        · exact missing_value_is_unique _ _ default
      · exact ih value later

theorem fill_sequence_keeps_unique_values {K : Type} (fields : List (Field K))
    (inputs values : List Json) (each : ∀ input ∈ inputs, Unique input)
    (filled : fillSequence fields inputs = .ok values) : ∀ value ∈ values, Unique value := by
  induction fields generalizing inputs values with
  | nil => cases inputs <;> simp [fillSequence] at filled; subst values; simp
  | cons field rest ih =>
      cases inputs with
      | nil =>
          cases defaultAt : field.onMissing.value with
          | error error => simp [fillSequence, defaultAt] at filled
          | ok first =>
              cases tailAt : fillSequence rest [] with
              | error error => simp [fillSequence, defaultAt, tailAt] at filled
              | ok tail =>
                  simp [fillSequence, defaultAt, tailAt] at filled
                  subst values
                  intro value present
                  rcases List.mem_cons.mp present with rfl | later
                  · exact missing_value_is_unique _ _ defaultAt
                  · exact ih [] tail (by simp) tailAt value later
      | cons first tail =>
          cases tailAt : fillSequence rest tail with
          | error error => simp [fillSequence, tailAt] at filled
          | ok output =>
              simp [fillSequence, tailAt] at filled
              subst values
              intro value present
              rcases List.mem_cons.mp present with rfl | later
              · exact each first (by simp)
              · exact ih tail output (fun child member => each child (List.mem_cons_of_mem _ member))
                  tailAt value later

theorem normalization_keeps_unique_values {K : Type} (fields : List (Field K))
    (input : Json) (values : List Json) (original : Unique input)
    (filled : normalize fields input = .ok values) : ∀ value ∈ values, Unique value := by
  cases input with
  | object members =>
      unfold normalize at filled
      split at filled
      · exact fill_map_keeps_unique_values fields members
          ((FullJsonValue.object_unique_iff _).mp original).2 values filled
      · simp at filled
  | array inputs =>
      exact fill_sequence_keeps_unique_values fields inputs values
        ((FullJsonValue.array_unique_iff _).mp original) filled
  | null | boolean _ | number _ | text _ => simp [normalize] at filled

theorem internal_keeps_unique_content (mode : Mode) (names : List String) (input content : Json)
    (name : String) (original : Unique input)
    (selected : internal mode names input = .ok (name, content)) : Unique content := by
  cases input with
  | object members =>
      cases found : lookup "kind" members with
      | none => simp [internal, found] at selected
      | some tag =>
          cases tagAt : identifier mode names tag with
          | error error => simp [internal, found, tagAt] at selected
          | ok tagName =>
              simp [internal, found, tagAt] at selected
              rcases selected with ⟨_, rfl⟩
              exact FullJsonValue.object_filter_preserves_uniqueness _ _ original
  | array values =>
      cases values with
      | nil => simp [internal] at selected
      | cons tag rest =>
          cases tagAt : identifier mode names tag with
          | error error => simp [internal, tagAt] at selected
          | ok tagName =>
              simp [internal, tagAt] at selected
              rcases selected with ⟨_, rfl⟩
              exact FullJsonValue.array_tail_preserves_uniqueness tag rest original
  | null | boolean _ | number _ | text _ => simp [internal] at selected

end Auths.Product.SerdeFieldLayout
