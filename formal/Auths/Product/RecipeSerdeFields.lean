import Auths.Product.RecipeSerdeSource
import Auths.Product.FullJsonUniqueness

/-!
Fixed serde field declarations with optional omission. Removing an absent
field preserves a sublist of the original declaration names; it cannot
introduce a duplicate or discard a present field's original value.
-/
namespace Auths.Product.RecipeSerde

def selectedFields : List (String × Option Json) → List (String × Json)
  | [] => []
  | (name, value) :: rest => optional name id value ++ selectedFields rest

def FieldUnique (field : String × Option Json) : Prop :=
  ∀ value, field.2 = some value → FullJsonValue.Unique value

@[simp] theorem present_field_unique (name : String) (value : Json) :
    FieldUnique (name, some value) ↔ FullJsonValue.Unique value := by simp [FieldUnique]

@[simp] theorem absent_field_unique (name : String) : FieldUnique (name, none) := by simp [FieldUnique]

theorem mapped_field_unique {T : Type} (name : String) (encode : T → Json) (input : Option T)
    (each : ∀ value, input = some value → FullJsonValue.Unique (encode value)) :
    FieldUnique (name, input.map encode) := by
  cases input with
  | none => simp [FieldUnique]
  | some original => simpa [FieldUnique] using each original rfl

@[simp] theorem optional_identity_map {T : Type} (name : String) (encode : T → Json) (input : Option T) :
    optional name id (input.map encode) = optional name encode input := by cases input <;> rfl

theorem selected_fields_append (left right : List (String × Option Json)) :
    selectedFields (left ++ right) = selectedFields left ++ selectedFields right := by
  induction left with
  | nil => rfl
  | cons first rest ih => cases first; simp only [List.cons_append, selectedFields, ih, List.append_assoc]

theorem selected_names_sublist (fields : List (String × Option Json)) :
    (selectedFields fields).map Prod.fst <+ fields.map Prod.fst := by
  induction fields with
  | nil => exact .refl []
  | cons first rest ih =>
      obtain ⟨name, value⟩ := first
      cases value with
      | none => simpa only [selectedFields, optional, List.nil_append, List.map_cons] using ih.cons name
      | some value => simpa only [selectedFields, optional, List.singleton_append, List.map_cons] using ih.cons_cons name

theorem selected_field_keeps_original_value (fields : List (String × Option Json))
    (member : String × Json) (present : member ∈ selectedFields fields) :
    ∃ field ∈ fields, field.1 = member.1 ∧ field.2 = some member.2 := by
  revert present
  induction fields with
  | nil => intro present; simp [selectedFields] at present
  | cons first rest ih =>
      intro present
      obtain ⟨name, value⟩ := first
      cases value with
      | none =>
          have later : member ∈ selectedFields rest := by simpa [selectedFields, optional] using present
          obtain ⟨field, belongs, same⟩ := ih later
          exact ⟨field, List.mem_cons_of_mem _ belongs, same⟩
      | some value =>
          have position : member = (name, value) ∨ member ∈ selectedFields rest := by
            simpa [selectedFields, optional] using present
          rcases position with rfl | later
          · exact ⟨_, by simp, rfl, rfl⟩
          · obtain ⟨field, belongs, same⟩ := ih later
            exact ⟨field, List.mem_cons_of_mem _ belongs, same⟩

theorem selected_fields_have_unique_objects (fields : List (String × Option Json))
    (names : (fields.map Prod.fst).Nodup) (each : ∀ field ∈ fields, FieldUnique field) :
    FullJsonValue.Unique (.object (selectedFields fields)) := by
  apply (FullJsonValue.object_unique_iff _).mpr
  refine ⟨(selected_names_sublist fields).nodup names, ?_⟩
  intro member present
  obtain ⟨field, declared, _, valueOriginal⟩ := selected_field_keeps_original_value fields member present
  exact each field declared member.2 valueOriginal

end Auths.Product.RecipeSerde
