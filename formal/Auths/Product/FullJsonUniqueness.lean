import Auths.Product.FullJsonValue
import Mathlib.Data.List.Nodup

/-!
Uniqueness of full JSON values, with complete names and original scalar
payloads retained. This is exactly the existing strict-member property through
memberShape, not an additional accepted-input flag or a canonical byte model.
-/
namespace Auths.Product.FullJsonValue

def Unique (input : Value) : Prop := StrictJsonMembers.Unique (memberShape input)

private theorem value_shapes_are_map (values : List Value) :
    valueShapes values = values.map memberShape := by
  induction values <;> simp_all [valueShapes]

private theorem member_shapes_are_map (members : List (String × Value)) :
    memberShapes members = members.map (fun member => (member.1, memberShape member.2)) := by
  induction members with
  | nil => rfl
  | cons first rest ih => cases first; simp [memberShapes, ih]

@[simp] theorem null_unique : Unique .null := .scalar
@[simp] theorem boolean_unique (value : Bool) : Unique (.boolean value) := .scalar
@[simp] theorem number_unique (value : Number) : Unique (.number value) := .scalar
@[simp] theorem text_unique (value : String) : Unique (.text value) := .scalar

@[simp] theorem array_unique_iff (values : List Value) :
    Unique (.array values) ↔ ∀ value ∈ values, Unique value := by
  unfold Unique
  rw [memberShape, value_shapes_are_map]
  constructor
  · intro original
    cases original with
    | array children each =>
        intro value member
        exact each _ (List.mem_map.mpr ⟨value, member, rfl⟩)
  · intro each
    apply StrictJsonMembers.Unique.array
    intro child member
    obtain ⟨value, original, rfl⟩ := List.mem_map.mp member
    exact each value original

@[simp] theorem object_unique_iff (members : List (String × Value)) :
    Unique (.object members) ↔ (members.map Prod.fst).Nodup ∧
      ∀ member ∈ members, Unique member.2 := by
  unfold Unique
  rw [memberShape, member_shapes_are_map]
  constructor
  · intro original
    cases original with
    | object members keys each =>
        refine ⟨by simpa only [List.map_map, Function.comp_def] using keys, ?_⟩
        intro member present
        exact each _ (List.mem_map.mpr ⟨member, present, rfl⟩)
  · rintro ⟨keys, each⟩
    apply StrictJsonMembers.Unique.object
    · simpa only [List.map_map, Function.comp_def] using keys
    · intro child member
      obtain ⟨original, present, rfl⟩ := List.mem_map.mp member
      exact each original present

theorem check_earns_full_uniqueness (input : Value) (checked : checkMembers input = .ok ()) :
    Unique input := (uniqueness_check_exact input).mp checked

theorem object_filter_preserves_uniqueness (members : List (String × Value)) (keep : String × Value → Bool)
    (original : Unique (.object members)) : Unique (.object (members.filter keep)) := by
  obtain ⟨keys, each⟩ := (object_unique_iff members).mp original
  apply (object_unique_iff _).mpr
  refine ⟨((List.filter_sublist (p := keep)).map Prod.fst).nodup keys, ?_⟩
  intro member present
  exact each member (List.mem_filter.mp present).1

theorem array_tail_preserves_uniqueness (head : Value) (tail : List Value)
    (original : Unique (.array (head :: tail))) : Unique (.array tail) := by
  apply (array_unique_iff _).mpr
  intro value present
  exact (array_unique_iff _).mp original value (List.mem_cons_of_mem _ present)

end Auths.Product.FullJsonValue
