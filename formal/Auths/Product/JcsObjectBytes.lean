import Auths.Product.JcsObjectBuffer
import Mathlib.Algebra.BigOperators.Group.List.Basic

/-!
Complete object framing from the original owned property buffers: braces,
commas, colons, key bytes and value bytes. Children are their complete already
serialized bytes, not placeholders or schema projections. These definitions
do not establish child serialization, nested formatter-stack adequacy, native
I/O behavior, aggregate allocation/time or a whole-source bound by themselves.
-/
namespace Auths.Product.JcsObjectBytes
open JcsObjectBuffer

def BytesBounded (bytes : Bytes) : Prop := ∀ byte ∈ bytes, byte < 256

def renderProperty (property : Property) : Bytes := property.keyBytes ++ 58 :: property.valueBytes

def renderTail : List Property → Bytes
  | [] => []
  | first :: rest => 44 :: (renderProperty first ++ renderTail rest)

def renderMembers : List Property → Bytes
  | [] => []
  | first :: rest => renderProperty first ++ renderTail rest

def renderObject (properties : List Property) : Bytes := 123 :: (renderMembers properties ++ [125])

def originalObject (members : List (String × Bytes)) : Bytes :=
  renderObject (collect (originalProperties members))

def propertySize (property : Property) : Nat := property.keyBytes.length + 1 + property.valueBytes.length

def propertyCost (property : Property) : Nat := property.keyBytes.length + property.valueBytes.length + 2

theorem property_retains_complete_buffers (property : Property) :
    renderProperty property = property.keyBytes ++ [58] ++ property.valueBytes := rfl

theorem property_length_exact (property : Property) : (renderProperty property).length = propertySize property := by
  simp only [renderProperty, propertySize, List.length_append, List.length_cons]
  omega

theorem tail_length_exact (properties : List Property) :
    (renderTail properties).length = (properties.map propertySize).sum + properties.length := by
  induction properties with
  | nil => rfl
  | cons first rest ih =>
      simp only [renderTail, List.length_cons, List.length_append, property_length_exact,
        List.map_cons, List.sum_cons, ih]
      omega

theorem tail_cost_exact (properties : List Property) :
    (renderTail properties).length = (properties.map propertyCost).sum := by
  induction properties with
  | nil => rfl
  | cons first rest ih =>
      simp only [renderTail, List.length_cons, List.length_append, property_length_exact,
        propertySize, propertyCost, List.map_cons, List.sum_cons, ih]
      omega

theorem member_length_exact (properties : List Property) :
    (renderMembers properties).length = (properties.map propertySize).sum + (properties.length - 1) := by
  cases properties with
  | nil => rfl
  | cons first rest =>
      simp only [renderMembers, List.length_append, property_length_exact, tail_length_exact,
        List.map_cons, List.sum_cons, List.length_cons]
      omega

theorem object_length_exact (properties : List Property) :
    (renderObject properties).length = 2 + (properties.map propertySize).sum + (properties.length - 1) := by
  simp only [renderObject, List.length_cons, List.length_append, List.length_singleton, member_length_exact]
  omega

theorem object_length_upper_bound (properties : List Property) :
    (renderObject properties).length ≤ 2 + (properties.map propertyCost).sum := by
  cases properties with
  | nil => simp [renderObject, renderMembers]
  | cons first rest =>
      simp only [renderObject, renderMembers, List.length_cons, List.length_append,
        List.length_singleton, property_length_exact, tail_cost_exact, List.map_cons, List.sum_cons,
        propertySize, propertyCost]
      omega

theorem property_bytes_bounded (property : Property) (key : BytesBounded property.keyBytes)
    (value : BytesBounded property.valueBytes) : BytesBounded (renderProperty property) := by
  intro byte member
  simp only [renderProperty, List.mem_append, List.mem_cons] at member
  rcases member with inKey | rfl | inValue
  · exact key byte inKey
  · decide
  · exact value byte inValue

theorem tail_bytes_bounded (properties : List Property)
    (each : ∀ property ∈ properties, BytesBounded property.keyBytes ∧ BytesBounded property.valueBytes) :
    BytesBounded (renderTail properties) := by
  revert each
  induction properties with
  | nil => simp [renderTail, BytesBounded]
  | cons first rest ih =>
      intro each byte member
      have head := property_bytes_bounded first (each first (by simp)).1 (each first (by simp)).2
      simp only [renderTail, List.mem_cons, List.mem_append] at member
      rcases member with rfl | inHead | inTail
      · decide
      · exact head byte inHead
      · exact ih (fun property present => each property (List.mem_cons_of_mem _ present)) byte inTail

theorem object_bytes_bounded (properties : List Property)
    (each : ∀ property ∈ properties, BytesBounded property.keyBytes ∧ BytesBounded property.valueBytes) :
    BytesBounded (renderObject properties) := by
  have members : BytesBounded (renderMembers properties) := by
    cases properties with
    | nil => simp [renderMembers, BytesBounded]
    | cons first rest =>
        intro byte member
        have head := property_bytes_bounded first (each first (by simp)).1 (each first (by simp)).2
        simp only [renderMembers, List.mem_append] at member
        rcases member with inHead | inTail
        · exact head byte inHead
        · exact tail_bytes_bounded rest
            (fun property present => each property (List.mem_cons_of_mem _ present)) byte inTail
  intro byte member
  simp only [renderObject, List.mem_cons, List.mem_append, List.mem_singleton] at member
  rcases member with rfl | inMembers | rfl
  · decide
  · exact members byte inMembers
  · decide

theorem original_object_preserves_byte_bounds (members : List (String × Bytes))
    (unique : (members.map Prod.fst).Nodup) (each : ∀ member ∈ members, BytesBounded member.2) :
    BytesBounded (originalObject members) := by
  apply object_bytes_bounded
  intro property present
  have original := (original_collection_keeps_all_columns members unique).mem_iff.mp present
  obtain ⟨member, memberAt, rfl⟩ := List.mem_map.mp original
  exact ⟨JcsStringEncoding.quoted_bytes_bounded member.1, each member memberAt⟩

theorem original_object_length_upper_bound (members : List (String × Bytes))
    (unique : (members.map Prod.fst).Nodup) :
    (originalObject members).length ≤ 2 +
      (members.map (fun member => (JcsStringEncoding.quoted member.1).length + member.2.length + 2)).sum := by
  have output := object_length_upper_bound (collect (originalProperties members))
  have preserved := ((original_collection_keeps_all_columns members unique).map propertyCost).sum_eq
  rw [preserved] at output
  simpa only [originalObject, originalProperties, originalProperty, List.map_map, propertyCost, Function.comp_def] using output

private theorem original_string_cost_bound (members : List (String × Bytes)) :
    (members.map (fun member => (JcsStringEncoding.quoted member.1).length + member.2.length + 2)).sum ≤
      (members.map (fun member => 6 * (NativeCompiler.textBytes member.1).length + member.2.length + 4)).sum := by
  induction members with
  | nil => exact Nat.le_refl _
  | cons first rest ih =>
      have key := JcsStringEncoding.quoted_length_relative_to_original_bytes first.1
      simp only [List.map_cons, List.sum_cons]
      omega

/-- A compositional output bound from complete original name bytes and child
byte lengths. It does not yet derive child length or allocations/time from
raw source limits; positional source aliases can expand into named fields. -/
theorem original_object_length_relative_to_original_parts (members : List (String × Bytes))
    (unique : (members.map Prod.fst).Nodup) :
    (originalObject members).length ≤ 2 +
      (members.map (fun member => 6 * (NativeCompiler.textBytes member.1).length + member.2.length + 4)).sum :=
  (original_object_length_upper_bound members unique).trans (Nat.add_le_add_left (original_string_cost_bound members) 2)

theorem original_object_is_permutation_invariant (left right : List (String × Bytes))
    (unique : (left.map Prod.fst).Nodup) (same : left.Perm right) : originalObject left = originalObject right :=
  congrArg renderObject (original_collection_is_permutation_invariant left right unique same)

end Auths.Product.JcsObjectBytes
