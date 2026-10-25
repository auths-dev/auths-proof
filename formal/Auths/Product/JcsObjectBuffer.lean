import Auths.Product.JcsUtf16Keys
import Auths.Product.JcsStringEncoding
import Mathlib.Data.List.Sort
import Mathlib.Data.List.Lex

/-!
Independent semantics of the pinned canonicalizer's object set. Every
property retains all three actual data columns: sorting key, original key
bytes and original value bytes. Equal sorting keys retain the first property.
The list representation specifies set contents/order, not BTreeSet's tree
shape, comparison count, allocation cost or actual implementation adequacy.
No Auths serialization/parser callback or claimed canonical result is supplied.
-/
namespace Auths.Product.JcsObjectBuffer

abbrev Bytes := List Nat

structure Property where
  sortingKey : List Nat
  keyBytes : Bytes
  valueBytes : Bytes
  deriving DecidableEq

def before (left right : Property) : Prop := left.sortingKey ≤ right.sortingKey

instance : DecidableRel before := fun _ _ => inferInstanceAs (Decidable (_ ≤ _))
instance : Std.Total before := ⟨fun left right => le_total left.sortingKey right.sortingKey⟩
instance : IsTrans Property before := ⟨fun _ _ _ first second => le_trans first second⟩

/-- This closed reference uses a membership scan and ordered insertion to
specify the standard set's observable result. Its complexity is not a bound
for the native tree implementation. -/
def insert (property : Property) (table : List Property) : Bool × List Property :=
  if property.sortingKey ∈ table.map Property.sortingKey then (false, table)
  else (true, table.orderedInsert before property)

def collectFrom (table : List Property) : List Property → List Property
  | [] => table
  | first :: rest => collectFrom (insert first table).2 rest

def collect (properties : List Property) : List Property := collectFrom [] properties

def originalProperty (name : String) (value : Bytes) : Property :=
  ⟨JcsUtf16Keys.key name, JcsStringEncoding.quoted name, value⟩

def originalProperties (members : List (String × Bytes)) : List Property :=
  members.map (fun member => originalProperty member.1 member.2)

theorem insertion_success_iff (property : Property) (table : List Property) :
    (insert property table).1 = true ↔ property.sortingKey ∉ table.map Property.sortingKey := by
  by_cases found : property.sortingKey ∈ table.map Property.sortingKey <;> simp [insert, found]

theorem duplicate_keeps_first_property (property : Property) (table : List Property)
    (found : property.sortingKey ∈ table.map Property.sortingKey) : insert property table = (false, table) := by
  simp [insert, found]

theorem fresh_insert_keeps_all_columns (property : Property) (table : List Property)
    (fresh : property.sortingKey ∉ table.map Property.sortingKey) :
    (insert property table).2.Perm (property :: table) := by
  simp only [insert, if_neg fresh]
  exact List.perm_orderedInsert before property table

theorem fresh_insert_increases_count (property : Property) (table : List Property)
    (fresh : property.sortingKey ∉ table.map Property.sortingKey) :
    (insert property table).2.length = table.length + 1 := by
  have length := (fresh_insert_keeps_all_columns property table fresh).length_eq
  simpa only [List.length_cons, Nat.add_comm] using length

theorem insertion_preserves_order (property : Property) (table : List Property)
    (ordered : table.Pairwise before) : (insert property table).2.Pairwise before := by
  by_cases found : property.sortingKey ∈ table.map Property.sortingKey
  · simpa [insert, found] using ordered
  · simpa [insert, found] using ordered.orderedInsert property table

theorem fresh_insert_preserves_unique_keys (property : Property) (table : List Property)
    (fresh : property.sortingKey ∉ table.map Property.sortingKey)
    (unique : (table.map Property.sortingKey).Nodup) :
    ((insert property table).2.map Property.sortingKey).Nodup :=
  ((fresh_insert_keeps_all_columns property table fresh).map Property.sortingKey).symm.nodup
    (List.nodup_cons.mpr ⟨fresh, unique⟩)

/-- Original prefix and unprocessed input must jointly have unique sorting
keys. This earns every fresh insertion, complete property permutation and
payload retention; the output is not assumed to have the desired contents. -/
theorem collection_keeps_all_columns (table input : List Property)
    (unique : ((table ++ input).map Property.sortingKey).Nodup) :
    (collectFrom table input).Perm (table ++ input) := by
  induction input generalizing table with
  | nil => simp [collectFrom]
  | cons first rest ih =>
      have move : (table ++ first :: rest).Perm (first :: (table ++ rest)) := List.perm_middle
      have headUnique := (move.map Property.sortingKey).nodup unique
      have absent : first.sortingKey ∉ (table ++ rest).map Property.sortingKey :=
        (List.nodup_cons.mp headUnique).1
      have fresh : first.sortingKey ∉ table.map Property.sortingKey := by
        intro found
        apply absent
        rw [List.map_append]
        exact List.mem_append_left _ found
      have step : ((insert first table).2 ++ rest).Perm (table ++ first :: rest) :=
        ((fresh_insert_keeps_all_columns first table fresh).append_right rest).trans move.symm
      have nextUnique := (step.symm.map Property.sortingKey).nodup unique
      exact (ih (insert first table).2 nextUnique).trans step

theorem collection_preserves_order (table input : List Property) (ordered : table.Pairwise before) :
    (collectFrom table input).Pairwise before := by
  induction input generalizing table with
  | nil => exact ordered
  | cons first rest ih => exact ih _ (insertion_preserves_order first table ordered)

theorem collected_members_are_original (input : List Property)
    (unique : (input.map Property.sortingKey).Nodup) : (collect input).Perm input := by
  simpa only [collect, List.nil_append] using collection_keeps_all_columns [] input unique

theorem collected_keys_remain_unique (input : List Property)
    (unique : (input.map Property.sortingKey).Nodup) :
    ((collect input).map Property.sortingKey).Nodup :=
  ((collected_members_are_original input unique).symm.map Property.sortingKey).nodup unique

theorem collected_properties_are_ordered (input : List Property) : (collect input).Pairwise before :=
  collection_preserves_order [] input (by simp)

theorem ordered_unique_permutation_exact (left right : List Property)
    (unique : (left.map Property.sortingKey).Nodup) (orderedLeft : left.Pairwise before)
    (orderedRight : right.Pairwise before) (same : left.Perm right) : left = right := by
  apply List.Perm.eq_of_pairwise (le := before) _ orderedLeft orderedRight same
  intro first second firstAt secondAt forward backward
  exact List.inj_on_of_nodup_map unique firstAt (same.mem_iff.mpr secondAt) (le_antisymm forward backward)

theorem collection_is_permutation_invariant (left right : List Property)
    (unique : (left.map Property.sortingKey).Nodup) (same : left.Perm right) : collect left = collect right := by
  have rightUnique := (same.map Property.sortingKey).nodup unique
  apply ordered_unique_permutation_exact _ _ (collected_keys_remain_unique left unique)
    (collected_properties_are_ordered left) (collected_properties_are_ordered right)
  exact (collected_members_are_original left unique).trans
    (same.trans (collected_members_are_original right rightUnique).symm)

theorem original_property_equality_exact (leftName rightName : String) (leftValue rightValue : Bytes) :
    originalProperty leftName leftValue = originalProperty rightName rightValue ↔
      leftName = rightName ∧ leftValue = rightValue := by
  constructor
  · intro same
    exact ⟨JcsUtf16Keys.key_injective (congrArg Property.sortingKey same), congrArg Property.valueBytes same⟩
  · rintro ⟨rfl, rfl⟩; rfl

theorem original_names_earn_unique_sorting_keys (members : List (String × Bytes))
    (unique : (members.map Prod.fst).Nodup) :
    ((originalProperties members).map Property.sortingKey).Nodup := by
  simpa only [originalProperties, originalProperty, List.map_map, Function.comp_def] using
    JcsUtf16Keys.distinct_members_have_distinct_keys members unique

theorem original_collection_keeps_all_columns (members : List (String × Bytes))
    (unique : (members.map Prod.fst).Nodup) :
    (collect (originalProperties members)).Perm (originalProperties members) :=
  collected_members_are_original _ (original_names_earn_unique_sorting_keys members unique)

theorem original_collection_keeps_count (members : List (String × Bytes))
    (unique : (members.map Prod.fst).Nodup) : (collect (originalProperties members)).length = members.length := by
  simpa only [originalProperties, List.length_map] using (original_collection_keeps_all_columns members unique).length_eq

theorem original_collection_is_permutation_invariant (left right : List (String × Bytes))
    (unique : (left.map Prod.fst).Nodup) (same : left.Perm right) :
    collect (originalProperties left) = collect (originalProperties right) :=
  collection_is_permutation_invariant _ _ (original_names_earn_unique_sorting_keys left unique)
    (same.map (fun member => originalProperty member.1 member.2))

end Auths.Product.JcsObjectBuffer
