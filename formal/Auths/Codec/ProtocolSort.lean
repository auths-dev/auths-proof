import qualification.aeneas.generated.protocol_codec.Funs
import Mathlib.Data.List.Sort

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolSort
open Auths.Codec.StdModel

/- This exposes the already reviewed stateless-key standard sorting interface.
Its Rust boundary requires a pure lawful concrete Ord dictionary; the source
comparison law and order laws must be earned for each Auths element/key type.
No Auths constructor or full decoder is a foreign sorting implementation. -/

def relation {T : Type} (comparison : T → T → Ordering) (left right : T) : Prop :=
  (comparison left right).isLE = true

instance relation_decidable {T : Type} (comparison : T → T → Ordering) :
    DecidableRel (relation comparison) := fun _ _ => inferInstanceAs (Decidable (_ = _))

theorem identity_key_call {T : Type} (value : T) :
    (@AuthsProtocolCodec.identityKey T).call_mut () value = ok (value, ()) := rfl

theorem identity_insert {T : Type} (order : core.cmp.Ord T)
    (comparison : T → T → Ordering) (law : ∀ left right, order.cmp left right = ok (comparison left right))
    (item : T) (values : List T) :
    insertKeyValues AuthsProtocolCodec.identityKey order () item values =
      ok ⟨values.orderedInsert (relation comparison) item,
        List.orderedInsert_length (relation comparison) values item⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [insertKeyValues_cons]
    simp only [identity_key_call, law, bind_tc_ok]
    cases ordering : comparison item first <;>
      simp [ordering, List.orderedInsert_cons, relation, ih]

theorem identity_sort {T : Type} (order : core.cmp.Ord T)
    (comparison : T → T → Ordering) (law : ∀ left right, order.cmp left right = ok (comparison left right))
    (values : List T) :
    sortKeyValues AuthsProtocolCodec.identityKey order () values =
      ok ⟨values.insertionSort (relation comparison), List.length_insertionSort _ values⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [sortKeyValues_cons, ih]
    simp only [bind_tc_ok, identity_insert order comparison law]
    rfl

def keyedRelation {T K : Type} (view : T → K) (comparison : K → K → Ordering)
    (left right : T) : Prop := relation comparison (view left) (view right)

instance keyed_relation_decidable {T K : Type} (view : T → K)
    (comparison : K → K → Ordering) : DecidableRel (keyedRelation view comparison) :=
  fun _ _ => inferInstanceAs (Decidable (relation comparison _ _))

/-- Standard sorting with a real stateless key callback. The two premises
are the callback and key-comparison leaves, not an expected sorting outcome.
Concrete source callers must earn them and the lawful-order contract. -/
theorem keyed_insert {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (view : T → K) (comparison : K → K → Ordering)
    (keyLaw : ∀ value, key.call_mut callback value = ok (view value, callback))
    (compareLaw : ∀ left right, order.cmp left right = ok (comparison left right))
    (item : T) (values : List T) :
    insertKeyValues key order callback item values =
      ok ⟨values.orderedInsert (keyedRelation view comparison) item,
        List.orderedInsert_length (keyedRelation view comparison) values item⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [insertKeyValues_cons]
    simp only [keyLaw, compareLaw, bind_tc_ok]
    cases ordering : comparison (view item) (view first) <;>
      simp [ordering, List.orderedInsert_cons, keyedRelation, relation, ih]

theorem keyed_sort {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (view : T → K) (comparison : K → K → Ordering)
    (keyLaw : ∀ value, key.call_mut callback value = ok (view value, callback))
    (compareLaw : ∀ left right, order.cmp left right = ok (comparison left right))
    (values : List T) :
    sortKeyValues key order callback values =
      ok ⟨values.insertionSort (keyedRelation view comparison),
        List.length_insertionSort _ values⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [sortKeyValues_cons, ih]
    simp only [bind_tc_ok, keyed_insert key order callback view comparison keyLaw compareLaw]
    rfl

theorem slice_keyed_sort_exact {T K F : Type} (key : core.ops.function.FnMut F T K)
    (order : core.cmp.Ord K) (callback : F) (view : T → K) (comparison : K → K → Ordering)
    (keyLaw : ∀ value, key.call_mut callback value = ok (view value, callback))
    (compareLaw : ∀ left right, order.cmp left right = ok (comparison left right))
    (values : Slice T) :
    _root_.alloc.slice.Slice.sort_by_key key order values callback =
      ok ⟨values.val.insertionSort (keyedRelation view comparison), by
        rw [List.length_insertionSort]; exact values.property⟩ := by
  rw [sort_by_key_values, keyed_sort key order callback view comparison keyLaw compareLaw]
  rfl

theorem slice_sort_exact {T : Type} (order : core.cmp.Ord T)
    (comparison : T → T → Ordering) (law : ∀ left right, order.cmp left right = ok (comparison left right))
    (values : Slice T) :
    AuthsProtocolCodec.alloc.slice.Slice.sort order values =
      ok ⟨values.val.insertionSort (relation comparison), by
        rw [List.length_insertionSort]; exact values.property⟩ := by
  unfold AuthsProtocolCodec.alloc.slice.Slice.sort
  rw [sort_by_key_values, identity_sort order comparison law]
  rfl

/-- A standard stable comparison sort is determined by the actual pure
comparison leaf. Callback state is explicitly unchanged at every call. -/
theorem compared_insert {T F : Type}
    (callbackFn : core.ops.function.FnMut F (T × T) Ordering) (callback : F)
    (comparison : T → T → Ordering)
    (law : ∀ left right,
      callbackFn.call_mut callback (left, right) = ok (comparison left right, callback))
    (item : T) (values : List T) :
    CompareSortModel.insert callbackFn callback item values =
      ok ⟨values.orderedInsert (relation comparison) item,
        List.orderedInsert_length (relation comparison) values item⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [CompareSortModel.insert]
    simp only [law, bind_tc_ok]
    cases ordering : comparison item first <;>
      simp [ordering, List.orderedInsert_cons, relation, ih]

theorem compared_sort {T F : Type}
    (callbackFn : core.ops.function.FnMut F (T × T) Ordering) (callback : F)
    (comparison : T → T → Ordering)
    (law : ∀ left right,
      callbackFn.call_mut callback (left, right) = ok (comparison left right, callback))
    (values : List T) :
    CompareSortModel.sort callbackFn callback values =
      ok ⟨values.insertionSort (relation comparison), List.length_insertionSort _ values⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [CompareSortModel.sort, ih]
    simp only [bind_tc_ok, compared_insert callbackFn callback comparison law]
    rfl

theorem slice_compared_sort_exact {T F : Type}
    (callbackFn : core.ops.function.FnMut F (T × T) Ordering) (callback : F)
    (comparison : T → T → Ordering)
    (law : ∀ left right,
      callbackFn.call_mut callback (left, right) = ok (comparison left right, callback))
    (values : Slice T) :
    AuthsProtocolCodec.alloc.slice.Slice.sort_by callbackFn values callback =
      ok ⟨values.val.insertionSort (relation comparison), by
        rw [List.length_insertionSort]; exact values.property⟩ := by
  unfold AuthsProtocolCodec.alloc.slice.Slice.sort_by
  rw [compared_sort callbackFn callback comparison law]
  rfl

def sortedVector {T : Type} (comparison : T → T → Ordering) (values : alloc.vec.Vec T) : alloc.vec.Vec T :=
  alloc.vec.Vec.ofBase ⟨values.val.insertionSort (relation comparison), by
    rw [List.length_insertionSort]; exact values.property⟩

theorem sorted_vector_contents {T : Type} (comparison : T → T → Ordering) (values : alloc.vec.Vec T) :
    (sortedVector comparison values).val = values.val.insertionSort (relation comparison) := by
  simp [sortedVector, alloc.vec.Vec.ofBase, alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

theorem sorted_vector_permutation {T : Type} (comparison : T → T → Ordering) (values : alloc.vec.Vec T) :
    (sortedVector comparison values).val.Perm values.val := by
  rw [sorted_vector_contents]
  exact List.perm_insertionSort _ _

theorem sorted_vector_length {T : Type} (comparison : T → T → Ordering) (values : alloc.vec.Vec T) :
    (sortedVector comparison values).val.length = values.val.length :=
  (sorted_vector_permutation comparison values).length_eq

theorem sorted_vector_preserves_fields {T : Type} (comparison : T → T → Ordering)
    (field : T → Prop) (values : alloc.vec.Vec T) :
    (∀ value ∈ (sortedVector comparison values).val, field value) ↔
      ∀ value ∈ values.val, field value := by
  have same := sorted_vector_permutation comparison values
  constructor
  · intro valid value member
    exact valid value (same.mem_iff.mpr member)
  · intro valid value member
    exact valid value (same.mem_iff.mp member)

end Auths.Codec.ProtocolSort
