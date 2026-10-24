import Auths.Codec.ProtocolSort
import Auths.Codec.ProtocolCollectionScans

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolBoundedSet
set_option maxHeartbeats 2000000

variable {T Key : Type} [DecidableEq Key]

def expected (maximum : Std.Usize) (comparison : T → T → Ordering) (view : T → Key)
    (values : alloc.vec.Vec T) :
    core.result.Result (alloc.vec.Vec T) auths_model.bounded.BoundError :=
  if values.val.isEmpty then .Err .Empty
  else if maximum.val < values.val.length then .Err .AboveMaximum
  else if CollectionInvariants.adjacent ((ProtocolSort.sortedVector comparison values).val.map view)
    then .Err .Duplicate
  else .Ok (ProtocolSort.sortedVector comparison values)

/- Trait laws below are comparison leaves, not a desired constructor result.
The concrete protocol dictionaries must discharge both inherited PartialEq
paths and the actual Ord implementation. The standard sorting primitive also
retains its pure lawful-order contract. -/
theorem source_exact (maximum : Std.Usize) (order : core.cmp.Ord T)
    (comparison : T → T → Ordering) (view : T → Key)
    (compareLaw : ∀ left right, order.cmp left right = ok (comparison left right))
    (equalLaw : ∀ left right,
      order.eqInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (partialEqualLaw : ∀ left right,
      order.partialOrdInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (values : alloc.vec.Vec T) :
    @auths_model.bounded.BoundedSet.new T maximum order values =
      ok (expected maximum comparison view values) := by
  unfold auths_model.bounded.BoundedSet.new
  simp only [alloc.vec.Vec.is_empty, bind_tc_ok]
  by_cases empty : values.val.isEmpty = true
  · simp [empty, expected]
  · simp only [empty, Bool.false_eq_true, ↓reduceIte]
    simp only [UScalar.lt_equiv, AuthsProtocolCodec.alloc.vec.len_value]
    by_cases oversized : maximum.val < values.val.length
    · simp [oversized, empty, expected]
    · simp only [oversized, ↓reduceIte]
      simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
        Aeneas.Std.alloc.vec.Vec.deref_mut, bind_tc_ok]
      rw [ProtocolSort.slice_sort_exact order comparison compareLaw]
      simp only [bind_tc_ok]
      first
      | rw [ProtocolCollectionScans.adjacent_exact order.eqInst.partialEqInst view equalLaw]
      | rw [ProtocolCollectionScans.adjacent_exact order.partialOrdInst.partialEqInst view partialEqualLaw]
      simp [expected, empty, oversized, ProtocolSort.sortedVector,
        alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.deref,
        auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
        auths_composition.alloc.vec.Vec.deref]

theorem accepts_iff (maximum : Std.Usize) (order : core.cmp.Ord T)
    (comparison : T → T → Ordering) (view : T → Key)
    (compareLaw : ∀ left right, order.cmp left right = ok (comparison left right))
    (equalLaw : ∀ left right,
      order.eqInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (partialEqualLaw : ∀ left right,
      order.partialOrdInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (values output : alloc.vec.Vec T) :
    @auths_model.bounded.BoundedSet.new T maximum order values = ok (.Ok output) ↔
      values.val ≠ [] ∧ values.val.length ≤ maximum.val ∧
        CollectionInvariants.adjacent ((ProtocolSort.sortedVector comparison values).val.map view) = false ∧
        output = ProtocolSort.sortedVector comparison values := by
  rw [source_exact maximum order comparison view compareLaw equalLaw partialEqualLaw]
  unfold expected
  split <;> split_ifs <;> simp_all [eq_comm]

theorem output_preserves_fields (maximum : Std.Usize) (order : core.cmp.Ord T)
    (comparison : T → T → Ordering) (view : T → Key)
    (compareLaw : ∀ left right, order.cmp left right = ok (comparison left right))
    (equalLaw : ∀ left right,
      order.eqInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (partialEqualLaw : ∀ left right,
      order.partialOrdInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (field : T → Prop) (values output : alloc.vec.Vec T)
    (valid : ∀ value ∈ values.val, field value)
    (accepted : @auths_model.bounded.BoundedSet.new T maximum order values = ok (.Ok output)) :
    output.val ≠ [] ∧ output.val.length ≤ maximum.val ∧
      output.val.Perm values.val ∧ ∀ value ∈ output.val, field value := by
  obtain ⟨nonempty, bounded, _, rfl⟩ :=
    (accepts_iff maximum order comparison view compareLaw equalLaw partialEqualLaw values output).mp accepted
  have same := ProtocolSort.sorted_vector_permutation comparison values
  refine ⟨?_, ?_, same, ?_⟩
  · intro empty
    have length := same.length_eq
    rw [empty, List.length_nil] at length
    exact nonempty (List.length_eq_zero_iff.mp length.symm)
  · simpa [same.length_eq] using bounded
  · exact (ProtocolSort.sorted_vector_preserves_fields comparison field values).mpr valid

/-- Global uniqueness follows from actual constructor success and the sorted
key-order property. The latter must be derived from the concrete Ord/sorting
proof; callers cannot assert a successful duplicate scan as that property. -/
theorem output_keys_unique (maximum : Std.Usize) (order : core.cmp.Ord T)
    (comparison : T → T → Ordering) (view : T → Key)
    (compareLaw : ∀ left right, order.cmp left right = ok (comparison left right))
    (equalLaw : ∀ left right,
      order.eqInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (partialEqualLaw : ∀ left right,
      order.partialOrdInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (relation : Key → Key → Prop)
    (antisymmetric : ∀ left right, relation left right → relation right left → left = right)
    (values output : alloc.vec.Vec T)
    (ordered : ((ProtocolSort.sortedVector comparison values).val.map view).Pairwise relation)
    (accepted : @auths_model.bounded.BoundedSet.new T maximum order values = ok (.Ok output)) :
    (output.val.map view).Nodup := by
  obtain ⟨_, _, clean, rfl⟩ :=
    (accepts_iff maximum order comparison view compareLaw equalLaw partialEqualLaw values output).mp accepted
  exact (CollectionInvariants.adjacent_false_nodup relation antisymmetric _ ordered).mp clean

end Auths.Codec.ProtocolBoundedSet
