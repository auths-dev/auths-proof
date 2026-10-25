import qualification.aeneas.generated.protocol_codec.Funs
import Auths.Support.ProtocolVec
import Mathlib.Tactic

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.OwnedRecords

/- The Auths-owned loop is translated in full. The only collection boundary
below is the concrete positive-vector standard-operation interface. Its pop
ABI/model review must be completed against fresh extraction; no opaque Auths
normalizer or assumed loop result is substituted for this source function. -/

variable {Key Value : Type}

theorem unkey_loop_exists (remaining : alloc.vec.Vec (Key × Value))
    (records : alloc.vec.Vec Value)
    (capacity : records.val.length + remaining.val.length ≤ Usize.max) :
    ∃ output, @canonical_value.unkey_records_loop Key Value remaining records = ok output ∧
      output.val = records.val ++ remaining.val.reverse.map Prod.snd := by
  have total : ∀ count (todo : alloc.vec.Vec (Key × Value)) (completed : alloc.vec.Vec Value),
      completed.val.length + todo.val.length ≤ Usize.max →
      todo.val.length = count →
      ∃ output, @canonical_value.unkey_records_loop Key Value todo completed = ok output ∧
        output.val = completed.val ++ todo.val.reverse.map Prod.snd := by
    intro count
    induction count using Nat.strong_induction_on with
    | h count ih =>
      intro todo completed space sized
      rw [canonical_value.unkey_records_loop.eq_def]
      simp only [alloc.vec.Vec.pop, bind_tc_ok]
      cases popped : todo.val.getLast? with
      | none =>
        have noneLeft : todo.val = [] := List.getLast?_eq_none_iff.mp popped
        refine ⟨completed, ?_, ?_⟩
        · simp [popped]
        · simp [noneLeft]
      | some item =>
        rcases item with ⟨key, value⟩
        have positive : 0 < todo.val.length := by
          by_contra absent
          have noneLeft : todo.val = [] := List.length_eq_zero.mp (by omega)
          simp [noneLeft] at popped
        have room : completed.val.length < Usize.max := by omega
        obtain ⟨next, pushed, appended⟩ :=
          spec_imp_exists (alloc.vec.push_spec completed value room)
        have prefixSpace : next.val.length + (alloc.vec.Vec.pop_prefix todo).val.length ≤ Usize.max := by
          simp only [appended, List.length_append, List.length_singleton,
            alloc.vec.pop_prefix_contents, List.length_dropLast]
          omega
        have smaller : (alloc.vec.Vec.pop_prefix todo).val.length < count := by
          simp only [alloc.vec.pop_prefix_contents, List.length_dropLast]
          omega
        obtain ⟨output, recurse, meaning⟩ := ih
          (alloc.vec.Vec.pop_prefix todo).val.length smaller
          (alloc.vec.Vec.pop_prefix todo) next prefixSpace rfl
        refine ⟨output, ?_, ?_⟩
        · simpa only [popped, pushed, bind_tc_ok] using recurse
        · have reassembled := alloc.vec.pop_reassembles todo
          rw [popped] at reassembled
          simp only [Option.toList_some] at reassembled
          have reversed : todo.val.reverse =
              (key, value) :: (alloc.vec.Vec.pop_prefix todo).val.reverse := by
            calc
              todo.val.reverse = ((alloc.vec.Vec.pop_prefix todo).val ++ [(key, value)]).reverse :=
                congrArg List.reverse reassembled.symm
              _ = _ := by simp
          rw [meaning, appended, reversed]
          simp [List.append_assoc]
  exact total remaining.val.length remaining records capacity rfl

@[step] theorem unkey_loop_exact (remaining : alloc.vec.Vec (Key × Value))
    (records : alloc.vec.Vec Value)
    (capacity : records.val.length + remaining.val.length ≤ Usize.max) :
    @canonical_value.unkey_records_loop Key Value remaining records
      ⦃ output => output.val = records.val ++ remaining.val.reverse.map Prod.snd ⦄ := by
  obtain ⟨output, runs, meaning⟩ := unkey_loop_exists remaining records capacity
  rw [runs]
  simpa only [spec_ok] using meaning

@[step] theorem unkey_exact (input : alloc.vec.Vec (Key × Value)) :
    @canonical_value.unkey_records Key Value input
      ⦃ output => output.val = input.val.map Prod.snd ⦄ := by
  unfold canonical_value.unkey_records
  simp only [alloc.vec.Vec.len, alloc.vec.Vec.with_capacity,
    core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut,
    Aeneas.Std.alloc.vec.Vec.deref_mut, Aeneas.Std.core.slice.Slice.reverse, bind_tc_ok]
  step with unkey_loop_exact _ _ (by
    simpa [alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
      auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
      auths_composition.alloc.vec.Vec.val,
      auths_composition.alloc.vec.SizedList.toList_ofList] using input.property)
    as ⟨output, exactOutput⟩
  simpa [alloc.vec.Vec.ofBase, alloc.vec.Vec.toBase, alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
    auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList] using exactOutput

theorem unkey_length (input : alloc.vec.Vec (Key × Value)) :
    @canonical_value.unkey_records Key Value input
      ⦃ output => output.val.length = input.val.length ⦄ := by
  apply spec_mono (unkey_exact input)
  intro output same
  simp [same]

theorem unkey_fields (field : Value → Prop) (input : alloc.vec.Vec (Key × Value)) :
    @canonical_value.unkey_records Key Value input
      ⦃ output => (∀ value ∈ output.val, field value) ↔
        ∀ entry ∈ input.val, field entry.2 ⦄ := by
  apply spec_mono (unkey_exact input)
  intro output same
  simpa [same] using
    (show (∀ value ∈ input.val.map Prod.snd, field value) ↔
      ∀ entry ∈ input.val, field entry.2 from by simp)

end Auths.Codec.OwnedRecords
