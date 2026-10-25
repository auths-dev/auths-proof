import Auths.Product.RecipePointerProperties
import Auths.Product.NativeCompilerConsumptionInterfaces

namespace Auths.Product.RecipeAdmissionAtoms
open NativeCompiler

def seenBefore (values : List String) (position : Nat) : Bool :=
  match values[position]? with
  | none => true
  | some value => decide (value ∈ values.take position)

/-- Full previous original names participate in uniqueness. A suffix does not
forget a collision with an earlier, already processed pointer. -/
def PointerSequence (prefix values : List String) : Prop :=
  values.Nodup ∧ ∀ value ∈ values, ResponsePointer (textBytes value) ∧ value ∉ prefix
instance (prefix values : List String) : Decidable (PointerSequence prefix values) := by
  unfold PointerSequence
  infer_instance

theorem pointer_sequence_cons (prefix : List String) (first : String) (rest : List String) :
    PointerSequence prefix (first :: rest) ↔
      ResponsePointer (textBytes first) ∧ first ∉ prefix ∧ PointerSequence (prefix ++ [first]) rest := by
  constructor
  · rintro ⟨unique, all⟩
    obtain ⟨valid, fresh⟩ := all first (by simp)
    refine ⟨valid, fresh, (List.nodup_cons.mp unique).2, ?_⟩
    intro value member
    obtain ⟨valid, fresh⟩ := all value (by simp [member])
    refine ⟨valid, ?_⟩
    intro used
    rcases List.mem_append.mp used with earlier | current
    · exact fresh earlier
    · have same : value = first := List.mem_singleton.mp current
      exact (List.nodup_cons.mp unique).1 (same ▸ member)
  · rintro ⟨valid, fresh, unique, all⟩
    have firstAbsent : first ∉ rest := by
      intro present
      exact (all first present).2 (by simp)
    refine ⟨List.nodup_cons.mpr ⟨firstAbsent, unique⟩, ?_⟩
    intro value member
    rcases List.mem_cons.mp member with rfl | later
    · exact ⟨valid, fresh⟩
    · exact ⟨(all value later).1, fun earlier => (all value later).2 (List.mem_append_left _ earlier)⟩

theorem original_pointer_bytes_unique (values : List String) :
    (values.map textBytes).Nodup ↔ values.Nodup := by
  induction values with
  | nil => simp
  | cons first rest ih =>
      simp [List.nodup_cons, ih, List.mem_map, NativeCompiler.StdModel.text_bytes_injective.eq_iff]

theorem pointer_sequence_original (values : List String) :
    PointerSequence [] values ↔ (values.map textBytes).Nodup ∧
      ∀ pointer ∈ values.map textBytes, ResponsePointer pointer := by
  simp [PointerSequence, original_pointer_bytes_unique, List.forall_mem_map]

end Auths.Product.RecipeAdmissionAtoms
