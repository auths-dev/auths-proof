import Auths.Product.RecipeReadProperties

namespace Auths.Product.RecipeAdmissionAtoms
open NativeCompiler

/-- Full original credential prefixes participate in uniqueness. Refusing a later
prefix cannot forget its collision with an earlier original prefix. -/
def GuardPrefixSequence (prefix values : List String) : Prop :=
  values.Nodup ∧ ∀ value ∈ values, Prefix (textBytes value) ∧ value ∉ prefix
instance (prefix values : List String) : Decidable (GuardPrefixSequence prefix values) := by
  unfold GuardPrefixSequence
  infer_instance

theorem guard_prefix_sequence_cons (prefix : List String) (first : String) (rest : List String) :
    GuardPrefixSequence prefix (first :: rest) ↔
      Prefix (textBytes first) ∧ first ∉ prefix ∧ GuardPrefixSequence (prefix ++ [first]) rest := by
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


theorem guard_prefix_sequence_original (values : List String) :
    GuardPrefixSequence [] values ↔ (values.map textBytes).Nodup ∧
      ∀ prefix ∈ values.map textBytes, Prefix prefix := by
  simp [GuardPrefixSequence, original_pointer_bytes_unique, List.forall_mem_map]

end Auths.Product.RecipeAdmissionAtoms
