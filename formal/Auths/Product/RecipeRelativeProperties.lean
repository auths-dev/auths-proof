import Auths.Product.RecipeRuleProperties
import Auths.Product.RecipeReadProperties

namespace Auths.Product.RecipeRuleAdmission
open RecipeConsumption NativeCompiler

theorem and_then_identity (previous : Outcome) : andThen previous accepted = previous := by
  rcases previous with ⟨verdict, state⟩
  cases verdict <;> rfl

/-- Duplicate detection concerns complete original pointer bytes. Pointer
grammar is a later, separate check; an invalid unique pointer can still pass
this structural uniqueness helper. Empty bind lists are permitted. -/
def BindPointerFresh (prefix remaining : List String) : Prop :=
  remaining.Nodup ∧ ∀ pointer ∈ remaining, pointer ∉ prefix
instance (prefix remaining : List String) : Decidable (BindPointerFresh prefix remaining) := by
  unfold BindPointerFresh
  infer_instance

theorem bind_pointer_fresh_cons (prefix : List String) (first : String) (rest : List String) :
    BindPointerFresh prefix (first :: rest) ↔
      first ∉ prefix ∧ BindPointerFresh (prefix ++ [first]) rest := by
  constructor
  · rintro ⟨unique, fresh⟩
    refine ⟨fresh first (by simp), (List.nodup_cons.mp unique).2, ?_⟩
    intro pointer present used
    rcases List.mem_append.mp used with earlier | current
    · exact fresh pointer (by simp [present]) earlier
    · have same : pointer = first := List.mem_singleton.mp current
      exact (List.nodup_cons.mp unique).1 (same ▸ present)
  · rintro ⟨fresh, unique, later⟩
    have absent : first ∉ rest := fun present => (later first present) (by simp)
    refine ⟨List.nodup_cons.mpr ⟨absent, unique⟩, ?_⟩
    intro pointer present
    rcases List.mem_cons.mp present with rfl | tail
    · exact fresh
    · exact fun used => later pointer tail (List.mem_append_left _ used)

theorem bind_pointer_fresh_empty (pointers : List String) :
    BindPointerFresh [] pointers ↔ (pointers.map textBytes).Nodup := by
  simp [BindPointerFresh, RecipeAdmissionAtoms.original_pointer_bytes_unique]

theorem consume_binds_exact_sets (sources : List Bind) (state : State) :
    consumeBinds sources state =
      ⟨state.all ∪ (sources.map Bind.field).toFinset, state.body,
        state.binds ∪ (sources.map Bind.field).toFinset⟩ := by
  induction sources generalizing state with
  | nil => simp [consumeBinds]
  | cons source rest ih =>
      simp [consumeBinds, ih, RecipeConsumption.bind, Finset.union_assoc,
        Finset.union_left_comm, Finset.union_comm]

/-- Repeated fields in distinct pointer bindings are intentionally allowed.
Set insertion does not manufacture additional field identities or discard
earlier uses; no freshness/disjointness premise is added to the source rules. -/
theorem consume_binds_frame (sources : List Bind) (state : State) :
    state.all ⊆ (consumeBinds sources state).all ∧
      (consumeBinds sources state).body = state.body ∧
      state.binds ⊆ (consumeBinds sources state).binds := by
  rw [consume_binds_exact_sets]
  exact ⟨Finset.subset_union_left, rfl, Finset.subset_union_left⟩

theorem relative_binds_earn_original_fields (fields : Fields) (argument : String) (sources : List Bind)
    (admitted : RelativeBindsAdmitted fields argument sources) :
    ∀ source ∈ sources, source.field ∈ fields.map Prod.fst := by
  intro source present
  exact field_test_earns_presence formSchema fields source.field (admitted.2.2 source present).2.1

theorem path_tail_body_frame (fields : Fields) (role : PathRole) (segments : List Segment)
    (responses : Nat) (state : State) :
    (pathTail fields role segments responses state).2.body = state.body := by
  induction segments generalizing responses state with
  | nil => rfl
  | cons segment rest ih =>
      cases segment with
      | fixed value => unfold pathTail; split <;> first | rfl | exact ih _ _
      | field name =>
          unfold pathTail
          split
          · simpa [consume] using ih responses (consume state name)
          · rfl
      | responseField pointer maximum => unfold pathTail; split <;> first | rfl | exact ih _ _
      | echo => rfl

theorem path_body_frame (fields : Fields) (role : PathRole) (segments : List Segment) (state : State) :
    (path fields role segments state).2.body = state.body := by
  unfold path
  split
  · exact path_tail_body_frame fields role segments 0 state
  · rfl

theorem relative_ceiling_body_frame (fields : Fields) (source : RelativeCeiling) (state : State) :
    (relativeCeiling fields source state).2.body = state.body := by
  unfold relativeCeiling
  split
  · split
    · rfl
    · split
      · rfl
      · have pathFrame := path_body_frame fields .relativeCeiling source.path state
        unfold andThen
        split
        · exact pathFrame
        · exact (consume_binds_frame _ _).2.1.trans pathFrame
  · rfl

end Auths.Product.RecipeRuleAdmission
