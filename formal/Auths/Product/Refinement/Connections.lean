import Auths.Product.ConnectionGenerations
import qualification.aeneas.generated.connections.Funs

/-!
# The translated connection-generation leaves refine their model

`next_generation`, `state_change`, `rotation`, `retained_generation`, and
`lease_generation` of `auths_connections::kernel` are translated by the
pinned Charon/Aeneas route. Each theorem here states that a translated
function terminates with `ok` and returns exactly its model's result under an
abstraction that maps machine integers to their natural-number values and
slices to lists. No theorem carries a premise: checked addition refuses the
last generation, and the retained-entry search reads each slice element once.
-/

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Product.Refinement.Connections

open auths_connections
open Auths.Product.ConnectionGenerations

/-- The model's generations of a translated record's generations. -/
def generationsOf (value : kernel.Generations) : Generations :=
  ⟨value.generation.val, value.credential_generation.val⟩

/-- The translated next generation is the model's: the successor, absent at
the machine bound. -/
theorem translated_next_generation_refines_model (generation : Std.U64) :
    kernel.next_generation generation ⦃ next =>
      next.map (·.val) = nextGeneration generation.val ⦄ := by
  unfold kernel.next_generation
  have specification := U64.checked_add_bv_spec generation 1#u64
  simp only [spec_ok]
  cases equation : U64.checked_add generation 1#u64 with
  | none =>
      rw [equation] at specification
      simp only [U64.max_eq] at specification
      simp only [Option.map_none, nextGeneration, generationMax]
      split <;> first | rfl | (exfalso; scalar_tac)
  | some next =>
      rw [equation] at specification
      simp only [U64.max_eq] at specification
      obtain ⟨within, nextVal, _⟩ := specification
      simp only [Option.map_some, nextGeneration, generationMax]
      split
      · simp only [Option.some.injEq]; scalar_tac
      · exfalso; scalar_tac

theorem next_generation_eq (generation : Std.U64) :
    ∃ next, kernel.next_generation generation = ok next ∧
      next.map (·.val) = nextGeneration generation.val :=
  spec_imp_exists (translated_next_generation_refines_model generation)

/-- The translated state change is the model's: the generation advances and
the credential generation is kept. -/
theorem translated_state_change_refines_model (current : kernel.Generations) :
    kernel.state_change current ⦃ next =>
      next.map generationsOf = stateChange (generationsOf current) ⦄ := by
  unfold kernel.state_change
  obtain ⟨next, nextEq, nextVal⟩ := next_generation_eq current.generation
  rw [nextEq, bind_tc_ok]
  simp only [stateChange, generationsOf]
  cases next with
  | none =>
      simp only [Option.map_none] at nextVal
      simp only [spec_ok, Option.map_none, ← nextVal]
  | some generation =>
      simp only [Option.map_some] at nextVal
      simp only [spec_ok, Option.map_some, ← nextVal, generationsOf]

/-- The translated rotation is the model's: both generations advance to the
next generation. -/
theorem translated_rotation_refines_model (current : kernel.Generations) :
    kernel.rotation current ⦃ next =>
      next.map generationsOf = rotation (generationsOf current) ⦄ := by
  unfold kernel.rotation
  obtain ⟨next, nextEq, nextVal⟩ := next_generation_eq current.generation
  rw [nextEq, bind_tc_ok]
  simp only [rotation, generationsOf]
  cases next with
  | none =>
      simp only [Option.map_none] at nextVal
      simp only [spec_ok, Option.map_none, ← nextVal]
  | some generation =>
      simp only [Option.map_some] at nextVal
      simp only [spec_ok, Option.map_some, ← nextVal, generationsOf]

/-- The search state as the model's optional best generation. -/
def bestOf (found : Bool) (best : Std.U64) : Option Nat :=
  if found then some best.val else none

theorem bestOf_step (record : Std.U64) (found : Bool) (best candidate : Std.U64) :
    bestOf
        (if candidate ≤ record then true else found)
        (if candidate ≤ record then (if found then (if candidate > best then candidate else best)
          else candidate) else best) =
      retainStep record.val (bestOf found best) candidate.val := by
  unfold bestOf retainStep
  by_cases within : candidate ≤ record
  · have within' : candidate.val ≤ record.val := by scalar_tac
    cases found with
    | false => simp [within, within']
    | true =>
        by_cases newer : candidate > best
        · have newer' : best.val < candidate.val := by scalar_tac
          simp [within, within', newer, newer']
        · have older' : ¬ best.val < candidate.val := by scalar_tac
          simp [within, within', newer, older']
  · have beyond' : ¬ candidate.val ≤ record.val := by scalar_tac
    cases found <;> simp [within, beyond']

/-- The translated retained-entry search returns exactly the model's newest
stored generation not after the record's generation. -/
theorem translated_retained_generation_refines_model (record : Std.U64)
    (stored : Slice Std.U64) :
    kernel.retained_generation record stored ⦃ result =>
      result.map (·.val) = retainedGeneration record.val (stored.val.map (·.val)) ⦄ := by
  unfold kernel.retained_generation
  have searched : kernel.retained_generation_loop record stored false 0#u64 0#usize ⦃ state =>
      bestOf state.1 state.2 = retainedGeneration record.val (stored.val.map (·.val)) ⦄ := by
    unfold kernel.retained_generation_loop
    apply loop.spec_decr_nat
      (measure := fun state => stored.val.length - state.2.2.val)
      (inv := fun state =>
        state.2.2.val ≤ stored.val.length ∧
          bestOf state.1 state.2.1 =
            ((stored.val.take state.2.2.val).map (·.val)).foldl (retainStep record.val) none)
    · rintro ⟨found, best, index⟩ ⟨indexBound, bestEq⟩
      dsimp only at indexBound bestEq
      unfold kernel.retained_generation_loop.body
      dsimp only
      split <;> rename_i withinBounds
      · have inBounds : index.val < stored.val.length := by simpa using withinBounds
        step as ⟨candidate, candidateEq⟩
        have stepped := bestOf_step record found best candidate
        by_cases within : candidate ≤ record
        · simp only [within, if_true] at stepped ⊢
          by_cases known : found
          · subst known
            by_cases newer : candidate > best
            · simp only [newer, if_true, bind_tc_ok] at stepped ⊢
              step as ⟨next, nextEq⟩
              refine ⟨by omega, ?_, by omega⟩
              rw [nextEq, List.take_succ_eq_append_getElem inBounds, List.map_append,
                List.foldl_append, ← bestEq]
              subst candidateEq
              simpa using stepped
            · simp only [newer, if_false, if_true, bind_tc_ok] at stepped ⊢
              step as ⟨next, nextEq⟩
              refine ⟨by omega, ?_, by omega⟩
              rw [nextEq, List.take_succ_eq_append_getElem inBounds, List.map_append,
                List.foldl_append, ← bestEq]
              subst candidateEq
              simpa using stepped
          · simp only [Bool.not_eq_true] at known
            subst known
            simp only [Bool.false_eq_true, if_false, bind_tc_ok] at stepped ⊢
            step as ⟨next, nextEq⟩
            refine ⟨by omega, ?_, by omega⟩
            rw [nextEq, List.take_succ_eq_append_getElem inBounds, List.map_append,
              List.foldl_append, ← bestEq]
            subst candidateEq
            simpa using stepped
        · simp only [within, if_false, bind_tc_ok] at stepped ⊢
          step as ⟨next, nextEq⟩
          refine ⟨by omega, ?_, by omega⟩
          rw [nextEq, List.take_succ_eq_append_getElem inBounds, List.map_append,
            List.foldl_append, ← bestEq]
          subst candidateEq
          simpa using stepped
      · simp only [spec_ok]
        have atEnd : stored.val.length ≤ index.val := by simpa using withinBounds
        rw [bestEq, List.take_of_length_le atEnd]
        rfl
    · exact ⟨by simp, by simp [bestOf]⟩
  obtain ⟨state, stateEq, stateVal⟩ := spec_imp_exists searched
  rw [stateEq, bind_tc_ok]
  obtain ⟨found, best⟩ := state
  cases found <;> simp_all [bestOf]

theorem retained_generation_eq (record : Std.U64) (stored : Slice Std.U64) :
    ∃ result, kernel.retained_generation record stored = ok result ∧
      result.map (·.val) = retainedGeneration record.val (stored.val.map (·.val)) :=
  spec_imp_exists (translated_retained_generation_refines_model record stored)

/-- The translated lease leaf returns exactly the model's selection: the
retained generation, only when it is the credential generation. -/
theorem translated_lease_generation_refines_model (record credential : Std.U64)
    (stored : Slice Std.U64) :
    kernel.lease_generation record credential stored ⦃ result =>
      result.map (·.val) =
        leaseGeneration record.val credential.val (stored.val.map (·.val)) ⦄ := by
  unfold kernel.lease_generation
  obtain ⟨retained, retainedEq, retainedVal⟩ := retained_generation_eq record stored
  rw [retainedEq, bind_tc_ok]
  unfold leaseGeneration
  rw [← retainedVal]
  cases retained with
  | none => simp
  | some value =>
      simp only [Option.map_some]
      by_cases same : value = credential
      · simp [same]
      · have different : value.val ≠ credential.val := by
          intro equal
          exact same (by scalar_tac)
        simp [same, different]

end Auths.Product.Refinement.Connections
