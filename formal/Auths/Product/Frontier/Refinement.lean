import Auths.Product.Frontier.Model
import qualification.aeneas.generated.gateway.Funs
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.Product.Frontier.Refinement
open auths_gateway_kernel
set_option maxHeartbeats 2000000

def view (state : frontier.FrontierSearch) : Model.Search := ⟨state.lower.val, state.upper.val⟩

@[step] theorem start_exact (bound : Std.U64) :
    frontier.FrontierSearch.new bound ⦃ actual => view actual = Model.start bound.val ⦄ := by
  simp [frontier.FrontierSearch.new, view, Model.start]

/-- Complete probe result, including closed intervals; all arithmetic safety
    is proved on the source u64 carrier, rather than assumed from a flag. -/
@[step] theorem probe_exact (state : frontier.FrontierSearch) :
    frontier.FrontierSearch.probe state ⦃ actual => actual.map UScalar.val = Model.probe (view state) ⦄ := by
  unfold frontier.FrontierSearch.probe
  split <;> rename_i active
  · have remaining : state.lower.val < state.upper.val := by simpa using active
    have upperBound := U64.le_max state.upper
    step as ⟨difference, differenceValue⟩
    step as ⟨half, halfValue⟩
    have additionFits : state.lower.val + half.val ≤ U64.max := by
      rw [U64.max_eq]
      omega
    step as ⟨middle, middleValue⟩
    simp [Model.probe, Model.width, view, remaining, middleValue, halfValue, differenceValue]
  · have finished : ¬state.lower.val < state.upper.val := by simpa using active
    simp [Model.probe, view, finished]

@[step] theorem observe_exact (state : frontier.FrontierSearch) (occupied : Bool) :
    frontier.FrontierSearch.observe state occupied ⦃ actual =>
      view actual = Model.observe (view state) occupied ⦄ := by
  unfold frontier.FrontierSearch.observe
  step with probe_exact as ⟨nextRead, readValue⟩
  cases nextRead with
  | none => simp [Model.observe, ← readValue]
  | some middle =>
    have found : Model.probe (view state) = some middle.val := by simpa using readValue.symm
    have inside : middle.val < state.upper.val := (Model.probe_inside _ _ found).2
    by_cases occupiedAnswer : occupied = true
    · simp only [occupiedAnswer, ↓reduceIte]
      have additionFits : middle.val + 1 ≤ U64.max := by
        rw [U64.max_eq]
        have upperBound := U64.le_max state.upper
        omega
      step as ⟨next, nextValue⟩
      simp only [Model.observe, found, occupiedAnswer, ↓reduceIte]
      simp [view, nextValue]
    · simp only [Model.observe, found, occupiedAnswer, ↓reduceIte, spec_ok]
      simp [view]

@[step] theorem candidate_exact (state : frontier.FrontierSearch) :
    frontier.FrontierSearch.candidate state ⦃ actual => actual.val = (view state).lower ⦄ := by
  simp [frontier.FrontierSearch.candidate, view]

/-- A proof-owned composition of the actual source methods, supplied with
    observed answers. Runtime store-read correspondence remains explicit. -/
def composeReads : frontier.FrontierSearch → List Bool → Result frontier.FrontierSearch
  | state, [] => ok state
  | state, answer :: rest => do
    let next ← frontier.FrontierSearch.observe state answer
    composeReads next rest

theorem reads_refine (state : frontier.FrontierSearch) (answers : List Bool) :
    composeReads state answers ⦃ actual => view actual = Model.run (view state) answers ⦄ := by
  induction answers generalizing state with
  | nil => simp [composeReads, Model.run]
  | cons answer rest ih =>
    unfold composeReads
    step with observe_exact as ⟨next, nextValue⟩
    apply spec_mono (ih next)
    intro actual actualValue
    simpa only [Model.run, List.foldl_cons, nextValue] using actualValue

/-- Any 64 source transitions finish the search over a full-width u64 bound.
    This bounds successful read transitions; a runtime read error exits earlier. -/
theorem source_work_bound (bound : Std.U64) (answers : List Bool) (enough : answers.length = 64) :
    (do
      let start ← frontier.FrontierSearch.new bound
      let final ← composeReads start answers
      frontier.FrontierSearch.probe final) ⦃ actual => actual = none ⦄ := by
  step with start_exact as ⟨start, startValue⟩
  step with reads_refine as ⟨final, finalValue⟩
  step with probe_exact as ⟨actual, actualValue⟩
  have fits : bound.val < 2 ^ 64 := bound.hBounds
  have finished := Model.sixty_four_reads_suffice bound.val fits answers enough
  rw [finalValue, startValue, finished] at actualValue
  exact Option.map_eq_none_iff.mp actualValue

end Auths.Product.Frontier.Refinement
