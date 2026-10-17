import Mathlib.Tactic

/-!
Readable bounded first-free-slot search. A store prefix contains precisely the
slots below its current frontier. Concurrent insertions may make individual
reads stale: the final candidate is conservative, and a successful atomic
insert at that candidate earns equality with the then-current frontier.
-/
namespace Auths.Product.Frontier.Model

structure Search where
  lower : Nat
  upper : Nat
  deriving DecidableEq, Repr

def valid (bound : Nat) (state : Search) : Prop := state.lower ≤ state.upper ∧ state.upper ≤ bound

def start (bound : Nat) : Search := ⟨0, bound⟩
def width (state : Search) : Nat := state.upper - state.lower

def probe (state : Search) : Option Nat :=
  if state.lower < state.upper then some (state.lower + width state / 2) else none

def observe (state : Search) (occupied : Bool) : Search :=
  match probe state with
  | none => state
  | some middle => if occupied then ⟨middle + 1, state.upper⟩ else ⟨state.lower, middle⟩

def run (state : Search) (answers : List Bool) : Search := answers.foldl observe state

theorem start_valid (bound : Nat) : valid bound (start bound) := by simp [valid, start]

theorem probe_inside (state : Search) (middle : Nat) (found : probe state = some middle) :
    state.lower ≤ middle ∧ middle < state.upper := by
  unfold probe width at found
  split at found
  · simp only [Option.some.injEq] at found
    omega
  · contradiction

theorem observe_valid (bound : Nat) (state : Search) (occupied : Bool) (invariant : valid bound state) :
    valid bound (observe state occupied) := by
  unfold observe
  cases found : probe state with
  | none => exact invariant
  | some middle =>
    have inside := probe_inside state middle found
    cases occupied <;> simp_all [valid] <;> omega

theorem width_halves (state : Search) (occupied : Bool) :
    width (observe state occupied) ≤ width state / 2 := by
  unfold observe
  cases found : probe state with
  | none =>
    have finished : state.upper ≤ state.lower := by simpa [probe] using found
    simp only [width]
    omega
  | some middle =>
    have middleValue : middle = state.lower + width state / 2 := by
      unfold probe at found
      split at found
      · exact (Option.some.inj found).symm
      · contradiction
    cases occupied <;> simp only [Bool.false_eq_true, ↓reduceIte, width]
    all_goals unfold width at middleValue
    all_goals omega

theorem run_valid (bound : Nat) (state : Search) (answers : List Bool) (invariant : valid bound state) :
    valid bound (run state answers) := by
  induction answers generalizing state with
  | nil => exact invariant
  | cons occupied rest ih => exact ih _ (observe_valid bound state occupied invariant)

theorem run_width (state : Search) (answers : List Bool) :
    width (run state answers) ≤ width state / 2 ^ answers.length := by
  induction answers generalizing state with
  | nil => simp [run]
  | cons occupied rest ih =>
    calc width (run state (occupied :: rest))
      ≤ width (observe state occupied) / 2 ^ rest.length := ih _
      _ ≤ (width state / 2) / 2 ^ rest.length := Nat.div_le_div_right (width_halves state occupied)
      _ = width state / 2 ^ (occupied :: rest).length := by
        simp only [List.length_cons, Nat.div_div_eq_div_mul, Nat.pow_succ]
        rw [Nat.mul_comm]

/-- At most 64 successful store reads on the full u64 bound, for every
    possible sequence of occupancy answers; no stable snapshot is needed. -/
theorem sixty_four_reads_suffice (bound : Nat) (fits : bound < 2 ^ 64)
    (answers : List Bool) (enough : answers.length = 64) :
    probe (run (start bound) answers) = none := by
  have reduced := run_width (start bound) answers
  have invariant := run_valid bound (start bound) answers (start_valid bound)
  have noWidth : width (run (start bound) answers) = 0 := by
    apply Nat.eq_zero_of_le_zero
    calc width (run (start bound) answers) ≤ width (start bound) / 2 ^ answers.length := reduced
         _ = 0 := by simpa [width, start, enough] using Nat.div_eq_of_lt fits
  have finished : (run (start bound) answers).upper ≤ (run (start bound) answers).lower := by
    unfold width at noWidth
    omega
  simp [probe, Nat.not_lt.mpr finished]

/-- Even a stale read cannot push the candidate beyond a later append-only
    prefix. This uses a store-prefix contract, not a trusted admission flag. -/
theorem observed_prefix_conservative (state : Search) (observed latest : Nat)
    (prior : state.lower ≤ latest) (monotone : observed ≤ latest) :
    (observe state (decide ((probe state).getD 0 < observed))).lower ≤ latest := by
  unfold observe
  cases found : probe state with
  | none => exact prior
  | some middle =>
    simp only [Option.getD_some, decide_eq_true_eq]
    split <;> dsimp only <;> omega

def runPrefixes (state : Search) (frontiers : List Nat) : Search :=
  frontiers.foldl (fun current frontier => observe current (decide ((probe current).getD 0 < frontier))) state

theorem candidate_conservative (state : Search) (frontiers : List Nat) (latest : Nat)
    (prior : state.lower ≤ latest) (appendOnly : ∀ frontier ∈ frontiers, frontier ≤ latest) :
    (runPrefixes state frontiers).lower ≤ latest := by
  induction frontiers generalizing state with
  | nil => exact prior
  | cons frontier rest ih =>
    apply ih
    · exact observed_prefix_conservative state frontier latest prior (appendOnly frontier (by simp))
    · intro later included
      exact appendOnly later (by simp [included])

/-- If the atomic batch still finds this candidate unoccupied, the candidate
    is exactly the current prefix end. Otherwise the caller must retry/refuse. -/
theorem successful_insertion_is_at_frontier (state : Search) (frontiers : List Nat) (latest : Nat)
    (prior : state.lower ≤ latest) (appendOnly : ∀ frontier ∈ frontiers, frontier ≤ latest)
    (stillFree : ¬ (runPrefixes state frontiers).lower < latest) :
    (runPrefixes state frontiers).lower = latest := by
  have conservative := candidate_conservative state frontiers latest prior appendOnly
  omega

end Auths.Product.Frontier.Model
