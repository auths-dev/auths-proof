import Std.Tactic

namespace Auths.Product.CollectionFence

/-- Durable cutoffs advance independently of a worker's wall-clock sample. -/
def advance (current : Option Nat) (requested : Nat) : Nat :=
  match current with
  | none => requested
  | some previous => max previous requested

/-- No caller-provided assertion substitutes for the stored cutoff. -/
def openWindow (cutoff : Option Nat) (expiry : Nat) : Prop :=
  match cutoff with
  | none => True
  | some collected => collected < expiry

instance (cutoff : Option Nat) (expiry : Nat) : Decidable (openWindow cutoff expiry) := by
  unfold openWindow
  split <;> infer_instance

def NoEarlier (previous next : Option Nat) : Prop :=
  ∀ cutoff, previous = some cutoff → ∃ later, next = some later ∧ cutoff ≤ later

theorem noEarlier_refl (cutoff : Option Nat) : NoEarlier cutoff cutoff := by
  intro previous equal
  exact ⟨previous, equal, Nat.le_refl _⟩

theorem noEarlier_trans {first second third : Option Nat}
    (left : NoEarlier first second) (right : NoEarlier second third) :
    NoEarlier first third := by
  intro cutoff equal
  obtain ⟨middle, middleEq, firstLe⟩ := left cutoff equal
  obtain ⟨last, lastEq, secondLe⟩ := right middle middleEq
  exact ⟨last, lastEq, Nat.le_trans firstLe secondLe⟩

theorem advance_noEarlier (current : Option Nat) (requested : Nat) :
    NoEarlier current (some (advance current requested)) := by
  intro previous equal
  subst current
  exact ⟨_, rfl, Nat.le_max_left previous requested⟩

theorem closed_stays_closed {previous next : Option Nat} (expiry : Nat)
    (ordered : NoEarlier previous next) (closed : ¬ openWindow previous expiry) :
    ¬ openWindow next expiry := by
  cases previous with
  | none => exact (closed trivial).elim
  | some cutoff =>
    obtain ⟨later, rfl, earlier⟩ := ordered cutoff rfl
    simp only [openWindow] at closed ⊢
    omega

/-- A linearization history permits any number of workers. An admission with
lost acknowledgement still commits; only acknowledged success may mint a
volatile execution handle in the full admission model. Neither outcome can
bypass this atomic cutoff predicate. -/
inductive Step : Option Nat → Option Nat → Prop where
  | collect (current : Option Nat) (requested : Nat) :
      Step current (some (advance current requested))
  | admit (current : Option Nat) (worker operation expiry : Nat)
      (eligible : openWindow current expiry) (acknowledged : Bool) : Step current current
  | sweep (current : Option Nat) (expiry : Nat)
      (eligible : ∃ cutoff, current = some cutoff ∧ expiry ≤ cutoff) : Step current current
  | crash (current : Option Nat) (worker : Nat) : Step current current
  | recover (current : Option Nat) (worker : Nat) : Step current current

theorem step_noEarlier {previous next : Option Nat} (step : Step previous next) :
    NoEarlier previous next := by
  cases step with
  | collect requested => exact advance_noEarlier _ requested
  | admit => exact noEarlier_refl _
  | sweep => exact noEarlier_refl _
  | crash => exact noEarlier_refl _
  | recover => exact noEarlier_refl _

inductive History : Option Nat → Option Nat → Prop where
  | empty (state : Option Nat) : History state state
  | append {first previous next : Option Nat} :
      History first previous → Step previous next → History first next

theorem history_noEarlier {first last : Option Nat} (history : History first last) :
    NoEarlier first last := by
  induction history with
  | empty => exact noEarlier_refl _
  | append _ step ih => exact noEarlier_trans ih (step_noEarlier step)

/-- Once a cutoff has been published, every later successful admission has an
expiry strictly after it, including across crashes, lost acknowledgements,
partial sweeps, and arbitrarily interleaved workers. -/
theorem collection_cannot_reopen_window (cutoff expiry : Nat)
    {current : Option Nat} (history : History (some cutoff) current)
    (admitted : openWindow current expiry) : cutoff < expiry := by
  obtain ⟨later, rfl, ordered⟩ := history_noEarlier history cutoff rfl
  simp only [openWindow] at admitted
  omega

theorem swept_window_cannot_readmit (cutoff expiry : Nat)
    {current : Option Nat} (history : History (some cutoff) current)
    (swept : expiry ≤ cutoff) : ¬ openWindow current expiry := by
  intro admitted
  have := collection_cannot_reopen_window cutoff expiry history admitted
  omega

-- The fence permits useful work in a later window.
theorem later_window_admits (cutoff expiry : Nat) (later : cutoff < expiry) :
    openWindow (some cutoff) expiry := later

end Auths.Product.CollectionFence
