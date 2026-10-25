import Mathlib.Tactic

/-!
Independent finite-history reference for shared fixed-window admission.
It includes commit-before-acknowledgement loss, durable claims, one-use entry,
crashes, read-only recovery and collection fences. Shipping reservation/store
correspondence is a separate obligation; this module is not that refinement.
-/
namespace Auths.Product.AdmissionHistory

abbrev Operation := String × String
abbrev Worker := Nat
abbrev Counter := Nat

structure Debit where
  counter : Counter
  amount : Nat
  deriving DecidableEq

structure Request where
  operation : Operation
  worker : Worker
  debits : List Debit

structure Policy where
  capacity : Counter → Nat
  expires : Counter → Nat

structure State where
  claims : Operation → Option Worker
  handles : Operation → Option Worker
  entries : List (Operation × Worker)
  slots : Counter → Nat
  historical : Counter → Nat
  collectedThrough : Nat

/-- Aggregate every duplicate occurrence before comparing with a capacity. -/
def charge (debits : List Debit) (counter : Counter) : Nat :=
  (debits.map fun debit => if debit.counter = counter then debit.amount else 0).sum

def fits (policy : Policy) (state : State) (request : Request) : Bool :=
  request.debits.all fun debit =>
    decide (state.slots debit.counter + charge request.debits debit.counter ≤ policy.capacity debit.counter) &&
      decide (state.collectedThrough < policy.expires debit.counter)

/-- A lost acknowledgement commits exactly the same durable claim and slots
    while granting no volatile execution handle. -/
def admit (policy : Policy) (state : State) (request : Request) (acknowledged : Bool) : State :=
  if state.claims request.operation = none ∧ fits policy state request then
    {state with
      claims := Function.update state.claims request.operation (some request.worker)
      handles := Function.update state.handles request.operation
        (if acknowledged then some request.worker else none)
      slots := fun counter => state.slots counter + charge request.debits counter
      historical := fun counter => state.historical counter + charge request.debits counter}
  else state

/-- Collection records its durable monotone fence before any deletion. This
    reference collapses deletion prefixes into the final conservative state. -/
def collect (policy : Policy) (state : State) (cutoff : Nat) : State :=
  let fence := max state.collectedThrough cutoff
  {state with
    collectedThrough := fence
    slots := fun counter => if policy.expires counter ≤ fence then 0 else state.slots counter}

def crash (state : State) (worker : Worker) : State :=
  {state with handles := fun operation =>
    if state.handles operation = some worker then none else state.handles operation}

/-- The write-entry event consumes the handle. Connection/deadline/authority
    permits must constrain source entry before composing this history model. -/
def enter (state : State) (operation : Operation) (worker : Worker) : State :=
  if state.handles operation = some worker then
    {state with
      handles := Function.update state.handles operation none
      entries := state.entries ++ [(operation, worker)]}
  else state

inductive Event where
  | admission (request : Request) (acknowledged : Bool)
  | collection (cutoff : Nat)
  | processCrash (worker : Worker)
  | writeEntry (operation : Operation) (worker : Worker)
  | readOnlyRecovery
  | failedBeforeCommit
  | terminalRefusal (operation : Operation) (worker : Worker)

def step (policy : Policy) (state : State) : Event → State
  | .admission request acknowledged => admit policy state request acknowledged
  | .collection cutoff => collect policy state cutoff
  | .processCrash worker => crash state worker
  | .writeEntry operation worker => enter state operation worker
  | .readOnlyRecovery => state
  | .failedBeforeCommit => state
  | .terminalRefusal operation worker => admit policy state ⟨operation, worker, []⟩ false

def run (policy : Policy) (initial : State) (events : List Event) : State :=
  events.foldl (step policy) initial

def empty : State :=
  {claims := fun _ => none, handles := fun _ => none, entries := [], slots := fun _ => 0,
    historical := fun _ => 0, collectedThrough := 0}

def BudgetInvariant (policy : Policy) (state : State) : Prop :=
  (∀ counter, state.historical counter ≤ policy.capacity counter) ∧
  ∀ counter, state.collectedThrough < policy.expires counter →
    state.slots counter = state.historical counter

theorem charge_zero_of_absent (debits : List Debit) (counter : Counter)
    (absent : ∀ debit ∈ debits, debit.counter ≠ counter) : charge debits counter = 0 := by
  induction debits with
  | nil => rfl
  | cons debit rest ih =>
    have different := absent debit (by simp)
    have tail : ∀ item ∈ rest, item.counter ≠ counter := fun item member => absent item (by simp [member])
    simpa only [charge, List.map_cons, List.sum_cons, if_neg different, Nat.zero_add] using ih tail

theorem charge_positive_member (debits : List Debit) (counter : Counter)
    (positive : 0 < charge debits counter) : ∃ debit ∈ debits, debit.counter = counter := by
  by_contra missing
  have zero := charge_zero_of_absent debits counter (by simpa using missing)
  omega

theorem fits_aggregate (policy : Policy) (state : State) (request : Request)
    (accepted : fits policy state request = true) (counter : Counter)
    (positive : 0 < charge request.debits counter) :
    state.slots counter + charge request.debits counter ≤ policy.capacity counter ∧
      state.collectedThrough < policy.expires counter := by
  obtain ⟨debit, member, same⟩ := charge_positive_member request.debits counter positive
  have guard := List.all_eq_true.mp accepted debit member
  simpa only [same, Bool.and_eq_true, decide_eq_true_eq] using guard

theorem admit_preserves_budget (policy : Policy) (state : State) (request : Request)
    (acknowledged : Bool) (valid : BudgetInvariant policy state) :
    BudgetInvariant policy (admit policy state request acknowledged) := by
  unfold admit
  split
  · rename_i allowed
    rcases allowed with ⟨_, fitted⟩
    constructor
    · intro counter
      by_cases zero : charge request.debits counter = 0
      · simpa [zero] using valid.1 counter
      · have guarded := fits_aggregate policy state request fitted counter (by omega)
        rw [valid.2 counter guarded.2] at guarded
        exact guarded.1
    · intro counter openWindow
      simp only
      rw [valid.2 counter openWindow]
  · exact valid

theorem collect_preserves_budget (policy : Policy) (state : State) (cutoff : Nat)
    (valid : BudgetInvariant policy state) : BudgetInvariant policy (collect policy state cutoff) := by
  constructor
  · exact valid.1
  · intro counter stillOpen
    have priorOpen : state.collectedThrough < policy.expires counter :=
      lt_of_le_of_lt (Nat.le_max_left _ _) stillOpen
    change (if policy.expires counter ≤ max state.collectedThrough cutoff then 0 else state.slots counter) = state.historical counter
    have closed : ¬ policy.expires counter ≤ max state.collectedThrough cutoff := by
      change max state.collectedThrough cutoff < policy.expires counter at stillOpen
      omega
    rw [if_neg closed]
    exact valid.2 counter priorOpen

theorem step_preserves_budget (policy : Policy) (state : State) (event : Event)
    (valid : BudgetInvariant policy state) : BudgetInvariant policy (step policy state event) := by
  cases event with
  | admission request acknowledged => exact admit_preserves_budget policy state request acknowledged valid
  | collection cutoff => exact collect_preserves_budget policy state cutoff valid
  | processCrash worker => exact valid
  | writeEntry operation worker =>
    change BudgetInvariant policy (enter state operation worker)
    unfold enter
    split <;> exact valid
  | readOnlyRecovery => exact valid
  | failedBeforeCommit => exact valid
  | terminalRefusal operation worker =>
    exact admit_preserves_budget policy state ⟨operation, worker, []⟩ false valid

theorem run_preserves_budget (policy : Policy) (events : List Event) (initial : State)
    (valid : BudgetInvariant policy initial) : BudgetInvariant policy (run policy initial events) := by
  induction events generalizing initial with
  | nil => exact valid
  | cons event rest ih =>
    exact ih (step policy initial event) (step_preserves_budget policy initial event valid)

/-- Arbitrarily many workers and every finite interleaving preserve each
    window's historical capacity, including collection and earlier clocks. -/
theorem every_history_preserves_capacity (policy : Policy) (events : List Event) :
    BudgetInvariant policy (run policy empty events) := by
  apply run_preserves_budget
  constructor
  · intro counter; exact Nat.zero_le _
  · intro counter _; rfl

end Auths.Product.AdmissionHistory
