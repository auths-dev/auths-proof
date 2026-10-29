import Auths.Product.RelativeCeiling

/-!
# The admission order of one gateway submission

The gateway performs I/O only as a closed step machine directs. Each step
takes the machine state and the result of the action the previous decision
named, and returns the next state and the next action. This file models that
machine and proves ordering properties over every event trace: whatever the
environment answers, in whatever order, the machine names a credential lease,
a store write, or the provider write only after the checks that must precede
it succeeded.

A trace is the list of steps the machine takes from `start plan` on a list of
events: each step records the phase the event arrived in (so which action it
answers), the event, and the action the machine named in response. The
theorems quantify over every prefix `pre` and next event `event`, which is
every position of every trace (`step_at`).
-/

namespace Auths.Product.SubmitOrder

open Auths.Product.RelativeCeiling (admits)

/-- The declarations the order depends on, fixed before the machine starts. -/
structure Plan where
  accountScope : Bool
  accountRead : Bool
  deniedReads : Nat
  preEntry : Bool
  relativeCeiling : Bool
  basisPoints : Nat
  deriving DecidableEq, Repr

/-- Where the machine is; each phase awaits the result of one action. -/
inductive Phase where
  | start
  | clock
  | verify
  | admit
  | scope
  | prepare
  | claim
  | reload
  | lease
  | prefixGuard
  | account
  | denied (index : Nat)
  | preEntry
  | ceiling
  | checkpoint
  | entryReload
  | deadline
  | grant
  | send
  | recordResponse
  | recordUnknown
  | recordNotEntered
  | done
  deriving DecidableEq, Repr

/-- The machine state: the plan, the phase, and the verified argument, known
once native verification authorized the action. -/
structure State where
  plan : Plan
  phase : Phase
  argument : Nat
  deriving DecidableEq, Repr

/-- The native verification result. -/
inductive Verification where
  | refused
  | authorized (argument : Nat)
  deriving DecidableEq, Repr

/-- The claim result. -/
inductive ClaimResult where
  | reserved
  | refused
  | replay
  | unavailable
  deriving DecidableEq, Repr

/-- The account read result. -/
inductive AccountResult where
  | equal
  | mismatch
  | unavailable
  deriving DecidableEq, Repr

/-- The result of one denied read. -/
inductive DeniedResult where
  | refused
  | answered
  | unavailable
  deriving DecidableEq, Repr

/-- The pre-entry re-read result. -/
inductive PreEntryResult where
  | satisfied
  | conditionFalse
  | unavailable
  deriving DecidableEq, Repr

/-- The relative-ceiling read result. -/
inductive CeilingRead where
  | unavailable
  | read (basis : Nat) (bindsEqual : Bool)
  deriving DecidableEq, Repr

/-- The provider write result. -/
inductive WriteResult where
  | unknown
  | response
  deriving DecidableEq, Repr

/-- The result of recording the response. -/
inductive ResponseRecord where
  | failed
  | recorded
  deriving DecidableEq, Repr

/-- The result of the action the previous decision named. -/
inductive Event where
  | start
  | clock (read : Bool)
  | verification (result : Verification)
  | admission (admitted : Bool)
  | scope (bound : Bool)
  | preparation (prepared : Bool)
  | claim (result : ClaimResult)
  | reload (unchanged : Bool)
  | lease (leased : Bool)
  | prefixGuard (allowed : Bool)
  | account (result : AccountResult)
  | denied (result : DeniedResult)
  | preEntry (result : PreEntryResult)
  | ceiling (read : CeilingRead)
  | recorded (stored : Bool)
  | deadline (within : Bool)
  | granted (granted : Bool)
  | write (result : WriteResult)
  | response (record : ResponseRecord)
  deriving DecidableEq, Repr

/-- Why an entry was refused after the claim. -/
inductive Refusal where
  | connectionChanged
  | credentialUnavailable
  | modeGuard
  | accountMismatch
  | accountUnavailable
  | capabilityExcess
  | capabilityUnavailable
  | preEntryConditionFalse
  | preEntryUnavailable
  | ceilingAbove
  | ceilingBindingMismatch
  | ceilingUnavailable
  | entryDeadline
  | transportNotEntered
  deriving DecidableEq, Repr

/-- How the machine stopped. -/
inductive Stop where
  | refused
  | storeUnavailable
  | claimRefused
  | notEntered
  | unknown
  | response
  | stored
  | grantUnavailable
  | halted
  deriving DecidableEq, Repr

/-- The next action. -/
inductive Action where
  | readClock
  | verify
  | admit
  | bindScope
  | prepare
  | claim
  | reload
  | lease
  | checkPrefix
  | readAccount
  | deniedRead (index : Nat)
  | preEntryRead
  | ceilingRead
  | recordCheckpoint
  | reloadBeforeEntry
  | checkDeadline
  | grantEntry
  | send
  | recordResponse
  | recordUnknown
  | recordNotEntered (refusal : Refusal)
  | stop (stop : Stop)
  deriving DecidableEq, Repr

/-- The next state and action. -/
structure Decision where
  state : State
  action : Action
  deriving DecidableEq, Repr

/-! ## The step machine -/

/-- The machine before its first event. -/
def start (plan : Plan) : State := { plan, phase := .start, argument := 0 }

/-- Moves to `phase`, keeping the plan and argument, and names `action`. -/
def go (state : State) (phase : Phase) (action : Action) : Decision :=
  { state := { plan := state.plan, phase, argument := state.argument }, action }

def stop (state : State) (reason : Stop) : Decision := go state .done (.stop reason)

def halt (state : State) : Decision := stop state .halted

def notEntered (state : State) (refusal : Refusal) : Decision :=
  go state .recordNotEntered (.recordNotEntered refusal)

def afterReads (state : State) : Decision :=
  if state.plan.preEntry || state.plan.relativeCeiling then
    go state .checkpoint .recordCheckpoint
  else
    go state .entryReload .reloadBeforeEntry

def ceilingFrom (state : State) : Decision :=
  if state.plan.relativeCeiling then go state .ceiling .ceilingRead else afterReads state

def preEntryFrom (state : State) : Decision :=
  if state.plan.preEntry then go state .preEntry .preEntryRead else ceilingFrom state

def deniedFrom (state : State) (index : Nat) : Decision :=
  if index < state.plan.deniedReads then
    go state (.denied index) (.deniedRead index)
  else
    preEntryFrom state

def afterPrefix (state : State) : Decision :=
  if state.plan.accountRead then go state .account .readAccount
  else deniedFrom state 0

def afterAdmission (state : State) : Decision :=
  if state.plan.accountScope then go state .scope .bindScope else go state .prepare .prepare

def preClaim (state : State) (passed : Bool) (next : Decision) : Decision :=
  if passed then next else stop state .refused

def afterClaim (state : State) : ClaimResult → Decision
  | .reserved => go state .reload .reload
  | .refused => stop state .claimRefused
  | .replay => stop state .stored
  | .unavailable => stop state .storeUnavailable

def afterAccount (state : State) : AccountResult → Decision
  | .equal => deniedFrom state 0
  | .mismatch => notEntered state .accountMismatch
  | .unavailable => notEntered state .accountUnavailable

def afterDenied (state : State) (index : Nat) : DeniedResult → Decision
  | .refused =>
      if index < state.plan.deniedReads then deniedFrom state (index + 1) else halt state
  | .answered => notEntered state .capabilityExcess
  | .unavailable => notEntered state .capabilityUnavailable

def afterPreEntry (state : State) : PreEntryResult → Decision
  | .satisfied => ceilingFrom state
  | .conditionFalse => notEntered state .preEntryConditionFalse
  | .unavailable => notEntered state .preEntryUnavailable

/-- A bind mismatch dominates, then the exact ratio comparison on the
verified argument. -/
def afterCeiling (state : State) : CeilingRead → Decision
  | .unavailable => notEntered state .ceilingUnavailable
  | .read basis bindsEqual =>
      if !bindsEqual then notEntered state .ceilingBindingMismatch
      else if admits state.argument basis state.plan.basisPoints then afterReads state
      else notEntered state .ceilingAbove

def afterWrite (state : State) : WriteResult → Decision
  | .unknown => go state .recordUnknown .recordUnknown
  | .response => go state .recordResponse .recordResponse

def afterResponse (state : State) : ResponseRecord → Decision
  | .failed => stop state .unknown
  | .recorded => stop state .response

/-- The step before the claim. -/
def preClaimStep (state : State) (event : Event) : Decision :=
  match state.phase, event with
  | .start, .start => go state .clock .readClock
  | .clock, .clock read => preClaim state read (go state .verify .verify)
  | .verify, .verification .refused => stop state .refused
  | .verify, .verification (.authorized argument) =>
      { state := { plan := state.plan, phase := .admit, argument }, action := .admit }
  | .admit, .admission admitted => preClaim state admitted (afterAdmission state)
  | .scope, .scope bound => preClaim state bound (go state .prepare .prepare)
  | .prepare, .preparation prepared => preClaim state prepared (go state .claim .claim)
  | .claim, .claim result => afterClaim state result
  | _, _ => halt state

/-- A lease-time step. -/
def leaseStep (state : State) (event : Event) : Decision :=
  match state.phase, event with
  | .reload, .reload unchanged =>
      if unchanged then go state .lease .lease
      else notEntered state .connectionChanged
  | .lease, .lease leased =>
      if leased then go state .prefixGuard .checkPrefix
      else notEntered state .credentialUnavailable
  | .prefixGuard, .prefixGuard allowed =>
      if allowed then afterPrefix state else notEntered state .modeGuard
  | .account, .account result => afterAccount state result
  | .denied index, .denied result => afterDenied state index result
  | _, _ => halt state

/-- A step between the credential checks and the stop. -/
def entryStep (state : State) (event : Event) : Decision :=
  match state.phase, event with
  | .preEntry, .preEntry result => afterPreEntry state result
  | .ceiling, .ceiling read => afterCeiling state read
  | .checkpoint, .recorded stored =>
      if stored then go state .entryReload .reloadBeforeEntry else stop state .unknown
  | .entryReload, .reload unchanged =>
      if unchanged then go state .deadline .checkDeadline
      else notEntered state .connectionChanged
  | .deadline, .deadline within =>
      if within then go state .grant .grantEntry else notEntered state .entryDeadline
  | .grant, .granted granted =>
      if granted then go state .send .send else stop state .grantUnavailable
  | .send, .write result => afterWrite state result
  | .recordResponse, .response record => afterResponse state record
  | .recordUnknown, .recorded _ => stop state .unknown
  | .recordNotEntered, .recorded stored =>
      if stored then stop state .notEntered else stop state .unknown
  | _, _ => halt state

/-- The next state and action for `event`. -/
def nextStep (state : State) (event : Event) : Decision :=
  match state.phase with
  | .start | .clock | .verify | .admit | .scope | .prepare | .claim => preClaimStep state event
  | .reload | .lease | .prefixGuard | .account | .denied _ =>
      leaseStep state event
  | .preEntry | .ceiling | .checkpoint | .entryReload | .deadline | .grant | .send | .recordResponse
  | .recordUnknown | .recordNotEntered => entryStep state event
  | .done => halt state

/-! ## Traces -/

/-- One step of a trace: the phase the event arrived in, the event, and the
action the machine named in response. -/
structure Step where
  phase : Phase
  event : Event
  action : Action
  deriving DecidableEq, Repr

/-- The steps the machine takes from `state` on `events`. -/
def run : State → List Event → List Step
  | _, [] => []
  | state, event :: rest =>
      ⟨state.phase, event, (nextStep state event).action⟩ :: run (nextStep state event).state rest

/-- The state after `events`. -/
def stateFrom (state : State) (events : List Event) : State :=
  events.foldl (fun current event => (nextStep current event).state) state

/-- The steps of the trace from `start plan`. -/
def steps (plan : Plan) (events : List Event) : List Step := run (start plan) events

/-- The state after the events of a trace from `start plan`. -/
def stateAfter (plan : Plan) (events : List Event) : State := stateFrom (start plan) events

/-- `event` answered the action awaited in `phase` at some step of `trace`. -/
def Answered (trace : List Step) (phase : Phase) (event : Event) : Prop :=
  ∃ action, (⟨phase, event, action⟩ : Step) ∈ trace

/-- The machine named `action` at some step of `trace`. -/
def Emitted (trace : List Step) (action : Action) : Prop :=
  action ∈ trace.map Step.action

/-- The actions that write the attempt store. -/
def writesStore : Action → Bool
  | .claim | .recordCheckpoint | .recordNotEntered _ | .recordResponse | .recordUnknown
  | .grantEntry => true
  | _ => false

/-- The actions that touch the credential or the provider write. -/
def leasesOrSends : Action → Bool
  | .lease | .send => true
  | _ => false

theorem run_append (state : State) (events : List Event) (event : Event) :
    run state (events ++ [event]) =
      run state events ++
        [⟨(stateFrom state events).phase, event,
          (nextStep (stateFrom state events) event).action⟩] := by
  induction events generalizing state with
  | nil => rfl
  | cons head rest induction =>
      simp only [List.cons_append, run, stateFrom, List.foldl_cons] at induction ⊢
      rw [induction]

theorem stateFrom_append (state : State) (events : List Event) (event : Event) :
    stateFrom state (events ++ [event]) = (nextStep (stateFrom state events) event).state := by
  simp [stateFrom, List.foldl_append]

theorem length_run (state : State) (events : List Event) :
    (run state events).length = events.length := by
  induction events generalizing state with
  | nil => rfl
  | cons head rest induction => simp [run, induction]

/-- The step at position `index` of a trace is the step from the state after
the first `index` events on the event at `index`: the theorems below, stated
for a prefix and its next event, therefore hold at every position of every
trace. -/
theorem step_at (plan : Plan) (events : List Event) (index : Nat)
    (bound : index < events.length) :
    (steps plan events)[index]'(by simp [steps, length_run, bound]) =
      ⟨(stateAfter plan (events.take index)).phase, events[index],
        (nextStep (stateAfter plan (events.take index)) events[index]).action⟩ := by
  have split : events = events.take index ++ [events[index]] ++ events.drop (index + 1) := by
    simp
  unfold steps stateAfter
  generalize start plan = state
  induction events generalizing state index with
  | nil => simp at bound
  | cons head rest induction =>
      cases index with
      | zero => simp [run, stateFrom]
      | succ index =>
          simp only [run, List.getElem_cons_succ, List.take_succ_cons, stateFrom,
            List.foldl_cons]
          exact induction index (by simpa using bound) (by simp) _

theorem answered_append (trace : List Step) (step : Step) (phase : Phase) (event : Event) :
    Answered (trace ++ [step]) phase event ↔
      Answered trace phase event ∨ (step.phase = phase ∧ step.event = event) := by
  constructor
  · rintro ⟨action, member⟩
    rcases List.mem_append.mp member with inTrace | isStep
    · exact Or.inl ⟨action, inTrace⟩
    · rw [List.mem_singleton] at isStep
      exact Or.inr ⟨by rw [← isStep], by rw [← isStep]⟩
  · rintro (⟨action, member⟩ | ⟨phaseEq, eventEq⟩)
    · exact ⟨action, List.mem_append_left _ member⟩
    · refine ⟨step.action, List.mem_append_right _ ?_⟩
      rw [List.mem_singleton, ← phaseEq, ← eventEq]

theorem emitted_append (trace : List Step) (step : Step) (action : Action) :
    Emitted (trace ++ [step]) action ↔ Emitted trace action ∨ step.action = action := by
  simp [Emitted, eq_comm]

theorem steps_append (plan : Plan) (events : List Event) (event : Event) :
    steps plan (events ++ [event]) =
      steps plan events ++
        [⟨(stateAfter plan events).phase, event,
          (nextStep (stateAfter plan events) event).action⟩] :=
  run_append _ _ _

theorem stateAfter_append (plan : Plan) (events : List Event) (event : Event) :
    stateAfter plan (events ++ [event]) = (nextStep (stateAfter plan events) event).state :=
  stateFrom_append _ _ _

theorem nextStep_plan (state : State) (event : Event) :
    (nextStep state event).state.plan = state.plan := by
  rcases state with ⟨plan, phase, argument⟩
  cases phase <;> cases event <;>
    simp only [nextStep, preClaimStep, leaseStep, entryStep, go, stop, halt, notEntered,
      afterReads, ceilingFrom, preEntryFrom, deniedFrom,
      afterPrefix, afterAdmission, preClaim, afterClaim, afterAccount, afterDenied, afterPreEntry,
      afterCeiling, afterWrite, afterResponse] <;>
    (repeat' split) <;> rfl

/-- Induction over a trace one event at a time, from the end. -/
theorem snoc_induction {motive : List Event → Prop} (nil : motive [])
    (snoc : ∀ events event, motive events → motive (events ++ [event]))
    (events : List Event) : motive events := by
  rw [← List.reverse_reverse events]
  induction events.reverse with
  | nil => exact nil
  | cons event rest induction =>
      rw [List.reverse_cons]
      exact snoc _ _ induction

theorem stateAfter_plan (plan : Plan) (events : List Event) :
    (stateAfter plan events).plan = plan := by
  induction events using snoc_induction with
  | nil => rfl
  | snoc events event induction => rw [stateAfter_append, nextStep_plan, induction]

/-! ## What a trace has established -/

/-- Native verification authorized the action with `argument`. -/
def Verified (trace : List Step) (argument : Nat) : Prop :=
  Answered trace .verify (.verification (.authorized argument))

/-- The durable reservation accepted before credential access. -/
def Claimed (trace : List Step) : Prop :=
  Answered trace .claim (.claim .reserved)

/-- Every credential check passed: the lease, the
prefix guard, the account read when declared, and every declared denied
read. -/
def CredentialsChecked (trace : List Step) (plan : Plan) : Prop :=
  Answered trace .lease (.lease true) ∧
    Answered trace .prefixGuard (.prefixGuard true) ∧
    (plan.accountRead = true → Answered trace .account (.account .equal)) ∧
    ∀ index, index < plan.deniedReads →
      Answered trace (.denied index) (.denied .refused)

/-- The relative-ceiling read produced a basis with every bind equal, and
the ratio admits `argument`. -/
def CeilingAdmitted (trace : List Step) (plan : Plan) (argument : Nat) : Prop :=
  ∃ basis, Answered trace .ceiling (.ceiling (.read basis true)) ∧
    admits argument basis plan.basisPoints = true

/-- The declared pre-entry reads passed. -/
def ReadsPassed (trace : List Step) (plan : Plan) (argument : Nat) : Prop :=
  (plan.preEntry = true → Answered trace .preEntry (.preEntry .satisfied)) ∧
    (plan.relativeCeiling = true → CeilingAdmitted trace plan argument)

/-- What a trace has established when the machine is in `state`. -/
def Facts (trace : List Step) (state : State) : Prop :=
  match state.phase with
  | .start | .clock | .verify | .recordNotEntered | .done => True
  | .admit | .scope => Verified trace state.argument
  | .prepare | .claim =>
      Verified trace state.argument ∧
        (state.plan.accountScope = true → Answered trace .scope (.scope true))
  | .reload | .lease => Verified trace state.argument ∧ Claimed trace
  | .prefixGuard =>
      Verified trace state.argument ∧ Claimed trace ∧
        Answered trace .lease (.lease true)
  | .account =>
      Verified trace state.argument ∧ Claimed trace ∧
        Answered trace .lease (.lease true) ∧
        Answered trace .prefixGuard (.prefixGuard true)
  | .denied index =>
      Verified trace state.argument ∧ Claimed trace ∧
        Answered trace .lease (.lease true) ∧
        Answered trace .prefixGuard (.prefixGuard true) ∧
        (state.plan.accountRead = true → Answered trace .account (.account .equal)) ∧
        ∀ earlier, earlier < index → Answered trace (.denied earlier) (.denied .refused)
  | .preEntry =>
      Verified trace state.argument ∧ Claimed trace ∧
        CredentialsChecked trace state.plan
  | .ceiling =>
      Verified trace state.argument ∧ Claimed trace ∧
        CredentialsChecked trace state.plan ∧
        (state.plan.preEntry = true → Answered trace .preEntry (.preEntry .satisfied))
  | .checkpoint | .entryReload =>
      Verified trace state.argument ∧ Claimed trace ∧
        CredentialsChecked trace state.plan ∧
        ReadsPassed trace state.plan state.argument
  | .deadline =>
      Verified trace state.argument ∧ Claimed trace ∧
        CredentialsChecked trace state.plan ∧
        ReadsPassed trace state.plan state.argument ∧
        Answered trace .entryReload (.reload true)
  | .grant | .send | .recordResponse | .recordUnknown =>
      Verified trace state.argument ∧ Claimed trace ∧
        CredentialsChecked trace state.plan ∧ ReadsPassed trace state.plan state.argument ∧
        Answered trace .entryReload (.reload true) ∧
        Answered trace .deadline (.deadline true)

theorem denied_extend {trace : List Step} {index bound : Nat}
    (prior : ∀ earlier, earlier < index → Answered trace (.denied earlier) (.denied .refused))
    (within : bound ≤ index + 1) :
    ∀ earlier, earlier < bound →
      Answered trace (.denied earlier) (.denied .refused) ∨ index = earlier := by
  intro earlier below
  by_cases before : earlier < index
  · exact Or.inl (prior earlier before)
  · exact Or.inr (by omega)

theorem facts_step (trace : List Step) (state : State) (event : Event)
    (facts : Facts trace state) :
    Facts (trace ++ [⟨state.phase, event, (nextStep state event).action⟩])
      (nextStep state event).state := by
  rcases state with ⟨plan, phase, argument⟩
  cases phase <;> cases event <;>
    simp only [nextStep, preClaimStep, leaseStep, entryStep, go, stop, halt, notEntered,
      afterReads, ceilingFrom, preEntryFrom, deniedFrom,
      afterPrefix, afterAdmission, preClaim, afterClaim, afterAccount, afterDenied, afterPreEntry,
      afterCeiling, afterWrite, afterResponse] at facts ⊢ <;>
    (repeat' split) <;>
    simp_all [Facts, Verified, Claimed, CredentialsChecked, CeilingAdmitted, ReadsPassed,
      answered_append] <;>
    (obtain ⟨-, -, -, -, -, prior⟩ := facts
     exact denied_extend prior (by omega))

/-- The phases before native verification answered. -/
def beforeVerification : Phase → Bool
  | .start | .clock | .verify => true
  | _ => false

/-- The phases before the claim was named. -/
def beforeClaim : Phase → Bool
  | .start | .clock | .verify | .admit | .scope | .prepare => true
  | _ => false

/-- The actions the machine names before the claim. -/
def preClaimAction : Action → Bool
  | .readClock | .verify | .admit | .bindScope | .prepare => true
  | _ => false

/-- The phases the machine can be in once it named the write. -/
def afterSend : Phase → Bool
  | .send | .recordResponse | .recordUnknown | .done => true
  | _ => false

/-- A replay returns the retained record without another effect. -/
def replaying : Phase → Bool
  | .done => true
  | _ => false

/-- The ordering invariant of a trace ending in `state`. -/
def Ordered (trace : List Step) (state : State) : Prop :=
  (∀ argument, Verified trace argument → argument = state.argument) ∧
    (beforeVerification state.phase = true → ∀ step ∈ trace, step.phase ≠ .verify) ∧
    (beforeClaim state.phase = true → ∀ step ∈ trace, preClaimAction step.action = true) ∧
    (trace.map Step.action).count .send ≤ 1 ∧
    (Emitted trace .send → afterSend state.phase = true) ∧
    (Answered trace .claim (.claim .replay) →
      replaying state.phase = true ∧ ¬ Emitted trace .send)

theorem not_verified_of_fresh {trace : List Step}
    (fresh : ∀ step ∈ trace, step.phase ≠ .verify) (argument : Nat) :
    ¬ Verified trace argument := by
  rintro ⟨action, member⟩
  exact fresh _ member rfl

/-- The argument after a step: the authorized argument when verification
answers, and unchanged otherwise. -/
def argumentAfter (state : State) (event : Event) : Nat :=
  match state.phase, event with
  | .verify, .verification (.authorized argument) => argument
  | _, _ => state.argument

set_option hygiene false in
/-- Unfolds one step of the machine and closes each case of the case split. -/
macro "step_cases" : tactic => `(tactic| (
  rcases state with ⟨plan, phase, argument⟩
  cases phase <;> cases event <;> (try cases ‹Verification›) <;>
    simp only [nextStep, preClaimStep, leaseStep, entryStep, go, stop, halt, notEntered,
      afterReads, ceilingFrom, preEntryFrom, deniedFrom,
      afterPrefix, afterAdmission, preClaim, afterClaim, afterAccount, afterDenied, afterPreEntry,
      afterCeiling, afterWrite, afterResponse] <;>
    (repeat' split) <;>
    simp_all [argumentAfter, beforeVerification, beforeClaim, preClaimAction, afterSend,
      replaying]))

theorem argument_step (state : State) (event : Event) :
    (nextStep state event).state.argument = argumentAfter state event := by
  step_cases

theorem before_verification_step (state : State) (event : Event)
    (before : beforeVerification (nextStep state event).state.phase = true) :
    beforeVerification state.phase = true ∧ state.phase ≠ .verify := by
  revert before
  step_cases

theorem before_claim_step (state : State) (event : Event)
    (before : beforeClaim (nextStep state event).state.phase = true) :
    beforeClaim state.phase = true ∧ preClaimAction (nextStep state event).action = true := by
  revert before
  step_cases

theorem send_step (state : State) (event : Event)
    (sent : (nextStep state event).action = .send) :
    state.phase = .grant ∧ event = .granted true ∧ (nextStep state event).state.phase = .send := by
  revert sent
  step_cases

theorem after_send_step (state : State) (event : Event) (sent : afterSend state.phase = true) :
    afterSend (nextStep state event).state.phase = true ∧ (nextStep state event).action ≠ .send := by
  revert sent
  step_cases

theorem replaying_step (state : State) (event : Event) (replayed : replaying state.phase = true) :
    replaying (nextStep state event).state.phase = true ∧ (nextStep state event).action ≠ .send := by
  revert replayed
  step_cases

theorem replay_step (state : State) (claiming : state.phase = .claim) :
    replaying (nextStep state (.claim .replay)).state.phase = true := by
  rcases state with ⟨plan, phase, argument⟩
  cases claiming
  rfl

theorem ordered_step (trace : List Step) (state : State) (event : Event)
    (ordered : Ordered trace state) :
    Ordered (trace ++ [⟨state.phase, event, (nextStep state event).action⟩])
      (nextStep state event).state := by
  rcases ordered with ⟨pinned, fresh, quiet, once, sent, replayed⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro value verified
    rw [argument_step]
    rcases (answered_append _ _ _ _).mp verified with old | ⟨phaseEq, eventEq⟩
    · by_cases verifying : state.phase = .verify
      · exact absurd old (not_verified_of_fresh (fresh (by rw [verifying]; rfl)) value)
      · rw [pinned value old]
        unfold argumentAfter
        split <;> simp_all
    · simp only at phaseEq eventEq
      unfold argumentAfter
      rw [phaseEq, eventEq]
  · intro before step member
    obtain ⟨beforeOld, notVerify⟩ := before_verification_step state event before
    rcases List.mem_append.mp member with old | isStep
    · exact fresh beforeOld step old
    · rw [List.mem_singleton] at isStep
      rw [isStep]
      exact notVerify
  · intro before step member
    obtain ⟨beforeOld, quietAction⟩ := before_claim_step state event before
    rcases List.mem_append.mp member with old | isStep
    · exact quiet beforeOld step old
    · rw [List.mem_singleton] at isStep
      rw [isStep]
      exact quietAction
  · rw [List.map_append, List.count_append]
    by_cases sending : (nextStep state event).action = .send
    · have noneBefore : ¬ Emitted trace .send := by
        intro emitted
        have := (after_send_step state event (sent emitted)).2
        exact this sending
      have zero : (trace.map Step.action).count .send = 0 :=
        List.count_eq_zero.mpr noneBefore
      simp [zero, sending]
    · simp [sending, once]
  · intro emitted
    rcases (emitted_append _ _ _).mp emitted with old | sending
    · exact (after_send_step state event (sent old)).1
    · rw [(send_step state event sending).2.2]
      rfl
  · intro replay
    rcases (answered_append _ _ _ _).mp replay with old | ⟨phaseEq, eventEq⟩
    · obtain ⟨replayingOld, noSend⟩ := replayed old
      obtain ⟨replayingNew, notSend⟩ := replaying_step state event replayingOld
      refine ⟨replayingNew, ?_⟩
      intro emitted
      rcases (emitted_append _ _ _).mp emitted with old | sending
      · exact noSend old
      · exact notSend sending
    · simp only at phaseEq eventEq
      subst eventEq
      refine ⟨replay_step state phaseEq, ?_⟩
      intro emitted
      rcases (emitted_append _ _ _).mp emitted with old | sending
      · have := sent old
        rw [phaseEq] at this
        exact absurd this (by decide)
      · have := (send_step state _ sending).1
        rw [phaseEq] at this
        cases this

theorem lease_named (state : State) (event : Event)
    (leased : (nextStep state event).action = .lease) :
    state.phase = .reload ∧ event = .reload true := by
  revert leased
  step_cases

theorem claim_named (state : State) (event : Event)
    (claimed : (nextStep state event).action = .claim) :
    state.phase = .prepare ∧ event = .preparation true := by
  revert claimed
  step_cases

theorem refused_named (state : State) (event : Event)
    (refused : (nextStep state event).action = .stop .refused) :
    beforeClaim state.phase = true := by
  revert refused
  step_cases

theorem quiet_action (action : Action) (quiet : preClaimAction action = true) :
    writesStore action = false ∧ leasesOrSends action = false := by
  cases action <;> simp_all [preClaimAction, writesStore, leasesOrSends]

/-- Every trace from `start plan` satisfies both invariants. -/
theorem invariant (plan : Plan) (events : List Event) :
    Facts (steps plan events) (stateAfter plan events) ∧
      Ordered (steps plan events) (stateAfter plan events) := by
  induction events using snoc_induction with
  | nil =>
      refine ⟨trivial, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
        simp [steps, stateAfter, run, stateFrom, start, Verified, Answered, Emitted]
  | snoc events event induction =>
      rw [steps_append, stateAfter_append]
      exact ⟨facts_step _ _ _ induction.1, ordered_step _ _ _ induction.2⟩

/-! ## Ordering theorems -/

/-- A credential lease requires native authorization and a durable reservation. -/
theorem lease_requires_verified_claim (plan : Plan) (pre : List Event) (event : Event)
    (leased : (nextStep (stateAfter plan pre) event).action = .lease) :
    event = .reload true ∧ (stateAfter plan pre).phase = .reload ∧
      (∃ argument, Verified (steps plan pre) argument) ∧
      Answered (steps plan pre) .claim (.claim .reserved) := by
  obtain ⟨phase, eventEq⟩ := lease_named _ _ leased
  have facts := (invariant plan pre).1
  unfold Facts at facts
  rw [phase] at facts
  exact ⟨eventEq, phase, ⟨_, facts.1⟩, facts.2⟩

/-- The write is named only on a successful durable grant, after the deadline
check and entry lease, after the declared pre-entry re-read was satisfied,
after the connection reload found the record unchanged, and after a durable
reservation of a verified action. -/
theorem send_requires_lease_and_deadline (plan : Plan) (pre : List Event) (event : Event)
    (sent : (nextStep (stateAfter plan pre) event).action = .send) :
    event = .granted true ∧ (stateAfter plan pre).phase = .grant ∧
      (∃ argument, Verified (steps plan pre) argument) ∧
      Answered (steps plan pre) .claim (.claim .reserved) ∧
      Answered (steps plan pre) .lease (.lease true) ∧
      (plan.preEntry = true → Answered (steps plan pre) .preEntry (.preEntry .satisfied)) ∧
      Answered (steps plan pre) .entryReload (.reload true) ∧
      Answered (steps plan pre) .deadline (.deadline true) := by
  obtain ⟨phase, eventEq, _⟩ := send_step _ _ sent
  have facts := (invariant plan pre).1
  unfold Facts at facts
  rw [phase, stateAfter_plan] at facts
  obtain ⟨verified, claimed, ⟨leased, _⟩, ⟨preEntry, _⟩, reloaded⟩ := facts
  exact ⟨eventEq, phase, ⟨_, verified⟩, claimed, leased, preEntry, reloaded⟩

/-- The write is named only after the entry lease passed every credential
check: the prefix guard, the account read with equal commitments when
declared, and every declared denied read refused with a declared status. -/
theorem send_requires_credential_checks (plan : Plan) (pre : List Event) (event : Event)
    (sent : (nextStep (stateAfter plan pre) event).action = .send) :
    Answered (steps plan pre) .prefixGuard (.prefixGuard true) ∧
      (plan.accountRead = true → Answered (steps plan pre) .account (.account .equal)) ∧
      ∀ index, index < plan.deniedReads →
        Answered (steps plan pre) (.denied index) (.denied .refused) := by
  obtain ⟨phase, _, _⟩ := send_step _ _ sent
  have facts := (invariant plan pre).1
  unfold Facts at facts
  rw [phase, stateAfter_plan] at facts
  obtain ⟨_, _, ⟨_, guarded, account, denied⟩, _, _⟩ := facts
  exact ⟨guarded, account, denied⟩

/-- With a declared relative ceiling, the write is named only after the
relative-ceiling read produced a basis with every bind equal and the exact
ratio admitted the argument that native verification authorized, the only
argument the trace authorized. -/
theorem send_requires_relative_ceiling (plan : Plan) (pre : List Event) (event : Event)
    (sent : (nextStep (stateAfter plan pre) event).action = .send)
    (declared : plan.relativeCeiling = true) :
    ∃ argument basis,
      Verified (steps plan pre) argument ∧
        (∀ other, Verified (steps plan pre) other → other = argument) ∧
        Answered (steps plan pre) .ceiling (.ceiling (.read basis true)) ∧
        admits argument basis plan.basisPoints = true := by
  obtain ⟨phase, _, _⟩ := send_step _ _ sent
  obtain ⟨facts, pinned, _⟩ := invariant plan pre
  unfold Facts at facts
  rw [phase, stateAfter_plan] at facts
  obtain ⟨verified, _, _, ⟨_, ceiling⟩, _⟩ := facts
  obtain ⟨basis, read, admitted⟩ := ceiling declared
  exact ⟨_, basis, verified, pinned, read, admitted⟩

/-- With a declared account scope, the claim is named only after the
account-scope binding found every link's scope listing the verified value. -/
theorem account_scope_requires_binding (plan : Plan) (pre : List Event) (event : Event)
    (claimed : (nextStep (stateAfter plan pre) event).action = .claim)
    (declared : plan.accountScope = true) :
    Answered (steps plan pre) .scope (.scope true) ∧
      ∃ argument, Verified (steps plan pre) argument := by
  obtain ⟨phase, _⟩ := claim_named _ _ claimed
  have facts := (invariant plan pre).1
  unfold Facts at facts
  rw [phase, stateAfter_plan] at facts
  exact ⟨facts.2 declared, _, facts.1⟩

/-- Every trace names the write at most once, and a trace whose claim
replayed never names it. -/
theorem at_most_one_send (plan : Plan) (events : List Event) :
    ((steps plan events).map Step.action).count .send ≤ 1 ∧
      (Answered (steps plan events) .claim (.claim .replay) →
        ¬ Emitted (steps plan events) .send) := by
  obtain ⟨_, _, _, _, once, _, replayed⟩ := invariant plan events
  exact ⟨once, fun replay => (replayed replay).2⟩

/-- A refusal before the claim is preceded by no store write, no lease, and
no write: every action named before it is the clock read, verification,
admission, the account-scope binding, or transport preparation. -/
theorem pre_claim_refusal_stores_nothing (plan : Plan) (pre : List Event) (event : Event)
    (refused : (nextStep (stateAfter plan pre) event).action = .stop .refused) :
    ∀ step ∈ steps plan pre,
      preClaimAction step.action = true ∧ writesStore step.action = false ∧
        leasesOrSends step.action = false := by
  intro step member
  obtain ⟨_, _, _, quiet, _⟩ := invariant plan pre
  have isQuiet := quiet (refused_named _ _ refused) step member
  exact ⟨isQuiet, quiet_action _ isQuiet⟩

/-- The refusal a failure after the claim and before transport entry
records, by phase and event; `none` for every other step. -/
def refusalOf (state : State) (event : Event) : Option Refusal :=
  match state.phase, event with
  | .reload, .reload false => some .connectionChanged
  | .lease, .lease false => some .credentialUnavailable
  | .prefixGuard, .prefixGuard false => some .modeGuard
  | .account, .account .mismatch => some .accountMismatch
  | .account, .account .unavailable => some .accountUnavailable
  | .denied _, .denied .answered => some .capabilityExcess
  | .denied _, .denied .unavailable => some .capabilityUnavailable
  | .preEntry, .preEntry .conditionFalse => some .preEntryConditionFalse
  | .preEntry, .preEntry .unavailable => some .preEntryUnavailable
  | .ceiling, .ceiling .unavailable => some .ceilingUnavailable
  | .ceiling, .ceiling (.read _ false) => some .ceilingBindingMismatch
  | .ceiling, .ceiling (.read basis true) =>
      if admits state.argument basis state.plan.basisPoints then none else some .ceilingAbove
  | .entryReload, .reload false => some .connectionChanged
  | .deadline, .deadline false => some .entryDeadline
  | _, _ => none

/-- The per-phase table: a step records `not-entered` with a refusal exactly
when the table assigns that refusal to its phase and event, and then the
machine awaits that store write. -/
theorem not_entered_refusal_table (state : State) (event : Event) (refusal : Refusal) :
    (nextStep state event).action = .recordNotEntered refusal ↔
      refusalOf state event = some refusal := by
  step_cases <;> simp_all [refusalOf]

theorem not_entered_phase (state : State) (event : Event) (refusal : Refusal)
    (recorded : (nextStep state event).action = .recordNotEntered refusal) :
    (nextStep state event).state.phase = .recordNotEntered := by
  revert recorded
  step_cases

theorem refusal_claimed (trace : List Step) (state : State) (event : Event) (refusal : Refusal)
    (facts : Facts trace state) (assigned : refusalOf state event = some refusal) :
    Answered trace .claim (.claim .reserved) := by
  rcases state with ⟨plan, phase, argument⟩
  cases phase <;> simp_all [Facts, Claimed, refusalOf]

theorem refusal_after_send (state : State) (event : Event) (refusal : Refusal)
    (sent : afterSend state.phase = true) (assigned : refusalOf state event = some refusal) :
    False := by
  rcases state with ⟨plan, phase, argument⟩
  cases phase <;> cases event <;> simp_all [afterSend, refusalOf] <;>
    (repeat' split at assigned) <;> simp_all

/-- Over every trace: a step records `not-entered` exactly when the claim
was reserved and the step's phase and event are a failure the table assigns
a refusal to, and the recorded refusal is that failure's. Once the write was
named, no such refusal can be emitted. -/
theorem post_claim_refusal_records_not_entered (plan : Plan) (pre : List Event)
    (event : Event) (refusal : Refusal) :
    ((nextStep (stateAfter plan pre) event).action = .recordNotEntered refusal ↔
        Answered (steps plan pre) .claim (.claim .reserved) ∧
          refusalOf (stateAfter plan pre) event = some refusal) ∧
      ((nextStep (stateAfter plan pre) event).action = .recordNotEntered refusal →
        (nextStep (stateAfter plan pre) event).state.phase = .recordNotEntered ∧
          ¬ Emitted (steps plan pre) .send) := by
  obtain ⟨facts, _, _, _, _, sent, _⟩ := invariant plan pre
  refine ⟨⟨fun recorded => ?_, fun ⟨_, assigned⟩ => ?_⟩, fun recorded => ?_⟩
  · have assigned := (not_entered_refusal_table _ _ _).mp recorded
    exact ⟨refusal_claimed _ _ _ _ facts assigned, assigned⟩
  · exact (not_entered_refusal_table _ _ _).mpr assigned
  · refine ⟨not_entered_phase _ _ _ recorded, fun emitted => ?_⟩
    exact refusal_after_send _ _ _ (sent emitted) ((not_entered_refusal_table _ _ _).mp recorded)

/-- A recorded response is a terminal submission result. Observation requires a
separate authorized operation; the submission machine emits no follow-up read. -/
theorem response_stops_without_read (state : State) (phase : state.phase = .recordResponse) :
    nextStep state (.response .recorded) = stop state .response := by
  rcases state with ⟨plan, phase', argument⟩
  cases phase
  rfl

/-- Losing or replaying an existing reservation returns its retained record;
it cannot resume credential acquisition or issue another entry grant. -/
theorem replay_returns_stored (state : State) (phase : state.phase = .claim) :
    nextStep state (.claim .replay) = stop state .stored := by
  rcases state with ⟨plan, phase', argument⟩
  cases phase
  rfl

/-- A failed durable grant stops without sending, and never fabricates a
not-entered refund after the authority boundary. -/
theorem refused_grant_stops_without_send (state : State) (phase : state.phase = .grant) :
    nextStep state (.granted false) = stop state .grantUnavailable := by
  rcases state with ⟨plan, phase', argument⟩
  cases phase
  rfl

end Auths.Product.SubmitOrder
