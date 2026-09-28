import Mathlib.Logic.ExistsUnique

/-!
# Recovery capability of a gateway recipe

What a recipe can prove after an ambiguous write is a total function of three
declarations (the observation locator, the echo, and the idempotency
mechanism) plus whether a pre-entry re-read is declared. The class names what
a later read-back can establish; `unknownResolution` says whether the gateway
can ever resolve an `unknown` write, which only a verified-locator link can.
No declaration makes the provider write conditional.

The attempt record then moves through a closed stage table. The gateway store
projects each stored record onto an `AttemptView`: the canonical bytes of the
fields no transition may change (identity, evaluation time, reserved counters,
and the observation plan), the stage, and the bytes or presence of every field
a transition may add. The transition theorems hold over every sequence of
records in which each replaces the previous by a valid transition.
-/

namespace Auths.Product.Recovery

/-- How provider state can be read after the write. -/
inductive Observation where
  | none
  | verifiedLocator
  | responseLocator
  deriving DecidableEq, Repr

/-- The declared idempotency mechanism. -/
inductive Mechanism where
  | derivedHeader
  | operationIdField
  deriving DecidableEq, Repr

/-- What a re-entry after a lost claim can rely on. -/
inductive Reentry where
  | none
  | declared (mechanism : Mechanism) (retentionSeconds : Nat)
  deriving DecidableEq, Repr

/-- The declarations the capability depends on. -/
structure Declarations where
  observation : Observation
  echo : Bool
  idempotency : Reentry
  preEntry : Bool
  deriving DecidableEq, Repr

/-- The recovery class. -/
inductive RecoveryClass where
  | linked
  | linkedAfterResponse
  | observed
  | recorded
  deriving DecidableEq, Repr

/-- Whether an `unknown` write can resolve. -/
inductive Resolution where
  | gatewayReobservation
  | none
  deriving DecidableEq, Repr

/-- `auths.gateway-recovery-capability/1`. -/
structure Capability where
  recoveryClass : RecoveryClass
  stateObservation : Observation
  providerLink : Observation
  unknownResolution : Resolution
  lostClaimReentry : Reentry
  preEntryReread : Bool
  writeIsConditional : Bool
  deriving DecidableEq, Repr

/-- The provider link: the observation locator when an echo is declared. -/
def providerLink (observation : Observation) (echo : Bool) : Observation :=
  if echo then observation else .none

/-- The class a link and an observation determine. -/
def classOf (observation link : Observation) : RecoveryClass :=
  match link with
  | .verifiedLocator => .linked
  | .responseLocator => .linkedAfterResponse
  | .none =>
      match observation with
      | .none => .recorded
      | .verifiedLocator | .responseLocator => .observed

/-- Only a verified-locator link resolves `unknown`. -/
def resolutionOf : RecoveryClass → Resolution
  | .linked => .gatewayReobservation
  | .linkedAfterResponse | .observed | .recorded => .none

/-- The capability of a declaration set. -/
def capability (declarations : Declarations) : Capability :=
  let link := providerLink declarations.observation declarations.echo
  let recoveryClass := classOf declarations.observation link
  { recoveryClass
    stateObservation := declarations.observation
    providerLink := link
    unknownResolution := resolutionOf recoveryClass
    lostClaimReentry := declarations.idempotency
    preEntryReread := declarations.preEntry
    writeIsConditional := false }

/-- Every declaration set maps to exactly one capability, and no capability
makes the write conditional. -/
theorem capability_total_deterministic (declarations : Declarations) :
    ∃! result : Capability,
      capability declarations = result ∧ result.writeIsConditional = false := by
  refine ⟨capability declarations, ⟨rfl, rfl⟩, ?_⟩
  intro other ⟨equal, _⟩
  exact equal.symm

/-- Each class holds exactly under its declaration rule: `linked` for a
verified-locator link, `linked-after-response` for a response-locator link,
`observed` for an observation without echo, and `recorded` otherwise. The
capability copies the observation, the idempotency declaration, and the
pre-entry flag, and only `linked` resolves `unknown`. -/
theorem class_matches_declarations (declarations : Declarations) :
    ((capability declarations).recoveryClass = .linked ↔
        declarations.observation = .verifiedLocator ∧ declarations.echo = true) ∧
      ((capability declarations).recoveryClass = .linkedAfterResponse ↔
        declarations.observation = .responseLocator ∧ declarations.echo = true) ∧
      ((capability declarations).recoveryClass = .observed ↔
        declarations.observation ≠ .none ∧ declarations.echo = false) ∧
      ((capability declarations).recoveryClass = .recorded ↔
        declarations.observation = .none) ∧
      ((capability declarations).unknownResolution = .gatewayReobservation ↔
        (capability declarations).recoveryClass = .linked) ∧
      (capability declarations).stateObservation = declarations.observation ∧
      (capability declarations).providerLink =
        (if declarations.echo then declarations.observation else .none) ∧
      (capability declarations).lostClaimReentry = declarations.idempotency ∧
      (capability declarations).preEntryReread = declarations.preEntry := by
  obtain ⟨observation, echo, idempotency, preEntry⟩ := declarations
  cases observation <;> cases echo <;>
    simp [capability, providerLink, classOf, resolutionOf]

/-- `write_is_conditional` is always `false`. -/
theorem write_never_conditional (declarations : Declarations) :
    (capability declarations).writeIsConditional = false := rfl

/-! ## Attempt-record transitions -/

/-- The stage of an attempt record. -/
inductive Stage where
  | attempting
  | notEntered
  | unknown
  | responseRecorded
  | observed
  | observedByProvider
  deriving DecidableEq, Repr

/-- The read-back comparison recorded with an `observed` stage. -/
inductive Reading where
  | none
  | matched
  | mismatched
  | echoMismatch
  deriving DecidableEq, Repr

/-- The provider link of the stored observation plan. -/
inductive Link where
  | none
  | verified
  | afterResponse
  deriving DecidableEq, Repr

/-- The fields of one stored attempt record the transition rule inspects;
byte strings are empty when absent. -/
structure AttemptView where
  fixed : List Nat
  stage : Stage
  refusal : Bool
  preEntry : List Nat
  response : List Nat
  locator : List Nat
  reading : Reading
  evidence : Bool
  observation : Bool
  link : Link
  deriving DecidableEq, Repr

/-- The stored link a capability's provider link becomes. -/
def linkOf : Observation → Link
  | .none => .none
  | .verifiedLocator => .verified
  | .responseLocator => .afterResponse

def resolvesUnknown : Link → Bool
  | .verified => true
  | .none | .afterResponse => false

def hasLink : Link → Bool
  | .none => false
  | .verified | .afterResponse => true

def refusalStage : Stage → Bool
  | .notEntered => true
  | _ => false

def requiresResponse : Stage → Bool
  | .responseRecorded | .observed => true
  | _ => false

def permitsResponse : Stage → Bool
  | .responseRecorded | .observed | .observedByProvider => true
  | _ => false

def observedStage : Stage → Bool
  | .observed => true
  | _ => false

def providerStage : Stage → Bool
  | .observedByProvider => true
  | _ => false

/-- The stages with no outgoing transition. -/
def terminalStage : Stage → Bool
  | .notEntered | .observed | .observedByProvider => true
  | .attempting | .unknown | .responseRecorded => false

def hasReading : Reading → Bool
  | .none => false
  | _ => true

/-- A view's fields agree with its stage. -/
def consistent (view : AttemptView) : Bool :=
  let hasResponse := !view.response.isEmpty
  decide (refusalStage view.stage = view.refusal) &&
    (!requiresResponse view.stage || hasResponse) &&
    (!hasResponse || permitsResponse view.stage) &&
    (view.locator.isEmpty || hasResponse) &&
    decide (observedStage view.stage = hasReading view.reading) &&
    (!hasReading view.reading || view.observation) &&
    decide (providerStage view.stage = view.evidence) &&
    (!view.evidence || hasLink view.link) &&
    (!view.evidence || hasResponse || resolvesUnknown view.link)

/-- The closed stage table, given the stored plan's link. -/
def stageTransitionAllowed (source target : Stage) (link : Link) : Bool :=
  match source, target with
  | .attempting, .attempting | .attempting, .notEntered | .attempting, .unknown
  | .attempting, .responseRecorded => true
  | .attempting, .observedByProvider => resolvesUnknown link
  | .unknown, .observedByProvider => resolvesUnknown link
  | .responseRecorded, .observed | .responseRecorded, .observedByProvider => true
  | _, _ => false

def addsPreEntry (source target : Stage) : Bool :=
  match source, target with
  | .attempting, .attempting | .attempting, .notEntered => true
  | _, _ => false

def addsResponse (source target : Stage) : Bool :=
  match source, target with
  | .attempting, .responseRecorded => true
  | _, _ => false

def checkpointValid (old new : AttemptView) : Bool :=
  match old.stage, new.stage with
  | .attempting, .attempting => old.preEntry.isEmpty && !new.preEntry.isEmpty
  | _, _ => true

def preEntryKept (old new : AttemptView) : Bool :=
  if old.preEntry.isEmpty then new.preEntry.isEmpty || addsPreEntry old.stage new.stage
  else decide (old.preEntry = new.preEntry)

def responseKept (old new : AttemptView) : Bool :=
  addsResponse old.stage new.stage ||
    (decide (old.response = new.response) && decide (old.locator = new.locator))

def planKept (old new : AttemptView) : Bool :=
  decide (old.observation = new.observation) && decide (old.link = new.link)

/-- Whether `new` may replace `old`. -/
def validTransition (old new : AttemptView) : Bool :=
  decide (old.fixed = new.fixed) && planKept old new &&
    stageTransitionAllowed old.stage new.stage old.link && checkpointValid old new &&
    preEntryKept old new && responseKept old new && consistent new

/-- Each record replaces the previous one by a valid transition. -/
def validChain : List AttemptView → Prop
  | first :: second :: rest => validTransition first second = true ∧ validChain (second :: rest)
  | _ => True

/-- What every transition keeps: the unchangeable bytes and the plan, and a
pre-entry record or response, once set, unchanged. -/
def Keeps (old new : AttemptView) : Prop :=
  new.fixed = old.fixed ∧ new.observation = old.observation ∧ new.link = old.link ∧
    (old.preEntry ≠ [] → new.preEntry = old.preEntry) ∧
    (old.response ≠ [] → new.response = old.response ∧ new.locator = old.locator)

theorem keeps_refl (view : AttemptView) : Keeps view view := by
  simp [Keeps]

theorem keeps_trans {first second third : AttemptView} (one : Keeps first second)
    (two : Keeps second third) : Keeps first third := by
  obtain ⟨f1, o1, l1, p1, r1⟩ := one
  obtain ⟨f2, o2, l2, p2, r2⟩ := two
  refine ⟨f2.trans f1, o2.trans o1, l2.trans l1, fun present => ?_, fun present => ?_⟩
  · rw [p2 (by rw [p1 present]; exact present), p1 present]
  · obtain ⟨response1, locator1⟩ := r1 present
    obtain ⟨response2, locator2⟩ := r2 (by rw [response1]; exact present)
    exact ⟨response2.trans response1, locator2.trans locator1⟩

theorem transition_consistent {old new : AttemptView} (valid : validTransition old new = true) :
    consistent new = true := by
  simp only [validTransition, Bool.and_eq_true] at valid
  exact valid.2

theorem transition_keeps {old new : AttemptView} (consistentOld : consistent old = true)
    (valid : validTransition old new = true) : Keeps old new := by
  simp only [validTransition, Bool.and_eq_true, decide_eq_true_eq] at valid
  obtain ⟨⟨⟨⟨⟨⟨fixedEq, planEq⟩, _⟩, _⟩, preKept⟩, responseKeptEq⟩, _⟩ := valid
  simp only [planKept, Bool.and_eq_true, decide_eq_true_eq] at planEq
  refine ⟨fixedEq.symm, planEq.1.symm, planEq.2.symm, fun present => ?_, fun present => ?_⟩
  · have nonempty : old.preEntry.isEmpty = false := by
      cases equal : old.preEntry with
      | nil => exact absurd equal present
      | cons _ _ => rfl
    simp only [preEntryKept, nonempty, Bool.false_eq_true, if_false, decide_eq_true_eq]
      at preKept
    exact preKept.symm
  · simp only [responseKept, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
      at responseKeptEq
    rcases responseKeptEq with adds | ⟨responseEq, locatorEq⟩
    · exfalso
      rcases old with ⟨fixed, stage, refusal, preEntry, response, locator, reading, evidence,
        observation, link⟩
      cases stage <;> cases equal : new.stage <;> simp_all [addsResponse] <;>
        cases response <;> simp_all [consistent, permitsResponse]
    · exact ⟨responseEq.symm, locatorEq.symm⟩

theorem chain_step {views : List AttemptView} (chain : validChain views) (index : Nat)
    (bound : index + 1 < views.length) :
    validTransition (views[index]'(by omega)) views[index + 1] = true := by
  induction views generalizing index with
  | nil => simp at bound
  | cons first rest induction =>
      cases rest with
      | nil => simp at bound
      | cons second rest =>
          cases index with
          | zero => exact chain.1
          | succ index =>
              exact induction chain.2 index (by simp at bound ⊢; omega)

theorem chain_tail {first : AttemptView} {rest : List AttemptView}
    (chain : validChain (first :: rest)) : validChain rest := by
  cases rest with
  | nil => trivial
  | cons second rest => exact chain.2

theorem chain_keeps (views : List AttemptView) (chain : validChain views)
    (start : ∀ bound : 0 < views.length, consistent views[0] = true) :
    ∀ (earlier later : Nat) (order : earlier ≤ later) (bound : later < views.length),
      Keeps (views[earlier]'(by omega)) views[later] := by
  induction views with
  | nil => intro _ _ _ bound; simp at bound
  | cons first rest induction =>
      intro earlier later order bound
      have restChain := chain_tail chain
      have restStart : ∀ bound : 0 < rest.length, consistent rest[0] = true := by
        intro bound
        cases rest with
        | nil => simp at bound
        | cons second rest => exact transition_consistent chain.1
      cases later with
      | zero =>
          cases earlier with
          | zero => exact keeps_refl _
          | succ _ => omega
      | succ later =>
          cases earlier with
          | zero =>
              have first_second : Keeps first (rest[0]'(by simp at bound; omega)) := by
                cases rest with
                | nil => simp at bound
                | cons second rest => exact transition_keeps (start (by simp)) chain.1
              exact keeps_trans first_second
                (induction restChain restStart 0 later (by omega) (by simp at bound; omega))
          | succ earlier =>
              exact induction restChain restStart earlier later (by omega)
                (by simp at bound; omega)

/-- A record in `unknown` leaves it only for `observed-by-provider`, only
with a verified-locator link (the link of exactly the `linked` class), and
only on a transition that records provider evidence; over every valid
sequence of records, the same holds at every position. -/
theorem unknown_resolves_only_linked :
    (∀ old new : AttemptView, validTransition old new = true → old.stage = .unknown →
        new.stage = .observedByProvider ∧ old.link = .verified ∧ new.link = .verified ∧
          new.evidence = true) ∧
      (∀ views : List AttemptView, validChain views →
        ∀ (index : Nat) (bound : index + 1 < views.length),
          (views[index]'(by omega)).stage = .unknown →
            views[index + 1].stage = .observedByProvider ∧
              views[index + 1].link = .verified ∧ views[index + 1].evidence = true) ∧
      (∀ declarations : Declarations,
        linkOf (capability declarations).providerLink = .verified ↔
          (capability declarations).recoveryClass = .linked) := by
  have single : ∀ old new : AttemptView, validTransition old new = true →
      old.stage = .unknown →
        new.stage = .observedByProvider ∧ old.link = .verified ∧ new.link = .verified ∧
          new.evidence = true := by
    intro old new valid unknown
    rcases old with ⟨fixed, stage, refusal, preEntry, response, locator, reading, evidence,
      observation, link⟩
    rcases new with ⟨fixed', stage', refusal', preEntry', response', locator', reading',
      evidence', observation', link'⟩
    subst unknown
    cases stage' <;> cases link <;>
      simp_all [validTransition, planKept, stageTransitionAllowed, resolvesUnknown, consistent,
        providerStage]
  refine ⟨single, ?_, ?_⟩
  · intro views chain index bound unknown
    obtain ⟨stage, _, link, evidence⟩ := single _ _ (chain_step chain index bound) unknown
    exact ⟨stage, link, evidence⟩
  · intro declarations
    obtain ⟨observation, echo, idempotency, preEntry⟩ := declarations
    cases observation <;> cases echo <;>
      simp [capability, providerLink, classOf, linkOf]

/-- `observed-by-provider` is reached only through a transition that records
provider evidence, under a declared link of the plan stored at the claim:
from `response-recorded`, or from `attempting` or `unknown` only with a
verified-locator link. For a sequence starting from a claimed `attempting`
record, every `observed-by-provider` record was reached this way. -/
theorem provider_claim_requires_evidence :
    (∀ old new : AttemptView, validTransition old new = true →
        new.stage = .observedByProvider →
          new.evidence = true ∧ hasLink new.link = true ∧ new.link = old.link ∧
            (old.stage = .responseRecorded ∨
              ((old.stage = .attempting ∨ old.stage = .unknown) ∧ old.link = .verified))) ∧
      (∀ (first : AttemptView) (rest : List AttemptView), first.stage = .attempting →
        consistent first = true → validChain (first :: rest) →
          ∀ (index : Nat) (bound : index < rest.length),
            rest[index].stage = .observedByProvider →
              rest[index].evidence = true ∧ rest[index].link = first.link ∧
                hasLink first.link = true ∧
                (((first :: rest)[index]'(by simp; omega)).stage = .responseRecorded ∨
                  ((((first :: rest)[index]'(by simp; omega)).stage = .attempting ∨
                      ((first :: rest)[index]'(by simp; omega)).stage = .unknown) ∧
                    first.link = .verified))) := by
  have single : ∀ old new : AttemptView, validTransition old new = true →
      new.stage = .observedByProvider →
        new.evidence = true ∧ hasLink new.link = true ∧ new.link = old.link ∧
          (old.stage = .responseRecorded ∨
            ((old.stage = .attempting ∨ old.stage = .unknown) ∧ old.link = .verified)) := by
    intro old new valid provider
    rcases old with ⟨fixed, stage, refusal, preEntry, response, locator, reading, evidence,
      observation, link⟩
    rcases new with ⟨fixed', stage', refusal', preEntry', response', locator', reading',
      evidence', observation', link'⟩
    subst provider
    cases stage <;> cases link <;> cases link' <;>
      simp_all [validTransition, planKept, stageTransitionAllowed, resolvesUnknown, consistent,
        providerStage, hasLink, checkpointValid, preEntryKept, responseKept, refusalStage,
        requiresResponse, permitsResponse, observedStage, hasReading] <;>
      grind
  refine ⟨single, ?_⟩
  intro first rest _ consistentFirst chain index bound provider
  have step := chain_step chain index (by simp; omega)
  obtain ⟨evidence, declared, linkEq, source⟩ := single _ _ step provider
  have kept := chain_keeps (first :: rest) chain (fun _ => consistentFirst) 0 (index + 1)
    (by omega) (by simp; omega)
  have firstLink : rest[index].link = first.link := kept.2.2.1
  have previousLink : ((first :: rest)[index]'(by simp; omega)).link = first.link := by
    have := chain_keeps (first :: rest) chain (fun _ => consistentFirst) 0 index
      (by omega) (by simp; omega)
    exact this.2.2.1
  refine ⟨evidence, firstLink, ?_, ?_⟩
  · rw [← firstLink]
    exact declared
  · rw [← previousLink]
    exact source

/-- `not-entered`, `observed`, and `observed-by-provider` are exactly the
terminal stages; no transition leaves them, so in every valid sequence a
terminal record is the last. -/
theorem terminal_stages_final :
    (∀ stage : Stage, terminalStage stage = true ↔
        stage = .notEntered ∨ stage = .observed ∨ stage = .observedByProvider) ∧
      (∀ old new : AttemptView, terminalStage old.stage = true →
        validTransition old new = false) ∧
      (∀ views : List AttemptView, validChain views →
        ∀ (index : Nat) (bound : index < views.length),
          terminalStage views[index].stage = true → index + 1 = views.length) := by
  have single : ∀ old new : AttemptView, terminalStage old.stage = true →
      validTransition old new = false := by
    intro old new terminal
    rcases old with ⟨fixed, stage, refusal, preEntry, response, locator, reading, evidence,
      observation, link⟩
    cases stage <;> simp_all [terminalStage, validTransition, stageTransitionAllowed]
  refine ⟨fun stage => by cases stage <;> simp [terminalStage], single, ?_⟩
  intro views chain index bound terminal
  rcases Nat.lt_or_ge (index + 1) views.length with notLast | last
  · have step := chain_step chain index notLast
    rw [single _ _ terminal] at step
    cases step
  · omega

/-- Every transition, and so every valid sequence starting from a consistent
record, keeps the identity fields, evaluation time, reserved counters, and
plan (the unchangeable bytes), the observation plan and link, and a
pre-entry record or response once it is set. -/
theorem transitions_preserve_identity :
    (∀ old new : AttemptView, consistent old = true → validTransition old new = true →
        Keeps old new) ∧
      (∀ views : List AttemptView, validChain views →
        (∀ bound : 0 < views.length, consistent views[0] = true) →
          ∀ (earlier later : Nat) (order : earlier ≤ later) (bound : later < views.length),
            Keeps (views[earlier]'(by omega)) views[later]) :=
  ⟨fun _ _ consistentOld valid => transition_keeps consistentOld valid, chain_keeps⟩

end Auths.Product.Recovery
