import Mathlib.Logic.ExistsUnique

/-!
# Recovery capability of a gateway recipe

What a recipe can prove after an ambiguous write is a total function of three
declarations (the observation locator, the echo, and the idempotency
mechanism) plus whether a pre-entry re-read is declared. The class names what
a later read-back can establish; `unknownResolution` says whether the gateway
can ever resolve an `unknown` write, which only a verified-locator link can.
No declaration makes the provider write conditional.

The transition theorems over attempt records (`unknown_resolves_only_linked`,
`provider_claim_requires_evidence`, `terminal_stages_final`,
`transitions_preserve_identity`) belong with the attempt-record state machine
and are stated there.
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

end Auths.Product.Recovery
