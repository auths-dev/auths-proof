import qualification.aeneas.generated.gateway.Funs
import Auths.Product.WritePermit

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel

namespace Auths.Product.WritePermit.Refinement

def phaseOf : write_permit.Phase → Phase
  | .Empty => .empty
  | .Armed => .armed
  | .Spent => .spent

def view {Payload : Type} (permit : write_permit.WritePermit Payload) : Permit Payload :=
  ⟨phaseOf permit.phase, permit.payload⟩

@[step] theorem empty_exact (Payload : Type) :
    write_permit.empty (T := Payload) ⦃ actual => view actual = (empty : Permit Payload) ⦄ := by
  simp [write_permit.empty, view, phaseOf, empty]

@[step] theorem can_arm_exact {Payload : Type} (permit : write_permit.WritePermit Payload) :
    write_permit.can_arm permit ⦃ actual => actual = canArm (view permit) ⦄ := by
  rcases permit with ⟨phase, payload⟩
  cases phase <;> cases payload <;> simp [write_permit.can_arm, view, phaseOf, canArm]

@[step] theorem spent_exact {Payload : Type} (permit : write_permit.WritePermit Payload) :
    write_permit.spent permit ⦃ actual => actual = spent (view permit) ⦄ := by
  rcases permit with ⟨phase, payload⟩
  cases phase <;> simp [write_permit.spent, view, phaseOf, spent]

@[step] theorem arm_exact {Payload : Type} (permit : write_permit.WritePermit Payload) (payload : Payload) :
    write_permit.arm permit payload ⦃ actual => view actual = arm (view permit) payload ⦄ := by
  rcases permit with ⟨phase, initial⟩
  cases phase <;> cases initial <;>
    simp [write_permit.arm, write_permit.can_arm, view, phaseOf, arm, canArm]

@[step] theorem consume_exact {Payload : Type} (permit : write_permit.WritePermit Payload)
    (claim lease : Bool) :
    write_permit.consume permit claim lease ⦃ actual =>
      (view actual.1, actual.2) = consume (view permit) claim lease ⦄ := by
  rcases permit with ⟨phase, payload⟩
  cases phase <;> cases claim <;> cases lease <;>
    simp [write_permit.consume, view, phaseOf, consume]

/-- The actual source slot preserves every field of a returned request. Its
original private payload must have contained the identical value. -/
theorem source_preserves_payload {Payload : Type} (permit : write_permit.WritePermit Payload)
    (claim lease : Bool) :
    write_permit.consume permit claim lease ⦃ actual =>
      ∀ value, actual.2 = some value → permit.payload = some value ⦄ := by
  apply spec_mono (consume_exact permit claim lease)
  intro actual meaning value returned
  have exactOutput : (consume (view permit) claim lease).2 = some value := by
    rw [← meaning]
    exact returned
  exact (returned_value_exact (view permit) claim lease value exactOutput).2.1

/-- Every actual source result spends the slot and erases the held payload,
including refusals for missing claims, leases and malformed representations. -/
theorem source_always_spends {Payload : Type} (permit : write_permit.WritePermit Payload)
    (claim lease : Bool) :
    write_permit.consume permit claim lease ⦃ actual =>
      view actual.1 = ⟨.spent, none⟩ ∧ actual.1.payload = none ⦄ := by
  apply spec_mono (consume_exact permit claim lease)
  intro actual meaning
  have same : view actual.1 = (consume (view permit) claim lease).1 := congrArg Prod.fst meaning
  exact ⟨same, congrArg Permit.payload same⟩

/-- A source output needs the armed state and both supplied resource flags;
those flags are projected from the runtime's actual handle/lease presence. -/
theorem source_requires_resources {Payload : Type} (permit : write_permit.WritePermit Payload)
    (claim lease : Bool) :
    write_permit.consume permit claim lease ⦃ actual =>
      actual.2.isSome = true → phaseOf permit.phase = .armed ∧ claim = true ∧ lease = true ⦄ := by
  apply spec_mono (consume_exact permit claim lease)
  intro actual meaning present
  obtain ⟨value, returned⟩ := Option.isSome_iff_exists.mp present
  have exactOutput : (consume (view permit) claim lease).2 = some value := by
    rw [← meaning]
    exact returned
  have required := returned_value_exact (view permit) claim lease value exactOutput
  exact ⟨required.1, required.2.2⟩

/-- Proof-owned history interpreter calling the real translated kernel leaves.
It contains no provider I/O and is not presented as the async-driver bridge. -/
def sourceStep {Payload : Type} (permit : write_permit.WritePermit Payload)
    (event : Event Payload) : Result (write_permit.WritePermit Payload × Option Payload) := do
  match event with
  | .arm value =>
      let next ← write_permit.arm permit value
      ok (next, none)
  | .consume claim lease => write_permit.consume permit claim lease

@[step] theorem source_step_exact {Payload : Type} (permit : write_permit.WritePermit Payload)
    (event : Event Payload) :
    sourceStep permit event ⦃ actual => (view actual.1, actual.2) = step (view permit) event ⦄ := by
  cases event with
  | arm value =>
    unfold sourceStep
    step with arm_exact permit value as ⟨next, meaning⟩
    simpa [step, meaning]
  | consume claim lease => simpa [sourceStep, step] using consume_exact permit claim lease

def sourceRun {Payload : Type} (permit : write_permit.WritePermit Payload) :
    List (Event Payload) → Result (write_permit.WritePermit Payload × List Payload)
  | [] => ok (permit, [])
  | event :: rest => do
      let (next, output) ← sourceStep permit event
      let (final, outputs) ← sourceRun next rest
      ok (final, output.toList ++ outputs)

@[step] theorem source_history_refines {Payload : Type} (permit : write_permit.WritePermit Payload)
    (events : List (Event Payload)) :
    sourceRun permit events ⦃ actual => (view actual.1, actual.2) = run (view permit) events ⦄ := by
  induction events generalizing permit with
  | nil => simp [sourceRun, run]
  | cons event rest ih =>
    unfold sourceRun
    step with source_step_exact permit event as ⟨next, output, first⟩
    step with ih next as ⟨final, outputs, tail⟩
    simp only [run, ← first, ← tail]

/-- Arbitrary finite sequences of actual source slot operations release at
most one payload. The durable cross-run claim and async I/O correspondence
remain distinct obligations and cannot be inferred from this kernel theorem. -/
theorem source_history_at_most_one {Payload : Type} (permit : write_permit.WritePermit Payload)
    (events : List (Event Payload)) :
    sourceRun permit events ⦃ actual => actual.2.length ≤ 1 ⦄ := by
  apply spec_mono (source_history_refines permit events)
  intro actual meaning
  have outputs := congrArg Prod.snd meaning
  simpa only [outputs] using every_history_at_most_one (view permit) events

/-- Proof wrapper over the actual shipping empty/arm/consume primitives.
The runtime must separately earn the acknowledgement that permits the arm. -/
def sourceCapturedRun {Payload : Type} (first : Payload) (events : List (Event Payload)) :
    Result (write_permit.WritePermit Payload × List Payload) := do
  let initial ← write_permit.empty (T := Payload)
  let captured ← write_permit.arm initial first
  sourceRun captured events

theorem source_captured_history_preserves_the_first_payload {Payload : Type}
    (first : Payload) (events : List (Event Payload)) :
    sourceCapturedRun first events ⦃ actual => actual.2 = [] ∨ actual.2 = [first] ⦄ := by
  unfold sourceCapturedRun
  step with empty_exact Payload as ⟨initial, emptyMeaning⟩
  step with arm_exact initial first as ⟨captured, capturedMeaning⟩
  apply spec_mono (source_history_refines captured events)
  intro actual meaning
  have capturedView : view captured = arm empty first := by
    simpa [emptyMeaning] using capturedMeaning
  have outputs : actual.2 = (run (arm empty first) events).2 := by
    simpa [capturedView] using congrArg Prod.snd meaning
  rw [outputs]
  exact captured_history_returns_only_first first events

theorem source_captured_history_preserves_every_request_projection {Payload Projection : Type}
    (first : Payload) (events : List (Event Payload)) (project : Payload → Projection) :
    sourceCapturedRun first events ⦃ actual => ∀ value ∈ actual.2,
      value = first ∧ project value = project first ⦄ := by
  apply spec_mono (source_captured_history_preserves_the_first_payload first events)
  intro actual exactHistory value emitted
  rcases exactHistory with none | one
  · rw [none] at emitted
    simp at emitted
  · rw [one] at emitted
    have same : value = first := List.mem_singleton.mp emitted
    exact ⟨same, congrArg project same⟩

end Auths.Product.WritePermit.Refinement
