import qualification.aeneas.generated.gateway.Funs
import Auths.Product.WritePermitRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel

namespace Auths.Product.ClaimedInput.Refinement

/- Complete opaque payload preservation. Capturing an arbitrary input is not
authority: the runtime must supply its actual verified command only after the
winning durable claim acknowledgement. These functions cannot alter or select
fields inside that command, evaluation time or pre-entry selection. -/

@[step] theorem capture_exact {Command Selection : Type}
    (command : Command) (evaluatedAt : Std.U64) (selection : Selection) :
    write_permit.capture_input command evaluatedAt selection ⦃ actual =>
      actual.command = command ∧ actual.evaluated_at = evaluatedAt ∧ actual.selection = selection ⦄ := by
  simp [write_permit.capture_input, spec_ok]

@[step] theorem command_exact {Command Selection : Type}
    (input : write_permit.ClaimedInput Command Selection) :
    write_permit.captured_command input ⦃ actual => actual = input.command ⦄ := by
  rfl

@[step] theorem time_exact {Command Selection : Type}
    (input : write_permit.ClaimedInput Command Selection) :
    write_permit.captured_time input ⦃ actual => actual = input.evaluated_at ⦄ := by
  rfl

@[step] theorem selection_exact {Command Selection : Type}
    (input : write_permit.ClaimedInput Command Selection) :
    write_permit.captured_selection input ⦃ actual => actual = input.selection ⦄ := by
  rfl

/-- Composition calls the actual constructor and all three actual projections;
no successful capture or expected intermediate carrier is a theorem premise. -/
theorem capture_projects {Command Selection : Type}
    (command : Command) (evaluatedAt : Std.U64) (selection : Selection) :
    (do
      let input ← write_permit.capture_input command evaluatedAt selection
      let command ← write_permit.captured_command input
      let time ← write_permit.captured_time input
      let selection ← write_permit.captured_selection input
      ok (command, time, selection)) = ok (command, evaluatedAt, selection) := by
  rfl

/-- This proof-owned wrapper calls the actual source capture, empty, arm and
history primitives. Arbitrary later arm payloads are permitted in the history;
none may replace the first captured command, time or selected requirements.
It does not manufacture a claim acknowledgement or assert physical dispatch. -/
def capturePermitHistory {Command Selection : Type}
    (command : Command) (evaluatedAt : Std.U64) (selection : Selection)
    (events : List (Auths.Product.WritePermit.Event
      (write_permit.ClaimedInput Command Selection))) :
    Result (write_permit.WritePermit (write_permit.ClaimedInput Command Selection) ×
      List (write_permit.ClaimedInput Command Selection)) := do
  let captured ← write_permit.capture_input command evaluatedAt selection
  Auths.Product.WritePermit.Refinement.sourceCapturedRun captured events

/-- Complete first-capture provenance across every finite permit history,
composed from translated shipping functions, rather than a successful capture
or an expected intermediate carrier supplied as a premise. Resource flags,
store identity, lease validity and driver correspondence remain separate. -/
@[step] theorem capture_permit_history_exact_input {Command Selection : Type}
    (command : Command) (evaluatedAt : Std.U64) (selection : Selection)
    (events : List (Auths.Product.WritePermit.Event
      (write_permit.ClaimedInput Command Selection))) :
    capturePermitHistory command evaluatedAt selection events ⦃ actual =>
      actual.2.length ≤ 1 ∧ ∀ output ∈ actual.2,
        output.command = command ∧ output.evaluated_at = evaluatedAt ∧
        output.selection = selection ⦄ := by
  unfold capturePermitHistory
  step with capture_exact command evaluatedAt selection as ⟨captured, meaning⟩
  apply spec_mono
    (Auths.Product.WritePermit.Refinement.source_captured_history_preserves_the_first_payload captured events)
  intro actual history
  rcases history with empty | singleton
  · rw [empty]
    simp
  · rw [singleton]
    constructor
    · simp
    · intro output member
      have same : output = captured := List.mem_singleton.mp member
      subst output
      exact meaning

/-- The exact captured input has a useful source execution: the first send
with both resources present yields that input. This witness neither calls a
provider nor treats supplied resource flags as proof of durable authority. -/
theorem capture_permit_first_send_is_useful {Command Selection : Type}
    (command : Command) (evaluatedAt : Std.U64) (selection : Selection) :
    capturePermitHistory command evaluatedAt selection [.consume true true] =
      ok (⟨.Spent, none⟩,
        [⟨command, evaluatedAt, selection⟩]) := by
  rfl

end Auths.Product.ClaimedInput.Refinement
