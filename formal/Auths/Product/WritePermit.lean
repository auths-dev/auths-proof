import Aeneas

namespace Auths.Product.WritePermit

inductive Phase where
  | empty
  | armed
  | spent
  deriving DecidableEq, Repr

/-- A request captured for one run. The payload is arbitrary, so every
request field and every identity projection is covered by value preservation. -/
structure Permit (Payload : Type) where
  phase : Phase
  payload : Option Payload

def empty {Payload : Type} : Permit Payload := ⟨.empty, none⟩

def canArm {Payload : Type} (permit : Permit Payload) : Bool :=
  match permit.phase, permit.payload with
  | .empty, none => true
  | _, _ => false

def spent {Payload : Type} (permit : Permit Payload) : Bool :=
  match permit.phase with | .spent => true | _ => false

def arm {Payload : Type} (permit : Permit Payload) (payload : Payload) : Permit Payload :=
  if canArm permit then ⟨.armed, some payload⟩ else permit

def consume {Payload : Type} (permit : Permit Payload) (hasClaim hasLease : Bool) :
    Permit Payload × Option Payload :=
  (⟨.spent, none⟩,
    match permit.phase with
    | .armed => if hasClaim && hasLease then permit.payload else none
    | .empty | .spent => none)

def Valid {Payload : Type} (permit : Permit Payload) : Prop :=
  match permit.phase with
  | .empty | .spent => permit.payload = none
  | .armed => ∃ value, permit.payload = some value

theorem empty_valid {Payload : Type} : Valid (empty : Permit Payload) := rfl

theorem arm_valid {Payload : Type} (permit : Permit Payload) (value : Payload)
    (valid : Valid permit) : Valid (arm permit value) := by
  by_cases ready : canArm permit = true
  · simp [arm, ready, Valid]
  · simpa [arm, ready] using valid

theorem consume_valid {Payload : Type} (permit : Permit Payload) (claim lease : Bool) :
    Valid (consume permit claim lease).1 := rfl

theorem consume_spends {Payload : Type} (permit : Permit Payload) (claim lease : Bool) :
    (consume permit claim lease).1 = ⟨.spent, none⟩ := rfl

/-- A value comes only from the stored payload, with both actual resources
present. This is an ownership/dataflow statement, not an authority theorem. -/
theorem returned_value_exact {Payload : Type} (permit : Permit Payload) (claim lease : Bool)
    (value : Payload) (returned : (consume permit claim lease).2 = some value) :
    permit.phase = .armed ∧ permit.payload = some value ∧ claim = true ∧ lease = true := by
  rcases permit with ⟨phase, payload⟩
  cases phase <;> cases claim <;> cases lease <;> simp_all [consume]

theorem useful_payload {Payload : Type} (value : Payload) :
    consume (arm empty value) true true = (⟨.spent, none⟩, some value) := rfl

theorem cannot_overwrite {Payload : Type} (first second : Payload) :
    arm (arm empty first) second = arm empty first := rfl

theorem spent_cannot_arm {Payload : Type} (permit : Permit Payload) (value : Payload)
    (used : permit.phase = .spent) : arm permit value = permit := by
  simp [arm, canArm, used]

theorem repeat_returns_none {Payload : Type} (permit : Permit Payload)
    (firstClaim firstLease secondClaim secondLease : Bool) (replacement : Payload) :
    (consume (arm (consume permit firstClaim firstLease).1 replacement) secondClaim secondLease).2 = none := by
  simp [consume, arm, canArm]

/-- Every projection of a returned request comes from the captured value,
including operation identity, recipe/action commitments and request bytes. -/
theorem returned_projection {Payload Projection : Type} (project : Payload → Projection)
    (permit : Permit Payload) (claim lease : Bool) (value : Payload)
    (returned : (consume permit claim lease).2 = some value) :
    permit.payload.map project = some (project value) := by
  rw [(returned_value_exact permit claim lease value returned).2.1]
  rfl

inductive Event (Payload : Type) where
  | arm (value : Payload)
  | consume (claim lease : Bool)

def step {Payload : Type} (permit : Permit Payload) : Event Payload → Permit Payload × Option Payload
  | .arm value => (arm permit value, none)
  | .consume claim lease => consume permit claim lease

def run {Payload : Type} (permit : Permit Payload) : List (Event Payload) → Permit Payload × List Payload
  | [] => (permit, [])
  | event :: rest =>
      let (next, output) := step permit event
      let (final, outputs) := run next rest
      (final, output.toList ++ outputs)

theorem spent_history_has_no_output {Payload : Type} (permit : Permit Payload)
    (used : permit.phase = .spent) (events : List (Event Payload)) :
    (run permit events).1.phase = .spent ∧ (run permit events).2 = [] := by
  induction events generalizing permit with
  | nil => exact ⟨used, rfl⟩
  | cons event rest ih =>
    cases event with
    | arm value =>
      simpa [run, step, spent_cannot_arm permit value used] using ih permit used
    | consume claim lease =>
      have tail := ih (consume permit claim lease).1 (by rfl)
      simpa [run, step, consume, used] using tail

/-- Arbitrary finite histories, including rearming attempts and malformed
resource flags, produce at most one payload for this run. No bounded worker or
trace length is assumed. Cross-run ownership still requires the durable store. -/
theorem every_history_at_most_one {Payload : Type} (permit : Permit Payload)
    (events : List (Event Payload)) : (run permit events).2.length ≤ 1 := by
  induction events generalizing permit with
  | nil => simp [run]
  | cons event rest ih =>
    cases event with
    | arm value => simpa [run, step] using ih (arm permit value)
    | consume claim lease =>
      have tail := spent_history_has_no_output (consume permit claim lease).1 (by rfl) rest
      simp only [run, step, tail.2, List.append_nil]
      cases output : (consume permit claim lease).2 <;> simp

/-- A complete history starting with a captured request can emit only that
first value. Rearming with a different command cannot substitute any field. -/
theorem captured_history_returns_only_first {Payload : Type} (first : Payload)
    (events : List (Event Payload)) :
    (run (arm empty first) events).2 = [] ∨ (run (arm empty first) events).2 = [first] := by
  induction events with
  | nil => exact Or.inl rfl
  | cons event rest ih =>
    cases event with
    | arm replacement => simpa [run, step, cannot_overwrite] using ih
    | consume claim lease =>
      have tail := spent_history_has_no_output (consume (arm empty first) claim lease).1 (by rfl) rest
      cases claim <;> cases lease <;>
        simp [run, step, consume, arm, empty, canArm, tail.2]

/-- Every identity/byte projection of an emitted payload still comes from the
first capture; this does not substitute a digest-only equality for the value. -/
theorem captured_history_preserves_every_projection {Payload Projection : Type}
    (first : Payload) (events : List (Event Payload)) (project : Payload → Projection)
    (value : Payload) (emitted : value ∈ (run (arm empty first) events).2) :
    value = first ∧ project value = project first := by
  rcases captured_history_returns_only_first first events with none | one
  · rw [none] at emitted
    simp at emitted
  · rw [one] at emitted
    have same : value = first := List.mem_singleton.mp emitted
    exact ⟨same, congrArg project same⟩

namespace Examples
private def request : Nat × List Nat := (7, [80, 65, 89])
private def substitute : Nat × List Nat := (8, [79, 84, 72, 69, 82])

theorem captured_request_is_useful :
    (run empty [.arm request, .consume true true]).2 = [request] := rfl

theorem rearm_and_repeated_send_cannot_substitute :
    (run empty [.arm request, .arm substitute, .consume true true,
      .arm substitute, .consume true true]).2 = [request] := rfl

theorem missing_claim_consumes_without_output :
    (run empty [.arm request, .consume false true, .arm request, .consume true true]).2 = [] := rfl
end Examples

end Auths.Product.WritePermit
