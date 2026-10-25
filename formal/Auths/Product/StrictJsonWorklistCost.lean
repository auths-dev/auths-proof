import Auths.Product.StrictJsonWorklist
import Auths.Product.JsonRawReader

/-!
Intrinsic structural cost of the original-child worklist. Counts are computed
from the complete input tree, not supplied by a caller. Every successful pop
consumes one node of potential, and a refusal attempt also fits within that
original potential. These are logical visits/frontiers, not original byte
counts, serde scanning work, String copies or physical Vec capacity bounds.
-/
namespace Auths.Product.StrictJsonWorklistCost

open StrictJsonMembers StrictJsonWorklist

mutual
  def nodeCount : Value → Nat
    | .scalar => 1
    | .array values => 1 + forestCount values
    | .object members => 1 + memberCount members
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def forestCount : List Value → Nat
    | [] => 0
    | value :: rest => nodeCount value + forestCount rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def memberCount : List (String × Value) → Nat
    | [] => 0
    | (_, value) :: rest => nodeCount value + memberCount rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

theorem forest_count_append (first rest : List Value) :
    forestCount (first ++ rest) = forestCount first + forestCount rest := by
  induction first with
  | nil => simp [forestCount]
  | cons value values ih => simp [forestCount, ih, Nat.add_assoc]

theorem forest_count_member_values (members : List (String × Value)) :
    forestCount (members.map Prod.snd) = memberCount members := by
  induction members with
  | nil => rfl
  | cons member rest ih => cases member; simp [forestCount, memberCount, ih]

theorem node_count_children (value : Value) :
    nodeCount value = 1 + forestCount (children value) := by
  cases value <;> simp [nodeCount, children, forestCount, forest_count_member_values]

theorem node_count_positive (value : Value) : 1 ≤ nodeCount value := by
  rw [node_count_children]
  omega

theorem forest_count_nonempty (value : Value) (rest : List Value) :
    1 ≤ forestCount (value :: rest) := by
  have positive := node_count_positive value
  simp only [forestCount]
  omega

theorem pending_length_bound (pending : List Value) : pending.length ≤ forestCount pending := by
  induction pending with
  | nil => simp [forestCount]
  | cons value rest ih =>
      have positive := node_count_positive value
      simp only [List.length_cons, forestCount]
      omega

theorem step_consumes_one (value : Value) (rest after : List Value)
    (performed : step (value :: rest) = .ok after) :
    forestCount after + 1 = forestCount (value :: rest) := by
  by_cases scope : scopeUnique value
  · have same : after = children value ++ rest := by simpa [step, scope] using performed.symm
    subst after
    rw [forest_count_append]
    simp only [forestCount]
    have count := node_count_children value
    omega
  · simp [step, scope] at performed

/-- A finite prefix of actual closed worklist steps. A duplicate stops before
another successful transition; an empty frontier cannot manufacture a visit. -/
inductive Steps : Nat → List Value → List Value → Prop where
  | empty (pending : List Value) : Steps 0 pending pending
  | next (value : Value) (rest after : List Value) (count : Nat) (final : List Value)
      (performed : step (value :: rest) = .ok after) (remaining : Steps count after final) :
      Steps (count + 1) (value :: rest) final

theorem steps_conserve_nodes (count : Nat) (pending final : List Value)
    (trace : Steps count pending final) : count + forestCount final = forestCount pending := by
  induction trace with
  | empty pending => simp
  | next value rest after count final performed remaining ih =>
      have consumed := step_consumes_one value rest after performed
      omega

theorem steps_pending_bound (count : Nat) (pending final : List Value)
    (trace : Steps count pending final) : count + final.length ≤ forestCount pending := by
  have conserved := steps_conserve_nodes count pending final trace
  have frontier := pending_length_bound final
  omega

/-- One next visit, successful or refused, fits the original input potential.
This covers the final duplicate-scope attempt as well as accepted prefixes. -/
theorem next_attempt_bound (count : Nat) (pending : List Value) (value : Value) (rest : List Value)
    (trace : Steps count pending (value :: rest)) : count + 1 ≤ forestCount pending := by
  have conserved := steps_conserve_nodes count pending (value :: rest) trace
  have remaining := forest_count_nonempty value rest
  omega

theorem drain_exact_steps (pending : List Value) (accepted : Drains pending) :
    Steps (forestCount pending) pending [] := by
  induction accepted with
  | empty => exact .empty []
  | next value rest scope remaining ih =>
      have performed : step (value :: rest) = .ok (children value ++ rest) := by
        simp [step, scope]
      have complete := Steps.next value rest (children value ++ rest)
        (forestCount (children value ++ rest)) [] performed ih
      have count := step_consumes_one value rest (children value ++ rest) performed
      simpa only [count] using complete

/-- The complete unique original tree has a useful, intrinsically counted
finite trace. There is no externally supplied fuel/success witness. -/
theorem complete_unique_exact_steps (value : Value) (unique : Unique value) :
    Steps (nodeCount value) [value] [] := by
  have complete := drain_exact_steps [value] (unique_drains_singleton value unique)
  simpa [forestCount] using complete

/-- Bind the worklist to the complete output of the independent original-byte
syntax reader. This does not assert native serde/float/recursion adequacy. -/
theorem syntax_document_worklist_exact (input : JsonStringScalars.Bytes) (output : JsonRawReader.Value) :
    JsonRawReader.uniqueSyntaxDocument input = .ok output ↔
      JsonRawReader.document input = .ok output ∧ Drains [JsonRawReader.memberShape output] := by
  rw [JsonRawReader.unique_syntax_document_acceptance_exact, singleton_acceptance_exact]

/-- Preserve the complete original prefix/suffix and whitespace-only end while
counting every value node of that same parsed tree, including ignored content. -/
theorem syntax_document_earns_counted_original_trace (input : JsonStringScalars.Bytes)
    (output : JsonRawReader.Value) (parsed : JsonRawReader.uniqueSyntaxDocument input = .ok output) :
    ∃ read : JsonStringScalars.Consumed input JsonRawReader.Value,
      JsonRawReader.value input = .ok read ∧ read.value = output ∧
      input = read.prefix ++ read.rest ∧ read.rest.length < input.length ∧
      (∀ byte ∈ read.rest, JsonDocumentEnd.whitespace byte = true) ∧
      Steps (nodeCount (JsonRawReader.memberShape output)) [JsonRawReader.memberShape output] [] := by
  obtain ⟨unique, read, readAt, same, original, progressed, trailing⟩ :=
    JsonRawReader.unique_syntax_document_earns_complete_original input output parsed
  exact ⟨read, readAt, same, original, progressed, trailing, complete_unique_exact_steps _ unique⟩

end Auths.Product.StrictJsonWorklistCost
