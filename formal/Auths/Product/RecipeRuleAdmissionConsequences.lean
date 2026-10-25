import Auths.Product.RecipeRuleProperties

namespace Auths.Product.RecipeRuleAdmission
open RecipeConsumption NativeCompiler

theorem and_then_success_earns_both_verdicts (previous : Outcome) (next : State → Outcome)
    (admitted : (andThen previous next).1 = .ok ()) :
    previous.1 = .ok () ∧ (next previous.2).1 = .ok () := by
  cases verdict : previous.1 with
  | error error => simp [andThen, verdict] at admitted
  | ok unit =>
      cases unit
      exact ⟨verdict, by simpa [andThen, verdict] using admitted⟩

/-- The complete caller earns every stage on its real preceding state. A
later stage cannot turn an earlier refusal into admission. The pure guard
stage retains the fact-stage state before bound validation. -/
theorem complete_rules_from_success_earns_stage_verdicts (fields : Fields) (source : Source) (initial : State)
    (admitted : (validateFrom fields source initial).1 = .ok ()) :
    let written := writeRules fields source initial
    let responded := responseRules fields source written.2
    let facts := factRules fields source responded.2
    written.1 = .ok () ∧ responded.1 = .ok () ∧ facts.1 = .ok () ∧
      headerGuardRules source = .ok () ∧ (boundRules fields source facts.2).1 = .ok () := by
  unfold validateFrom at admitted
  obtain ⟨write, afterWrite⟩ := and_then_success_earns_both_verdicts _ _ admitted
  obtain ⟨response, afterResponse⟩ := and_then_success_earns_both_verdicts _ _ afterWrite
  obtain ⟨facts, afterFacts⟩ := and_then_success_earns_both_verdicts _ _ afterResponse
  obtain ⟨guard, afterGuard⟩ := and_then_success_earns_both_verdicts _ _ afterFacts
  obtain ⟨bounds, _⟩ := and_then_success_earns_both_verdicts _ _ afterGuard
  exact ⟨write, response, facts, guard, bounds⟩

theorem write_rules_success_earns_path (fields : Fields) (source : Source) (state : State)
    (admitted : (writeRules fields source state).1 = .ok ()) :
    (path fields .write source.writePath state).1 = .ok () :=
  (and_then_success_earns_both_verdicts _ _ admitted).1

theorem write_rules_success_earns_body (fields : Fields) (source : Source) (state : State)
    (admitted : (writeRules fields source state).1 = .ok ()) :
    (body fields source.body (path fields .write source.writePath state).2).1 = .ok () := by
  have afterPath := (and_then_success_earns_both_verdicts _ _ admitted).2
  exact (and_then_success_earns_both_verdicts _ _ afterPath).1

theorem response_rules_success_earns_echo (fields : Fields) (source : Source) (state : State)
    (admitted : (responseRules fields source state).1 = .ok ()) :
    ∀ placement, source.echo = some placement → ∃ read, source.observation = some read ∧
      RecipeRuleAdmission.echo placement source.body read = .ok () := by
  intro placement present
  unfold responseRules at admitted
  have afterObservation := (and_then_success_earns_both_verdicts _ _ admitted).2
  have checked := (and_then_success_earns_both_verdicts _ _ afterObservation).1
  cases readAt : source.observation with
  | none => simp [present, readAt, refused] at checked
  | some read => exact ⟨read, readAt, by simpa [present, readAt, applyPure] using checked⟩

theorem response_rules_success_earns_read_paths (fields : Fields) (source : Source) (state : State)
    (admitted : (responseRules fields source state).1 = .ok ()) :
    (∀ read, source.observation = some read → ∃ before, (path fields .observation read.path before).1 = .ok ()) ∧
      (∀ read, source.preEntry = some read → ∃ before, (path fields .preEntry read.path before).1 = .ok ()) := by
  unfold responseRules at admitted
  obtain ⟨observed, afterObservation⟩ := and_then_success_earns_both_verdicts _ _ admitted
  obtain ⟨_, afterEcho⟩ := and_then_success_earns_both_verdicts _ _ afterObservation
  constructor
  · intro read present
    have accepted : (observation fields read state).1 = .ok () := by simpa [present] using observed
    exact ⟨state, (and_then_success_earns_both_verdicts _ _ accepted).1⟩
  · intro read present
    have accepted : (preEntry fields read _).1 = .ok () := by simpa [present] using afterEcho
    exact ⟨_, (and_then_success_earns_both_verdicts _ _ accepted).1⟩

theorem fact_rules_success_earns_relative_path (fields : Fields) (source : Source) (state : State)
    (admitted : (factRules fields source state).1 = .ok ()) :
    ∀ ceiling, source.relativeCeiling = some ceiling → (path fields .relativeCeiling ceiling.path state).1 = .ok () := by
  intro ceiling present
  have checked := (and_then_success_earns_both_verdicts _ _ admitted).1
  have accepted : (relativeCeiling fields ceiling state).1 = .ok () := by simpa [present] using checked
  unfold relativeCeiling at accepted
  split at accepted
  · split at accepted
    · simp [refused] at accepted
    · split at accepted
      · simp [refused] at accepted
      · exact (and_then_success_earns_both_verdicts _ _ accepted).1
  · simp [refused] at accepted

theorem bound_rules_success_earns_scope (fields : Fields) (source : Source) (state : State)
    (admitted : (boundRules fields source state).1 = .ok ()) :
    ∀ scope, source.scope = some scope →
      scope.header = HeaderCompiler.stripeAccountName ∧ fieldTest pathSchema fields scope.field = true := by
  intro scope present
  have checked := (and_then_success_earns_both_verdicts _ _ admitted).1
  have accepted : (accountScope fields scope state).1 = .ok () := by simpa [present] using checked
  unfold accountScope at accepted
  split at accepted
  · rename_i allowed
    exact ⟨allowed.1, allowed.2.1⟩
  · simp [refused] at accepted

/-- Whole-rule success earns the complete header/guard decision even though
later bound and original-field-use checks still run. No child success is an
input, and earlier refusal cannot skip this requirement. -/
theorem complete_rules_success_earns_header_guard (fields : Fields) (source : Source)
    (admitted : (validate fields source).1 = .ok ()) : headerGuardRules source = .ok () := by
  have completed : validateFrom fields source empty = accepted (validate fields source).2 := by
    apply Prod.ext
    · simpa [validate, accepted] using admitted
    · rfl
  unfold validateFrom at completed
  obtain ⟨_, afterWrite⟩ := and_then_success _ _ _ completed
  obtain ⟨_, afterResponse⟩ := and_then_success _ _ _ afterWrite
  obtain ⟨_, afterFacts⟩ := and_then_success _ _ _ afterResponse
  obtain ⟨guard, _⟩ := and_then_success _ _ _ afterFacts
  exact guard

theorem header_guard_success_earns_original_guard (source : Source)
    (admitted : headerGuardRules source = .ok ()) :
    ∀ guard, source.guard = some guard → RecipeCredentialAdmission.GuardAdmitted guard (paths source) := by
  intro guard present
  unfold headerGuardRules at admitted
  cases headersAt : source.providerHeaders with
  | none =>
      by_contra refused
      simp [headersAt, present, RecipeCredentialAdmission.validateGuard, refused] at admitted
  | some headers =>
      by_contra refused
      by_cases allowed : HeaderCompiler.VersionsValid headers
      · simp [headersAt, allowed, present, RecipeCredentialAdmission.validateGuard, refused] at admitted
      · simp [headersAt, allowed] at admitted

end Auths.Product.RecipeRuleAdmission
