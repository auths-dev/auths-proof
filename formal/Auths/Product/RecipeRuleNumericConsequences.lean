import Auths.Product.RecipeRuleAdmissionConsequences
import Auths.Product.RecipeNumericRounding

/-!
Whole original rule admission earns every numeric source domain on actual
preceding states. No selected compiled plan, native child success, serialization
result or opaque admission callback is supplied. Template fuel is the existing
rule model's native depth relation; this adds no new semantic cutoff.
-/
namespace Auths.Product.RecipeRuleAdmission
open RecipeConsumption RecipeAdmissionAtoms

def PathNumbersSafe (segments : List Segment) : Prop :=
  ∀ segment ∈ segments, match segment with
    | .responseField _ maximum => 1 ≤ maximum ∧ maximum ≤ 255
    | _ => True

inductive JsonIntegersSafe : TemplateAst.Value → Prop where
  | text (value : Bytes) : JsonIntegersSafe (.text value)
  | integer (value : Int) (safe : value.natAbs ≤ 9007199254740991) : JsonIntegersSafe (.integer value)
  | boolean (value : Bool) : JsonIntegersSafe (.boolean value)
  | field (name : Bytes) : JsonIntegersSafe (.field name)
  | array (values : List TemplateAst.Value) (each : ∀ value ∈ values, JsonIntegersSafe value) : JsonIntegersSafe (.array values)
  | object (members : List (Bytes × TemplateAst.Value)) (each : ∀ member ∈ members, JsonIntegersSafe member.2) :
      JsonIntegersSafe (.object members)

def FormIntegersSafe : TemplateAst.FormValue → Prop
  | .text _ | .field _ => True
  | .json value => JsonIntegersSafe value
  | .authorEcho => False

def BodyIntegersSafe : TemplateAst.Body → Prop
  | .json value => JsonIntegersSafe value
  | .form members => ∀ member ∈ members, FormIntegersSafe member.2

theorem path_tail_success_earns_numeric_bounds (fields : Fields) (role : PathRole) (segments : List Segment)
    (responses : Nat) (state : State) (admitted : (pathTail fields role segments responses state).1 = .ok ()) :
    PathNumbersSafe segments := by
  induction segments generalizing responses state with
  | nil => simp [PathNumbersSafe]
  | cons segment rest ih =>
      cases segment with
      | fixed value =>
          unfold pathTail at admitted
          split at admitted
          · have tail := ih responses state admitted
            simpa [PathNumbersSafe] using tail
          · simp [refused] at admitted
      | field name =>
          unfold pathTail at admitted
          split at admitted
          · have tail := ih responses (consume state name) admitted
            simpa [PathNumbersSafe] using tail
          · simp [refused] at admitted
      | responseField pointer maximum =>
          unfold pathTail at admitted
          split at admitted
          · rename_i bounds
            have tail := ih (responses + 1) state admitted
            simpa [PathNumbersSafe] using And.intro bounds.2.2 tail
          · simp [refused] at admitted
      | echo => simp [pathTail, refused] at admitted

theorem path_success_earns_numeric_bounds (fields : Fields) (role : PathRole) (segments : List Segment)
    (state : State) (admitted : (path fields role segments state).1 = .ok ()) : PathNumbersSafe segments := by
  unfold path at admitted
  split at admitted
  · exact path_tail_success_earns_numeric_bounds fields role segments 0 state admitted
  · simp [refused] at admitted

theorem fold_nodes_success_earns_each_step {T : Type} (visit : T → Nat → State → NodeOutcome)
    (items : List T) (nodes : Nat) (state : State)
    (admitted : (foldNodes visit items nodes state).1.1 = .ok ()) :
    ∀ item ∈ items, ∃ count before, (visit item count before).1.1 = .ok () := by
  induction items generalizing nodes state with
  | nil => simp
  | cons first rest ih =>
      cases stepAt : visit first nodes state with
      | mk result nextNodes =>
          cases verdictAt : result.1 with
          | error error => simp [foldNodes, stepAt, verdictAt] at admitted
          | ok unit =>
              cases unit
              have remaining : (foldNodes visit rest nextNodes result.2).1.1 = .ok () := by
                simpa [foldNodes, stepAt, verdictAt] using admitted
              intro item present
              rcases List.mem_cons.mp present with rfl | later
              · exact ⟨nodes, state, by simp [stepAt, verdictAt]⟩
              · exact ih nextNodes result.2 remaining item later

theorem value_success_earns_safe_integers (fuel : Nat) (expression : TemplateAst.Value)
    (depth nodes : Nat) (state : State) (fields : Fields)
    (admitted : (value fuel expression depth nodes state fields).1.1 = .ok ()) : JsonIntegersSafe expression := by
  induction fuel generalizing expression depth nodes state with
  | zero => simp [value, refused] at admitted
  | succ fuel ih =>
      unfold value at admitted
      split at admitted
      · cases expression with
        | text bytes => exact .text bytes
        | integer literal =>
            split at admitted
            · rename_i safe
              exact .integer literal safe
            · simp [refused] at admitted
        | boolean value => exact .boolean value
        | field name => exact .field name
        | authorEcho => simp [refused] at admitted
        | array children =>
            split at admitted
            · apply JsonIntegersSafe.array
              intro child present
              obtain ⟨count, before, accepted⟩ := fold_nodes_success_earns_each_step _ children _ state admitted child present
              exact ih child (depth + 1) count before accepted
            · simp [refused] at admitted
        | object members =>
            split at admitted
            · apply JsonIntegersSafe.object
              intro member present
              obtain ⟨count, before, accepted⟩ := fold_nodes_success_earns_each_step _ members _ state admitted member present
              split at accepted
              · exact ih member.2 (depth + 1) count before accepted
              · simp [refused] at accepted
            · simp [refused] at admitted
      · simp [refused] at admitted

theorem form_member_success_earns_safe_integers (fields : Fields) (member : Bytes × TemplateAst.FormValue)
    (nodes : Nat) (state : State) (admitted : (formMember fields member nodes state).1.1 = .ok ()) :
    FormIntegersSafe member.2 := by
  unfold formMember at admitted
  split at admitted
  · simp [refused] at admitted
  · split at admitted
    · cases member with
      | mk name expression =>
          cases expression with
          | text value | field name => trivial
          | authorEcho => simp [refused] at admitted
          | json expression =>
              split at admitted
              · exact value_success_earns_safe_integers 7 expression 0 nodes state fields admitted
              · simp [refused] at admitted
    · simp [refused] at admitted

theorem body_success_earns_safe_integers (fields : Fields) (source : TemplateAst.Body) (state : State)
    (admitted : (body fields source state).1 = .ok ()) : BodyIntegersSafe source := by
  cases source with
  | json expression => exact value_success_earns_safe_integers 7 expression 0 0 state fields admitted
  | form members =>
      unfold body bodyWithNodes at admitted
      split at admitted
      · intro member present
        obtain ⟨count, before, accepted⟩ := fold_nodes_success_earns_each_step _ members 0 state admitted member present
        exact form_member_success_earns_safe_integers fields member count before accepted
      · simp [refused] at admitted

theorem observation_success_earns_numeric_bounds (fields : Fields) (source : Observation) (state : State)
    (admitted : (observation fields source state).1 = .ok ()) : PathNumbersSafe source.path ∧ ReadBound source.maximum := by
  unfold observation at admitted
  obtain ⟨pathAccepted, afterPath⟩ := and_then_success_earns_both_verdicts _ _ admitted
  refine ⟨path_success_earns_numeric_bounds fields .observation source.path state pathAccepted, ?_⟩
  split at afterPath
  · rename_i bounds; exact bounds.1
  · simp [refused] at afterPath

theorem pre_entry_success_earns_numeric_bounds (fields : Fields) (source : PreEntry) (state : State)
    (admitted : (preEntry fields source state).1 = .ok ()) : PathNumbersSafe source.path ∧ ReadBound source.maximum := by
  unfold preEntry at admitted
  obtain ⟨pathAccepted, afterPath⟩ := and_then_success_earns_both_verdicts _ _ admitted
  refine ⟨path_success_earns_numeric_bounds fields .preEntry source.path state pathAccepted, ?_⟩
  split at afterPath
  · rename_i bounds; exact bounds.2.2.2.2
  · simp [refused] at afterPath

theorem relative_success_earns_numeric_bounds (fields : Fields) (source : RelativeCeiling) (state : State)
    (admitted : (relativeCeiling fields source state).1 = .ok ()) :
    (1 ≤ source.basisPoints ∧ source.basisPoints ≤ 10000) ∧ ReadBound source.maximum ∧ PathNumbersSafe source.path := by
  unfold relativeCeiling at admitted
  split at admitted
  · rename_i allowed
    have bounds : 1 ≤ source.basisPoints ∧ source.basisPoints ≤ 10000 ∧
        ReadBound source.maximum ∧ ResponsePointer source.pointer := by simpa using (Bool.and_eq_true.mp allowed).2
    refine ⟨⟨bounds.1, bounds.2.1⟩, bounds.2.2.1, ?_⟩
    split at admitted
    · simp [refused] at admitted
    · split at admitted
      · simp [refused] at admitted
      · exact path_success_earns_numeric_bounds fields .relativeCeiling source.path state
          (and_then_success_earns_both_verdicts _ _ admitted).1
  · simp [refused] at admitted

def retention : RecipePlanModel.Idempotency → Nat
  | .derivedHeader seconds | .operationIdField _ seconds => seconds

theorem idempotency_success_earns_retention (source : RecipePlanModel.Idempotency) (body : TemplateAst.Body)
    (admitted : idempotency source body = .ok ()) : 1 ≤ retention source ∧ retention source ≤ 2592000 := by
  unfold idempotency at admitted
  split at admitted
  · rename_i bounded
    simpa only [retention] using bounded
  · simp at admitted

structure SourceNumbersSafe (source : Source) : Prop where
  writePath : PathNumbersSafe source.writePath
  body : BodyIntegersSafe source.body
  idempotency : ∀ current, source.idempotency = some current → 1 ≤ retention current ∧ retention current ≤ 2592000
  observation : ∀ current, source.observation = some current → PathNumbersSafe current.path ∧ ReadBound current.maximum
  preEntry : ∀ current, source.preEntry = some current → PathNumbersSafe current.path ∧ ReadBound current.maximum
  relativeCeiling : ∀ current, source.relativeCeiling = some current →
    (1 ≤ current.basisPoints ∧ current.basisPoints ≤ 10000) ∧ ReadBound current.maximum ∧ PathNumbersSafe current.path
  guard : ∀ current, source.guard = some current → RecipeCredentialAdmission.GuardAdmitted current (paths source)

theorem complete_rules_success_earns_all_numeric_domains (fields : Fields) (source : Source)
    (admitted : (validate fields source).1 = .ok ()) : SourceNumbersSafe source := by
  have stages := complete_rules_from_success_earns_stage_verdicts fields source empty admitted
  let written := writeRules fields source empty
  let responded := responseRules fields source written.2
  refine ⟨path_success_earns_numeric_bounds fields .write source.writePath empty
    (write_rules_success_earns_path fields source empty stages.1),
    body_success_earns_safe_integers fields source.body _
      (write_rules_success_earns_body fields source empty stages.1), ?_, ?_, ?_, ?_, ?_⟩
  · intro current present
    have afterPath := (and_then_success_earns_both_verdicts _ _ stages.1).2
    have afterBody := (and_then_success_earns_both_verdicts _ _ afterPath).2
    exact idempotency_success_earns_retention current source.body (by simpa [present, applyPure] using afterBody)
  · intro current present
    have checked := (and_then_success_earns_both_verdicts _ _ stages.2.1).1
    exact observation_success_earns_numeric_bounds fields current written.2 (by simpa [present] using checked)
  · intro current present
    have afterRead := (and_then_success_earns_both_verdicts _ _ stages.2.1).2
    have checked := (and_then_success_earns_both_verdicts _ _ afterRead).2
    exact pre_entry_success_earns_numeric_bounds fields current _ (by simpa [present] using checked)
  · intro current present
    have checked := (and_then_success_earns_both_verdicts _ _ stages.2.2.1).1
    exact relative_success_earns_numeric_bounds fields current responded.2 (by simpa [present] using checked)
  · exact header_guard_success_earns_original_guard source stages.2.2.2.1

end Auths.Product.RecipeRuleAdmission
