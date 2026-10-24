import Auths.Product.RecipeRuleAdmission

namespace Auths.Product.RecipeRuleAdmission
open NativeCompiler RecipeConsumption
set_option maxHeartbeats 10000000
set_option maxRecDepth 4096

theorem and_then_refusal (error : Error) (state : State) (next : State → Outcome) :
    andThen (refused error state) next = refused error state := rfl

theorem and_then_success (previous : Outcome) (next : State → Outcome) (output : State)
    (completed : andThen previous next = accepted output) :
    previous.1 = .ok () ∧ next previous.2 = accepted output := by
  cases verdict : previous.1 with
  | error error => simp [andThen, verdict, accepted] at completed
  | ok unit => cases unit; exact ⟨verdict, by simpa [andThen, verdict] using completed⟩

theorem and_then_well_formed (fields : Fields) (previous : Outcome) (next : State → Outcome)
    (valid : WellFormed fields previous.2)
    (preserves : ∀ state, WellFormed fields state → WellFormed fields (next state).2) :
    WellFormed fields (andThen previous next).2 := by
  cases verdict : previous.1 <;> simp [andThen, verdict, valid, preserves _ valid]

theorem path_tail_well_formed (fields : Fields) (role : PathRole) (segments : List Segment)
    (responses : Nat) (state : State) (valid : WellFormed fields state) :
    WellFormed fields (pathTail fields role segments responses state).2 := by
  induction segments generalizing responses state with
  | nil => exact valid
  | cons segment rest ih =>
      cases segment with
      | fixed value =>
          simp only [pathTail]
          split
          · exact ih _ _ valid
          · exact valid
      | field name =>
          simp only [pathTail]
          split <;> rename_i allowed
          · have schema := (Bool.and_eq_true.mp allowed).1
            exact ih _ _ (consume_well_formed fields state name valid
              (field_test_earns_presence pathSchema fields name schema))
          · exact valid
      | responseField pointer maximum =>
          simp only [pathTail]
          split
          · exact ih _ _ valid
          · exact valid
      | echo => exact valid

theorem path_well_formed (fields : Fields) (role : PathRole) (segments : List Segment)
    (state : State) (valid : WellFormed fields state) : WellFormed fields (path fields role segments state).2 := by
  unfold path
  split
  · exact path_tail_well_formed fields role segments 0 state valid
  · exact valid

theorem field_ref_well_formed (fields : Fields) (name : Bytes) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (fieldRef fields name state).2 := by
  unfold fieldRef
  cases decoded : Rules.decodeName name with
  | none => exact valid
  | some original =>
      split <;> rename_i admitted
      · have present := (Bool.and_eq_true.mp admitted).1
        cases schemaAt : schemaFor original fields with
        | none => simp [schemaAt] at present
        | some schema =>
            exact render_well_formed fields state original valid (schema_for_present fields original schema schemaAt)
      · exact valid

theorem fold_nodes_well_formed {T : Type} (fields : Fields)
    (visit : T → Nat → State → NodeOutcome) (items : List T) (nodes : Nat) (state : State)
    (valid : WellFormed fields state)
    (preserves : ∀ item ∈ items, ∀ count current, WellFormed fields current →
      WellFormed fields (visit item count current).1.2) :
    WellFormed fields (foldNodes visit items nodes state).1.2 := by
  induction items generalizing nodes state with
  | nil => exact valid
  | cons item rest ih =>
      have next := preserves item (by simp) nodes state valid
      unfold foldNodes
      split
      · exact next
      · exact ih _ _ next (fun child member => preserves child (by simp [member]))

theorem value_well_formed (fuel : Nat) (expression : TemplateAst.Value) (depth nodes : Nat)
    (state : State) (fields : Fields) (valid : WellFormed fields state) :
    WellFormed fields (value fuel expression depth nodes state fields).1.2 := by
  induction fuel generalizing expression depth nodes state with
  | zero => exact valid
  | succ fuel ih =>
      unfold value
      split
      · cases expression with
        | text bytes => split <;> exact valid
        | integer literal => split <;> exact valid
        | boolean literal => exact valid
        | field name => exact field_ref_well_formed fields name state valid
        | authorEcho => exact valid
        | array children =>
            split
            · exact fold_nodes_well_formed fields _ children _ state valid
                (fun child _ count current currentValid => ih child _ count current currentValid)
            · exact valid
        | object members =>
            split
            · apply fold_nodes_well_formed fields _ members _ state valid
              intro member present count current currentValid
              split
              · exact ih member.2 _ count current currentValid
              · exact currentValid
            · exact valid
      · exact valid

theorem checked_claim_well_formed (test : ScalarProjection.Schema → Bool) (fields : Fields)
    (state : State) (name : String) (valid : WellFormed fields state) :
    WellFormed fields (claimUnused state name (fieldTest test fields name)).2 := by
  unfold claimUnused
  split <;> rename_i admissible
  · split
    · exact valid
    · exact consume_well_formed fields state name valid
        (field_test_earns_presence test fields name (Bool.and_eq_true.mp admissible).1)
  · exact valid

theorem form_member_well_formed (fields : Fields) (member : Bytes × TemplateAst.FormValue)
    (nodes : Nat) (state : State) (valid : WellFormed fields state) :
    WellFormed fields (formMember fields member nodes state).1.2 := by
  unfold formMember
  split
  · exact valid
  · split
    · cases member.2 with
      | text bytes => split <;> exact valid
      | field name =>
          cases Rules.decodeName name with
          | none => exact valid
          | some original =>
              split
              · exact field_ref_well_formed fields name state valid
              · exact valid
      | json expression =>
          split
          · exact value_well_formed 7 expression 0 nodes state fields valid
          · exact valid
      | authorEcho => exact valid
    · exact valid

theorem body_well_formed (fields : Fields) (source : TemplateAst.Body) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (body fields source state).2 := by
  cases source with
  | json expression => exact value_well_formed 7 expression 0 0 state fields valid
  | form members =>
      unfold body bodyWithNodes
      split
      · exact fold_nodes_well_formed fields (formMember fields) members 0 state valid
          (fun member _ nodes current currentValid => form_member_well_formed fields member nodes current currentValid)
      · exact valid

theorem observation_well_formed (fields : Fields) (source : Observation) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (observation fields source state).2 := by
  unfold observation
  apply and_then_well_formed fields _ _ (path_well_formed fields .observation source.path state valid)
  intro next nextValid
  split
  · split <;> rename_i eligible
    · have present := (Bool.and_eq_true.mp eligible).1
      cases selected : schemaFor source.expectedField fields with
      | none => simp [selected] at present
      | some schema =>
          exact consume_well_formed fields next source.expectedField nextValid
            (schema_for_present fields source.expectedField schema selected)
    · exact nextValid
  · exact nextValid

theorem pre_entry_well_formed (fields : Fields) (source : PreEntry) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (preEntry fields source state).2 := by
  unfold preEntry
  apply and_then_well_formed fields _ _ (path_well_formed fields .preEntry source.path state valid)
  intro next nextValid
  split <;> exact nextValid

theorem preconditions_well_formed (fields : Fields) (source : Preconditions)
    (read : Option Observation) (state : State) (valid : WellFormed fields state) :
    WellFormed fields (preconditions fields source read state).2 := by
  unfold preconditions
  split
  · exact valid
  · split
    · exact valid
    · cases source.readBackSubject with
      | none => exact claim_verified_well_formed fields state source.verified valid
      | some subject =>
          cases read with
          | none => exact valid
          | some read =>
              split
              · exact valid
              · exact and_then_well_formed fields _ _
                  (checked_claim_well_formed textFactSchema fields state subject valid)
                  (fun next nextValid => claim_verified_well_formed fields next source.verified nextValid)

theorem consume_binds_well_formed (fields : Fields) (sources : List Bind) (state : State)
    (valid : WellFormed fields state)
    (known : ∀ source ∈ sources, fieldTest formSchema fields source.field = true) :
    WellFormed fields (consumeBinds sources state) := by
  induction sources generalizing state with
  | nil => exact valid
  | cons source rest ih =>
      apply ih
      · exact bind_well_formed fields state source.field valid
          (field_test_earns_presence formSchema fields source.field (known source (by simp)))
      · exact fun other member => known other (by simp [member])

theorem relative_ceiling_well_formed (fields : Fields) (source : RelativeCeiling) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (relativeCeiling fields source state).2 := by
  unfold relativeCeiling
  split
  · split
    · exact valid
    · split <;> rename_i invalidBinds
      · exact valid
      · apply and_then_well_formed fields _ _ (path_well_formed fields .relativeCeiling source.path state valid)
        intro next nextValid
        cases bindsAt : source.binds with
        | none => simpa [bindsAt, consumeBinds, accepted] using nextValid
        | some binds =>
            have admitted : RelativeBindsAdmitted fields source.argument binds := by
              simpa [bindsAt] using invalidBinds
            exact consume_binds_well_formed fields binds next nextValid
              (fun bind member => (admitted.2.2 bind member).2.1)
  · exact valid

theorem account_scope_well_formed (fields : Fields) (source : Scope) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (accountScope fields source state).2 := by
  unfold accountScope
  split <;> rename_i admitted
  · exact consume_well_formed fields state source.field valid
      (field_test_earns_presence pathSchema fields source.field admitted.2.1)
  · exact valid

theorem bounds_preserve_state (fields : Fields) (source : Bounds) (scope : Option Scope) (state : State) :
    (bounds fields source scope state).2 = state := by
  unfold bounds
  cases source.sum <;> repeat' first | split | rfl

theorem write_rules_well_formed (fields : Fields) (source : Source) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (writeRules fields source state).2 := by
  unfold writeRules
  apply and_then_well_formed fields _ _ (path_well_formed fields .write source.writePath state valid)
  intro next nextValid
  apply and_then_well_formed fields _ _ (body_well_formed fields source.body next nextValid)
  intro next nextValid
  cases source.idempotency <;> exact nextValid

theorem response_rules_well_formed (fields : Fields) (source : Source) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (responseRules fields source state).2 := by
  unfold responseRules
  apply and_then_well_formed fields
  · cases source.observation with
    | none => exact valid
    | some read => exact observation_well_formed fields read state valid
  · intro next nextValid
    apply and_then_well_formed fields
    · cases source.echo with
      | none => exact nextValid
      | some echo => cases source.observation <;> exact nextValid
    · intro next nextValid
      cases source.preEntry with
      | none => exact nextValid
      | some read => exact pre_entry_well_formed fields read next nextValid

theorem fact_rules_well_formed (fields : Fields) (source : Source) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (factRules fields source state).2 := by
  unfold factRules
  apply and_then_well_formed fields
  · cases source.relativeCeiling with
    | none => exact valid
    | some current => exact relative_ceiling_well_formed fields current state valid
  · intro next nextValid
    cases source.preconditions with
    | none => exact nextValid
    | some current => exact preconditions_well_formed fields current source.observation next nextValid

theorem bound_rules_well_formed (fields : Fields) (source : Source) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (boundRules fields source state).2 := by
  unfold boundRules
  apply and_then_well_formed fields
  · cases source.scope with
    | none => exact valid
    | some scope => exact account_scope_well_formed fields scope state valid
  · intro next nextValid
    cases source.bounds with
    | none => exact nextValid
    | some bounds => simpa only [bounds_preserve_state] using nextValid

theorem complete_rules_well_formed (fields : Fields) (source : Source) (state : State)
    (valid : WellFormed fields state) : WellFormed fields (validateFrom fields source state).2 := by
  unfold validateFrom
  apply and_then_well_formed fields _ _ (write_rules_well_formed fields source state valid)
  intro next nextValid
  apply and_then_well_formed fields _ _ (response_rules_well_formed fields source next nextValid)
  intro next nextValid
  apply and_then_well_formed fields _ _ (fact_rules_well_formed fields source next nextValid)
  intro next nextValid
  apply and_then_well_formed fields _ _ nextValid
  intro next nextValid
  apply and_then_well_formed fields _ _ (bound_rules_well_formed fields source next nextValid)
  intro next nextValid
  split <;> exact nextValid

theorem complete_rules_field_cardinality (fields : Fields) (source : Source) (bound : fields.length ≤ 32) :
    (validate fields source).2.all.card ≤ 32 ∧
    (validate fields source).2.body.card ≤ 32 ∧ (validate fields source).2.binds.card ≤ 32 := by
  have valid := complete_rules_well_formed fields source empty (empty_well_formed fields)
  obtain ⟨all, body, binds⟩ := consumed_card_bounded fields (validate fields source).2 valid
  exact ⟨all.trans bound, body.trans bound, binds.trans bound⟩

theorem complete_rules_success_consumes_original_fields (fields : Fields) (source : Source)
    (initial output : State) (completed : validateFrom fields source initial = accepted output) :
    ∀ entry ∈ fields, bindingField entry.1 = false → entry.1 ∈ output.all := by
  unfold validateFrom at completed
  obtain ⟨_, afterWrite⟩ := and_then_success _ _ output completed
  obtain ⟨_, afterResponse⟩ := and_then_success _ _ output afterWrite
  obtain ⟨_, afterFacts⟩ := and_then_success _ _ output afterResponse
  obtain ⟨_, afterGuard⟩ := and_then_success _ _ output afterFacts
  obtain ⟨_, afterBounds⟩ := and_then_success _ _ output afterGuard
  split at afterBounds <;> rename_i used
  · have same : _ = output := by simpa [accepted, Prod.mk.injEq] using afterBounds
    subst output
    exact (RecipeConsumption.all_fields_consumed_exact _ _).mp used
  · simp [refused, accepted] at afterBounds

end Auths.Product.RecipeRuleAdmission
