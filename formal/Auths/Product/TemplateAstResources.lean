import Auths.Product.TemplateAst

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler BodyCompiler.Resources

structure JsonFrame (before after : JsonBuild) : Prop where
  invariant : JsonInvariant after
  nodes : before.nodes ≤ after.nodes
  prefix : before.pieces <+: after.pieces

structure FormFrame (before after : FormBuild) : Prop where
  invariant : FormInvariant after
  nodes : before.nodes ≤ after.nodes
  prefix : before.pieces <+: after.pieces

theorem JsonFrame.refl (value : JsonBuild) (valid : JsonInvariant value) : JsonFrame value value :=
  ⟨valid, le_rfl, List.prefix_rfl⟩
theorem FormFrame.refl (value : FormBuild) (valid : FormInvariant value) : FormFrame value value :=
  ⟨valid, le_rfl, List.prefix_rfl⟩

theorem JsonFrame.trans {first middle last : JsonBuild} (left : JsonFrame first middle)
    (right : JsonFrame middle last) : JsonFrame first last :=
  ⟨right.invariant, left.nodes.trans right.nodes, left.prefix.trans right.prefix⟩
theorem FormFrame.trans {first middle last : FormBuild} (left : FormFrame first middle)
    (right : FormFrame middle last) : FormFrame first last :=
  ⟨right.invariant, left.nodes.trans right.nodes, left.prefix.trans right.prefix⟩

theorem json_push_frame (before after : JsonBuild) (piece : NamedJson)
    (valid : JsonInvariant before) (run : pushJson before piece = .ok after) : JsonFrame before after := by
  obtain ⟨invariant, nodes, pieces⟩ := json_push_preserves_invariant _ _ _ valid run
  exact ⟨invariant, by omega, ⟨[piece], pieces.symm⟩⟩

theorem form_push_frame (before after : FormBuild) (piece : NamedForm)
    (valid : FormInvariant before) (run : pushForm before piece = .ok after) : FormFrame before after := by
  obtain ⟨invariant, nodes, pieces⟩ := form_push_preserves_invariant _ _ _ valid run
  exact ⟨invariant, by omega, ⟨[piece], pieces.symm⟩⟩

private theorem bind_success {α β : Type} {first : Except Error α} {next : α → Except Error β}
    {output : β} (run : (first >>= next) = .ok output) :
    ∃ middle, first = .ok middle ∧ next middle = .ok output := by
  cases first with
  | error error => simp [Bind.bind, Except.bind] at run
  | ok middle => exact ⟨middle, rfl, by simpa [Bind.bind, Except.bind] using run⟩

private theorem fold_json_frame {α : Type} (step : JsonBuild → α → Except Error JsonBuild)
    (preserve : ∀ before item after, JsonInvariant before → step before item = .ok after → JsonFrame before after)
    (items : List α) (before after : JsonBuild) (valid : JsonInvariant before)
    (run : items.foldlM step before = .ok after) : JsonFrame before after := by
  induction items generalizing before with
  | nil =>
    have same : before = after := by simpa using run
    subst after
    exact JsonFrame.refl _ valid
  | cons item rest ih =>
    rw [List.foldlM_cons] at run
    obtain ⟨middle, first, tail⟩ := bind_success run
    have start := preserve before item middle valid first
    exact start.trans (ih middle start.invariant tail)

private theorem fold_form_frame {α : Type} (step : FormBuild → α → Except Error FormBuild)
    (preserve : ∀ before item after, FormInvariant before → step before item = .ok after → FormFrame before after)
    (items : List α) (before after : FormBuild) (valid : FormInvariant before)
    (run : items.foldlM step before = .ok after) : FormFrame before after := by
  induction items generalizing before with
  | nil =>
    have same : before = after := by simpa using run
    subst after
    exact FormFrame.refl _ valid
  | cons item rest ih =>
    rw [List.foldlM_cons] at run
    obtain ⟨middle, first, tail⟩ := bind_success run
    have start := preserve before item middle valid first
    exact start.trans (ih middle start.invariant tail)

/-- Every successful recursive JSON emission preserves the complete resource
invariant and the entire earlier piece prefix, and strictly advances the
shared node meter. No AST validity or expected emitted buffer is assumed. -/
theorem emit_json_preserves_resources (fuel : Nat) (value : Value) (echo : Option (List Bytes))
    (depth : Nat) (before after : JsonBuild) (valid : JsonInvariant before)
    (run : emitJson fuel value echo depth before = .ok after) :
    JsonFrame before after ∧ before.nodes < after.nodes := by
  induction fuel generalizing value echo depth before after with
  | zero => simp [emitJson] at run
  | succ fuel ih =>
    rw [emitJson] at run
    obtain ⟨nodes, charged, rest⟩ := bind_success run
    obtain ⟨nodeRoom, depthBound, nodeValue, nodeBound⟩ := charge_node_earns_domain _ _ _ charged
    let initial : JsonBuild := { before with nodes }
    have initialValid : JsonInvariant initial := ⟨nodeBound, valid.2⟩
    have initialFrame : JsonFrame before initial := ⟨initialValid, by dsimp [initial]; omega, by simp [initial]⟩
    have advanced : before.nodes < initial.nodes := by dsimp [initial]; omega
    have finish : JsonFrame initial after → JsonFrame before after ∧ before.nodes < after.nodes :=
      fun frame => ⟨initialFrame.trans frame, lt_of_lt_of_le advanced frame.nodes⟩
    change (if echo.isSome && !isObject value then .error .echoConflict else _) = .ok after at rest
    split at rest
    · contradiction
    · cases value with
      | text text =>
        split at rest
        · exact finish (json_push_frame initial after _ initialValid rest)
        · contradiction
      | integer value =>
        split at rest
        · exact finish (json_push_frame initial after _ initialValid rest)
        · contradiction
      | boolean value => exact finish (json_push_frame initial after _ initialValid rest)
      | field name =>
        split at rest
        · exact finish (json_push_frame initial after _ initialValid rest)
        · contradiction
      | authorEcho => contradiction
      | array items =>
        split at rest
        · obtain ⟨opened, openRun, afterOpen⟩ := bind_success rest
          obtain ⟨folded, foldRun, closeRun⟩ := bind_success afterOpen
          have openFrame := json_push_frame initial opened (.raw [91]) initialValid openRun
          have preserve : ∀ current (item : Value × Nat) next, JsonInvariant current →
              (do
                let separated ← if 0 < item.2 then pushJson current (.raw [44]) else .ok current
                emitJson fuel item.1 none (depth + 1) separated) = .ok next → JsonFrame current next := by
            intro current item next currentValid stepRun
            obtain ⟨separated, separatorRun, childRun⟩ := bind_success stepRun
            have separatorFrame : JsonFrame current separated := by
              by_cases present : 0 < item.2
              · exact json_push_frame _ _ _ currentValid (by simpa [present] using separatorRun)
              · have same : current = separated := by simpa [present] using separatorRun
                subst separated
                exact JsonFrame.refl _ currentValid
            exact separatorFrame.trans (ih item.1 none (depth + 1) separated next separatorFrame.invariant childRun).1
          have foldedFrame := fold_json_frame _ preserve items.zipIdx opened folded openFrame.invariant foldRun
          have closeFrame := json_push_frame folded after (.raw [93]) foldedFrame.invariant closeRun
          exact finish (openFrame.trans (foldedFrame.trans closeFrame))
        · contradiction
      | object fields =>
        split at rest
        · obtain ⟨target, targetRun, afterTarget⟩ := bind_success rest
          obtain ⟨insertion, insertionRun, afterInsertion⟩ := bind_success afterTarget
          obtain ⟨choices, choicesRun, afterChoices⟩ := bind_success afterInsertion
          obtain ⟨opened, openRun, afterOpen⟩ := bind_success afterChoices
          obtain ⟨folded, foldRun, closeRun⟩ := bind_success afterOpen
          have openFrame := json_push_frame initial opened (.raw [123]) initialValid openRun
          have preserve : ∀ current (item : TemplateMembers.Choice × Nat) next, JsonInvariant current →
              (do
                match item.1 with
                | .source index => match fields[index]? with
                  | none => .error .shape
                  | some (name, child) => do
                    let prefixed ← pushJson current (.raw (jsonPrefix name (decide (0 < item.2))))
                    let nested ← match target, echo with
                      | some (.descend selected), some tokens =>
                        if selected = index then
                          if 0 < tokens.length then .ok (some (tokens.drop 1)) else .error .echoConflict
                        else .ok none
                      | _, _ => .ok none
                    emitJson fuel child nested (depth + 1) prefixed
                | .echo => match insertion with
                  | none => .error .echoConflict
                  | some name => do
                    let prefixed ← pushJson current (.raw (jsonPrefix name (decide (0 < item.2))))
                    pushJson prefixed .echo) = .ok next → JsonFrame current next := by
            intro current item next currentValid stepRun
            obtain ⟨choice, position⟩ := item
            cases choice with
            | source index =>
              cases atSource : fields[index]? with
              | none => simp [atSource] at stepRun
              | some member =>
                obtain ⟨name, child⟩ := member
                simp only [atSource] at stepRun
                obtain ⟨prefixed, prefixRun, afterPrefix⟩ := bind_success stepRun
                obtain ⟨nested, nestedRun, childRun⟩ := bind_success afterPrefix
                have prefixFrame := json_push_frame _ _ _ currentValid prefixRun
                exact prefixFrame.trans (ih child nested (depth + 1) prefixed next prefixFrame.invariant childRun).1
            | echo =>
              cases insertion with
              | none => simp at stepRun
              | some name =>
                obtain ⟨prefixed, prefixRun, echoRun⟩ := bind_success stepRun
                have prefixFrame := json_push_frame _ _ _ currentValid prefixRun
                exact prefixFrame.trans (json_push_frame _ _ _ prefixFrame.invariant echoRun)
          have foldedFrame := fold_json_frame _ preserve choices.zipIdx opened folded openFrame.invariant foldRun
          have closeFrame := json_push_frame folded after (.raw [125]) foldedFrame.invariant closeRun
          exact finish (openFrame.trans (foldedFrame.trans closeFrame))
        · contradiction

/-- Form literals retain the meter, while each nested JSON value starts with
the current meter and returns its incremented count. Parent resources and
earlier pieces survive both branches. -/
theorem emit_form_value_preserves_resources (value : FormValue) (before after : FormBuild)
    (valid : FormInvariant before) (run : emitFormValue value before = .ok after) : FormFrame before after := by
  cases value with
  | text text =>
    unfold emitFormValue at run
    split at run
    · exact form_push_frame _ _ _ valid run
    · contradiction
  | field name =>
    unfold emitFormValue at run
    split at run
    · exact form_push_frame _ _ _ valid run
    · contradiction
  | authorEcho => simp [emitFormValue] at run
  | json value =>
    unfold emitFormValue at run
    split at run
    · obtain ⟨nested, nestedRun, appendRun⟩ := bind_success run
      have nestedFrame := (emit_json_preserves_resources 7 value none 0 (jsonStart before.nodes) nested
        (json_start_invariant before.nodes valid.1) nestedRun).1
      let rebased : FormBuild := { before with nodes := nested.nodes }
      have rebasedValid : FormInvariant rebased := ⟨nestedFrame.invariant.1, valid.2⟩
      have rebaseFrame : FormFrame before rebased :=
        ⟨rebasedValid, by simpa [jsonStart, rebased] using nestedFrame.nodes, by simp [rebased]⟩
      exact rebaseFrame.trans (form_push_frame rebased after (.json nested.pieces) rebasedValid appendRun)
    · contradiction

def TemplateDomain : NamedTemplate → Prop
  | .json pieces => pieces.length ≤ 256 ∧ JsonResourceDomain pieces
  | .form pieces => pieces.length ≤ 256 ∧ FormResourceDomain pieces

theorem json_invariant_earns_template_domain (output : JsonBuild) (valid : JsonInvariant output) :
    TemplateDomain (.json output.pieces) := by
  refine ⟨valid.2.1, ?_⟩
  have resourceBound := valid.2.2.1
  rw [valid.2.2.2] at resourceBound
  simpa [JsonResourceDomain, Bounded, totals, jsonQuantity, jsonLiterals, jsonDynamics] using resourceBound

theorem form_invariant_earns_template_domain (output : FormBuild) (valid : FormInvariant output) :
    TemplateDomain (.form output.pieces) := by
  have resourceBound := valid.2.2.1
  rw [valid.2.2.2.1] at resourceBound
  have bounds : formLiterals output.pieces ≤ 524288 ∧ formDynamics output.pieces ≤ 256 := by
    simpa [Bounded, totals, formQuantity, formLiterals, formDynamics] using resourceBound
  exact ⟨valid.2.1, bounds.1, bounds.2, valid.2.2.2.2⟩

/-- The complete compiler earns its named-template count/aggregate/nested
domains from the actual model run. No AST validity, bounded input resource,
successful helper or expected emitted template is a caller premise. -/
theorem compile_body_earns_template_domain (body : Body) (echo : Option Echo) (output : NamedTemplate)
    (run : compileBody body echo = .ok output) : TemplateDomain output := by
  cases body with
  | json value =>
    unfold compileBody at run
    obtain ⟨tokens, placementRun, afterPlacement⟩ := bind_success run
    obtain ⟨emitted, emittedRun, resultRun⟩ := bind_success afterPlacement
    have frame := (emit_json_preserves_resources 7 value tokens 0 (jsonStart 0) emitted
      (json_start_invariant 0 (by omega)) emittedRun).1
    have same : NamedTemplate.json emitted.pieces = output := by simpa using resultRun
    subst output
    exact json_invariant_earns_template_domain _ frame.invariant
  | form fields =>
    unfold compileBody at run
    split at run
    · obtain ⟨insertion, placementRun, afterPlacement⟩ := bind_success run
      obtain ⟨choices, choicesRun, afterChoices⟩ := bind_success afterPlacement
      obtain ⟨emitted, emittedRun, resultRun⟩ := bind_success afterChoices
      have preserve : ∀ current (item : TemplateMembers.Choice × Nat) next, FormInvariant current →
          (do
            match item.1 with
            | .source index => match fields[index]? with
              | none => .error .shape
              | some (name, value) => do
                let prefixed ← pushForm current (.raw (formPrefix name (decide (0 < item.2))))
                emitFormValue value prefixed
            | .echo => match insertion with
              | none => .error .echoConflict
              | some name => do
                let prefixed ← pushForm current (.raw (formPrefix name (decide (0 < item.2))))
                pushForm prefixed .echo) = .ok next → FormFrame current next := by
        intro current item next currentValid stepRun
        obtain ⟨choice, position⟩ := item
        cases choice with
        | source index =>
          cases atSource : fields[index]? with
          | none => simp [atSource] at stepRun
          | some member =>
            obtain ⟨name, value⟩ := member
            simp only [atSource] at stepRun
            obtain ⟨prefixed, prefixRun, valueRun⟩ := bind_success stepRun
            have prefixFrame := form_push_frame _ _ _ currentValid prefixRun
            exact prefixFrame.trans (emit_form_value_preserves_resources value prefixed next prefixFrame.invariant valueRun)
        | echo =>
          cases insertion with
          | none => simp at stepRun
          | some name =>
            obtain ⟨prefixed, prefixRun, echoRun⟩ := bind_success stepRun
            have prefixFrame := form_push_frame _ _ _ currentValid prefixRun
            exact prefixFrame.trans (form_push_frame _ _ _ prefixFrame.invariant echoRun)
      have frame := fold_form_frame _ preserve choices.zipIdx formStart emitted form_start_invariant emittedRun
      have same : NamedTemplate.form emitted.pieces = output := by simpa using resultRun
      subst output
      exact form_invariant_earns_template_domain _ frame.invariant
    · contradiction

end Auths.Product.TemplateAst
