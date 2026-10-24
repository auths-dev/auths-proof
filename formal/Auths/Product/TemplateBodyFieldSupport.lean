import Auths.Product.TemplateJsonFieldSupport

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler FieldSupport RecipeRuleAdmission
set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

theorem emit_form_value_preserves_original_fields (names : List Bytes) (expression : FormValue)
    (before after : FormBuild) (sourceFields : FormFieldsWithin names expression) (initial : FormFields names before.pieces)
    (completed : emitFormValue expression before = .ok after) : FormFields names after.pieces := by
  cases expression with
  | text bytes =>
      unfold emitFormValue at completed
      split at completed
      · exact form_push_preserves_fields names before after _ initial trivial completed
      · contradiction
  | field name =>
      unfold emitFormValue at completed
      split at completed
      · exact form_push_preserves_fields names before after _ initial sourceFields completed
      · contradiction
  | authorEcho => simp [emitFormValue] at completed
  | json expression =>
      unfold emitFormValue at completed
      split at completed
      · obtain ⟨nested, nestedAt, appended⟩ := bind_success _ _ _ completed
        have nestedFields := emit_json_preserves_original_fields names 7 expression none 0 (jsonStart before.nodes) nested
          sourceFields (by simp [JsonFields, jsonStart]) nestedAt
        exact form_push_preserves_fields names {before with nodes := nested.nodes} after (.json nested.pieces) initial nestedFields appended
      · contradiction

/-- Whole original body support reaches every emitted piece, including nested
form JSON and declared echoes. The emitter cannot turn a literal key into an
argument reference or substitute another name during indexed traversal. -/
theorem compile_body_preserves_original_fields (names : List Bytes) (body : Body) (echo : Option Echo)
    (output : NamedTemplate) (sourceFields : BodyFieldsWithin names body)
    (completed : compileBody body echo = .ok output) : TemplateFields names output := by
  cases body with
  | json expression =>
      unfold compileBody at completed
      obtain ⟨tokens, _, afterPlacement⟩ := bind_success _ _ _ completed
      obtain ⟨emitted, emittedAt, resultAt⟩ := bind_success _ _ _ afterPlacement
      have fields := emit_json_preserves_original_fields names 7 expression tokens 0 (jsonStart 0) emitted sourceFields
        (by simp [JsonFields, jsonStart]) emittedAt
      have same : NamedTemplate.json emitted.pieces = output := by simpa using resultAt
      simpa only [← same, TemplateFields] using fields
  | form members =>
      unfold compileBody at completed
      split at completed
      · obtain ⟨insertion, _, afterPlacement⟩ := bind_success _ _ _ completed
        obtain ⟨choices, _, afterChoices⟩ := bind_success _ _ _ afterPlacement
        obtain ⟨emitted, emittedAt, resultAt⟩ := bind_success _ _ _ afterChoices
        have preserve : ∀ current (item : TemplateMembers.Choice × Nat) next, item ∈ choices.zipIdx →
            FormFields names current.pieces →
            (do
              match item.1 with
              | .source index => match members[index]? with
                | none => .error .shape
                | some (key, value) => do
                  let prefixed ← pushForm current (.raw (formPrefix key (decide (0 < item.2))))
                  emitFormValue value prefixed
              | .echo => match insertion with
                | none => .error .echoConflict
                | some key => do
                  let prefixed ← pushForm current (.raw (formPrefix key (decide (0 < item.2))))
                  pushForm prefixed .echo) = .ok next → FormFields names next.pieces := by
          intro current item next _ known stepAt
          rcases item with ⟨choice, position⟩
          cases choice with
          | source index =>
              cases atSource : members[index]? with
              | none => simp [atSource] at stepAt
              | some member =>
                  rcases member with ⟨key, value⟩
                  simp only [atSource] at stepAt
                  obtain ⟨prefixed, prefixAt, valueAt⟩ := bind_success _ _ _ stepAt
                  have prefixFields := form_push_preserves_fields names current prefixed _ known trivial prefixAt
                  exact emit_form_value_preserves_original_fields names value prefixed next
                    (sourceFields _ (List.mem_iff_getElem?.mpr ⟨index, atSource⟩)) prefixFields valueAt
          | echo =>
              cases insertion with
              | none => simp at stepAt
              | some key =>
                  obtain ⟨prefixed, prefixAt, echoAt⟩ := bind_success _ _ _ stepAt
                  have prefixFields := form_push_preserves_fields names current prefixed _ known trivial prefixAt
                  exact form_push_preserves_fields names prefixed next .echo prefixFields trivial echoAt
        have fields := fold_preserves (fun build : FormBuild => FormFields names build.pieces) _ choices.zipIdx formStart emitted
          (by simp [FormFields, formStart]) preserve emittedAt
        have same : NamedTemplate.form emitted.pieces = output := by simpa using resultAt
        simpa only [← same, TemplateFields] using fields
      · contradiction

theorem named_body_preserves_original_fields {E : Type} (errors : RecipePlanModel.Errors E) (names : List Bytes)
    (body : Body) (placement : Option RecipePlanModel.EchoSource) (output : NamedTemplate)
    (sourceFields : BodyFieldsWithin names body) (completed : RecipePlanModel.namedBody errors body placement = .ok output) :
    TemplateFields names output := by
  unfold RecipePlanModel.namedBody at completed
  cases placement with
  | none =>
      have compiled : compileBody body none = .ok output := by
        cases result : compileBody body none <;> simp_all [Except.mapError]
      exact compile_body_preserves_original_fields names body none output sourceFields compiled
  | some placement =>
      cases parsed : RecipePlanModel.echo errors placement with
      | error error => simp [parsed] at completed
      | ok echo =>
          have compiled : compileBody body (some echo) = .ok output := by
            cases result : compileBody body (some echo) <;> simp_all [Except.mapError]
          exact compile_body_preserves_original_fields names body (some echo) output sourceFields compiled

end Auths.Product.TemplateAst
