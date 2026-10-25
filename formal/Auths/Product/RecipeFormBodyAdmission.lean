import Auths.Product.RecipeJsonBodyAdmission

namespace Auths.Product.RecipeRuleAdmission
open RequestConstruction NativeCompiler RecipeConsumption TemplateAst
set_option maxHeartbeats 28000000
set_option maxRecDepth 4096

theorem form_member_success_earns_body_domain (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (member : Bytes × TemplateAst.FormValue) (nodes : Nat) (state : State) (initial : nodes ≤ 64)
    (order : FormMemberOrder member.2)
    (admitted : (formMember fields member nodes state).1.1 = .ok ()) :
    OperationIdentity.validToken member.1 64 = true ∧ FormShape member.2 ∧
      FormFieldsWithin (FieldProjection.names original) member.2 ∧
      (formMember fields member nodes state).2 = nodes + formValueNodes member.2 ∧
      (formMember fields member nodes state).2 ≤ 64 := by
  rcases member with ⟨key, expression⟩
  cases expression with
  | authorEcho => simp [formMember, refused] at admitted
  | text bytes =>
      have token : OperationIdentity.validToken key 64 = true := by
        by_contra invalid
        simp [formMember, invalid, refused] at admitted
      have bounded : bytes.length ≤ 1024 := by
        by_contra invalid
        simp [formMember, token, invalid, refused] at admitted
      refine ⟨token, .text bytes bounded, trivial, ?_, ?_⟩ <;>
        simp [formMember, token, bounded, formValueNodes, initial]
  | field name =>
      have token : OperationIdentity.validToken key 64 = true := by
        by_contra invalid
        simp [formMember, invalid, refused] at admitted
      cases decoded : Rules.decodeName name with
      | none => simp [formMember, token, decoded, refused] at admitted
      | some originalName =>
          have scalar : fieldTest formSchema fields originalName = true := by
            by_contra invalid
            simp [formMember, token, decoded, invalid, refused] at admitted
          have checked : (fieldRef fields name state).1 = .ok () := by
            simpa [formMember, token, decoded, scalar] using admitted
          obtain ⟨lexical, present⟩ := field_ref_success_earns_original_name original fields layout meaning name state checked
          refine ⟨token, .field name lexical, present, ?_, ?_⟩ <;>
            simp [formMember, token, decoded, scalar, formValueNodes, initial]
  | json expression =>
      have token : OperationIdentity.validToken key 64 = true := by
        by_contra invalid
        simp [formMember, invalid, refused] at admitted
      have allowed : formJsonShape expression = true := by
        by_contra invalid
        simp [formMember, token, invalid, refused] at admitted
      have shapeAllowed : FormJsonAllowed expression := by
        cases expression <;> simp_all [formJsonShape, FormJsonAllowed]
      have checked : (value 7 expression 0 nodes state fields).1.1 = .ok () := by
        simpa [formMember, token, allowed] using admitted
      obtain ⟨shape, names, spent, bound⟩ := value_success_earns_body_domain original fields layout meaning 7 expression 0 nodes state order checked
      exact ⟨token, .json expression shapeAllowed shape, names,
        by simpa [formMember, token, allowed, formValueNodes] using spent,
        by simpa [formMember, token, allowed] using bound⟩

/-- Shared-node accounting covers all nested JSON members in a form. A new
inner JSON builder cannot reset the source validator's parent node counter.
Original key order is representation input; all shape/resource admission is
earned from the actual source-rule traversal. -/
theorem form_body_success_earns_original_domain (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (members : List (Bytes × TemplateAst.FormValue)) (state : State) (order : BodyMemberOrder (.form members))
    (admitted : (body fields (.form members) state).1 = .ok ()) :
    BodyShape (.form members) none ∧ BodyFieldsWithin (FieldProjection.names original) (.form members) ∧
      (bodyWithNodes fields (.form members) state).2 = bodyNodes (.form members) ∧ bodyNodes (.form members) ≤ 64 := by
  have count : 0 < members.length ∧ members.length ≤ 16 := by
    by_contra invalid
    simp [body, bodyWithNodes, invalid, refused] at admitted
  have accepted : (foldNodes (formMember fields) members 0 state).1.1 = .ok () := by
    simpa [body, bodyWithNodes, count] using admitted
  have each : ∀ member ∈ members, ∀ nodes before, nodes ≤ 64 →
      (formMember fields member nodes before).1.1 = .ok () →
        (OperationIdentity.validToken member.1 64 = true ∧ FormShape member.2 ∧
          FormFieldsWithin (FieldProjection.names original) member.2) ∧
        (formMember fields member nodes before).2 = nodes + formValueNodes member.2 ∧
        (formMember fields member nodes before).2 ≤ 64 := by
    intro member present nodes before initial checked
    obtain ⟨token, shape, names, spent, bound⟩ := form_member_success_earns_body_domain original fields layout meaning
      member nodes before initial (order.2 member present) checked
    exact ⟨⟨token, shape, names⟩, spent, bound⟩
  obtain ⟨childrenDomain, spent, finalBound⟩ := fold_nodes_success_earns_domain (formMember fields) members
    (fun member => OperationIdentity.validToken member.1 64 = true ∧ FormShape member.2 ∧
      FormFieldsWithin (FieldProjection.names original) member.2)
    (fun member => formValueNodes member.2) 0 state (by omega) each accepted
  have keys : TemplateMembers.KeyColumn (members.map Prod.fst) .form := by
    refine ⟨by simpa using count.1, by simpa [TemplateMembers.maximum] using count.2, ?_, order.1⟩
    intro key member
    obtain ⟨row, belongs, same⟩ := List.mem_map.mp member
    simpa only [same] using (childrenDomain row belongs).1
  refine ⟨.form members none keys trivial (fun member present => (childrenDomain member present).2.1),
    (fun member present => (childrenDomain member present).2.2), ?_, ?_⟩
  · simpa [bodyWithNodes, count, bodyNodes] using spent
  · simpa [spent, bodyNodes] using finalBound

theorem body_success_earns_original_domain (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (source : TemplateAst.Body) (state : State) (order : BodyMemberOrder source)
    (admitted : (body fields source state).1 = .ok ()) :
    BodyShape source none ∧ BodyFieldsWithin (FieldProjection.names original) source ∧
      (bodyWithNodes fields source state).2 = bodyNodes source ∧ bodyNodes source ≤ 64 := by
  cases source with
  | json expression => exact json_body_success_earns_original_domain original fields layout meaning expression state order admitted
  | form members => exact form_body_success_earns_original_domain original fields layout meaning members state order admitted

/-- Original syntax, independently earned shape and the shared node limit
earn every conservative emitter resource envelope. No demand, compiled buffer,
success flag or resource counter is supplied by the caller. -/
theorem body_success_earns_resource_admission (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (source : TemplateAst.Body) (state : State) (order : BodyMemberOrder source)
    (admitted : (body fields source state).1 = .ok ()) : TemplateAst.BodyAdmissible source none := by
  obtain ⟨shape, _, _, nodes⟩ := body_success_earns_original_domain original fields layout meaning source state order admitted
  exact bounded_shape_is_admissible source none shape nodes

theorem body_success_compiles_without_echo {E : Type} (errors : RecipePlanModel.Errors E)
    (original : List FieldProjection.Field) (fields : Fields) (layout : FieldProjection.LayoutValid original)
    (meaning : Rules.Meaning original fields) (source : TemplateAst.Body) (state : State)
    (order : BodyMemberOrder source) (admitted : (body fields source state).1 = .ok ()) :
    ∃ output, RecipePlanModel.namedBody errors source none = .ok output ∧ TemplateAst.TemplateDomain output := by
  obtain ⟨output, compiled⟩ := admitted_body_compiles source none
    (body_success_earns_resource_admission original fields layout meaning source state order admitted)
  exact ⟨output, by simp [RecipePlanModel.namedBody, compiled], compile_body_earns_template_domain source none output compiled⟩

end Auths.Product.RecipeRuleAdmission
