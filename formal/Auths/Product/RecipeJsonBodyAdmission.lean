import Auths.Product.RecipeBodyStructure

namespace Auths.Product.RecipeRuleAdmission
open RequestConstruction NativeCompiler RecipeConsumption TemplateAst
set_option maxHeartbeats 28000000
set_option maxRecDepth 4096

/-- Complete successful original JSON validation earns compiler shape,
original field containment and the exact shared-node count. The original map
order is representation input; literal/name/arity/depth/resource admission is
earned. No selected compiler output or successful emitter is a premise. -/
theorem value_success_earns_body_domain (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (fuel : Nat) (expression : TemplateAst.Value) (depth nodes : Nat) (state : State)
    (order : JsonMemberOrder expression)
    (admitted : (value fuel expression depth nodes state fields).1.1 = .ok ()) :
    JsonShape depth expression none ∧ JsonFieldsWithin (FieldProjection.names original) expression ∧
      (value fuel expression depth nodes state fields).2 = nodes + jsonNodes expression ∧
      (value fuel expression depth nodes state fields).2 ≤ 64 := by
  induction fuel generalizing expression depth nodes state with
  | zero => simp [value, refused] at admitted
  | succ fuel ih =>
      unfold value at admitted
      split at admitted
      · rename_i charge
        have chargedBound : nodes + 1 ≤ 64 := by omega
        cases expression with
        | text bytes =>
            split at admitted
            · rename_i bounded
              refine ⟨.leaf depth _ charge.2 (.text bytes bounded), .text bytes, ?_, ?_⟩ <;>
                simp [value, charge, bounded, jsonNodes] <;> omega
            · simp [refused] at admitted
        | integer literal =>
            split at admitted
            · rename_i bounded
              have absolute : (literal.natAbs : Int) ≤ 9007199254740991 := by exact_mod_cast bounded
              rw [Int.natCast_natAbs] at absolute
              have safe := abs_le.mp absolute
              refine ⟨.leaf depth _ charge.2 (.integer literal safe), .integer literal, ?_, ?_⟩ <;>
                simp [value, charge, bounded, jsonNodes] <;> omega
            · simp [refused] at admitted
        | boolean literal =>
            refine ⟨.leaf depth _ charge.2 (.boolean literal), .boolean literal, ?_, ?_⟩ <;>
              simp [value, charge, jsonNodes] <;> omega
        | field name =>
            have checked : (fieldRef fields name state).1 = .ok () := admitted
            obtain ⟨lexical, present⟩ := field_ref_success_earns_original_name original fields layout meaning name state checked
            refine ⟨.leaf depth _ charge.2 (.field name lexical), .field name present, ?_, ?_⟩ <;>
              simp [value, charge, jsonNodes] <;> omega
        | authorEcho => simp [refused] at admitted
        | array children =>
            split at admitted
            · rename_i count
              have ordered : ∀ child ∈ children, JsonMemberOrder child := by cases order; assumption
              have each : ∀ child ∈ children, ∀ current before, current ≤ 64 →
                  (value fuel child (depth + 1) current before fields).1.1 = .ok () →
                    (JsonShape (depth + 1) child none ∧ JsonFieldsWithin (FieldProjection.names original) child) ∧
                    (value fuel child (depth + 1) current before fields).2 = current + jsonNodes child ∧
                    (value fuel child (depth + 1) current before fields).2 ≤ 64 := by
                intro child member current before _ accepted
                obtain ⟨shape, names, spent, bound⟩ := ih child (depth + 1) current before (ordered child member) accepted
                exact ⟨⟨shape, names⟩, spent, bound⟩
              obtain ⟨childrenDomain, spent, finalBound⟩ := fold_nodes_success_earns_domain
                (fun child current before => value fuel child (depth + 1) current before fields)
                children (fun child => JsonShape (depth + 1) child none ∧ JsonFieldsWithin (FieldProjection.names original) child)
                jsonNodes (nodes + 1) state chargedBound each admitted
              refine ⟨.array depth children charge.2 count (fun child member => (childrenDomain child member).1),
                .array children (fun child member => (childrenDomain child member).2), ?_, ?_⟩
              · simpa [value, charge, count, jsonNodes, original_array_nodes_sum, Nat.add_assoc] using spent
              · simpa [value, charge, count] using finalBound
            · simp [refused] at admitted
        | object members =>
            split at admitted
            · rename_i count
              have ordered : (members.map Prod.fst).Pairwise (· < ·) ∧
                  ∀ member ∈ members, JsonMemberOrder member.2 := by cases order; exact ⟨by assumption, by assumption⟩
              let visit := fun (member : Bytes × TemplateAst.Value) current before =>
                if OperationIdentity.validToken member.1 64 then
                  value fuel member.2 (depth + 1) current before fields
                else (refused .unsafeTemplate before, current)
              have each : ∀ member ∈ members, ∀ current before, current ≤ 64 →
                  (visit member current before).1.1 = .ok () →
                    (OperationIdentity.validToken member.1 64 = true ∧ JsonShape (depth + 1) member.2 none ∧
                      JsonFieldsWithin (FieldProjection.names original) member.2) ∧
                    (visit member current before).2 = current + jsonNodes member.2 ∧
                    (visit member current before).2 ≤ 64 := by
                intro member belongs current before _ accepted
                by_cases token : OperationIdentity.validToken member.1 64 = true
                · have checked : (value fuel member.2 (depth + 1) current before fields).1.1 = .ok () := by
                    simpa [visit, token] using accepted
                  obtain ⟨shape, names, spent, bound⟩ := ih member.2 (depth + 1) current before (ordered.2 member belongs) checked
                  exact ⟨⟨token, shape, names⟩, by simpa [visit, token] using spent, by simpa [visit, token] using bound⟩
                · simp [visit, token, refused] at accepted
              obtain ⟨childrenDomain, spent, finalBound⟩ := fold_nodes_success_earns_domain visit members
                (fun member => OperationIdentity.validToken member.1 64 = true ∧ JsonShape (depth + 1) member.2 none ∧
                  JsonFieldsWithin (FieldProjection.names original) member.2)
                (fun member => jsonNodes member.2) (nodes + 1) state chargedBound each admitted
              have keys : TemplateMembers.KeyColumn (members.map Prod.fst) .json := by
                refine ⟨by simpa using count.1, by simpa [TemplateMembers.maximum] using count.2, ?_, ordered.1⟩
                intro key member
                obtain ⟨row, belongs, same⟩ := List.mem_map.mp member
                simpa only [same] using (childrenDomain row belongs).1
              have shape : JsonShape depth (.object members) none :=
                .object depth members none ⟨none, none⟩ charge.2 keys rfl
                  (fun member belongs => by simpa [namedChildEcho] using (childrenDomain member belongs).2.1)
              refine ⟨shape, .object members (fun member belongs => (childrenDomain member belongs).2.2), ?_, ?_⟩
              · simpa [value, charge, count, visit, jsonNodes, original_member_nodes_sum, Nat.add_assoc] using spent
              · simpa [value, charge, count, visit] using finalBound
            · simp [refused] at admitted
      · simp [refused] at admitted

theorem json_body_success_earns_original_domain (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (expression : TemplateAst.Value) (state : State) (order : JsonMemberOrder expression)
    (admitted : (body fields (.json expression) state).1 = .ok ()) :
    BodyShape (.json expression) none ∧ BodyFieldsWithin (FieldProjection.names original) (.json expression) ∧
      (bodyWithNodes fields (.json expression) state).2 = bodyNodes (.json expression) ∧ bodyNodes (.json expression) ≤ 64 := by
  have checked : (value 7 expression 0 0 state fields).1.1 = .ok () := admitted
  obtain ⟨shape, names, spent, bounded⟩ := value_success_earns_body_domain original fields layout meaning 7 expression 0 0 state order checked
  refine ⟨.json expression none shape, names, by simpa [bodyWithNodes, bodyNodes] using spent, ?_⟩
  simpa [spent, bodyNodes] using bounded

theorem admitted_json_body_compiles_without_echo (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (expression : TemplateAst.Value) (state : State) (order : JsonMemberOrder expression)
    (admitted : (body fields (.json expression) state).1 = .ok ()) :
    ∃ output, TemplateAst.compileBody (.json expression) none = .ok output := by
  obtain ⟨shape, _, _, nodes⟩ := json_body_success_earns_original_domain original fields layout meaning expression state order admitted
  exact bounded_shape_compiles _ _ shape nodes

end Auths.Product.RecipeRuleAdmission
