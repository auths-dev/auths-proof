import Auths.Product.RecipeFormBodyAdmission
import Auths.Product.RecipeEchoProperties

namespace Auths.Product.RecipeRuleAdmission
open RequestConstruction NativeCompiler RecipeConsumption TemplateAst
set_option maxHeartbeats 28000000
set_option maxRecDepth 4096

theorem find_member_has_original_lookup {T : Type} (name : Bytes) (members : List (Bytes × T)) :
    findMember name members = TemplateAst.lookupSource name members := by
  induction members with
  | nil => rfl
  | cons member rest ih => cases member; simp [findMember, TemplateAst.lookupSource, ih]

theorem json_body_shape_components (expression : TemplateAst.Value) (echo : Option TemplateAst.Echo)
    (shape : BodyShape (.json expression) echo) :
    ∃ pointer, echo = pointer.map TemplateAst.Echo.json ∧ JsonShape 0 expression pointer := by
  cases shape with
  | json expression pointer shape => exact ⟨pointer, rfl, shape⟩

theorem form_body_shape_components (members : List (Bytes × TemplateAst.FormValue)) (echo : Option TemplateAst.Echo)
    (shape : BodyShape (.form members) echo) :
    ∃ insertion, echo = insertion.map TemplateAst.Echo.form ∧
      TemplateMembers.KeyColumn (members.map Prod.fst) .form ∧
      TemplateMembers.EchoAdmitted (members.map Prod.fst) insertion .form ∧
      ∀ member ∈ members, FormShape member.2 := by
  cases shape with
  | form members insertion keys admitted children => exact ⟨insertion, rfl, keys, admitted, children⟩

/-- A successful original echo route extends the original JSON shape at
exactly its named parent. The source child is recovered by complete key/value
association; no desired child index, emitted template or validity flag occurs. -/
theorem json_echo_success_earns_shape (depth : Nat) (expression : TemplateAst.Value) (tokens : List Bytes)
    (base : JsonShape depth expression none) (admitted : jsonEchoTokens expression tokens = .ok ()) :
    JsonShape depth expression (some tokens) := by
  generalize sizeAt : tokens.length = size
  induction size using Nat.strong_induction_on generalizing depth expression tokens with
  | h size ih =>
      cases base with
      | leaf depth value within leaf => cases leaf <;> simp [jsonEchoTokens] at admitted
      | array depth values within count children => simp [jsonEchoTokens] at admitted
      | object depth members route within keys routeAt children =>
          have emptyRoute : route = ⟨none, none⟩ := by simpa [namedEchoRoute] using routeAt.symm
          subst route
          have originalChildren : ∀ member ∈ members, JsonShape (depth + 1) member.2 none := by
            simpa [namedChildEcho] using children
          have lexical : members.all (fun member => OperationIdentity.validToken member.1 64) = true := by
            apply List.all_eq_true.mpr
            intro member belongs
            exact keys.2.2.1 member.1 (List.mem_map.mpr ⟨member, belongs, rfl⟩)
          cases targetAt : TemplateMembers.jsonEchoTarget (members.map Prod.fst) tokens with
          | error error => simp [jsonEchoTokens, lexical, targetAt] at admitted
          | ok target =>
              have domain := TemplateMembers.target_success_retains_pointer _ _ _ targetAt
              cases target with
              | insert =>
                  have inserted := TemplateMembers.target_insert_is_new_member _ _ targetAt
                  cases tokens with
                  | nil => simp at inserted
                  | cons name rest =>
                      have empty : rest = [] := List.length_eq_zero_iff.mp (by simpa using inserted.1)
                      subst rest
                      have fresh : name ∉ members.map Prod.fst ∧ (members.map Prod.fst).length < 32 := by
                        simpa using inserted.2
                      exact .object depth members (some [name]) ⟨some name, none⟩ within keys
                        (by simp [namedEchoRoute, domain.2, fresh])
                        (fun member belongs => by simpa [namedChildEcho] using originalChildren member belongs)
              | descend index =>
                  have descended := TemplateMembers.target_descends_to_original_name _ _ index targetAt
                  cases tokens with
                  | nil => simp at descended
                  | cons parent rest =>
                      have tailNonempty : 0 < rest.length := by simpa using descended.1
                      have parentMember : parent ∈ members.map Prod.fst := by
                        apply List.mem_iff_getElem?.mpr
                        exact ⟨index, by simpa using descended.2⟩
                      cases found : findMember parent members with
                      | none => simp [jsonEchoTokens, lexical, targetAt, found] at admitted
                      | some child =>
                          have checked : jsonEchoTokens child rest = .ok () := by
                            simpa [jsonEchoTokens, lexical, targetAt, found] using admitted
                          have lookedUp : TemplateAst.lookupSource parent members = some child := by
                            simpa only [find_member_has_original_lookup] using found
                          have childMember := TemplateAst.lookup_source_member members parent child lookedUp
                          have childShape := ih rest.length (by simp_all) (depth + 1) child rest
                            (originalChildren (parent, child) childMember) checked rfl
                          have routeMeaning : namedEchoRoute (members.map Prod.fst) (some (parent :: rest)) =
                              .ok ⟨none, some (parent, rest)⟩ := by
                            cases rest with
                            | nil => simp at tailNonempty
                            | cons next tail => simp [namedEchoRoute, domain.2, parentMember]
                          refine .object depth members (some (parent :: rest)) ⟨none, some (parent, rest)⟩ within keys routeMeaning ?_
                          intro member belongs
                          by_cases selected : parent = member.1
                          · obtain ⟨position, atMember⟩ := List.mem_iff_getElem?.mp belongs
                            have memberLookup : TemplateAst.lookupSource parent members = some member.2 :=
                              TemplateAst.lookup_source_at_unique members parent member.2 position
                                (TemplateAst.admitted_keys_are_unique _ .json keys)
                                (by simpa [selected] using atMember)
                            have sameChild : child = member.2 := Option.some.inj (lookedUp.symm.trans memberLookup)
                            simpa [namedChildEcho, selected, sameChild] using childShape
                          · simpa [namedChildEcho, selected] using originalChildren member belongs

/-- Full declared echo admission retains type and parent association and
earns compiler shape with that same echo. The base shape is the original body
without insertion; the original node count is unchanged by routing. -/
theorem echo_success_earns_body_shape {E : Type} (errors : RecipePlanModel.Errors E)
    (source : Echo) (body : TemplateAst.Body) (read : Observation)
    (base : BodyShape body none) (admitted : RecipeRuleAdmission.echo source body read = .ok ()) :
    ∃ declared, RecipePlanModel.echo errors source.write = .ok declared ∧ BodyShape body (some declared) := by
  unfold RecipeRuleAdmission.echo at admitted
  split at admitted
  · split at admitted
    · contradiction
    · cases placementAt : source.write with
      | jsonPointer pointer =>
          cases body with
          | form members => simp [placementAt] at admitted
          | json expression =>
              cases decoded : EchoPointer.decode pointer with
              | error error => simp [placementAt, decoded] at admitted
              | ok tokens =>
                  have checked : jsonEchoTokens expression tokens = .ok () := by simpa [placementAt, decoded] using admitted
                  have baseJson : JsonShape 0 expression none := by
                    obtain ⟨pointer, empty, shape⟩ := json_body_shape_components expression none base
                    cases pointer with
                    | none => exact shape
                    | some tokens => simp at empty
                  exact ⟨.json tokens, by simp [RecipePlanModel.echo, placementAt, decoded],
                    .json expression (some tokens) (json_echo_success_earns_shape 0 expression tokens baseJson checked)⟩
      | formField name =>
          cases body with
          | json expression => simp [placementAt] at admitted
          | form members =>
              have lexical : members.all (fun member => OperationIdentity.validToken member.1 64) = true := by
                by_contra invalid
                simp [placementAt, invalid] at admitted
              cases compiled : TemplateMembers.canonicalMembers (members.map Prod.fst) (some name) .form with
              | error error => simp [placementAt, lexical, compiled] at admitted
              | ok order =>
                  have domain := TemplateMembers.canonical_success_earns_admission _ _ _ order compiled
                  obtain ⟨_, _, _, _, children⟩ := form_body_shape_components members none base
                  exact ⟨.form name, by simp [RecipePlanModel.echo, placementAt],
                    .form members (some name) domain.1 domain.2 children⟩
  · contradiction

/-- Complete source-rule success earns base body shape, exact shared nodes,
all original field references and, when present, the actual declared echo.
Consequently the original named body compiles with independently earned
resource bounds. Original map order remains a parser/representation premise. -/
theorem complete_rules_earn_named_body {E : Type} (errors : RecipePlanModel.Errors E)
    (original : List FieldProjection.Field) (fields : Fields) (layout : FieldProjection.LayoutValid original)
    (meaning : Rules.Meaning original fields) (source : Source) (order : BodyMemberOrder source.body)
    (admitted : (validate fields source).1 = .ok ()) :
    BodyFieldsWithin (FieldProjection.names original) source.body ∧ bodyNodes source.body ≤ 64 ∧
      ∃ output, RecipePlanModel.namedBody errors source.body (source.echo.map (·.write)) = .ok output ∧ TemplateDomain output := by
  obtain ⟨written, responded, _, _, _⟩ := complete_rules_from_success_earns_stage_verdicts fields source empty admitted
  have bodyChecked := write_rules_success_earns_body fields source empty written
  obtain ⟨base, names, _, nodes⟩ := body_success_earns_original_domain original fields layout meaning source.body _ order bodyChecked
  refine ⟨names, nodes, ?_⟩
  cases present : source.echo with
  | none =>
      obtain ⟨output, compiled⟩ := bounded_shape_compiles source.body none base nodes
      exact ⟨output, by simp [present, RecipePlanModel.namedBody, compiled],
        compile_body_earns_template_domain source.body none output compiled⟩
  | some placement =>
      obtain ⟨read, _, checked⟩ := response_rules_success_earns_echo fields source _ responded placement present
      obtain ⟨declared, selected, shape⟩ := echo_success_earns_body_shape errors placement source.body read base checked
      obtain ⟨output, compiled⟩ := bounded_shape_compiles source.body (some declared) shape nodes
      exact ⟨output, by simp [present, RecipePlanModel.namedBody, selected, compiled],
        compile_body_earns_template_domain source.body (some declared) output compiled⟩

end Auths.Product.RecipeRuleAdmission
