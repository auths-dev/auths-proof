import Auths.Product.TemplateFieldSupport

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler FieldSupport RecipeRuleAdmission
set_option maxHeartbeats 24000000
set_option maxRecDepth 4096

/-- Every emitted JSON field comes from the complete original AST and retains
its exact name. Literal prefixes and declared echoes cannot manufacture field
references. Earlier known pieces survive every successful recursive branch. -/
theorem emit_json_preserves_original_fields (names : List Bytes) (fuel : Nat) (expression : Value)
    (echo : Option (List Bytes)) (depth : Nat) (before after : JsonBuild)
    (sourceFields : JsonFieldsWithin names expression) (initial : JsonFields names before.pieces)
    (completed : emitJson fuel expression echo depth before = .ok after) : JsonFields names after.pieces := by
  induction fuel generalizing expression echo depth before after with
  | zero => simp [emitJson] at completed
  | succ fuel ih =>
      rw [emitJson] at completed
      obtain ⟨nodes, _, remaining⟩ := bind_success _ _ _ completed
      let charged : JsonBuild := { before with nodes }
      have chargedFields : JsonFields names charged.pieces := initial
      change (if echo.isSome && !isObject expression then .error .echoConflict else _) = .ok after at remaining
      split at remaining
      · contradiction
      · cases expression with
        | text bytes =>
            split at remaining
            · exact json_push_preserves_fields names charged after _ chargedFields trivial remaining
            · contradiction
        | integer literal =>
            split at remaining
            · exact json_push_preserves_fields names charged after _ chargedFields trivial remaining
            · contradiction
        | boolean literal => exact json_push_preserves_fields names charged after _ chargedFields trivial remaining
        | field name =>
            split at remaining
            · have known : name ∈ names := by cases sourceFields; assumption
              exact json_push_preserves_fields names charged after _ chargedFields known remaining
            · contradiction
        | authorEcho => contradiction
        | array items =>
            split at remaining
            · obtain ⟨opened, openAt, afterOpen⟩ := bind_success _ _ _ remaining
              obtain ⟨folded, foldedAt, closeAt⟩ := bind_success _ _ _ afterOpen
              have children : ∀ child ∈ items, JsonFieldsWithin names child := by cases sourceFields; assumption
              have openedFields := json_push_preserves_fields names charged opened (.raw [91]) chargedFields trivial openAt
              have preserve : ∀ current (item : Value × Nat) next, item ∈ items.zipIdx → JsonFields names current.pieces →
                  (do
                    let separated ← if 0 < item.2 then pushJson current (.raw [44]) else .ok current
                    emitJson fuel item.1 none (depth + 1) separated) = .ok next → JsonFields names next.pieces := by
                intro current item next member known stepAt
                obtain ⟨separated, separatorAt, childAt⟩ := bind_success _ _ _ stepAt
                have separatorFields : JsonFields names separated.pieces := by
                  by_cases hasSeparator : 0 < item.2
                  · exact json_push_preserves_fields names current separated (.raw [44]) known trivial
                      (by simpa [hasSeparator] using separatorAt)
                  · have same : current = separated := by simpa [hasSeparator] using separatorAt
                    simpa only [← same] using known
                have originalMember : item.1 ∈ items := List.mem_iff_getElem?.mpr
                  ⟨item.2, List.mem_zipIdx_iff_getElem?.mp member⟩
                exact ih item.1 none (depth + 1) separated next (children item.1 originalMember) separatorFields childAt
              have foldedFields := fold_preserves (fun build : JsonBuild => JsonFields names build.pieces)
                _ items.zipIdx opened folded openedFields preserve foldedAt
              exact json_push_preserves_fields names folded after (.raw [93]) foldedFields trivial closeAt
            · contradiction
        | object members =>
            split at remaining
            · obtain ⟨target, _, afterTarget⟩ := bind_success _ _ _ remaining
              obtain ⟨insertion, _, afterInsertion⟩ := bind_success _ _ _ afterTarget
              obtain ⟨choices, _, afterChoices⟩ := bind_success _ _ _ afterInsertion
              obtain ⟨opened, openAt, afterOpen⟩ := bind_success _ _ _ afterChoices
              obtain ⟨folded, foldedAt, closeAt⟩ := bind_success _ _ _ afterOpen
              have children : ∀ member ∈ members, JsonFieldsWithin names member.2 := by cases sourceFields; assumption
              have openedFields := json_push_preserves_fields names charged opened (.raw [123]) chargedFields trivial openAt
              have preserve : ∀ current (item : TemplateMembers.Choice × Nat) next, item ∈ choices.zipIdx →
                  JsonFields names current.pieces →
                  (do
                    match item.1 with
                    | .source index => match members[index]? with
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
                        pushJson prefixed .echo) = .ok next → JsonFields names next.pieces := by
                intro current item next _ known stepAt
                rcases item with ⟨choice, position⟩
                cases choice with
                | source index =>
                    cases atSource : members[index]? with
                    | none => simp [atSource] at stepAt
                    | some member =>
                        rcases member with ⟨name, child⟩
                        simp only [atSource] at stepAt
                        obtain ⟨prefixed, prefixAt, afterPrefix⟩ := bind_success _ _ _ stepAt
                        obtain ⟨nested, _, childAt⟩ := bind_success _ _ _ afterPrefix
                        have prefixFields := json_push_preserves_fields names current prefixed _ known trivial prefixAt
                        have originalMember : (name, child) ∈ members := List.mem_iff_getElem?.mpr ⟨index, atSource⟩
                        exact ih child nested (depth + 1) prefixed next (children _ originalMember) prefixFields childAt
                | echo =>
                    cases insertion with
                    | none => simp at stepAt
                    | some name =>
                        obtain ⟨prefixed, prefixAt, echoAt⟩ := bind_success _ _ _ stepAt
                        have prefixFields := json_push_preserves_fields names current prefixed _ known trivial prefixAt
                        exact json_push_preserves_fields names prefixed next .echo prefixFields trivial echoAt
              have foldedFields := fold_preserves (fun build : JsonBuild => JsonFields names build.pieces)
                _ choices.zipIdx opened folded openedFields preserve foldedAt
              exact json_push_preserves_fields names folded after (.raw [125]) foldedFields trivial closeAt
            · contradiction

end Auths.Product.TemplateAst
