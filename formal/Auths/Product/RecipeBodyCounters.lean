import Auths.Product.RecipeRuleAdmission

namespace Auths.Product.RecipeRuleAdmission
open RecipeConsumption NativeCompiler

def CounterFrame (before after : Nat) : Prop := before ≤ after ∧ after ≤ max 64 before

theorem counter_frame_refl (before : Nat) : CounterFrame before before := by
  exact ⟨le_rfl, le_max_right _ _⟩

theorem counter_frame_trans (before middle after : Nat)
    (first : CounterFrame before middle) (second : CounterFrame middle after) : CounterFrame before after := by
  unfold CounterFrame at *
  omega

theorem fold_nodes_counter_frame {T : Type} (visit : T → Nat → State → NodeOutcome)
    (items : List T) (nodes : Nat) (state : State)
    (charges : ∀ item ∈ items, ∀ count current, CounterFrame count (visit item count current).2) :
    CounterFrame nodes (foldNodes visit items nodes state).2 := by
  induction items generalizing nodes state with
  | nil => exact counter_frame_refl nodes
  | cons item rest ih =>
      have first := charges item (by simp) nodes state
      unfold foldNodes
      split
      · exact first
      · exact counter_frame_trans _ _ _ first
          (ih _ _ (fun child member => charges child (by simp [member])))

/-- Every outcome retains prior node charges, including refused literals,
invalid keys and exhausted sibling budgets. Starting above the cap refuses
without erasing that input counter. No allocation/time claim is made here. -/
theorem value_counter_frame (fuel : Nat) (expression : TemplateAst.Value) (depth nodes : Nat)
    (state : State) (fields : Fields) : CounterFrame nodes (value fuel expression depth nodes state fields).2 := by
  induction fuel generalizing expression depth nodes state with
  | zero => exact counter_frame_refl nodes
  | succ fuel ih =>
      unfold value
      split <;> rename_i room
      · have charged : CounterFrame nodes (nodes + 1) := by unfold CounterFrame; omega
        cases expression with
        | text bytes => exact charged
        | integer literal => exact charged
        | boolean literal => exact charged
        | field name => exact charged
        | authorEcho => exact charged
        | array children =>
            split
            · exact counter_frame_trans _ _ _ charged
                (fold_nodes_counter_frame _ children _ state (fun child _ count current => ih child _ count current))
            · exact charged
        | object members =>
            split
            · apply counter_frame_trans _ _ _ charged
              apply fold_nodes_counter_frame
              intro member present count current
              split
              · exact ih member.2 _ count current
              · exact counter_frame_refl count
            · exact charged
      · exact counter_frame_refl nodes

theorem form_member_counter_frame (fields : Fields) (member : Bytes × TemplateAst.FormValue)
    (nodes : Nat) (state : State) : CounterFrame nodes (formMember fields member nodes state).2 := by
  unfold formMember
  split
  · exact counter_frame_refl nodes
  · split
    · cases member.2 with
      | text bytes => exact counter_frame_refl nodes
      | field name => cases Rules.decodeName name <;> exact counter_frame_refl nodes
      | json expression =>
          split
          · exact value_counter_frame 7 expression 0 nodes state fields
          · exact counter_frame_refl nodes
      | authorEcho => exact counter_frame_refl nodes
    · exact counter_frame_refl nodes

theorem body_node_counter_bounded (fields : Fields) (source : TemplateAst.Body) (state : State) :
    (bodyWithNodes fields source state).2 ≤ 64 := by
  have frame : CounterFrame 0 (bodyWithNodes fields source state).2 := by
    cases source with
    | json expression => exact value_counter_frame 7 expression 0 0 state fields
    | form members =>
        unfold bodyWithNodes
        split
        · exact fold_nodes_counter_frame _ members 0 state
            (fun member _ nodes current => form_member_counter_frame fields member nodes current)
        · exact counter_frame_refl 0
  simpa [CounterFrame] using frame.2

end Auths.Product.RecipeRuleAdmission
