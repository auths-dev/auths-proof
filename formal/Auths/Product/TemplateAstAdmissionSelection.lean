import Auths.Product.TemplateAstAdmissionBudget
import Auths.Product.TemplateAstCorrespondence

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler

theorem named_route_member_admission (keys : List Bytes) (echo : Option (List Bytes)) (route : NamedEchoRoute)
    (column : TemplateMembers.KeyColumn keys .json) (meaning : namedEchoRoute keys echo = .ok route) :
    TemplateMembers.Admitted keys route.insertion .json := by
  refine ⟨column, ?_⟩
  cases echo with
  | none =>
    have same : route = ⟨none, none⟩ := by simpa [namedEchoRoute] using meaning.symm
    simp [same, TemplateMembers.EchoAdmitted]
  | some tokens =>
    unfold namedEchoRoute at meaning
    split at meaning
    · rename_i pointer
      cases tokens with
      | nil => contradiction
      | cons parent tail =>
        cases tail with
        | nil =>
          split at meaning
          · rename_i fresh
            have same : route = ⟨some parent, none⟩ := by simpa using meaning.symm
            have lexical := pointer.2.2.1 parent (by simp)
            simpa [same, TemplateMembers.EchoAdmitted, TemplateMembers.EchoName, TemplateMembers.maximum] using
              And.intro lexical (And.intro fresh.2 fresh.1)
          · contradiction
        | cons next rest =>
          split at meaning
          · have same : route = ⟨none, some (parent, next :: rest)⟩ := by simpa using meaning.symm
            simp [same, TemplateMembers.EchoAdmitted]
          · contradiction
    · contradiction

theorem named_route_compiles (keys : List Bytes) (echo : Option (List Bytes)) (route : NamedEchoRoute)
    (column : TemplateMembers.KeyColumn keys .json) (meaning : namedEchoRoute keys echo = .ok route) :
    ∃ target, objectTarget keys echo = .ok target ∧ objectInsertion target echo = .ok route.insertion ∧
      ∀ index name, keys[index]? = some name → objectChildEcho target echo index = .ok (namedChildEcho route name) := by
  have selectors : ∃ target insertion, objectTarget keys echo = .ok target ∧ objectInsertion target echo = .ok insertion := by
    cases echo with
    | none => exact ⟨none, none, rfl, rfl⟩
    | some tokens =>
      have admitted : TemplateMembers.TargetAdmitted keys tokens := by
        refine ⟨column, ?_⟩
        unfold namedEchoRoute at meaning
        split at meaning
        · rename_i pointer
          refine ⟨pointer, ?_⟩
          cases tokens with
          | nil => contradiction
          | cons parent tail =>
            cases tail with
            | nil =>
              split at meaning
              · rename_i fresh
                simpa using fresh
              · contradiction
            | cons next rest =>
              split at meaning
              · rename_i present
                simpa using present
              · contradiction
        · contradiction
      obtain ⟨target, run⟩ := TemplateMembers.target_admitted_compiles keys tokens admitted
      have called : objectTarget keys (some tokens) = .ok (some target) := by
        simp [objectTarget, run, Except.mapError, Except.map]
      cases target with
      | descend index => exact ⟨some (.descend index), none, called, rfl⟩
      | insert =>
        have length := (TemplateMembers.target_insert_is_new_member keys tokens run).1
        cases tokens with
        | nil => simp at length
        | cons first rest =>
          have empty : rest = [] := List.length_eq_zero_iff.mp (by simpa using length)
          subst rest
          exact ⟨some .insert, some first, called, rfl⟩
  obtain ⟨target, insertion, targetRun, insertionRun⟩ := selectors
  obtain ⟨actualRoute, actualRun, inserted, children⟩ := object_selection_named_route keys column echo target insertion targetRun insertionRun
  have same : actualRoute = route := by simpa [meaning] using actualRun.symm
  subst actualRoute
  exact ⟨target, targetRun, by simpa [inserted] using insertionRun, children⟩

def choiceDemand (costs : List Demand) (echo : Demand) : TemplateMembers.Choice → Demand
  | .source index => (costs[index]?).getD Demand.zero
  | .echo => echo

private theorem choice_demand_sum (costs : List Demand) (echo : Demand) (order : List TemplateMembers.Choice) :
    Demand.sum (order.map (choiceDemand costs echo)) = Demand.plus
      (Demand.sum ((TemplateMembers.sourceIndices order).map (fun index => (costs[index]?).getD Demand.zero)))
      (Demand.times (TemplateMembers.echoCount order) echo) := by
  induction order with
  | nil => simp [Demand.sum, TemplateMembers.sourceIndices, TemplateMembers.echoCount]
  | cons choice rest ih =>
    cases choice
    all_goals
      have nodes := congrArg Demand.nodes ih
      have pieces := congrArg Demand.pieces ih
      have literals := congrArg Demand.literals ih
      have dynamics := congrArg Demand.dynamics ih
      apply Demand.ext <;>
        simp_all [Demand.sum, choiceDemand, TemplateMembers.sourceIndices, TemplateMembers.echoCount,
          Demand.plus, Demand.times, Nat.add_mul, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]

private theorem source_positions_demand (prefix : List Demand) (keys : List Bytes) (costs : List Demand)
    (length : keys.length = costs.length) : Demand.sum ((TemplateMembers.sourcePositions prefix.length keys).map
      (fun index => ((prefix ++ costs)[index]?).getD Demand.zero)) = Demand.sum costs := by
  induction keys generalizing prefix costs with
  | nil =>
    have empty : costs = [] := List.length_eq_zero_iff.mp (by omega)
    simp [empty, TemplateMembers.sourcePositions, Demand.sum]
  | cons key rest ih =>
    cases costs with
    | nil => simp at length
    | cons first remaining =>
      have tail := ih (prefix ++ [first]) remaining (by simp_all)
      have original : (prefix ++ first :: remaining)[prefix.length]? = some first := by simp
      simpa [TemplateMembers.sourcePositions, Demand.sum, original, List.append_assoc] using congrArg (Demand.plus first) tail

theorem canonical_choice_demand (keys : List Bytes) (insertion : Option Bytes) (domain : TemplateMembers.Domain)
    (order : List TemplateMembers.Choice) (run : TemplateMembers.canonicalMembers keys insertion domain = .ok order)
    (costs : List Demand) (length : costs.length = keys.length) (echo : Demand) :
    Demand.sum (order.map (choiceDemand costs echo)) = Demand.plus (Demand.sum costs)
      (if insertion.isSome then echo else Demand.zero) := by
  have preserved := TemplateMembers.canonical_success_preserves_source keys insertion domain order run
  rw [choice_demand_sum, preserved.1, preserved.2]
  have original := source_positions_demand [] keys costs length.symm
  have result := congrArg (fun costs => Demand.plus costs (Demand.times (if insertion.isSome then 1 else 0) echo)) original
  cases insertion <;> simpa using result

theorem canonical_choices_safe (keys : List Bytes) (insertion : Option Bytes) (domain : TemplateMembers.Domain)
    (order : List TemplateMembers.Choice) (run : TemplateMembers.canonicalMembers keys insertion domain = .ok order) :
    ∀ choice ∈ order, match choice with
      | .source index => ∃ name, keys[index]? = some name
      | .echo => ∃ name, insertion = some name := by
  obtain ⟨labels, selected, sorted, permutation⟩ := TemplateMembers.canonical_selected_names keys insertion domain order run
  clear sorted permutation
  induction order generalizing labels with
  | nil => simp
  | cons choice rest ih =>
    cases choice with
    | source index =>
      cases found : keys[index]? with
      | none => simp [TemplateMembers.selectedNames, found] at selected
      | some name =>
        cases tail : TemplateMembers.selectedNames keys insertion rest with
        | none => simp [TemplateMembers.selectedNames, found, tail] at selected
        | some remaining =>
          intro actual member
          rcases List.mem_cons.mp member with same | later
          · subst actual; exact ⟨name, found⟩
          · exact ih remaining tail actual later
    | echo =>
      cases insertion with
      | none => simp [TemplateMembers.selectedNames] at selected
      | some name =>
        cases tail : TemplateMembers.selectedNames keys (some name) rest with
        | none => simp [TemplateMembers.selectedNames, tail] at selected
        | some remaining =>
          intro actual member
          rcases List.mem_cons.mp member with same | later
          · subst actual; exact ⟨name, rfl⟩
          · exact ih remaining tail actual later

end Auths.Product.TemplateAst
