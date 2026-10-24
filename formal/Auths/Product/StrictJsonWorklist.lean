import Auths.Product.StrictJsonMemberCorrectness

/-!
Structural acceptance of the production raw-child worklist. An object's own
complete member-name scan happens before its descendants are queued. This
models the worklist ordering and uniqueness condition, not serde parsing,
original raw-slice correspondence, numeric/Unicode acceptance, diagnostics,
allocation bounds or a native refinement. Those boundaries remain separate.
-/
namespace Auths.Product.StrictJsonWorklist

open StrictJsonMembers

/-- Every immediate original child, in its original occurrence order. -/
def children : Value → List Value
  | .scalar => []
  | .array values => values
  | .object members => members.map Prod.snd

/-- Each object has a fresh name set; arrays/scalars add no name constraint. -/
def scopeUnique : Value → Prop
  | .scalar => True
  | .array _ => True
  | .object members => (members.map Prod.fst).Nodup

instance (value : Value) : Decidable (scopeUnique value) := by
  cases value <;> simp only [scopeUnique] <;> infer_instance

/-- The front of the list is the next work item. Native reverse-push/pop is
related to this representation by `reverse_push_preserves_order`. -/
def step : List Value → Except Unit (List Value)
  | [] => .ok []
  | value :: rest =>
      if scopeUnique value then .ok (children value ++ rest) else .error ()

/-- A finite successful drain, with every local scope check earned at its own
step. No caller-supplied fuel, recursive-visitor success or arbitrary callback
is part of this relation. -/
inductive Drains : List Value → Prop where
  | empty : Drains []
  | next (value : Value) (rest : List Value) (scope : scopeUnique value)
      (remaining : Drains (children value ++ rest)) : Drains (value :: rest)

theorem push_fold_exact (values pending : List Value) :
    values.foldl (fun stack value => value :: stack) pending = values.reverse ++ pending := by
  induction values generalizing pending with
  | nil => simp
  | cons value rest ih => simp [List.foldl, ih, List.reverse_cons, List.append_assoc]

theorem reverse_push_preserves_order (values pending : List Value) :
    values.reverse.foldl (fun stack value => value :: stack) pending = values ++ pending := by
  simpa using push_fold_exact values.reverse pending

theorem step_acceptance_exact (value : Value) (rest : List Value) :
    step (value :: rest) = .ok (children value ++ rest) ↔ scopeUnique value := by
  by_cases unique : scopeUnique value <;> simp [step, unique]

theorem step_refusal_exact (value : Value) (rest : List Value) :
    step (value :: rest) = .error () ↔ ¬scopeUnique value := by
  by_cases unique : scopeUnique value <;> simp [step, unique]

theorem drains_append (first rest : List Value) (left : Drains first) (right : Drains rest) :
    Drains (first ++ rest) := by
  induction left with
  | empty => exact right
  | next value pending scope remaining ih =>
      apply Drains.next value (pending ++ rest) scope
      simpa [List.append_assoc] using ih

theorem drains_of_singletons (values : List Value)
    (each : ∀ value ∈ values, Drains [value]) : Drains values := by
  induction values with
  | nil => exact .empty
  | cons value rest ih =>
      exact drains_append [value] rest (each value (by simp))
        (ih (fun child belongs => each child (List.mem_cons_of_mem _ belongs)))

theorem unique_drains_singleton (value : Value) (unique : Unique value) : Drains [value] := by
  induction unique with
  | scalar => exact .next .scalar [] trivial .empty
  | array values each ih =>
      apply Drains.next (.array values) [] trivial
      simpa [children] using drains_of_singletons values ih
  | object members keys each ih =>
      apply Drains.next (.object members) [] keys
      have complete : Drains (members.map Prod.snd) := drains_of_singletons _ (by
        intro child belongs
        obtain ⟨member, original, rfl⟩ := List.mem_map.mp belongs
        exact ih member original)
      simpa [children] using complete

theorem drains_unique (pending : List Value) (accepted : Drains pending) :
    ∀ value ∈ pending, Unique value := by
  induction accepted with
  | empty => simp
  | next value rest scope remaining ih =>
      intro original belongs
      rcases List.mem_cons.mp belongs with rfl | later
      · cases value with
        | scalar => exact .scalar
        | array values =>
            exact .array values (fun child member => ih child
              (List.mem_append.mpr (Or.inl member)))
        | object members =>
            exact .object members scope (fun member belongs => ih member.2
              (List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨member, belongs, rfl⟩))))
      · exact ih original (List.mem_append.mpr (Or.inr later))

theorem drains_acceptance_exact (pending : List Value) :
    Drains pending ↔ ∀ value ∈ pending, Unique value := by
  constructor
  · exact drains_unique pending
  · intro each
    exact drains_of_singletons pending (fun value belongs => unique_drains_singleton value (each value belongs))

theorem singleton_acceptance_exact (value : Value) : Drains [value] ↔ Unique value := by
  simpa using drains_acceptance_exact [value]

/-- The new scope-first worklist and the original recursive checker admit the
same complete original tree. This does not equate diagnostic/error priority. -/
theorem original_checker_acceptance_exact (value : Value) :
    Drains [value] ↔ check value = .ok () :=
  (singleton_acceptance_exact value).trans (check_acceptance_exact value).symm

theorem original_checker_refusal_exact (value : Value) :
    check value = .error () ↔ ¬Drains [value] := by
  rw [check_refusal_exact, singleton_acceptance_exact]

end Auths.Product.StrictJsonWorklist
