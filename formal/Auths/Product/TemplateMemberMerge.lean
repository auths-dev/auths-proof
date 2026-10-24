import Auths.Product.TemplateMemberSelection

namespace Auths.Product.TemplateMembers

/-- Pending output is counted separately from the loop's emitted prefix. -/
def pendingEcho (echo : Option Bytes) (inserted : Bool) : Nat :=
  if echo.isSome && !inserted then 1 else 0

def finalEcho (echo : Option Bytes) (inserted : Bool) : List Choice :=
  if echo.isSome && !inserted then [.echo] else []

/-- An accumulator invariant for the source merge loop. Collision admission
is supplied by its real preflight; `membersFrom` remains the result oracle. -/
def mergeState : List Bytes → Option Bytes → Nat → Bool → List Choice × Bool
  | [], _, _, inserted => ([], inserted)
  | key :: rest, echo, index, inserted =>
      let before := match echo with
        | none => false
        | some name => !inserted && byteLess name key
      let next := mergeState rest echo (index + 1) (inserted || before)
      ((if before then [.echo, .source index] else [.source index]) ++ next.1, next.2)

theorem merge_state_length (keys : List Bytes) (echo : Option Bytes) (index : Nat)
    (inserted : Bool) :
    (mergeState keys echo index inserted).1.length +
      pendingEcho echo (mergeState keys echo index inserted).2 = keys.length + pendingEcho echo inserted := by
  induction keys generalizing echo index inserted with
  | nil => simp [mergeState]
  | cons key rest ih =>
      cases echo with
      | none => simpa [mergeState, pendingEcho, Nat.add_assoc] using ih none (index + 1) inserted
      | some name =>
          cases inserted with
          | true => simpa [mergeState, pendingEcho, Nat.add_assoc] using ih (some name) (index + 1) true
          | false =>
              cases before : byteLess name key <;>
                simp only [mergeState, Bool.not_false, Bool.true_and, before, Bool.false_or,
                  Bool.or_false, Bool.or_true, Bool.false_eq_true, ↓reduceIte,
                  List.length_append, List.length_cons, List.length_nil]
              · simpa [pendingEcho, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
                  ih (some name) (index + 1) false
              · simpa [pendingEcho, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
                  ih (some name) (index + 1) true

theorem merge_state_full_meaning (keys : List Bytes) (echo : Option Bytes) (index : Nat)
    (inserted : Bool) (fresh : ∀ name, echo = some name → name ∉ keys) :
    membersFrom keys echo index inserted = .ok
      ((mergeState keys echo index inserted).1 ++ finalEcho echo (mergeState keys echo index inserted).2) := by
  induction keys generalizing index inserted with
  | nil => rfl
  | cons key rest ih =>
      have restFresh : ∀ name, echo = some name → name ∉ rest := by
        intro name same present
        exact fresh name same (by simp [present])
      cases echo with
      | none =>
          simpa [membersFrom, mergeState, Except.map, List.append_assoc] using
            congrArg (Except.map (Choice.source index :: ·)) (ih (index + 1) inserted restFresh)
      | some name =>
          have different : key ≠ name := by
            intro same
            exact fresh name rfl (by simp [same])
          cases inserted with
          | true => simp [membersFrom, mergeState, different, ih (index + 1) true restFresh,
              Except.map, List.append_assoc]
          | false =>
              cases before : byteLess name key <;>
                simp [membersFrom, mergeState, different, before,
                  ih (index + 1) false restFresh, ih (index + 1) true restFresh,
                  Except.map, List.append_assoc]

/-- Collision is the only refusal of the private merge, irrespective of key
grammar or ordering. The public canonical selector checks those separately. -/
theorem merge_preflight_outcome (keys : List Bytes) (echo : Option Bytes) :
    membersFrom keys echo 0 false =
      if ∃ name, echo = some name ∧ name ∈ keys then .error .echoConflict
      else .ok ((mergeState keys echo 0 false).1 ++ finalEcho echo (mergeState keys echo 0 false).2) := by
  by_cases collision : ∃ name, echo = some name ∧ name ∈ keys
  · obtain ⟨name, same, present⟩ := collision
    subst echo
    simp only [show (∃ other, some name = some other ∧ other ∈ keys) by exact ⟨name, rfl, present⟩,
      ↓reduceIte]
    exact members_from_collision_refuses keys name 0 false present
  · simp only [collision, ↓reduceIte]
    apply merge_state_full_meaning
    intro name same present
    exact collision ⟨name, same, present⟩

end Auths.Product.TemplateMembers
