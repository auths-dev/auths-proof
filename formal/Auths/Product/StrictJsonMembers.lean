import Mathlib.Data.Finset.Basic
import Mathlib.Data.List.Defs
import Lean.Elab.Tactic.Omega

/-!
Independent structural meaning of the strict JSON duplicate-member pass.
Names are complete decoded Strings. Scalar payloads are intentionally erased:
the shipping visitor ignores their values, but visits every array/object child.
This is not a typed recipe decoder, byte parser or canonical serializer model.
-/
namespace Auths.Product.StrictJsonMembers

inductive Value where
  | scalar
  | array (children : List Value)
  | object (members : List (String × Value))
  deriving DecidableEq

inductive Unique : Value → Prop where
  | scalar : Unique .scalar
  | array (children : List Value) (each : ∀ child ∈ children, Unique child) : Unique (.array children)
  | object (members : List (String × Value)) (keys : (members.map Prod.fst).Nodup)
      (each : ∀ member ∈ members, Unique member.2) : Unique (.object members)

mutual
  def check : Value → Except Unit Unit
    | .scalar => .ok ()
    | .array children => checkValues children
    | .object members => checkMembers ∅ members
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def checkValues : List Value → Except Unit Unit
    | [] => .ok ()
    | child :: rest => do
        check child
        checkValues rest
  termination_by children => sizeOf children
  decreasing_by all_goals simp_wf <;> omega

  def checkMembers (seen : Finset String) : List (String × Value) → Except Unit Unit
    | [] => .ok ()
    | (name, child) :: rest =>
        if name ∈ seen then .error () else do
          check child
          checkMembers (insert name seen) rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

def memberContinuation (fresh : Bool) (seen : Finset String) (child : Value) (rest : List (String × Value)) : Except Unit Unit :=
  if fresh then do
    check child
    checkMembers seen rest
  else .error ()

/-- The native insertion result feeds the unchanged closed child/rest
semantics. No child-success flag or user-supplied visitor is accepted. -/
theorem original_member_step_exact (seen : Finset String) (name : String) (child : Value) (rest : List (String × Value)) :
    memberContinuation (decide (name ∉ seen)) (insert name seen) child rest =
      checkMembers seen ((name, child) :: rest) := by
  by_cases repeated : name ∈ seen <;> simp [memberContinuation, checkMembers, repeated]

/-- The original remaining object has unique decoded names, every name is
fresh against its actual earlier prefix, and each value has its own complete
recursive uniqueness. Nested object name sets never inherit parent names. -/
def RemainingUnique (seen : Finset String) (members : List (String × Value)) : Prop :=
  (members.map Prod.fst).Nodup ∧ (∀ member ∈ members, member.1 ∉ seen) ∧
    ∀ member ∈ members, Unique member.2

theorem remaining_unique_cons (seen : Finset String) (name : String) (child : Value) (rest : List (String × Value)) :
    RemainingUnique seen ((name, child) :: rest) ↔
      name ∉ seen ∧ Unique child ∧ RemainingUnique (insert name seen) rest := by
  constructor
  · rintro ⟨distinct, fresh, children⟩
    obtain ⟨headAbsent, restDistinct⟩ := List.nodup_cons.mp distinct
    refine ⟨fresh _ (by simp), children _ (by simp), restDistinct, ?_, ?_⟩
    · intro member belongs used
      rcases Finset.mem_insert.mp used with same | earlier
      · exact headAbsent (List.mem_map.mpr ⟨member, belongs, same⟩)
      · exact fresh member (List.mem_cons_of_mem _ belongs) earlier
    · intro member belongs
      exact children member (List.mem_cons_of_mem _ belongs)
  · rintro ⟨fresh, childUnique, restDistinct, restFresh, restUnique⟩
    refine ⟨List.nodup_cons.mpr ⟨?_, restDistinct⟩, ?_, ?_⟩
    · intro used
      obtain ⟨member, belongs, same⟩ := List.mem_map.mp used
      exact restFresh member belongs (Finset.mem_insert.mpr (Or.inl same))
    · intro member belongs
      rcases List.mem_cons.mp belongs with rfl | later
      · exact fresh
      · exact fun used => restFresh member later (Finset.mem_insert.mpr (Or.inr used))
    · intro member belongs
      rcases List.mem_cons.mp belongs with rfl | later
      · exact childUnique
      · exact restUnique member later

end Auths.Product.StrictJsonMembers
