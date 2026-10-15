import Std.Tactic

namespace Auths.Product.EntryDeadline

structure Bound where
  deadline : Nat
  inclusive : Bool
  deriving DecidableEq

def permits (bound : Bound) (now : Nat) : Prop :=
  now < bound.deadline ∨ (now = bound.deadline ∧ bound.inclusive = true)

instance (bound : Bound) (now : Nat) : Decidable (permits bound now) := by
  unfold permits
  infer_instance

def meet (left right : Bound) : Bound :=
  if left.deadline < right.deadline then left
  else if right.deadline < left.deadline then right
  else ⟨left.deadline, left.inclusive && right.inclusive⟩

theorem permits_meet (left right : Bound) (now : Nat) :
    permits (meet left right) now ↔ permits left now ∧ permits right now := by
  unfold meet
  split <;> rename_i first
  · simp only [permits]
    constructor
    · intro h
      exact ⟨h, Or.inl (by rcases h with h | ⟨h, _⟩ <;> omega)⟩
    · exact And.left
  · split <;> rename_i second
    · simp only [permits]
      constructor
      · intro h
        exact ⟨Or.inl (by rcases h with h | ⟨h, _⟩ <;> omega), h⟩
      · exact And.right
    · have equal : left.deadline = right.deadline := by omega
      simp only [permits, equal, Bool.and_eq_true]
      constructor
      · rintro (h | ⟨h, hl, hr⟩)
        · exact ⟨Or.inl h, Or.inl h⟩
        · exact ⟨Or.inr ⟨h, hl⟩, Or.inr ⟨h, hr⟩⟩
      · rintro ⟨hl, hr⟩
        rcases hl with h | ⟨h, hl⟩
        · exact Or.inl h
        · rcases hr with hr | ⟨_, hr⟩
          · exact Or.inl hr
          · exact Or.inr ⟨h, hl, hr⟩

def admits (evaluatedAt : Nat) (bound : Bound) (now : Nat) : Prop :=
  evaluatedAt ≤ now ∧ permits bound now

instance (evaluatedAt : Nat) (bound : Bound) (now : Nat) :
    Decidable (admits evaluatedAt bound now) := by
  unfold admits
  infer_instance

theorem no_clock_rollback (evaluatedAt : Nat) (bound : Bound) (now : Nat)
    (accepted : admits evaluatedAt bound now) : evaluatedAt ≤ now := accepted.1

theorem every_deadline_holds (evaluatedAt : Nat) (left right : Bound) (now : Nat) :
    admits evaluatedAt (meet left right) now ↔
      admits evaluatedAt left now ∧ admits evaluatedAt right now := by
  simp only [admits, permits_meet]
  constructor
  · rintro ⟨h, hl, hr⟩; exact ⟨⟨h, hl⟩, ⟨h, hr⟩⟩
  · rintro ⟨⟨h, hl⟩, ⟨_, hr⟩⟩; exact ⟨h, hl, hr⟩

end Auths.Product.EntryDeadline

namespace Auths.Product.EntryDeadline

theorem permits_fold (bounds : List Bound) (initial : Bound) (now : Nat) :
    permits (bounds.foldl meet initial) now ↔
      permits initial now ∧ ∀ bound ∈ bounds, permits bound now := by
  induction bounds generalizing initial with
  | nil => simp
  | cons bound rest ih =>
    simp only [List.foldl_cons, ih, permits_meet, List.mem_cons]
    constructor
    · rintro ⟨⟨hi, hb⟩, hr⟩
      exact ⟨hi, fun candidate member => by
        rcases member with rfl | member
        · exact hb
        · exact hr candidate member⟩
    · rintro ⟨hi, hall⟩
      exact ⟨⟨hi, hall bound (Or.inl rfl)⟩,
        fun candidate member => hall candidate (Or.inr member)⟩

theorem exclusive_endpoint_refuses (evaluatedAt endpoint : Nat) :
    ¬ admits evaluatedAt ⟨endpoint, false⟩ endpoint := by
  simp [admits, permits]

theorem inclusive_endpoint_admits (evaluatedAt endpoint : Nat)
    (ordered : evaluatedAt ≤ endpoint) :
    admits evaluatedAt ⟨endpoint, true⟩ endpoint := by
  simp [admits, permits, ordered]

end Auths.Product.EntryDeadline
