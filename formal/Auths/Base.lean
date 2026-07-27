namespace Auths

inductive Truth where
  | denied
  | indeterminate
  | authorized
  deriving BEq, DecidableEq, Repr

def Truth.rank : Truth → Nat
  | .denied => 0
  | .indeterminate => 1
  | .authorized => 2

def Truth.le (left right : Truth) : Prop := left.rank ≤ right.rank

theorem Truth.rank_injective : Function.Injective Truth.rank := by
  intro left right equality
  cases left <;> cases right <;> simp_all [Truth.rank]

inductive Outcome where
  | authorized
  | denied (code : Nat)
  | indeterminate (code : Nat)
  | structurallyInvalid (code : Nat)
  deriving BEq, DecidableEq, Repr

def Outcome.truth : Outcome → Truth
  | .authorized => .authorized
  | .denied _ | .structurallyInvalid _ => .denied
  | .indeterminate _ => .indeterminate

def canonicalCode (left right : Nat) : Nat := min left right

theorem canonicalCode_commutative (left right : Nat) :
    canonicalCode left right = canonicalCode right left := by
  simp [canonicalCode, Nat.min_comm]

end Auths
