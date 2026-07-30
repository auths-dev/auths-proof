import Mathlib.Data.Nat.Basic

namespace Auths.Product

def u64Max : Nat := 18446744073709551615

structure UnitQuantity where
  unit : List UInt8
  amount : Nat
  bounded : amount ≤ u64Max

inductive ArithmeticFailure where
  | overflow
  | underflow
  | divisionByZero
  | incompatibleUnit
  | basisPointsOutOfRange
  deriving DecidableEq, Repr

def checkedAdd (left right : UnitQuantity) :
    Except ArithmeticFailure UnitQuantity :=
  if left.unit ≠ right.unit then
    .error .incompatibleUnit
  else if _bounded : left.amount + right.amount ≤ u64Max then
    .ok ⟨left.unit, left.amount + right.amount, _bounded⟩
  else
    .error .overflow

def checkedSub (left right : UnitQuantity) :
    Except ArithmeticFailure UnitQuantity :=
  if left.unit ≠ right.unit then
    .error .incompatibleUnit
  else if _bounded : right.amount ≤ left.amount then
    .ok ⟨left.unit, left.amount - right.amount,
      Nat.le_trans (Nat.sub_le left.amount right.amount) left.bounded⟩
  else
    .error .underflow

def checkedDiv (quantity : UnitQuantity) (divisor : Nat) :
    Except ArithmeticFailure UnitQuantity :=
  if _zero : divisor = 0 then
    .error .divisionByZero
  else
    .ok ⟨quantity.unit, quantity.amount / divisor,
      Nat.le_trans (Nat.div_le_self quantity.amount divisor)
        quantity.bounded⟩

theorem checked_add_never_wraps {left right result}
    (evaluated : checkedAdd left right = .ok result) :
    result.amount = left.amount + right.amount ∧
      result.amount ≤ u64Max := by
  simp only [checkedAdd] at evaluated
  split at evaluated
  · contradiction
  · split at evaluated
    · cases evaluated
      exact ⟨rfl, by assumption⟩
    · contradiction

theorem checked_sub_never_underflows {left right result}
    (evaluated : checkedSub left right = .ok result) :
    right.amount ≤ left.amount := by
  simp only [checkedSub] at evaluated
  split at evaluated
  · contradiction
  · split at evaluated
    · assumption
    · contradiction

theorem checked_div_rejects_zero {quantity result}
    (evaluated : checkedDiv quantity 0 = .ok result) : False := by
  simp [checkedDiv] at evaluated

end Auths.Product
