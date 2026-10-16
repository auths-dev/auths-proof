import Aeneas
open Aeneas Aeneas.Std Result
namespace Auths.Support.UnitCallback

/-- Restores the unit output erased by the backend at a concrete callback ABI. -/
def restore {S : Type} (operation : Result S) : Result (Unit × S) := do
  let state ← operation
  ok ((), state)

def erase {S : Type} (operation : Result (Unit × S)) : Result S := do
  let (_, state) ← operation
  ok state

theorem erase_restore {S : Type} (operation : Result S) : erase (restore operation) = operation := by
  cases operation <;> rfl

theorem restore_erase {S : Type} (operation : Result (Unit × S)) : restore (erase operation) = operation := by
  cases operation with
  | fail reason => rfl
  | div => rfl
  | ok value => cases value with | mk empty state => cases empty; rfl
end Auths.Support.UnitCallback
