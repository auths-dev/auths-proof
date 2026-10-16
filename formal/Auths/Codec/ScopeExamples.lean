import Auths.Codec.ScopeConsequences
open Aeneas Aeneas.Std Result
namespace Auths.ScopeConstructor.Examples

def pair : alloc.vec.Vec String := ⟨["anchor:c", "anchor:a"], by scalar_tac⟩
def duplicate : alloc.vec.Vec String := ⟨["anchor:a", "anchor:a"], by scalar_tac⟩
def empty : alloc.vec.Vec String := ⟨[], by scalar_tac⟩

theorem accepts_unsorted :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new pair =
      ok (.Ok ⟨["anchor:a", "anchor:c"], by scalar_tac⟩) := by
  rw [constructor_refines]
  rfl

theorem rejects_duplicate :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new duplicate =
      ok (.Err .InvalidStatusSnapshot) := by
  rw [constructor_refines]
  rfl

theorem rejects_empty :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new empty =
      ok (.Err .InvalidStatusSnapshot) := by
  rw [constructor_refines]
  rfl

theorem rejects_oversized (values : alloc.vec.Vec String)
    (oversized : Model.maximum < values.val.length) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new values =
      ok (.Err .InvalidStatusSnapshot) := by
  rw [constructor_refines]
  simp [expectedConstructor, oversized]

end Auths.ScopeConstructor.Examples
