import Auths.Product.RecipeBinding

namespace Auths.Product.RecipePublicInputBounds

def maximumSourceBytes : Nat := 65536
def maximumLockBytes : Nat := 65536

/-- Original encoded lengths before either strict parser. This says nothing
about JSON syntax, duplicate names, typed schema or canonical serialization. -/
def Admitted (sourceBytes lockBytes : Nat) : Prop :=
  0 < sourceBytes ∧ sourceBytes ≤ maximumSourceBytes ∧ 0 < lockBytes ∧ lockBytes ≤ maximumLockBytes

instance (sourceBytes lockBytes : Nat) : Decidable (Admitted sourceBytes lockBytes) := by
  unfold Admitted
  infer_instance

def validate {E : Type} (invalidSource : E) (sourceBytes lockBytes : Nat) : Except E Unit :=
  if Admitted sourceBytes lockBytes then .ok () else .error invalidSource

theorem acceptance_exact {E : Type} (invalidSource : E) (sourceBytes lockBytes : Nat) :
    validate invalidSource sourceBytes lockBytes = .ok () ↔ Admitted sourceBytes lockBytes := by
  simp [validate]

theorem refusal_exact {E : Type} (invalidSource : E) (sourceBytes lockBytes : Nat) :
    validate invalidSource sourceBytes lockBytes = .error invalidSource ↔ ¬Admitted sourceBytes lockBytes := by
  by_cases admitted : Admitted sourceBytes lockBytes <;> simp [validate, admitted]

theorem admitted_earns_original_bounds (sourceBytes lockBytes : Nat) (admitted : Admitted sourceBytes lockBytes) :
    sourceBytes ≠ 0 ∧ sourceBytes ≤ 65536 ∧ lockBytes ≠ 0 ∧ lockBytes ≤ 65536 := by
  simpa [Admitted, maximumSourceBytes, maximumLockBytes, Nat.pos_iff_ne_zero] using admitted

end Auths.Product.RecipePublicInputBounds
