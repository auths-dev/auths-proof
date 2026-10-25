import Auths.Product.ConnectionGenerations

namespace Auths.Product.LeaseBinding
open ConnectionGenerations

/-- Valid connection/credential pairs retain a credential from this or an
earlier generation. Both generations are positive. -/
def Valid (value : Generations) : Prop :=
  0 < value.generation ∧ 0 < value.credentialGeneration ∧
    value.credentialGeneration ≤ value.generation

instance (value : Generations) : Decidable (Valid value) :=
  inferInstanceAs (Decidable (0 < value.generation ∧ 0 < value.credentialGeneration ∧
    value.credentialGeneration ≤ value.generation))

/-- Reusing a credential across state-only changes does not make a lease from
the old connection generation valid for a newly prepared entry. -/
def Matches (expected leased : Generations) : Prop := Valid expected ∧ leased = expected

instance (expected leased : Generations) : Decidable (Matches expected leased) :=
  inferInstanceAs (Decidable (Valid expected ∧ leased = expected))

theorem matches_iff (expected leased : Generations) :
    Matches expected leased ↔ Valid expected ∧
      leased.generation = expected.generation ∧
      leased.credentialGeneration = expected.credentialGeneration := by
  constructor
  · rintro ⟨valid, same⟩
    exact ⟨valid, congrArg Generations.generation same, congrArg Generations.credentialGeneration same⟩
  · rintro ⟨valid, generation, credential⟩
    refine ⟨valid, ?_⟩
    cases expected
    cases leased
    simp_all

theorem changed_connection_refuses (expected leased : Generations)
    (changed : leased.generation ≠ expected.generation) : ¬ Matches expected leased := by
  rintro ⟨valid, same⟩
  exact changed (congrArg Generations.generation same)

theorem changed_credential_refuses (expected leased : Generations)
    (changed : leased.credentialGeneration ≠ expected.credentialGeneration) : ¬ Matches expected leased := by
  rintro ⟨valid, same⟩
  exact changed (congrArg Generations.credentialGeneration same)

end Auths.Product.LeaseBinding
