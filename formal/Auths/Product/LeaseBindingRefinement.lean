import qualification.aeneas.generated.connections.Funs
import Auths.Product.LeaseBinding

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_connections

namespace Auths.Product.LeaseBinding.Refinement

def view (value : kernel.Generations) : ConnectionGenerations.Generations :=
  ⟨value.generation.val, value.credential_generation.val⟩

@[step] theorem generations_exact (expected leased : kernel.Generations) :
    kernel.same_lease_generations expected leased ⦃ actual =>
      actual = decide (Matches (view expected) (view leased)) ⦄ := by
  cases expected
  cases leased
  simp [kernel.same_lease_generations, view, matches_iff, Valid,
    UScalar.lt_equiv, UScalar.le_equiv, UScalar.eq_equiv, spec_ok,
    Bool.and_eq_true, decide_and]

@[step] theorem success_earns_exact_generations (expected leased : kernel.Generations) :
    kernel.same_lease_generations expected leased ⦃ actual =>
      actual = true → Valid (view expected) ∧
        leased.generation = expected.generation ∧
        leased.credential_generation = expected.credential_generation ⦄ := by
  apply spec_mono (generations_exact expected leased)
  intro actual meaning accepted
  have matched : Matches (view expected) (view leased) := by
    apply of_decide_eq_true
    rw [← meaning]
    exact accepted
  have dimensions := (matches_iff _ _).mp matched
  exact ⟨dimensions.1,
    UScalar.eq_of_val_eq dimensions.2.1,
    UScalar.eq_of_val_eq dimensions.2.2⟩

theorem valid_pair_accepts (expected : kernel.Generations) (valid : Valid (view expected)) :
    kernel.same_lease_generations expected expected = ok true := by
  obtain ⟨actual, run, meaning⟩ := spec_imp_exists (generations_exact expected expected)
  have matched : Matches (view expected) (view expected) := ⟨valid, rfl⟩
  simpa only [meaning, decide_true, matched] using run

theorem different_pair_refuses (expected leased : kernel.Generations)
    (different : leased.generation ≠ expected.generation ∨
      leased.credential_generation ≠ expected.credential_generation) :
    kernel.same_lease_generations expected leased = ok false := by
  obtain ⟨actual, run, meaning⟩ := spec_imp_exists (generations_exact expected leased)
  have refused : ¬ Matches (view expected) (view leased) := by
    intro matched
    have dimensions := (matches_iff _ _).mp matched
    rcases different with generation | credential
    · exact generation (UScalar.eq_of_val_eq dimensions.2.1)
    · exact credential (UScalar.eq_of_val_eq dimensions.2.2)
  simpa only [meaning, refused, decide_false] using run

end Auths.Product.LeaseBinding.Refinement
