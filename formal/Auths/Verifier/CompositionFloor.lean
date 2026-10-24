import qualification.aeneas.generated.temporal_witness.Funs

open Aeneas Aeneas.Std Result
open AuthsTemporalWitness

namespace Auths.Verifier.CompositionFloor

/-- Composition counts refer to successful branch results and distinct
principal identifiers in the actor/root roles. Their source derivation remains
a separate obligation; no claim of distinct humans or keys follows. -/
def Allowed (branches actors roots minimumBranches minimumActors minimumRoots : Nat) : Prop :=
  minimumBranches ≤ branches ∧ minimumActors ≤ actors ∧ minimumRoots ≤ roots

theorem source_exact (branches actors roots : Std.Usize)
    (minimumBranches minimumActors minimumRoots : Std.U16) :
    authority.check_composition branches actors roots minimumBranches minimumActors minimumRoots =
      ok (if Allowed branches.val actors.val roots.val minimumBranches.val minimumActors.val minimumRoots.val
        then .Ok () else .Err (.Denied .CompositionRequirementNotMet)) := by
  simp only [authority.check_composition, lift, bind_tc_ok,
    core.convert.num.FromUsizeU16.from_val_eq, UScalar.lt_equiv]
  by_cases branchesFit : minimumBranches.val ≤ branches.val <;>
    by_cases actorsFit : minimumActors.val ≤ actors.val <;>
    by_cases rootsFit : minimumRoots.val ≤ roots.val <;>
    simp_all [Allowed, Nat.not_lt, Nat.lt_of_not_ge]

end Auths.Verifier.CompositionFloor
