import Auths.Product.Commitment

namespace Auths.Product

structure OutputCommitments where
  reservationIntents : Digest
  obligations : Digest
  reservationCount : Nat
  obligationCount : Nat
  reservationBounded : reservationCount ≤ 32
  obligationBounded : obligationCount ≤ 32
  canonicalBytes : Nat
  bytesBounded : canonicalBytes ≤ 65536

inductive Eligibility where
  | eligible (outputs : OutputCommitments)
  | denied (stableCode stage : SemanticId)
  | indeterminate (stableCode stage : SemanticId)

def gateConfiguration
    (required executed : ConfigurationCommitment)
    (onMatch : Eligibility)
    (mismatchCode mismatchStage : SemanticId) : Eligibility :=
  match configurationMatch required executed with
  | .matches => onMatch
  | _ => .denied mismatchCode mismatchStage

def isEligible : Eligibility → Bool
  | .eligible _ => true
  | .denied _ _ | .indeterminate _ _ => false

theorem configuration_mismatch_never_eligible
    {required executed : ConfigurationCommitment}
    {result mismatchCode mismatchStage}
    (mismatch : configurationMatch required executed ≠ .matches) :
    isEligible
      (gateConfiguration required executed result mismatchCode mismatchStage) =
        false := by
  unfold gateConfiguration
  split <;> simp_all [isEligible]

theorem eligible_has_complete_outputs {result : Eligibility}
    (eligible : isEligible result = true) :
    ∃ outputs, result = .eligible outputs := by
  cases result <;> simp_all [isEligible]

theorem three_way_partition (result : Eligibility) :
    (∃ outputs, result = .eligible outputs) ∨
    (∃ code stage, result = .denied code stage) ∨
    (∃ code stage, result = .indeterminate code stage) := by
  cases result with
  | eligible outputs => exact Or.inl ⟨outputs, rfl⟩
  | denied code stage => exact Or.inr (Or.inl ⟨code, stage, rfl⟩)
  | indeterminate code stage =>
      exact Or.inr (Or.inr ⟨code, stage, rfl⟩)

end Auths.Product
