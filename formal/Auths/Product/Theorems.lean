import Auths.Product.Arithmetic
import Auths.Product.Tightening

namespace Auths.Product

theorem product_contract_configuration_safety
    {required executed : ConfigurationCommitment}
    {result mismatchCode mismatchStage}
    (mismatch : configurationMatch required executed ≠ .matches) :
    isEligible
      (gateConfiguration required executed result mismatchCode mismatchStage) =
        false :=
  configuration_mismatch_never_eligible mismatch

theorem product_contract_output_completeness {result : Eligibility}
    (eligible : isEligible result = true) :
    ∃ outputs, result = .eligible outputs :=
  eligible_has_complete_outputs eligible

end Auths.Product
