import qualification.aeneas.generated.bounded_policy.Funs

open Aeneas Aeneas.Std Result

namespace qualification.aeneas.cases

open auths_bounded_policy

example :
    kernel.configuration_match_code true true true true =
      ok kernel.ConfigurationMatchCode.Match := by
  rfl

example :
    kernel.configuration_match_code false true true true =
      ok kernel.ConfigurationMatchCode.SemanticMismatch := by
  rfl

example :
    kernel.checked_add_u64 (U64.ofNat U64.rMax) (U64.ofNat 1) =
      ok none := by
  rfl

example :
    kernel.checked_sub_u64 (U64.ofNat 0) (U64.ofNat 1) =
      ok none := by
  rfl

example :
    kernel.checked_div_u64 (U64.ofNat 1) (U64.ofNat 0) =
      ok none := by
  rfl

end qualification.aeneas.cases
