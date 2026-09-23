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


-- The ceiling is checked before the window count.
example : kernel.ceiling_count_code 11#u64 10#u64 5#u64 1#u64 =
    ok kernel.CeilingCountCode.AboveCeiling := by
  rfl

example : kernel.ceiling_count_code 10#u64 10#u64 1#u64 1#u64 =
    ok kernel.CeilingCountCode.WindowExhausted := by
  rfl

example : kernel.ceiling_count_code 10#u64 10#u64 0#u64 1#u64 =
    ok kernel.CeilingCountCode.Eligible := by
  rfl

-- The decider refuses a different window and a larger ceiling or count.
example : kernel.ceiling_count_tightens 5#u64 1#u64 60#u64 10#u64 2#u64 60#u64 = ok true := by
  rfl

example : kernel.ceiling_count_tightens 5#u64 1#u64 60#u64 10#u64 2#u64 120#u64 = ok false := by
  rfl

example : kernel.ceiling_count_tightens 11#u64 1#u64 60#u64 10#u64 2#u64 60#u64 = ok false := by
  rfl

example : kernel.ceiling_count_tightens 5#u64 3#u64 60#u64 10#u64 2#u64 60#u64 = ok false := by
  rfl

end qualification.aeneas.cases
