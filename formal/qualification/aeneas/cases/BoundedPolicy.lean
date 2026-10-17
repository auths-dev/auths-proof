import Auths.Product.ReservationAdmissionRefinement
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

-- A child that raises its parent's sum limit, drops its sum, or adds a
-- partition under an unpartitioned parent is refused; a child that adds a
-- sum under a parent without one only narrows.
example : kernel.sum_tightens (some { limit := 2000#u64, partition := none })
    (some { limit := 1000#u64, partition := none }) = ok false := by
  rfl

example : kernel.sum_tightens none (some { limit := 1000#u64, partition := none }) =
    ok false := by
  rfl

example : kernel.sum_tightens (some { limit := 500#u64, partition := none })
    (some { limit := 1000#u64, partition := none }) = ok true := by
  rfl

example : kernel.sum_tightens (some { limit := 500#u64, partition := none }) none =
    ok true := by
  rfl

example : kernel.partition_narrows
    (some { argument := ⟨[], by simp⟩, values := ⟨[], by simp⟩ }) none = ok false := by
  rfl

-- A child that drops its parent's scope is refused.
example : kernel.scope_tightens none
    (some { argument := ⟨[], by simp⟩, values := ⟨[], by simp⟩ }) = ok false := by
  rfl

end qualification.aeneas.cases

#check Auths.Product.ReservationAdmission.Refinement.reservation_admission_exact
#check Auths.Product.ReservationAdmission.Refinement.source_admission_earns_bounds
#check Auths.Product.ReservationAdmission.Refinement.source_window_refusal_precedes_sum
#check Auths.Product.ReservationAdmission.Refinement.source_admitted_has_complete_vectors
#check Auths.Product.ReservationAdmission.Refinement.source_admitted_sums_do_not_overflow

namespace qualification.aeneas.cases.ReservationAdmission
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_bounded_policy
open Auths.Product.ReservationAdmission.Refinement
private def oneWord (value : U64) : Slice U64 := ⟨[value], by simp; scalar_tac⟩

-- A nonempty count/slot reservation at the inclusive sum boundary admits.
example : kernel.reservation_admission (oneWord 0#u64) (oneWord 1#u64)
    (oneWord 0#u64) (oneWord 1#u64) (oneWord 400#u64) (oneWord 1000#u64) 600#u64
      ⦃ actual => actual = .Admit ⦄ := by
  step with reservation_admission_exact as ⟨actual, exactMeaning⟩
  change codeView actual = Auths.Product.ReservationAdmission.decideReservation [0] [1] [0] [1] [400] [1000] 600 at exactMeaning
  have model : Auths.Product.ReservationAdmission.decideReservation [0] [1] [0] [1] [400] [1000] 600 = .admit := by decide
  rw [model] at exactMeaning
  cases actual <;> simp_all [codeView]

-- When both count and sum are exhausted, the shipping window code wins.
example : kernel.reservation_admission (oneWord 1#u64) (oneWord 1#u64)
    (oneWord 0#u64) (oneWord 1#u64) (oneWord 1000#u64) (oneWord 1000#u64) 1#u64
      ⦃ actual => actual = .WindowExhausted ⦄ := by
  step with reservation_admission_exact as ⟨actual, exactMeaning⟩
  change codeView actual = Auths.Product.ReservationAdmission.decideReservation [1] [1] [0] [1] [1000] [1000] 1 at exactMeaning
  have model : Auths.Product.ReservationAdmission.decideReservation [1] [1] [0] [1] [1000] [1000] 1 = .windowExhausted := by decide
  rw [model] at exactMeaning
  cases actual <;> simp_all [codeView]
end qualification.aeneas.cases.ReservationAdmission
