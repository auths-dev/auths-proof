import Auths.Product.JcsIntegerRounding
import Auths.Product.RecipeCredentialAdmission
import Auths.Product.ScalarProjection

/-!
Existing recipe/scalar admission bounds earn exact mathematical integer to
binary64 conversion. These are source bounds already enforced by Rust, not
new restrictions or a native cast/ryu/decimal-formatting adequacy claim.
-/
namespace Auths.Product.RecipeNumericRounding

theorem unsigned_safe_rounding (value : Nat) (safe : value ≤ 9007199254740991) :
    JcsIntegerRounding.magnitude value = value :=
  JcsIntegerRounding.magnitude_exact_below_precision value (by unfold JcsIntegerRounding.precisionLimit; omega)

theorem signed_absolute_safe_range (value : Int) (safe : value.natAbs ≤ 9007199254740991) :
    -9007199254740991 ≤ value ∧ value ≤ 9007199254740991 := by
  cases value with
  | ofNat magnitude => change magnitude ≤ 9007199254740991 at safe; omega
  | negSucc magnitude => change magnitude + 1 ≤ 9007199254740991 at safe; omega

theorem signed_absolute_safe_rounding (value : Int) (safe : value.natAbs ≤ 9007199254740991) :
    JcsIntegerRounding.integer value = value :=
  JcsIntegerRounding.integer_exact_in_safe_range value (signed_absolute_safe_range value safe)

theorem bounded_unsigned_rounding (value maximum : Nat) (bounded : value ≤ maximum)
    (small : maximum ≤ 9007199254740991) : JcsIntegerRounding.magnitude value = value :=
  unsigned_safe_rounding value (bounded.trans small)

theorem admitted_read_bound_rounding (maximum : Nat) (admitted : RecipeAdmissionAtoms.ReadBound maximum) :
    JcsIntegerRounding.magnitude maximum = maximum :=
  bounded_unsigned_rounding maximum 65536 admitted.2 (by decide)

theorem admitted_refused_status_rounding (status : Nat) (admitted : RecipeAdmissionAtoms.RefusedStatus status) :
    JcsIntegerRounding.magnitude status = status :=
  bounded_unsigned_rounding status 499 admitted.2.1 (by decide)

theorem admitted_refused_statuses_rounding (statuses : List Nat)
    (admitted : RecipeAdmissionAtoms.RefusedStatuses statuses) :
    ∀ status ∈ statuses, JcsIntegerRounding.magnitude status = status :=
  fun status present => admitted_refused_status_rounding status (admitted.2.2.2 status present)

theorem bounded_response_field_rounding (maximum : Nat) (admitted : 1 ≤ maximum ∧ maximum ≤ 255) :
    JcsIntegerRounding.magnitude maximum = maximum :=
  bounded_unsigned_rounding maximum 255 admitted.2 (by decide)

theorem bounded_basis_points_rounding (value : Nat) (admitted : 1 ≤ value ∧ value ≤ 10000) :
    JcsIntegerRounding.magnitude value = value :=
  bounded_unsigned_rounding value 10000 admitted.2 (by decide)

theorem bounded_retention_rounding (seconds : Nat) (admitted : 1 ≤ seconds ∧ seconds ≤ 2592000) :
    JcsIntegerRounding.magnitude seconds = seconds :=
  bounded_unsigned_rounding seconds 2592000 admitted.2 (by decide)

def ProbeNumbersExact : RecipeCredentialAdmission.Literal → Prop
  | .integer value => JcsIntegerRounding.integer value = value
  | .boolean _ | .text _ => True
  | .unsupported => False

theorem admitted_probe_numbers_exact (literal : RecipeCredentialAdmission.Literal)
    (admitted : RecipeCredentialAdmission.ProbeLiteralAdmitted literal) : ProbeNumbersExact literal := by
  cases literal with
  | boolean value | text value => trivial
  | integer value => exact signed_absolute_safe_rounding value admitted
  | unsupported => exact False.elim admitted

theorem admitted_integer_schema_endpoints_rounding (minimum maximum : Int)
    (admitted : ScalarProjection.IntegerSchema minimum maximum) :
    JcsIntegerRounding.integer minimum = minimum ∧ JcsIntegerRounding.integer maximum = maximum := by
  unfold ScalarProjection.IntegerSchema at admitted
  exact ⟨JcsIntegerRounding.integer_exact_in_safe_range minimum ⟨admitted.2.1, by omega⟩,
    JcsIntegerRounding.integer_exact_in_safe_range maximum ⟨by omega, admitted.2.2⟩⟩

theorem admitted_integer_value_rounding (minimum maximum value : Int)
    (admitted : ScalarProjection.IntegerValue minimum maximum value) : JcsIntegerRounding.integer value = value := by
  unfold ScalarProjection.IntegerValue ScalarProjection.IntegerSchema at admitted
  apply JcsIntegerRounding.integer_exact_in_safe_range
  omega

def ScalarNumbersExact : ScalarProjection.Scalar → Prop
  | .integer value => JcsIntegerRounding.integer value = value
  | .text _ | .boolean _ => True
  | .unsupported => False

theorem accepted_scalar_numbers_exact (schema : ScalarProjection.Schema) (value : ScalarProjection.Scalar)
    (admitted : ScalarProjection.Accepts schema value) : ScalarNumbersExact value := by
  cases value with
  | text bytes | boolean value => trivial
  | unsupported => cases schema <;> simp [ScalarProjection.Accepts] at admitted
  | integer value =>
      cases schema with
      | integer minimum maximum => exact admitted_integer_value_rounding minimum maximum value admitted
      | text _ _ | enumeration _ | boolean => simp [ScalarProjection.Accepts] at admitted

end Auths.Product.RecipeNumericRounding
