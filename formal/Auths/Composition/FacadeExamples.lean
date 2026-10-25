import Auths.Composition.Facade
import Auths.Composition.ValidationExamples
open Aeneas Aeneas.Std Result
open auths_composition Auths.Composition.PlanExamples Auths.Composition.ValidationExamples
set_option cbv.warning false
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000
namespace Auths.Composition.FacadeExamples

theorem conjunction_authorizes : auths_composition.evaluate branch twoLeaves limits 0 =
    ok (.Ok .Authorized, 2) := by
  rw [Auths.Composition.Facade.evaluate_refines branch (fun count _ => (.Authorized, count + 1))
    (by intro count reference; rfl) twoLeaves limits limits_bounded]
  cbv

theorem duplicate_refused : auths_composition.evaluate branch duplicate limits 5 =
    ok (.Err .AuthorizationPlanInvalid, 5) :=
  Auths.Composition.Facade.invalid_plan_preserves_callback branch duplicate limits limits_bounded duplicate_invalid 5

theorem threshold_indeterminate : auths_composition.evaluate mixedBranch
    (.mk (.KOfN 2#u16 threeMembers)) limits 0 =
    ok (.Ok (.Indeterminate .ExternalFactUnavailable), 3) := by
  rw [Auths.Composition.Facade.evaluate_refines mixedBranch (fun count _ => (mixedOutcome count, count + 1))
    (by intro count reference; rfl) (.mk (.KOfN 2#u16 threeMembers)) limits limits_bounded]
  cbv
end Auths.Composition.FacadeExamples
