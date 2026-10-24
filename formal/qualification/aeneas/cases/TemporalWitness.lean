import Auths.Verifier.ObservationControl
import Auths.Verifier.SealedProjection
import Auths.Verifier.CompositionFloor
import Auths.Verifier.WorkMeterRefinement
import Auths.Verifier.TemporalExamples

-- Selected expiry, accounting and observation-control source helpers.
-- Complete verification and runtime consumption remain separate.

namespace Auths.Verifier.WorkMeterCases
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsTemporalWitness
open WorkMeterRefinement WorkMeterModel

example : work_meter.WorkMeter.impl.reserve ⟨0#u64, 5#u64⟩ 3#u64
    ⦃ actual => actual.1 = .Ok () ∧ view actual.2 = ⟨3, 5⟩ ⦄ := by
  simpa [reserve, Refines, ResultMatches, view, wordMaximum] using
    method_reserve_exact ⟨0#u64, 5#u64⟩ 3#u64

example : work_meter.WorkMeter.impl.reserve ⟨3#u64, 5#u64⟩ 3#u64
    ⦃ actual => actual.1 = .Err (.Denied .ResourceLimitExceeded) ∧ view actual.2 = ⟨3, 5⟩ ⦄ := by
  simpa [reserve, Refines, ResultMatches, view, wordMaximum] using
    method_reserve_exact ⟨3#u64, 5#u64⟩ 3#u64

example : work_meter.WorkMeter.impl.reserve
    ⟨18446744073709551615#u64, 18446744073709551615#u64⟩ 1#u64
    ⦃ actual => actual.1 = .Err (.Denied .ResourceLimitExceeded) ∧
      view actual.2 = ⟨18446744073709551615, 18446744073709551615⟩ ⦄ := by
  simpa [reserve, Refines, ResultMatches, view, wordMaximum] using
    method_reserve_exact ⟨18446744073709551615#u64, 18446744073709551615#u64⟩ 1#u64
end Auths.Verifier.WorkMeterCases

namespace Auths.Verifier.ObservationControlCases
open Aeneas Aeneas.Std Result
open AuthsTemporalWitness

example (payload : List Nat) : observation.control_result (T := List Nat) (.Ok payload) =
    ok (.Ok (some payload)) := ObservationControl.payload_exact payload

example : observation.control_result (T := List Nat) (.Err .ResourceLimitExceeded) =
    ok (.Err (.Denied .ResourceLimitExceeded)) := ObservationControl.resource_refused (List Nat)

example : observation.control_result (T := List Nat) (.Err .InvalidEvidence) = ok (.Ok none) := by
  apply ObservationControl.ordinary_ignored
  intro impossible
  cases impossible
end Auths.Verifier.ObservationControlCases

namespace Auths.Verifier.CompositionFloorCases
open Aeneas Aeneas.Std Result
open AuthsTemporalWitness

example : authority.check_composition 3#usize 2#usize 1#usize 2#u16 2#u16 1#u16 = ok (.Ok ()) := by
  simpa [CompositionFloor.Allowed] using CompositionFloor.source_exact 3#usize 2#usize 1#usize 2#u16 2#u16 1#u16

example : authority.check_composition 1#usize 2#usize 2#usize 2#u16 1#u16 1#u16 =
    ok (.Err (.Denied .CompositionRequirementNotMet)) := by
  simpa [CompositionFloor.Allowed] using CompositionFloor.source_exact 1#usize 2#usize 2#usize 2#u16 1#u16 1#u16

example : authority.check_composition 3#usize 1#usize 2#usize 2#u16 2#u16 1#u16 =
    ok (.Err (.Denied .CompositionRequirementNotMet)) := by
  simpa [CompositionFloor.Allowed] using CompositionFloor.source_exact 3#usize 1#usize 2#usize 2#u16 2#u16 1#u16

example : authority.check_composition 3#usize 2#usize 1#usize 2#u16 1#u16 2#u16 =
    ok (.Err (.Denied .CompositionRequirementNotMet)) := by
  simpa [CompositionFloor.Allowed] using CompositionFloor.source_exact 3#usize 2#usize 1#usize 2#u16 1#u16 2#u16
end Auths.Verifier.CompositionFloorCases

namespace Auths.Verifier.SealedProjectionCases
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsTemporalWitness

example (source : sealed.VerifiedAuthority) :
    sealed.bind_verified_action source ⦃ output => SealedProjection.Preserves source output ⦄ :=
  SealedProjection.source_exact source
end Auths.Verifier.SealedProjectionCases
