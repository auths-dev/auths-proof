import Auths.Verifier.WorkMeterModel
import qualification.aeneas.generated.temporal_witness.Funs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsTemporalWitness

namespace Auths.Verifier.WorkMeterRefinement
open WorkMeterModel

set_option maxHeartbeats 2000000

def view (meter : work_meter.WorkMeter) : State := ⟨meter.used.val, meter.limit.val⟩

def ResultMatches (accepted : Bool) (actual : core.result.Result Unit VerificationFailure) : Prop :=
  if accepted then actual = .Ok () else actual = .Err (.Denied .ResourceLimitExceeded)

def Refines (expected : Reservation)
    (actual : core.result.Result Unit VerificationFailure × work_meter.WorkMeter) : Prop :=
  ResultMatches expected.accepted actual.1 ∧ view actual.2 = expected.state

private theorem checked_sum (left right : Std.U64) :
    match U64.checked_add left right with
    | none => wordMaximum < left.val + right.val
    | some output => left.val + right.val ≤ wordMaximum ∧ output.val = left.val + right.val := by
  have specification := U64.checked_add_bv_spec left right
  cases equation : U64.checked_add left right <;>
    simp_all [wordMaximum, U64.max_eq]

@[step] theorem new_exact (limit : Std.U64) :
    work_meter.new limit ⦃ actual => view actual = ⟨0, limit.val⟩ ⦄ := by
  simp [work_meter.new, view]

@[step] theorem from_used_exact (limit used : Std.U64) :
    work_meter.from_used limit used ⦃ actual => view actual = ⟨used.val, limit.val⟩ ⦄ := by
  simp [work_meter.from_used, view]

/-- All represented states and charges, including overflow and an already
over-limit state. Refusal is the exact resource-limit code with identical state.
No premise assumes the expected source outcome or a successful reservation. -/
@[step] theorem reserve_exact (meter : work_meter.WorkMeter) (maximum : Std.U64) :
    work_meter.reserve meter maximum ⦃ actual => Refines (reserve (view meter) maximum.val) actual ⦄ := by
  have arithmetic := checked_sum meter.used maximum
  unfold work_meter.reserve
  cases addition : U64.checked_add meter.used maximum with
  | none =>
    have overflow : wordMaximum < meter.used.val + maximum.val := by simpa [addition] using arithmetic
    have notFit : ¬ meter.used.val + maximum.val ≤ wordMaximum := by omega
    simp [addition, core.option.Option.ok_or, reserve, view, notFit, Refines, ResultMatches]
  | some next =>
    obtain ⟨wordFits, nextValue⟩ : meter.used.val + maximum.val ≤ wordMaximum ∧
        next.val = meter.used.val + maximum.val := by simpa [addition] using arithmetic
    by_cases allowed : meter.used.val + maximum.val ≤ meter.limit.val
    · have guard : ¬ next > meter.limit := by scalar_tac
      simp [addition, core.option.Option.ok_or, guard, reserve, view, wordFits, allowed,
        nextValue, Refines, ResultMatches]
    · have guard : next > meter.limit := by scalar_tac
      simp [addition, core.option.Option.ok_or, guard, reserve, view, wordFits, allowed,
        nextValue, Refines, ResultMatches]

/-- The actual production method delegates to the same proved free leaf. -/
@[step] theorem method_reserve_exact (meter : work_meter.WorkMeter) (maximum : Std.U64) :
    work_meter.WorkMeter.impl.reserve meter maximum
      ⦃ actual => Refines (reserve (view meter) maximum.val) actual ⦄ := by
  simpa only [work_meter.WorkMeter.impl.reserve] using reserve_exact meter maximum

end Auths.Verifier.WorkMeterRefinement
