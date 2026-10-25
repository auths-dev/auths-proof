import Auths.Composition.Refinement
import Auths.Codec.Evaluation
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
open auths_composition
set_option cbv.warning false
set_option maxRecDepth 4096
namespace Auths.Composition.Examples

-- A kernel-proved equality avoids evaluating the opaque platform word width.
attribute [local cbv_eval] Auths.Composition.Refinement.threshold_exact

-- These execute the shipping summary operations over explicit child outcomes.
-- Plan validation, recursive traversal and callback/event correspondence are
-- separate obligations; these examples do not assert a complete verifier.
def decideChildren (all : Bool) (required : Std.U16) (children : List BranchOutcome) :
    Result BranchOutcome := do
  let state ← Auths.Composition.Refinement.sourceFold
    ⟨0#usize, 0#usize, none, none⟩ children
  if all then summary.all state else summary.threshold state required

theorem all_positive : decideChildren true 2#u16 [.Authorized, .Authorized] = ok .Authorized := by
  cbv

theorem all_denial_before_missing : decideChildren true 2#u16
    [.Indeterminate .StaleStatus, .Denied .InvalidSignature] = ok (.Denied .InvalidSignature) := by
  cbv

theorem all_smallest_code : decideChildren true 3#u16
    [.Denied .InvalidSignature, .StructurallyInvalid .ActionBodyMismatch, .Denied .MissingReference] =
      ok (.Denied .ActionBodyMismatch) := by
  cbv

theorem any_positive_overrides_invalid : decideChildren false 1#u16
    [.StructurallyInvalid .MissingReference, .Authorized] = ok .Authorized := by
  cbv

theorem any_missing_before_denial : decideChildren false 1#u16
    [.Denied .InvalidSignature, .Indeterminate .StaleStatus] = ok (.Indeterminate .StaleStatus) := by
  cbv

theorem any_smallest_requirement : decideChildren false 1#u16
    [.Indeterminate .StaleStatus, .Indeterminate .ApprovalUnavailable] =
      ok (.Indeterminate .ApprovalUnavailable) := by
  cbv

theorem threshold_lower_bound : decideChildren false 1#u16
    [.Authorized, .Indeterminate .StaleStatus, .Denied .InvalidSignature] = ok .Authorized := by
  cbv

theorem threshold_reachable : decideChildren false 2#u16
    [.Authorized, .Indeterminate .StaleStatus, .Denied .InvalidSignature] =
      ok (.Indeterminate .StaleStatus) := by
  cbv

theorem threshold_impossible : decideChildren false 3#u16
    [.Authorized, .Indeterminate .StaleStatus, .Denied .InvalidSignature] =
      ok (.Denied .InvalidSignature) := by
  cbv

end Auths.Composition.Examples
