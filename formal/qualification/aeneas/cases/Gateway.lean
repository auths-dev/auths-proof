import qualification.aeneas.generated.gateway.Funs
import Auths.Product.Refinement.Gateway

open Aeneas Aeneas.Std Result

namespace qualification.aeneas.cases

open auths_gateway_kernel

-- A verified-locator observation with an echo is linked and resolves
-- `unknown`; no declaration makes the write conditional.
example :
    recovery.recovery_capability
        { observation := recovery.StateObservation.VerifiedLocator, echo := true,
          idempotency := recovery.LostClaimReentry.None, pre_entry := false } =
      ok { «class» := recovery.RecoveryClass.Linked,
           state_observation := recovery.StateObservation.VerifiedLocator,
           provider_link := recovery.StateObservation.VerifiedLocator,
           unknown_resolution := recovery.UnknownResolution.GatewayReobservation,
           lost_claim_reentry := recovery.LostClaimReentry.None,
           pre_entry_reread := false, write_is_conditional := false } := by
  rfl

-- An observation without an echo is observed and never resolves `unknown`.
example :
    recovery.recovery_capability
        { observation := recovery.StateObservation.ResponseLocator, echo := false,
          idempotency := recovery.LostClaimReentry.None, pre_entry := true } =
      ok { «class» := recovery.RecoveryClass.Observed,
           state_observation := recovery.StateObservation.ResponseLocator,
           provider_link := recovery.StateObservation.None,
           unknown_resolution := recovery.UnknownResolution.None,
           lost_claim_reentry := recovery.LostClaimReentry.None,
           pre_entry_reread := true, write_is_conditional := false } := by
  rfl

-- Path and form encoding: `/` and a space never pass through unencoded.
example : construct.is_path_literal 47#u8 = ok false := by rfl
example : construct.is_path_literal 126#u8 = ok true := by rfl
example : construct.is_form_literal 32#u8 = ok false := by rfl
example : construct.hex_upper 15#u8 = ok 70#u8 := by rfl

-- The relative ceiling rounds toward zero with an inclusive boundary, and a
-- negative difference is an unavailable basis, never zero.
example : ratio.relative_ceiling_admits 500#u64 1001#u64 5000#u16 = ok true := by
  with_unfolding_all rfl
example : ratio.relative_ceiling_admits 501#u64 1001#u64 5000#u16 = ok false := by
  with_unfolding_all rfl
example : ratio.relative_basis 1001#u64 (some 1#u64) = ok (some 1000#u64) := by rfl
example : ratio.relative_basis 1001#u64 (some 1002#u64) = ok none := by rfl

-- Only a verified-locator link lets `unknown` reach `observed-by-provider`,
-- and a terminal stage has no outgoing transition.
example :
    transition.stage_transition_allowed transition.Stage.Unknown
        transition.Stage.ObservedByProvider transition.Link.Verified = ok true := by
  rfl
example :
    transition.stage_transition_allowed transition.Stage.Unknown
        transition.Stage.ObservedByProvider transition.Link.AfterResponse = ok false := by
  rfl
example :
    transition.stage_transition_allowed transition.Stage.Observed
        transition.Stage.ObservedByProvider transition.Link.Verified = ok false := by
  rfl

-- The machine reads the clock first, a refused verification stores nothing,
-- and an event the phase does not expect halts.
def plan : order.SubmitPlan :=
  { account_scope := false, account_read := true, denied_reads := 2#u8, pre_entry := false,
    relative_ceiling := true, basis_points := 5000#u16 }

example :
    order.next_step { plan, phase := order.Phase.Start, argument := 0#u64 }
        order.SubmitEvent.Start =
      ok { state := { plan, phase := order.Phase.Clock, argument := 0#u64 },
           action := order.SubmitAction.ReadClock } := by
  rfl
example :
    order.next_step { plan, phase := order.Phase.Verify, argument := 0#u64 }
        (order.SubmitEvent.Verification order.Verification.Refused) =
      ok { state := { plan, phase := order.Phase.Done, argument := 0#u64 },
           action := order.SubmitAction.Stop order.Stop.Refused } := by
  rfl
example :
    order.next_step { plan, phase := order.Phase.Ceiling, argument := 501#u64 }
        (order.SubmitEvent.Ceiling (order.CeilingRead.Read 1001#u64 true)) =
      ok { state := { plan, phase := order.Phase.RecordNotEntered, argument := 501#u64 },
           action := order.SubmitAction.RecordNotEntered order.Refusal.CeilingAbove } := by
  with_unfolding_all rfl
example :
    order.next_step { plan, phase := order.Phase.Start, argument := 0#u64 }
        (order.SubmitEvent.Write order.WriteResult.Response) =
      ok { state := { plan, phase := order.Phase.Done, argument := 0#u64 },
           action := order.SubmitAction.Stop order.Stop.Halted } := by
  rfl

-- AP074: the deadline names durable grant creation; only its successful
-- result names the send. Failure stops and replay returns stored state.
example :
    order.next_step { plan, phase := .Deadline, argument := 1#u64 } (.Deadline true) =
      ok { state := { plan, phase := .Grant, argument := 1#u64 }, action := .GrantEntry } := by
  rfl
example :
    order.next_step { plan, phase := .Grant, argument := 1#u64 } (.Granted true) =
      ok { state := { plan, phase := .Send, argument := 1#u64 }, action := .Send } := by
  rfl
example :
    order.next_step { plan, phase := .Grant, argument := 1#u64 } (.Granted false) =
      ok { state := { plan, phase := .Done, argument := 1#u64 },
           action := .Stop .GrantUnavailable } := by
  rfl
example :
    order.next_step { plan, phase := .Claim, argument := 1#u64 } (.Claim .Replay) =
      ok { state := { plan, phase := .Done, argument := 1#u64 }, action := .Stop .Stored } := by
  rfl
example :
    order.next_step { plan, phase := .RecordResponse, argument := 1#u64 } (.Response .Recorded) =
      ok { state := { plan, phase := .Done, argument := 1#u64 }, action := .Stop .Response } := by
  rfl

-- Late source response and recipient ACK are allowed evidence routes, but
-- an unknown cannot gain a second grant or become refundable not-entered.
example : transition.stage_transition_allowed .Unknown .ResponseRecorded .None = ok true := by
  rfl
example : transition.stage_transition_allowed .Unknown .Acknowledged .None = ok true := by
  rfl
example : transition.stage_transition_allowed .Unknown .EntryGranted .Verified = ok false := by
  rfl
example : transition.stage_transition_allowed .Unknown .NotEntered .Verified = ok false := by
  rfl
example : transition.stage_transition_allowed .Acknowledged .Unknown .None = ok false := by
  rfl

-- Full projected records demonstrate inhabited evidence routes and reject
-- changed source grants, protocol substitution, and non-successor revisions.
private def byteVec (byte : Std.U8) : alloc.vec.Vec Std.U8 :=
  ⟨[byte], by simp; scalar_tac⟩

private def unknownView (protocol : transition.Protocol) : transition.AttemptView :=
  { protocol, revision := 2#u64, fixed := byteVec 1#u8, entry := byteVec 2#u8,
    stage := .Unknown, refusal := false, pre_entry := ⟨[], by simp⟩,
    response := ⟨[], by simp⟩, acknowledgement := ⟨[], by simp⟩,
    locator := ⟨[], by simp⟩, reading := .None, evidence := false,
    observation := false, link := .None }

private def lateResponse : transition.AttemptView :=
  { unknownView .Mutation with revision := 3#u64, stage := .ResponseRecorded, response := byteVec 3#u8 }

private def lateAcknowledgement : transition.AttemptView :=
  { unknownView .Disclosure with revision := 3#u64, stage := .Acknowledged, acknowledgement := byteVec 4#u8 }

private theorem projected_transition (old new : transition.AttemptView) :
    transition.valid_transition old new =
      ok (Auths.Product.Recovery.validTransition
        (Auths.Product.Refinement.Gateway.viewOf old)
        (Auths.Product.Refinement.Gateway.viewOf new)) := by
  obtain ⟨result, resultEq, refined⟩ := Aeneas.Std.WP.spec_imp_exists
    (Auths.Product.Refinement.Gateway.translated_valid_transition_refines_model old new)
  rw [resultEq, refined]

example : transition.valid_transition (unknownView .Mutation) lateResponse = ok true := by
  rw [projected_transition]
  rfl
example : transition.valid_transition (unknownView .Disclosure) lateAcknowledgement = ok true := by
  rw [projected_transition]
  rfl
example : transition.valid_transition (unknownView .Mutation)
    { lateResponse with entry := byteVec 5#u8 } = ok false := by
  rw [projected_transition]
  rfl
example : transition.valid_transition (unknownView .Mutation)
    { lateResponse with revision := 4#u64 } = ok false := by
  rw [projected_transition]
  rfl
example : transition.valid_transition (unknownView .Mutation)
    { lateAcknowledgement with protocol := .Mutation } = ok false := by
  rw [projected_transition]
  rfl
example : transition.valid_transition (unknownView .Mutation) lateAcknowledgement = ok false := by
  rw [projected_transition]
  rfl

end qualification.aeneas.cases
