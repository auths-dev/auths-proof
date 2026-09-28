import qualification.aeneas.generated.gateway.Funs

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

end qualification.aeneas.cases
