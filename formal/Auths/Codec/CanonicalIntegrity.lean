import Auths.Codec.CanonicalEncoding
import Mathlib.Tactic.CasesM
import Aesop

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.CanonicalIntegrity

/- These are complete-payload preservation consequences of the actual
integrity constructors. Actual construction success is the premise; no hash
result, expected encoding, flag or decoder success is assumed. Establishing
the independent integrity predicates and totality/work still requires the
called algorithms' source refinements. These lemmas do not replace them. -/

macro "auths_integrity_payload" accepted:ident : tactic => `(tactic|
  (simp only [Bind.bind, Aeneas.Std.bind] at $accepted
   repeat' first
     | casesm* _ × _
     | dsimp only at $accepted
     | split at $accepted
     | simp (failIfUnchanged := true) only [
         uncurry, Bind.bind, Aeneas.Std.bind,
         core.result.Result.Insts.CoreOpsTry.branch,
         core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
         core.convert.FromSame, core.convert.FromSame.from,
         bind_tc_ok, bind_tc_fail, bind_tc_div, Result.ok.injEq,
         core.result.Result.Ok.injEq, reduceCtorEq] at $accepted
     | contradiction
   all_goals subst_vars
   all_goals simp only [canonical_value.Canonical.as_value]
   all_goals aesop))

variable [primitive : Auths.Crypto.Sha256Primitives]

@[aesop safe forward]
theorem signed_approval_retains (input : auths_model.approval.SignedApproval)
    (output : canonical_value.Canonical auths_model.approval.SignedApproval)
    (accepted : canonical_value.checked_signed_approval input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input := by
  unfold canonical_value.checked_signed_approval at accepted
  auths_integrity_payload accepted

@[aesop safe forward]
theorem signed_observation_retains (input : auths_model.observation.SignedObservation)
    (output : canonical_value.Canonical auths_model.observation.SignedObservation)
    (accepted : canonical_value.checked_signed_observation input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input := by
  unfold canonical_value.checked_signed_observation at accepted
  auths_integrity_payload accepted

@[aesop safe forward]
theorem bounded_policy_retains (input : auths_model.bounded_policy.BoundedPolicyCommitment)
    (output : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : canonical_value.checked_bounded_policy input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input := by
  unfold canonical_value.checked_bounded_policy at accepted
  auths_integrity_payload accepted

@[aesop safe forward]
theorem verification_result_retains (input : auths_model.PortableVerificationResult)
    (output : canonical_value.Canonical auths_model.PortableVerificationResult)
    (accepted : canonical_value.checked_verification_result input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input := by
  unfold canonical_value.checked_verification_result at accepted
  auths_integrity_payload accepted

end Auths.Codec.CanonicalIntegrity
