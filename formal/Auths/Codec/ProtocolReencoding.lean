import Auths.Codec.ProtocolCanonical
import Auths.Codec.CanonicalIntegrity
import Mathlib.Tactic.CasesM
import Aesop

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec
namespace Auths.Codec.ProtocolReencoding
set_option maxHeartbeats 2000000

/- These are source-wrapper necessity proofs. They expose each real parser,
constructor, complete-input gate and actual encoder call, then use the real
byte-identity gate. They do not establish inner-parser totality, constructor
validity or useful inverse completeness. Those remain required separately. -/
macro "auths_protocol_reencoding" accepted:ident : tactic => `(tactic|
  (simp only [Bind.bind, Aeneas.Std.bind] at $accepted
   repeat' first
     | casesm* _ × _
     | dsimp only at $accepted
     | split at $accepted
     | simp (failIfUnchanged := true) only [
         uncurry, Bind.bind, Aeneas.Std.bind,
         ProtocolCanonical.accept_result, ProtocolCanonical.with_error_result,
         core.result.Result.Insts.CoreOpsTry.branch,
         core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
         core.convert.FromSame, core.convert.FromSame.from,
         bind_tc_ok, bind_tc_fail, bind_tc_div, Result.ok.injEq,
         core.result.Result.Ok.injEq, reduceCtorEq] at $accepted
     | contradiction
   all_goals subst_vars
   all_goals simp only [CanonicalEncoding.bundle_exact, CanonicalEncoding.context_exact,
     CanonicalEncoding.signed_approval_exact, CanonicalEncoding.result_exact,
     CanonicalEncoding.bounded_policy_exact, Bind.bind, Aeneas.Std.bind] at *
   all_goals aesop))

variable [primitive : Auths.Crypto.Sha256Primitives]

theorem decode_bundle_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : canonical_value.Canonical auths_model.ProofBundle)
    (accepted : decode.decode_bundle input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_bundle value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_bundle at accepted
  auths_protocol_reencoding accepted

theorem decode_grant_statement_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.GrantStatement)
    (accepted : decode.decode_grant_statement input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_grant_statement value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_grant_statement at accepted
  auths_protocol_reencoding accepted

theorem decode_signed_grant_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.SignedGrant)
    (accepted : decode.decode_signed_grant input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_signed_grant value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_signed_grant at accepted
  auths_protocol_reencoding accepted

theorem decode_signed_action_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.SignedAction)
    (accepted : decode.decode_signed_action input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_signed_action value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_signed_action at accepted
  auths_protocol_reencoding accepted

theorem decode_action_envelope_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.ActionEnvelope)
    (accepted : decode.decode_action_envelope input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_action_envelope value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_action_envelope at accepted
  auths_protocol_reencoding accepted

theorem decode_principal_status_statement_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.PrincipalStatusStatement)
    (accepted : decode.decode_principal_status_statement input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_principal_status_statement value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_principal_status_statement at accepted
  auths_protocol_reencoding accepted

theorem decode_signed_principal_status_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.SignedPrincipalStatus)
    (accepted : decode.decode_signed_principal_status input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_signed_principal_status value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_signed_principal_status at accepted
  auths_protocol_reencoding accepted

theorem decode_grant_status_statement_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.GrantStatusStatement)
    (accepted : decode.decode_grant_status_statement input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_grant_status_statement value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_grant_status_statement at accepted
  auths_protocol_reencoding accepted

theorem decode_signed_grant_status_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.SignedGrantStatus)
    (accepted : decode.decode_signed_grant_status input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_signed_grant_status value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_signed_grant_status at accepted
  auths_protocol_reencoding accepted

theorem decode_principal_status_snapshot_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : canonical_value.Canonical auths_model.PrincipalStatusSnapshot)
    (accepted : decode.decode_principal_status_snapshot input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_principal_status_snapshot value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_principal_status_snapshot at accepted
  auths_protocol_reencoding accepted

theorem decode_grant_status_snapshot_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : canonical_value.Canonical auths_model.GrantStatusSnapshot)
    (accepted : decode.decode_grant_status_snapshot input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_grant_status_snapshot value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_grant_status_snapshot at accepted
  auths_protocol_reencoding accepted

theorem decode_canonical_action_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_canonical_action value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_canonical_action at accepted
  auths_protocol_reencoding accepted

theorem decode_verification_result_reencodes (input : Slice Std.U8)
    (value : canonical_value.Canonical auths_model.PortableVerificationResult)
    (accepted : decode.decode_verification_result input = ok (.Ok value)) :
    ∃ encoded, encode.encode_verification_result value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_verification_result at accepted
  auths_protocol_reencoding accepted

theorem decode_verifier_context_reencodes (input : Slice Std.U8)
    (value : canonical_value.Canonical auths_model.TrustedContext)
    (accepted : decode.decode_verifier_context input = ok (.Ok value)) :
    ∃ encoded, encode.encode_verifier_context value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold decode.decode_verifier_context at accepted
  auths_protocol_reencoding accepted

theorem decode_approval_requirements_reencodes (input : Slice Std.U8)
    (value : canonical_value.Canonical auths_model.approval.ApprovalRequirements)
    (accepted : approval.decode_approval_requirements input = ok (.Ok value)) :
    ∃ encoded, approval.encode_approval_requirements value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold approval.decode_approval_requirements at accepted
  auths_protocol_reencoding accepted

theorem decode_approval_statement_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : auths_model.approval.ApprovalStatement)
    (accepted : approval.decode_approval_statement input limits = ok (.Ok value)) :
    ∃ encoded, approval.encode_approval_statement value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold approval.decode_approval_statement at accepted
  auths_protocol_reencoding accepted

theorem decode_signed_approval_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : canonical_value.Canonical auths_model.approval.SignedApproval)
    (accepted : approval.decode_signed_approval input limits = ok (.Ok value)) :
    ∃ encoded, approval.encode_signed_approval value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold approval.decode_signed_approval at accepted
  auths_protocol_reencoding accepted

theorem decode_signed_observation_reencodes (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : canonical_value.Canonical auths_model.observation.SignedObservation)
    (accepted : observation.decode_signed_observation input limits = ok (.Ok value)) :
    ∃ encoded, observation.encode_signed_observation value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold observation.decode_signed_observation at accepted
  auths_protocol_reencoding accepted

theorem decode_observation_requirements_reencodes (input : Slice Std.U8)
    (value : auths_model.observation.ObservationRequirements)
    (accepted : observation.decode_observation_requirements input = ok (.Ok value)) :
    ∃ encoded, observation.encode_observation_requirements value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold observation.decode_observation_requirements at accepted
  auths_protocol_reencoding accepted

theorem decode_bounded_policy_commitment_reencodes (input : Slice Std.U8)
    (value : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : bounded_policy.decode_bounded_policy_commitment input = ok (.Ok value)) :
    ∃ encoded, bounded_policy.encode_bounded_policy_commitment value = ok (.Ok encoded) ∧ encoded.val = input.val := by
  unfold bounded_policy.decode_bounded_policy_commitment at accepted
  auths_protocol_reencoding accepted

end Auths.Codec.ProtocolReencoding
