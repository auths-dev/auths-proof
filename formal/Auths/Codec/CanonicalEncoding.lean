import Auths.Codec.ProtocolCanonical

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.CanonicalEncoding

/- Public canonical encoding and borrowed commitment hashing share the same
actual writer. These equations expose the complete call, including the real
immutable projection. They make no successful-encoding, expected-byte or hash
injectivity assumption. Constructor validity and the useful inverse remain
separate obligations. -/

variable [primitive : Auths.Crypto.Sha256Primitives]

theorem bundle_exact (carrier : canonical_value.Canonical auths_model.ProofBundle) :
    encode.encode_bundle carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      encode.encode_bundle_value value) := by
  rfl

theorem context_exact (carrier : canonical_value.Canonical auths_model.TrustedContext) :
    encode.encode_verifier_context carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      encode.encode_verifier_context_value value) := by
  rfl

theorem principal_snapshot_exact (carrier : canonical_value.Canonical auths_model.PrincipalStatusSnapshot) :
    encode.encode_principal_status_snapshot carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      encode.encode_principal_status_snapshot_value value) := by rfl

theorem grant_snapshot_exact (carrier : canonical_value.Canonical auths_model.GrantStatusSnapshot) :
    encode.encode_grant_status_snapshot carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      encode.encode_grant_status_snapshot_value value) := by rfl

theorem signed_approval_exact
    (carrier : canonical_value.Canonical auths_model.approval.SignedApproval) :
    approval.encode_signed_approval carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      approval.encode_signed_approval_value value) := by
  rfl

theorem signed_observation_exact
    (carrier : canonical_value.Canonical auths_model.observation.SignedObservation) :
    observation.encode_signed_observation carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      observation.encode_signed_observation_value value) := by
  rfl

theorem result_exact
    (carrier : canonical_value.Canonical auths_model.PortableVerificationResult) :
    encode.encode_verification_result carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      encode.encode_verification_result_value value) := by
  rfl

theorem bounded_policy_exact
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment) :
    bounded_policy.encode_bounded_policy_commitment carrier = (do
      let value ← canonical_value.Canonical.as_value carrier
      bounded_policy.encode_bounded_policy_commitment_value value) := by
  rfl

end Auths.Codec.CanonicalEncoding
