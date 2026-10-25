import Auths.Crypto.ResultCost
import Auths.Codec.ProtocolEquality

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.ResultIntegrity
open Auths.Codec.Refinement Auths.Crypto
open Auths.Crypto.SigningObjectWriters

/- Independent integrity of reported data, not verifier origin or authority.
Code consistency is a three-way tag relation. Opening binds the full zeroed
projection to its declared self-digest under an explicit SHA function. -/
def Consistent (value : auths_model.PortableVerificationResult) : Prop :=
  ResultObjects.decision value.decision = ResultObjects.codeClass value.code

def Opening (sha256 : List Nat → auths_model.Digest) (value : auths_model.PortableVerificationResult) : Prop :=
  sha256 (ResultObjects.result false value) = value.result_digest

theorem self_digest_length (value : auths_model.VerificationResultDigest) :
    (ResultObjects.selfDigest false value).length = (ResultObjects.selfDigest true value).length := by
  have length : value.val.length = 32 := by simpa using value.property
  simp [ResultObjects.selfDigest, UnsignedObjects.digest, UnsignedWire.bytes, length]

theorem projection_length (value : auths_model.PortableVerificationResult) :
    (ResultObjects.result false value).length = (ResultObjects.result true value).length := by
  simp only [ResultObjects.result, UnsignedWire.map, UnsignedWire.entries, List.length_append, self_digest_length]

theorem digest_equal (left right : auths_model.VerificationResultDigest) :
    auths_model.VerificationResultDigest.Insts.CoreCmpPartialEqVerificationResultDigest.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.VerificationResultDigest.Insts.CoreCmpPartialEqVerificationResultDigest.eq,
    ProtocolEquality.digest_exact]

variable [primitive : Sha256Primitives]

theorem rejects_inconsistent (value : auths_model.PortableVerificationResult)
    (inconsistent : ¬ Consistent value) :
    canonical_value.checked_verification_result value = ok (.Err .Malformed) := by
  unfold canonical_value.checked_verification_result
  cases decision : value.decision <;> cases code : value.code <;>
    simp_all [auths_model.PortableVerificationResult.impl.decision,
      auths_model.PortableVerificationResult.impl.code, Consistent,
      ResultObjects.decision, ResultObjects.codeClass, bind_tc_ok]

theorem checked_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PortableVerificationResult)
    (fits : (ResultObjects.result true value).length ≤ 8388608) :
    canonical_value.checked_verification_result value =
      ok (if Consistent value then if Opening sha256 value then .Ok ⟨value⟩ else .Err .DigestMismatch
        else .Err .Malformed) := by
  have hashingFits : (ResultObjects.result false value).length ≤ 8388608 := by rw [projection_length]; exact fits
  have hashRun := ResultCost.digest_bounded_exact sha256 contract value hashingFits
  unfold canonical_value.checked_verification_result
  cases decision : value.decision <;> cases code : value.code <;>
    simp only [auths_model.PortableVerificationResult.impl.decision,
      auths_model.PortableVerificationResult.impl.code, decision, code,
      hashRun, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
      auths_model.PortableVerificationResult.impl.result_digest,
      core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
      digest_equal, Consistent, ResultObjects.decision, ResultObjects.codeClass]
  all_goals by_cases opened : Opening sha256 value <;> simp_all [Opening]

@[step] theorem checked_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PortableVerificationResult)
    (fits : (ResultObjects.result true value).length ≤ 8388608) :
    canonical_value.checked_verification_result value ⦃ result =>
      match result with
      | .Err reason => (reason = .Malformed ∧ ¬ Consistent value) ∨
          (reason = .DigestMismatch ∧ Consistent value ∧ ¬ Opening sha256 value)
      | .Ok carrier => canonical_value.Canonical.as_value carrier = ok value ∧
          Consistent value ∧ Opening sha256 value ∧
          (encode.encode_verification_result carrier ⦃ encoded => Encodes (ResultObjects.result true value) encoded ⦄) ⦄ := by
  rw [checked_exact sha256 contract value fits]
  by_cases consistent : Consistent value
  · by_cases opened : Opening sha256 value
    · simp only [if_pos consistent, if_pos opened, spec_ok]
      exact ⟨rfl, consistent, opened, ResultCost.canonical_encoder_bounded ⟨value⟩ value rfl fits⟩
    · simp [consistent, opened, spec_ok]
  · simp [consistent, spec_ok]

theorem checked_accepts (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PortableVerificationResult)
    (fits : (ResultObjects.result true value).length ≤ 8388608)
    (consistent : Consistent value) (opened : Opening sha256 value) :
    canonical_value.checked_verification_result value = ok (.Ok ⟨value⟩) := by
  rw [checked_exact sha256 contract value fits]
  simp only [if_pos consistent, if_pos opened]

theorem checked_refuses_opening (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PortableVerificationResult)
    (fits : (ResultObjects.result true value).length ≤ 8388608)
    (consistent : Consistent value) (unopened : ¬ Opening sha256 value) :
    canonical_value.checked_verification_result value = ok (.Err .DigestMismatch) := by
  rw [checked_exact sha256 contract value fits]
  simp only [if_pos consistent, if_neg unopened]

end Auths.Codec.ResultIntegrity
