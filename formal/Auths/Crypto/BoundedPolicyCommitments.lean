import Auths.Crypto.BoundedPolicyObjects
import Auths.Crypto.FramedHash

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BoundedPolicyCommitments
open Auths.Codec Auths.Codec.Refinement

/- Closed actual application domains are tied to independent literal bytes.
The real common framing and SHA primitive contract are composed below; no
successful digest, policy opening or evaluator acceptance is assumed. -/
variable [primitive : Sha256Primitives]

def policyFrame (payload : List Nat) : CommitmentFrames.Application :=
  ⟨UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain, payload⟩

theorem policy_domain_exact :
    byteList auths_model.bounded_policy.BOUNDED_POLICY_DIGEST_DOMAIN.val =
      UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain := by decide

@[step] theorem policy_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8) :
    bounded_policy.bounded_policy_digest payload ⦃ result =>
      FramedHash.HashResult (FramedHash.ApplicationAdmissible
        (UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain) (byteList payload.val))
        (sha256 (CommitmentFrames.application (policyFrame (byteList payload.val)))) result ⦄ := by
  unfold bounded_policy.bounded_policy_digest
  apply spec_mono (FramedHash.application_hash_total sha256 contract
    auths_model.bounded_policy.BOUNDED_POLICY_DIGEST_DOMAIN payload)
  intro result classified
  simpa only [ProtocolFraming.applicationFrame, policy_domain_exact, policyFrame, byteList] using classified

theorem policy_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8)
    (fits : FramedHash.ApplicationAdmissible
      (UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain) (byteList payload.val)) :
    bounded_policy.bounded_policy_digest payload =
      ok (.Ok (sha256 (CommitmentFrames.application (policyFrame (byteList payload.val))))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (policy_total sha256 contract payload)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem policy_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8)
    (outside : ¬ FramedHash.ApplicationAdmissible
      (UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain) (byteList payload.val)) :
    bounded_policy.bounded_policy_digest payload = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (policy_total sha256 contract payload)
  simpa only [FramedHash.hash_refused classified outside] using runs

def linkFrame (payload : List Nat) : CommitmentFrames.Application :=
  ⟨UnsignedObjects.utf8 BoundedPolicyObjects.linkDomain, payload⟩

theorem link_domain_exact :
    byteList auths_model.bounded_policy.BOUNDED_POLICY_LINK_DOMAIN.val =
      UnsignedObjects.utf8 BoundedPolicyObjects.linkDomain := by decide

@[step] theorem link_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8) :
    bounded_policy.bounded_policy_link payload ⦃ result =>
      FramedHash.HashResult (FramedHash.ApplicationAdmissible
        (UnsignedObjects.utf8 BoundedPolicyObjects.linkDomain) (byteList payload.val))
        (sha256 (CommitmentFrames.application (linkFrame (byteList payload.val)))) result ⦄ := by
  unfold bounded_policy.bounded_policy_link
  apply spec_mono (FramedHash.application_hash_total sha256 contract
    auths_model.bounded_policy.BOUNDED_POLICY_LINK_DOMAIN payload)
  intro result classified
  simpa only [ProtocolFraming.applicationFrame, link_domain_exact, linkFrame, byteList] using classified

theorem link_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8)
    (fits : FramedHash.ApplicationAdmissible
      (UnsignedObjects.utf8 BoundedPolicyObjects.linkDomain) (byteList payload.val)) :
    bounded_policy.bounded_policy_link payload =
      ok (.Ok (sha256 (CommitmentFrames.application (linkFrame (byteList payload.val))))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (link_total sha256 contract payload)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem link_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8)
    (outside : ¬ FramedHash.ApplicationAdmissible
      (UnsignedObjects.utf8 BoundedPolicyObjects.linkDomain) (byteList payload.val)) :
    bounded_policy.bounded_policy_link payload = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (link_total sha256 contract payload)
  simpa only [FramedHash.hash_refused classified outside] using runs

theorem policy_resources (payload : Slice Std.U8) (bounded : payload.val.length ≤ 4096) :
    FramedHash.ApplicationAdmissible (UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain)
      (byteList payload.val) := by
  have positive : 0 < (UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain).length := by decide
  have maximum : (UnsignedObjects.utf8 BoundedPolicyObjects.policyDomain).length ≤ 128 := by decide
  unfold FramedHash.ApplicationAdmissible
  simp only [byteList, List.length_map]
  constructor
  · exact positive
  constructor
  · exact maximum
  constructor
  · scalar_tac
  constructor <;> scalar_tac

theorem policy_bounded_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8) (bounded : payload.val.length ≤ 4096) :
    bounded_policy.bounded_policy_digest payload =
      ok (.Ok (sha256 (CommitmentFrames.application (policyFrame (byteList payload.val))))) :=
  policy_exact sha256 contract payload (policy_resources payload bounded)

end Auths.Crypto.BoundedPolicyCommitments
