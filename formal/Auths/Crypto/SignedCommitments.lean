import Auths.Crypto.SignedObjectWriters
import Auths.Crypto.FramedHash

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SignedCommitments
open Auths.Codec Auths.Codec.Refinement
open Auths.Crypto.SigningObjectWriters

variable [primitive : Sha256Primitives]

/- The approval commitment covers the complete signed object, including all
control-evidence records. It is a raw SHA commitment to canonical signed bytes,
not an identifier frame or an authenticity claim. -/
theorem approval_digest_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.approval.SignedApproval)
    (valid : ProtocolValidity.SignedApproval value)
    (space : SignedObjectWriters.approvalCost value ≤ Usize.max) :
    hash.approval_digest value = ok (.Ok (sha256 (UnsignedObjects.signedApproval value))) := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (SignedObjectWriters.approval_encoder_valid value valid space)
  unfold hash.approval_digest
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  rw [FramedHash.raw_hash_exact sha256 contract]
  simp only [bind_tc_ok, auths_model.ApprovalDigest.from_digest,
    alloc.vec.deref_exact, payloadBytes]

end Auths.Crypto.SignedCommitments
