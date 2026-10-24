import Auths.Crypto.ResultWriters
import Auths.Crypto.FramedHash

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ResultCommitments
open Auths.Codec Auths.Codec.Refinement
open Auths.Crypto.SigningObjectWriters

/- Actual self-binding digest over the full result with exactly its self-
digest field zeroed. All other record fields and arrays stay byte-bound. The
functional SHA premise does not imply collision resistance or verifier origin. -/
variable [primitive : Sha256Primitives]

theorem digest_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PortableVerificationResult)
    (fields : ResultWriters.Fields value) (space : ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * ResultObjects.resultCost value : Int) ≤ Isize.max) :
    hash.verification_result_digest value = ok (.Ok (sha256 (ResultObjects.result false value))) := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ResultWriters.digest_input_encoder value fields space native)
  unfold hash.verification_result_digest
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  rw [FramedHash.raw_hash_exact sha256 contract]
  simp only [bind_tc_ok, auths_model.VerificationResultDigest.from_digest,
    alloc.vec.deref_exact, payloadBytes]

theorem set_digest_exact (value : auths_model.PortableVerificationResult)
    (digest : auths_model.VerificationResultDigest) :
    auths_model.PortableVerificationResult.impl.with_result_digest value digest =
      ok { value with result_digest := digest } := by rfl

theorem zero_projection_erases (value : auths_model.PortableVerificationResult)
    (digest : auths_model.VerificationResultDigest) :
    ResultObjects.result false { value with result_digest := digest } = ResultObjects.result false value := by rfl

theorem rebinding_digest_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PortableVerificationResult)
    (digest : auths_model.VerificationResultDigest)
    (fields : ResultWriters.Fields value) (space : ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * ResultObjects.resultCost value : Int) ≤ Isize.max) :
    (do let changed ← auths_model.PortableVerificationResult.impl.with_result_digest value digest
        hash.verification_result_digest changed) = ok (.Ok (sha256 (ResultObjects.result false value))) := by
  rw [set_digest_exact, bind_tc_ok]
  have unchangedFields : ResultWriters.Fields { value with result_digest := digest } := fields
  have unchangedCost : ResultObjects.resultCost { value with result_digest := digest } =
      ResultObjects.resultCost value := rfl
  have hashed := digest_exact sha256 contract { value with result_digest := digest }
    unchangedFields (by simpa only [unchangedCost] using space)
    (by simpa only [unchangedCost] using native)
  simpa only [zero_projection_erases] using hashed

end Auths.Crypto.ResultCommitments
