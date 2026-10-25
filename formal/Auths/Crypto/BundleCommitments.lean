import Auths.Crypto.BundleWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BundleCommitments
open Auths.Codec Auths.Codec.Refinement
open Auths.Crypto.SigningObjectWriters

variable [primitive : Sha256Primitives]

/- The actual proof commitment covers the complete independently specified
bundle, including normalization, every signed payload, bindings, attachments,
optional-body presence and stored approval order. Both inner identifier hashes
and this outer raw SHA use the same explicit functional primitive contract.
No hash injectivity, successful encoder premise or authority follows. -/
theorem proof_digest_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.ProofBundle)
    (fields : BundleWriters.Fields value) (dimensions : BundleWriters.Dimensions value)
    (domains : BundleWriters.IdentifierDomains value)
    (space : BundleObjects.cost value ≤ Usize.max)
    (native : (2 * BundleObjects.cost value : Int) ≤ Isize.max) :
    hash.proof_digest value = ok (.Ok (sha256 (BundleObjects.bundle sha256 value))) := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (BundleWriters.bundle_encoder sha256 contract value fields dimensions domains space native)
  unfold hash.proof_digest
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  rw [FramedHash.raw_hash_exact sha256 contract]
  simp only [bind_tc_ok, alloc.vec.deref_exact, payloadBytes]

end Auths.Crypto.BundleCommitments
