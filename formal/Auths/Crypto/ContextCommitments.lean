import Auths.Crypto.ContextWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextCommitments
open Auths.Codec Auths.Codec.Refinement
open Auths.Crypto.SigningObjectWriters

/- The native commitment and measured size come from the same complete
encoding. Inner status/requirement IDs and outer context framing share an
explicit SHA function/output-representation contract. These byte claims do
not establish collision resistance, configuration trust or authorization. -/
variable [primitive : Sha256Primitives]

def frame (sha256 : List Nat → auths_model.Digest) (value : auths_model.TrustedContext) :
    CommitmentFrames.Identifier := ⟨9, ContextObjects.context sha256 value⟩

def DigestAndSizeResult (admitted : Prop) (expected : auths_model.ContextDigest) (length : Nat)
    (result : core.result.Result (auths_model.ContextDigest × Std.Usize) error.CodecError) : Prop :=
  match result with
  | .Ok (digest, measured) => admitted ∧ digest = expected ∧ measured.val = length
  | .Err reason => reason = .LimitExceeded ∧ ¬ admitted

@[step] theorem digest_and_size_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.TrustedContext)
    (fields : ContextWriters.Fields value) (domains : ContextWriters.Domains value)
    (dimensions : ContextWriters.Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max) :
    hash.context_digest_and_size value ⦃ result =>
      DigestAndSizeResult (FramedHash.IdentifierAdmissible (ContextObjects.context sha256 value))
        (sha256 (CommitmentFrames.identifier (frame sha256 value)))
        (ContextObjects.context sha256 value).length result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ContextWriters.context_encoder sha256 contract value fields domains dimensions space native)
  have measured : (alloc.vec.Vec.len payload).val = (ContextObjects.context sha256 value).length := by
    have length := congrArg List.length payloadBytes
    simpa only [byteList, List.length_map, alloc.vec.Vec.len_val] using length
  unfold hash.context_digest_and_size
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .Context (alloc.vec.Vec.deref payload))
  rw [runs]
  cases hashed with
  | Err reason =>
    simpa only [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, bind_tc_ok, spec_ok, DigestAndSizeResult, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes] using classified
  | Ok identifier =>
    have hashMeaning : FramedHash.IdentifierAdmissible (ContextObjects.context sha256 value) ∧
        identifier = sha256 (CommitmentFrames.identifier (frame sha256 value)) := by
      simpa only [FramedHash.HashResult, ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
        alloc.vec.deref_exact, payloadBytes, frame] using classified
    simpa only [core.result.Result.Insts.CoreOpsTry.branch, auths_model.ContextDigest.from_digest,
      bind_tc_ok, spec_ok, DigestAndSizeResult] using
      And.intro hashMeaning.1 (And.intro hashMeaning.2 measured)

theorem digest_and_size_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.TrustedContext)
    (fields : ContextWriters.Fields value) (domains : ContextWriters.Domains value)
    (dimensions : ContextWriters.Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max)
    (fits : FramedHash.IdentifierAdmissible (ContextObjects.context sha256 value)) :
    ∃ measured, hash.context_digest_and_size value =
      ok (.Ok (sha256 (CommitmentFrames.identifier (frame sha256 value)), measured)) ∧
      measured.val = (ContextObjects.context sha256 value).length := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (digest_and_size_total sha256 contract value fields domains dimensions space native)
  cases result with
  | Err reason => exact False.elim (classified.2 fits)
  | Ok pair =>
    rcases pair with ⟨digest, measured⟩
    exact ⟨measured, by simpa only [DigestAndSizeResult, classified.2.1] using runs, classified.2.2⟩

theorem digest_and_size_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.TrustedContext)
    (fields : ContextWriters.Fields value) (domains : ContextWriters.Domains value)
    (dimensions : ContextWriters.Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (ContextObjects.context sha256 value)) :
    hash.context_digest_and_size value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (digest_and_size_total sha256 contract value fields domains dimensions space native)
  cases result with
  | Err reason => simpa only [DigestAndSizeResult, classified.1] using runs
  | Ok pair => exact False.elim (outside classified.1)

@[step] theorem digest_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.TrustedContext)
    (fields : ContextWriters.Fields value) (domains : ContextWriters.Domains value)
    (dimensions : ContextWriters.Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max) :
    hash.context_digest value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (ContextObjects.context sha256 value))
        (sha256 (CommitmentFrames.identifier (frame sha256 value))) result ⦄ := by
  unfold hash.context_digest
  step with digest_and_size_total sha256 contract value fields domains dimensions space native
    as ⟨result, classified⟩
  cases result with
  | Err reason =>
    simpa only [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, bind_tc_ok, spec_ok, DigestAndSizeResult, FramedHash.HashResult] using classified
  | Ok pair =>
    rcases pair with ⟨digest, measured⟩
    simpa only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok, spec_ok, FramedHash.HashResult] using
      And.intro classified.1 classified.2.1

theorem digest_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.TrustedContext)
    (fields : ContextWriters.Fields value) (domains : ContextWriters.Domains value)
    (dimensions : ContextWriters.Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max)
    (fits : FramedHash.IdentifierAdmissible (ContextObjects.context sha256 value)) :
    hash.context_digest value = ok (.Ok (sha256 (CommitmentFrames.identifier (frame sha256 value)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (digest_total sha256 contract value fields domains dimensions space native)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem digest_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.TrustedContext)
    (fields : ContextWriters.Fields value) (domains : ContextWriters.Domains value)
    (dimensions : ContextWriters.Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (ContextObjects.context sha256 value)) :
    hash.context_digest value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (digest_total sha256 contract value fields domains dimensions space native)
  simpa only [FramedHash.hash_refused classified outside] using runs

end Auths.Crypto.ContextCommitments
