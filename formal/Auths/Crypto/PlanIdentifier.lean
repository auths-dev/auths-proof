import Auths.Crypto.FramedHash
import Auths.Crypto.PlanWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.PlanIdentifier
open Auths.Codec Auths.Codec.Refinement
open Auths.Crypto.SigningObjectWriters

/- Every represented finite tree is serialized in full under its explicit
writer envelope; the actual ID caller then returns the independently framed
SHA result or typed framing refusal. Plan-validation/deployment-limit closure,
cryptographic security and authorization are separate from these equations. -/
variable [primitive : Sha256Primitives]

def planFrame (value : auths_model.AuthorizationPlan) : CommitmentFrames.Identifier :=
  ⟨3, PlanWire.encode (PlanWriters.viewPlan value)⟩

@[step] theorem plan_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.AuthorizationPlan)
    (space : PlanWriters.cost value ≤ Usize.max) :
    hash.plan_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (PlanWire.encode (PlanWriters.viewPlan value)))
        (sha256 (CommitmentFrames.identifier (planFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (PlanWriters.plan_encoder value space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.plan_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .Plan (alloc.vec.Vec.deref payload))
  rw [runs]
  cases hashed with
  | Err reason =>
    simpa only [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes] using classified
  | Ok identifier =>
    simpa only [core.result.Result.Insts.CoreOpsTry.branch,
      auths_model.PlanId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, planFrame] using classified

theorem plan_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.AuthorizationPlan)
    (space : PlanWriters.cost value ≤ Usize.max)
    (fits : FramedHash.IdentifierAdmissible (PlanWire.encode (PlanWriters.viewPlan value))) :
    hash.plan_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (planFrame value)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (plan_total sha256 contract value space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem plan_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.AuthorizationPlan)
    (space : PlanWriters.cost value ≤ Usize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (PlanWire.encode (PlanWriters.viewPlan value))) :
    hash.plan_id value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (plan_total sha256 contract value space)
  simpa only [FramedHash.hash_refused classified outside] using runs

end Auths.Crypto.PlanIdentifier
