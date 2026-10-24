import Auths.Crypto.FramedHash
import Auths.Crypto.RequirementWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.RequirementIdentifiers
open Auths.Codec Auths.Codec.Refinement
open Auths.Crypto.SigningObjectWriters

/- Exact actual requirement IDs, with independently defined complete schemas.
Input model validity earns UTF-8 conditions. Concrete constructor limits earn
both writer and native framing space in the useful valid-domain consequences.
Only the SHA implementation-meets-function/output-representation contract is
an explicit cryptographic premise; no source success or desired byte vector
is assumed. Authenticity and downstream requirement matching remain separate. -/

variable [primitive : Sha256Primitives]

def approvalFrame (value : auths_model.approval.ApprovalRequirement) : CommitmentFrames.Identifier :=
  ⟨12, UnsignedObjects.approvalRequirement value⟩

@[step] theorem approval_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.approval.ApprovalRequirement)
    (valid : ProtocolValidity.ApprovalRequirement value) (space : RequirementWriters.approvalCost value ≤ Usize.max) :
    hash.approval_requirement_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (UnsignedObjects.approvalRequirement value))
        (sha256 (CommitmentFrames.identifier (approvalFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (RequirementWriters.approval_encoder_valid value valid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.approval_requirement_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .ApprovalRequirement (alloc.vec.Vec.deref payload))
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
      auths_model.ApprovalRequirementId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, approvalFrame] using classified

theorem approval_resources (value : auths_model.approval.ApprovalRequirement)
    (valid : ProtocolValidity.ApprovalRequirement value) :
    RequirementWriters.approvalCost value ≤ Usize.max ∧
      FramedHash.IdentifierAdmissible (UnsignedObjects.approvalRequirement value) := by
  have capacity : RequirementWriters.approvalCost value ≤ 8381 :=
    RequirementWriters.approval_cost_valid value valid
  have lengthBound := RequirementWriters.approval_length value
  constructor
  · scalar_tac
  · unfold FramedHash.IdentifierAdmissible
    constructor
    · scalar_tac
    · constructor <;> scalar_tac

theorem approval_valid_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.approval.ApprovalRequirement)
    (valid : ProtocolValidity.ApprovalRequirement value) :
    hash.approval_requirement_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (approvalFrame value)))) := by
  obtain ⟨space, fits⟩ := approval_resources value valid
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (approval_total sha256 contract value valid space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

def observationFrame (value : auths_model.observation.ObservationRequirement) : CommitmentFrames.Identifier :=
  ⟨11, UnsignedObjects.observationRequirement value⟩

@[step] theorem observation_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.observation.ObservationRequirement)
    (valid : ProtocolValidity.ObservationRequirement value) (space : RequirementWriters.observationCost value ≤ Usize.max) :
    hash.observation_requirement_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (UnsignedObjects.observationRequirement value))
        (sha256 (CommitmentFrames.identifier (observationFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (RequirementWriters.observation_encoder_valid value valid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.observation_requirement_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .ObservationRequirement (alloc.vec.Vec.deref payload))
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
      auths_model.ObservationRequirementId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, observationFrame] using classified

theorem observation_resources (value : auths_model.observation.ObservationRequirement)
    (valid : ProtocolValidity.ObservationRequirement value) :
    RequirementWriters.observationCost value ≤ Usize.max ∧
      FramedHash.IdentifierAdmissible (UnsignedObjects.observationRequirement value) := by
  have capacity : RequirementWriters.observationCost value ≤ 72311 :=
    RequirementWriters.observation_cost_valid value valid
  have lengthBound := RequirementWriters.observation_length value
  constructor
  · scalar_tac
  · unfold FramedHash.IdentifierAdmissible
    constructor
    · scalar_tac
    · constructor <;> scalar_tac

theorem observation_valid_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.observation.ObservationRequirement)
    (valid : ProtocolValidity.ObservationRequirement value) :
    hash.observation_requirement_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (observationFrame value)))) := by
  obtain ⟨space, fits⟩ := observation_resources value valid
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (observation_total sha256 contract value valid space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

end Auths.Crypto.RequirementIdentifiers
