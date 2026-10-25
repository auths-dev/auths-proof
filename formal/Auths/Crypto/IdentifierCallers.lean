import Auths.Crypto.FramedHash
import Auths.Crypto.ValidatedWriters
import Auths.Crypto.EvidenceWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.IdentifierCallers
open Auths.Codec Auths.Codec.Refinement
open Auths.Crypto.StatementWriters Auths.Crypto.SigningObjectWriters

/- Actual core identifier callers, with their complete independent unsigned
schemas. Model validity and a computed writer-space envelope suffice to obtain
an encoded payload. Framing then returns either the exact identifier or a
LimitExceeded refusal, classified by independent native length bounds.
The SHA function/representation contract remains explicit; these results
neither assume successful callers nor assert collision resistance. -/

variable [primitive : Sha256Primitives]

theorem body_digest_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8) :
    hash.body_digest payload = ok (sha256 (byteList payload.val)) := by
  simpa only [hash.body_digest] using FramedHash.raw_hash_exact sha256 contract payload

theorem transaction_binding_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8) :
    hash.transaction_binding payload = ok (sha256 (byteList payload.val)) := by
  simpa only [hash.transaction_binding] using FramedHash.raw_hash_exact sha256 contract payload

theorem attachment_digest_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (payload : Slice Std.U8) :
    hash.attachment_digest payload = ok (sha256 (byteList payload.val)) := by
  unfold hash.attachment_digest
  rw [FramedHash.raw_hash_exact sha256 contract payload]
  simp only [bind_tc_ok, auths_model.AttachmentDigest.from_digest]

def grantFrame (value : auths_model.GrantStatement) : CommitmentFrames.Identifier :=
  ⟨1, UnsignedObjects.grant value⟩

@[step] theorem grant_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.GrantStatement)
    (valid : ProtocolValidity.Grant value) (space : grantCost value ≤ Usize.max) :
    hash.grant_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (UnsignedObjects.grant value))
        (sha256 (CommitmentFrames.identifier (grantFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.grant_encoder_valid value valid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.grant_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .Grant (alloc.vec.Vec.deref payload))
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
      auths_model.GrantId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, grantFrame] using classified

theorem grant_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.GrantStatement)
    (valid : ProtocolValidity.Grant value) (space : grantCost value ≤ Usize.max)
    (fits : FramedHash.IdentifierAdmissible (UnsignedObjects.grant value)) :
    hash.grant_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (grantFrame value)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (grant_total sha256 contract value valid space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem grant_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.GrantStatement)
    (valid : ProtocolValidity.Grant value) (space : grantCost value ≤ Usize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (UnsignedObjects.grant value)) :
    hash.grant_id value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (grant_total sha256 contract value valid space)
  simpa only [FramedHash.hash_refused classified outside] using runs

def actionFrame (value : auths_model.ActionEnvelope) : CommitmentFrames.Identifier :=
  ⟨2, UnsignedObjects.action value⟩

@[step] theorem action_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.ActionEnvelope)
    (valid : ProtocolValidity.Action value) (space : actionCost value ≤ Usize.max) :
    hash.action_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (UnsignedObjects.action value))
        (sha256 (CommitmentFrames.identifier (actionFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.action_encoder_valid value valid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.action_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .Action (alloc.vec.Vec.deref payload))
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
      auths_model.ActionId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, actionFrame] using classified

theorem action_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.ActionEnvelope)
    (valid : ProtocolValidity.Action value) (space : actionCost value ≤ Usize.max)
    (fits : FramedHash.IdentifierAdmissible (UnsignedObjects.action value)) :
    hash.action_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (actionFrame value)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (action_total sha256 contract value valid space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem action_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.ActionEnvelope)
    (valid : ProtocolValidity.Action value) (space : actionCost value ≤ Usize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (UnsignedObjects.action value)) :
    hash.action_id value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (action_total sha256 contract value valid space)
  simpa only [FramedHash.hash_refused classified outside] using runs

def principal_statusFrame (value : auths_model.PrincipalStatusStatement) : CommitmentFrames.Identifier :=
  ⟨5, UnsignedObjects.principalStatus value⟩

@[step] theorem principal_status_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PrincipalStatusStatement)
    (valid : ProtocolValidity.PrincipalStatus value) (space : principal_statusCost value ≤ Usize.max) :
    hash.principal_status_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (UnsignedObjects.principalStatus value))
        (sha256 (CommitmentFrames.identifier (principal_statusFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.principal_status_encoder_valid value valid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.principal_status_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .PrincipalStatus (alloc.vec.Vec.deref payload))
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
      auths_model.PrincipalStatusId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, principal_statusFrame] using classified

theorem principal_status_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PrincipalStatusStatement)
    (valid : ProtocolValidity.PrincipalStatus value) (space : principal_statusCost value ≤ Usize.max)
    (fits : FramedHash.IdentifierAdmissible (UnsignedObjects.principalStatus value)) :
    hash.principal_status_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (principal_statusFrame value)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (principal_status_total sha256 contract value valid space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem principal_status_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PrincipalStatusStatement)
    (valid : ProtocolValidity.PrincipalStatus value) (space : principal_statusCost value ≤ Usize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (UnsignedObjects.principalStatus value)) :
    hash.principal_status_id value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (principal_status_total sha256 contract value valid space)
  simpa only [FramedHash.hash_refused classified outside] using runs

def grant_statusFrame (value : auths_model.GrantStatusStatement) : CommitmentFrames.Identifier :=
  ⟨6, UnsignedObjects.grantStatus value⟩

@[step] theorem grant_status_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.GrantStatusStatement)
    (valid : ProtocolValidity.GrantStatus value) (space : grant_statusCost value ≤ Usize.max) :
    hash.grant_status_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (UnsignedObjects.grantStatus value))
        (sha256 (CommitmentFrames.identifier (grant_statusFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (ValidatedWriters.grant_status_encoder_valid value valid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.grant_status_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .GrantStatus (alloc.vec.Vec.deref payload))
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
      auths_model.GrantStatusId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, grant_statusFrame] using classified

theorem grant_status_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.GrantStatusStatement)
    (valid : ProtocolValidity.GrantStatus value) (space : grant_statusCost value ≤ Usize.max)
    (fits : FramedHash.IdentifierAdmissible (UnsignedObjects.grantStatus value)) :
    hash.grant_status_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (grant_statusFrame value)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (grant_status_total sha256 contract value valid space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem grant_status_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.GrantStatusStatement)
    (valid : ProtocolValidity.GrantStatus value) (space : grant_statusCost value ≤ Usize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (UnsignedObjects.grantStatus value)) :
    hash.grant_status_id value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (grant_status_total sha256 contract value valid space)
  simpa only [FramedHash.hash_refused classified outside] using runs

def evidenceFrame (value : auths_model.EvidenceObject) : CommitmentFrames.Identifier :=
  ⟨4, UnsignedObjects.evidenceContent value⟩

@[step] theorem evidence_total (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.EvidenceObject)
    (valid : ProtocolValidity.Evidence value) (space : EvidenceWriters.contentCost value ≤ Usize.max) :
    hash.evidence_id value ⦃ result =>
      FramedHash.HashResult (FramedHash.IdentifierAdmissible (UnsignedObjects.evidenceContent value))
        (sha256 (CommitmentFrames.identifier (evidenceFrame value))) result ⦄ := by
  obtain ⟨payload, encoded, payloadBytes⟩ := encoder_success
    (EvidenceWriters.content_encoder_valid value valid space)
  change payload.val.map UScalar.val = _ at payloadBytes
  unfold hash.evidence_id
  simp only [encoded, core.result.Result.Insts.CoreOpsTry.branch,
    core.ops.deref.DerefVec, bind_tc_ok]
  obtain ⟨hashed, runs, classified⟩ := spec_imp_exists
    (FramedHash.identifier_hash_total sha256 contract .Evidence (alloc.vec.Vec.deref payload))
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
      auths_model.EvidenceId.from_digest, bind_tc_ok, spec_ok, FramedHash.HashResult,
      ProtocolFraming.identifierFrame, ProtocolFraming.identifierTag,
      alloc.vec.deref_exact, payloadBytes, evidenceFrame] using classified

theorem evidence_resources (value : auths_model.EvidenceObject)
    (valid : ProtocolValidity.Evidence value) :
    EvidenceWriters.contentCost value ≤ Usize.max ∧
      FramedHash.IdentifierAdmissible (UnsignedObjects.evidenceContent value) := by
  have typeBound : value.evidence_type.toByteArray.size ≤ 128 := valid.1.2.1
  have mediaBound : value.media_type.toByteArray.size ≤ 128 := valid.2.1.2.1
  have bytesBound : value.bytes.val.length ≤ 2097152 := valid.2.2.2
  have capacity : EvidenceWriters.contentCost value ≤ 2097471 := by
    simp only [EvidenceWriters.contentCost]
    omega
  have lengthBound := EvidenceWriters.content_length value
  constructor
  · scalar_tac
  · unfold FramedHash.IdentifierAdmissible
    constructor
    · scalar_tac
    · constructor <;> scalar_tac

theorem evidence_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.EvidenceObject)
    (valid : ProtocolValidity.Evidence value) (space : EvidenceWriters.contentCost value ≤ Usize.max)
    (fits : FramedHash.IdentifierAdmissible (UnsignedObjects.evidenceContent value)) :
    hash.evidence_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (evidenceFrame value)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (evidence_total sha256 contract value valid space)
  simpa only [FramedHash.hash_accepted classified fits] using runs

theorem evidence_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.EvidenceObject)
    (valid : ProtocolValidity.Evidence value) (space : EvidenceWriters.contentCost value ≤ Usize.max)
    (outside : ¬ FramedHash.IdentifierAdmissible (UnsignedObjects.evidenceContent value)) :
    hash.evidence_id value = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists (evidence_total sha256 contract value valid space)
  simpa only [FramedHash.hash_refused classified outside] using runs

theorem evidence_valid_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.EvidenceObject)
    (valid : ProtocolValidity.Evidence value) :
    hash.evidence_id value = ok (.Ok (sha256 (CommitmentFrames.identifier (evidenceFrame value)))) := by
  obtain ⟨space, fits⟩ := evidence_resources value valid
  exact evidence_exact sha256 contract value valid space fits

end Auths.Crypto.IdentifierCallers
