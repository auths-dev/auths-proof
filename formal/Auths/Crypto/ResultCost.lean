import Auths.Crypto.WireCost
import Auths.Crypto.ResultCommitments

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ResultCost
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolArrayWriters
open Auths.Crypto.SigningObjectWriters

/- Complete result writer conditions are earned from independent full wire
size. The budget uses no successful encoder or trusted field/capacity flag.
Representation/decision/digest validity and decoder inverses remain separate
from encoding arbitrary bounded reported data. -/

theorem parameters_item_bound (value : auths_model.ClaimParameterId × auths_model.ClaimParameterId) :
    WireCost.Dominates (ContextObjects.parameterCost value) (ContextObjects.parameter value) := by
  have bound := WireCost.array_bound (fun value : String => 9 + value.toByteArray.size)
    UnsignedObjects.identifier [value.1, value.2] (fun item member => WireCost.identifier_bound item)
  simpa [allocation, ContextObjects.parameterCost, ContextObjects.parameter, Nat.add_assoc] using bound

theorem parameters_bound (values : List (auths_model.ClaimParameterId × auths_model.ClaimParameterId)) :
    WireCost.Dominates (9 + allocation ContextObjects.parameterCost values)
      (UnsignedWire.array (values.map ContextObjects.parameter)) :=
  WireCost.array_bound _ _ values (fun value member => parameters_item_bound value)

theorem ids_bound (values : List auths_model.Digest) :
    WireCost.Dominates (9 + 41 * values.length) (UnsignedWire.array (values.map UnsignedObjects.digest)) := by
  simpa only [ResultSatisfactions.constant_allocation] using WireCost.array_bound (fun _ => 41)
    UnsignedObjects.digest values (fun value member => WireCost.digest_bound value)

theorem time_bound (value : Option auths_model.Timestamp) : WireCost.Dominates 9 (ResultObjects.optionalTime value) := by
  cases value with
  | none => exact WireCost.fixed_bound 9 _ (by decide) (by simp [ResultObjects.optionalTime, UnsignedWire.null])
  | some value => exact WireCost.uint_bound value.val

theorem self_digest_bound (include : Bool) (value : auths_model.VerificationResultDigest) :
    WireCost.Dominates 41 (ResultObjects.selfDigest include value) := by
  cases include with
  | false => exact WireCost.fixed_bound 41 _ (by decide) (WireCost.bytes_positive _)
  | true => exact WireCost.digest_bound value

theorem code_bound (value : auths_model.VerificationCode) :
    WireCost.Dominates (ResultObjects.codeCost value) (ResultObjects.code value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 9, UnsignedWire.uint (ResultObjects.codeClass value)),
    (1, 9 + (ResultObjects.codeLabel value).toByteArray.size, UnsignedObjects.identifier (ResultObjects.codeLabel value))]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    · exact WireCost.uint_bound _
    · exact WireCost.identifier_bound _
  have cost : WireCost.mapCost fields = ResultObjects.codeCost value := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    simp only [ResultObjects.codeCost]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.code value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem claim_bound (value : auths_model.AssuranceClaim) :
    WireCost.Dominates (ResultObjects.claimCost value) (ResultObjects.claim value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 9 + value.kind.toByteArray.size, UnsignedObjects.identifier value.kind),
    (1, 9 + allocation ContextObjects.parameterCost value.parameters.val, UnsignedWire.array (value.parameters.val.map ContextObjects.parameter)),
    (2, 9, ResultObjects.optionalTime value.observed_at),
    (3, 9 + value.source.toByteArray.size, UnsignedObjects.identifier value.source)]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl
    · exact WireCost.identifier_bound _
    · exact parameters_bound _
    · exact time_bound _
    · exact WireCost.identifier_bound _
  have cost : WireCost.mapCost fields = ResultObjects.claimCost value := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    simp only [ResultObjects.claimCost]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.claim value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem claims_bound (values : List auths_model.AssuranceClaim) :
    WireCost.Dominates (9 + allocation ResultObjects.claimCost values) (UnsignedWire.array (values.map ResultObjects.claim)) :=
  WireCost.array_bound _ _ values (fun value member => claim_bound value)

theorem report_bound (value : auths_model.ParticipantAssurance) :
    WireCost.Dominates (ResultObjects.reportCost value) (ResultObjects.report value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 9 + value.principal.toByteArray.size, UnsignedObjects.identifier value.principal),
    (1, 9, UnsignedWire.uint (ContextObjects.role value.role)),
    (2, 9 + allocation ResultObjects.claimCost value.claims.val, UnsignedWire.array (value.claims.val.map ResultObjects.claim)),
    (3, 9 + 41 * value.evidence.val.length, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest)),
    (4, 9 + value.adapter.toByteArray.size, UnsignedObjects.identifier value.adapter),
    (5, 9, UnsignedWire.uint value.adapter_version.val)]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl
    · exact WireCost.identifier_bound _
    · exact WireCost.uint_bound _
    · exact claims_bound _
    · exact ids_bound _
    · exact WireCost.identifier_bound _
    · exact WireCost.uint_bound _
  have cost : WireCost.mapCost fields = ResultObjects.reportCost value := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    simp only [ResultObjects.reportCost]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.report value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem reports_bound (values : List auths_model.ParticipantAssurance) :
    WireCost.Dominates (9 + allocation ResultObjects.reportCost values) (UnsignedWire.array (values.map ResultObjects.report)) :=
  WireCost.array_bound _ _ values (fun value member => report_bound value)

theorem assurance_satisfaction_bound (value : auths_model.AssuranceSatisfaction) :
    WireCost.Dominates (ResultObjects.assuranceSatisfactionCost value) (ResultObjects.assuranceSatisfaction value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 9, UnsignedWire.uint value.requirement_index.val),
    (1, 9 + value.principal.toByteArray.size, UnsignedObjects.identifier value.principal),
    (2, ResultObjects.claimCost value.claim, ResultObjects.claim value.claim),
    (3, 9 + 41 * value.evidence.val.length, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest))]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl
    · exact WireCost.uint_bound _
    · exact WireCost.identifier_bound _
    · exact claim_bound _
    · exact ids_bound _
  have cost : WireCost.mapCost fields = ResultObjects.assuranceSatisfactionCost value := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    simp only [ResultObjects.assuranceSatisfactionCost]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.assuranceSatisfaction value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem assurance_satisfactions_bound (values : List auths_model.AssuranceSatisfaction) :
    WireCost.Dominates (9 + allocation ResultObjects.assuranceSatisfactionCost values)
      (UnsignedWire.array (values.map ResultObjects.assuranceSatisfaction)) :=
  WireCost.array_bound _ _ values (fun value member => assurance_satisfaction_bound value)

theorem resources_bound (value : auths_model.VerificationResources) :
    WireCost.Dominates (135) (ResultObjects.resources value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 9, UnsignedWire.uint value.proof_bytes.val),
    (1, 9, UnsignedWire.uint value.action_bytes.val),
    (2, 9, UnsignedWire.uint value.context_bytes.val),
    (3, 9, UnsignedWire.uint value.object_count.val),
    (4, 9, UnsignedWire.uint value.plan_leaves.val),
    (5, 9, UnsignedWire.uint value.plan_depth.val),
    (6, 9, UnsignedWire.uint value.work_units.val)]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · exact WireCost.uint_bound _
    · exact WireCost.uint_bound _
    · exact WireCost.uint_bound _
    · exact WireCost.uint_bound _
    · exact WireCost.uint_bound _
    · exact WireCost.uint_bound _
    · exact WireCost.uint_bound _
  have cost : WireCost.mapCost fields = 135 := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.resources value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem observation_satisfaction_bound (value : auths_model.observation.ObservationSatisfaction) :
    WireCost.Dominates (109) (ResultObjects.observationSatisfaction value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 41, UnsignedObjects.digest value.requirement),
    (1, 41, UnsignedObjects.digest value.observation)]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    · exact WireCost.digest_bound _
    · exact WireCost.digest_bound _
  have cost : WireCost.mapCost fields = 109 := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.observationSatisfaction value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem observation_satisfactions_bound (values : List auths_model.observation.ObservationSatisfaction) :
    WireCost.Dominates (9 + 109 * values.length) (UnsignedWire.array (values.map ResultObjects.observationSatisfaction)) := by
  simpa only [ResultSatisfactions.constant_allocation] using WireCost.array_bound (fun _ => 109)
    ResultObjects.observationSatisfaction values (fun value member => observation_satisfaction_bound value)

theorem approval_satisfaction_bound (value : auths_model.approval.ApprovalSatisfaction) :
    WireCost.Dominates (ResultObjects.approvalSatisfactionCost value) (ResultObjects.approvalSatisfaction value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 41, UnsignedObjects.digest value.requirement),
    (1, 9 + 41 * value.approvals.val.length, UnsignedWire.array (value.approvals.val.map UnsignedObjects.digest))]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    · exact WireCost.digest_bound _
    · exact ids_bound _
  have cost : WireCost.mapCost fields = ResultObjects.approvalSatisfactionCost value := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    simp only [ResultObjects.approvalSatisfactionCost]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.approvalSatisfaction value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem approval_satisfactions_bound (values : List auths_model.approval.ApprovalSatisfaction) :
    WireCost.Dominates (9 + allocation ResultObjects.approvalSatisfactionCost values)
      (UnsignedWire.array (values.map ResultObjects.approvalSatisfaction)) :=
  WireCost.array_bound _ _ values (fun value member => approval_satisfaction_bound value)

theorem result_bound (include : Bool) (value : auths_model.PortableVerificationResult) :
    WireCost.Dominates (ResultObjects.resultCost value) (ResultObjects.result include value) := by
  let fields : List (Nat × Nat × List Nat) := [
    (0, 9, UnsignedWire.uint (ResultObjects.decision value.decision)),
    (1, 9, UnsignedWire.uint (ResultObjects.stage value.stage)),
    (2, ResultObjects.codeCost value.code, ResultObjects.code value.code),
    (3, 41, UnsignedObjects.digest value.proof_digest),
    (4, 41, UnsignedObjects.digest value.action_digest),
    (5, 41, UnsignedObjects.digest value.context_digest),
    (6, 41, UnsignedObjects.optionalDigest value.plan_id),
    (7, 41, ResultObjects.selfDigest include value.result_digest),
    (8, 9 + 41 * value.authorized_branches.val.length, UnsignedWire.array (value.authorized_branches.val.map UnsignedObjects.digest)),
    (9, 9 + allocation ResultObjects.reportCost value.assurance.val, UnsignedWire.array (value.assurance.val.map ResultObjects.report)),
    (10, 9 + allocation ResultObjects.assuranceSatisfactionCost value.assurance_satisfactions.val, UnsignedWire.array (value.assurance_satisfactions.val.map ResultObjects.assuranceSatisfaction)),
    (11, 135, ResultObjects.resources value.resources),
    (12, 41, UnsignedObjects.digest value.registry_manifest),
    (13, 41, UnsignedObjects.optionalDigest value.required_configuration),
    (14, 41, UnsignedObjects.digest value.local_configuration),
    (15, 9, UnsignedWire.uint 4),
    (16, 9 + 109 * value.observation_satisfactions.val.length, UnsignedWire.array (value.observation_satisfactions.val.map ResultObjects.observationSatisfaction)),
    (17, 9 + allocation ResultObjects.approvalSatisfactionCost value.approval_satisfactions.val, UnsignedWire.array (value.approval_satisfactions.val.map ResultObjects.approvalSatisfaction))]
  have components : ∀ field ∈ fields, WireCost.Dominates field.2.1 field.2.2 := by
    intro field member
    simp only [fields, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · exact WireCost.uint_bound _
    · exact WireCost.uint_bound _
    · exact code_bound _
    · exact WireCost.digest_bound _
    · exact WireCost.digest_bound _
    · exact WireCost.digest_bound _
    · exact WireCost.optional_digest_bound _
    · exact self_digest_bound _ _
    · exact ids_bound _
    · exact reports_bound _
    · exact assurance_satisfactions_bound _
    · exact resources_bound _
    · exact WireCost.digest_bound _
    · exact WireCost.optional_digest_bound _
    · exact WireCost.digest_bound _
    · exact WireCost.uint_bound _
    · exact observation_satisfactions_bound _
    · exact approval_satisfactions_bound _
  have cost : WireCost.mapCost fields = ResultObjects.resultCost value := by
    simp only [WireCost.mapCost, fields, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    simp only [ResultObjects.resultCost, List.sum_cons, List.sum_nil]
    omega
  have wire : WireCost.mapBytes fields = ResultObjects.result include value := by rfl
  simpa only [cost, wire] using WireCost.map_bound fields components

theorem parameter_fields (value : auths_model.ClaimParameterId × auths_model.ClaimParameterId)
    (bounded : ContextObjects.parameterCost value ≤ U32.max) : ContextAssurance.ParameterStrings value := by
  simp only [ContextObjects.parameterCost] at bounded
  constructor <;> omega

theorem claim_fields (value : auths_model.AssuranceClaim) (bounded : ResultObjects.claimCost value ≤ U32.max) :
    ResultAssurance.ClaimFields value := by
  have budget := bounded
  simp only [ResultObjects.claimCost] at budget
  refine ⟨by omega, ?_, by omega⟩
  intro parameter member
  have item := WireCost.member_cost ContextObjects.parameterCost value.parameters.val parameter member
  exact parameter_fields parameter (by omega)

theorem report_fields (value : auths_model.ParticipantAssurance) (bounded : ResultObjects.reportCost value ≤ U32.max) :
    ResultAssurance.ReportFields value := by
  have budget := bounded
  simp only [ResultObjects.reportCost] at budget
  refine ⟨by omega, ?_, by omega⟩
  intro claim member
  have item := WireCost.member_cost ResultObjects.claimCost value.claims.val claim member
  exact claim_fields claim (by omega)

theorem satisfaction_fields (value : auths_model.AssuranceSatisfaction)
    (bounded : ResultObjects.assuranceSatisfactionCost value ≤ U32.max) : ResultAssurance.SatisfactionFields value := by
  have budget := bounded
  simp only [ResultObjects.assuranceSatisfactionCost] at budget
  exact ⟨by omega, claim_fields value.claim (by omega)⟩

theorem fields_from_cost (value : auths_model.PortableVerificationResult)
    (bounded : ResultObjects.resultCost value ≤ U32.max) : ResultWriters.Fields value := by
  have budget := bounded
  simp only [ResultObjects.resultCost, List.sum_cons, List.sum_nil] at budget
  constructor
  · intro report member
    have item := WireCost.member_cost ResultObjects.reportCost value.assurance.val report member
    exact report_fields report (by omega)
  · intro satisfaction member
    have item := WireCost.member_cost ResultObjects.assuranceSatisfactionCost value.assurance_satisfactions.val satisfaction member
    exact satisfaction_fields satisfaction (by omega)

theorem resources (include : Bool) (value : auths_model.PortableVerificationResult)
    (fits : (ResultObjects.result include value).length ≤ 8388608) :
    ResultWriters.Fields value ∧ ResultObjects.resultCost value ≤ Usize.max ∧
      (2 * ResultObjects.resultCost value : Int) ≤ Isize.max := by
  have budget := result_bound include value
  unfold WireCost.Dominates at budget
  have cost : ResultObjects.resultCost value ≤ 41 * 8388608 := by omega
  refine ⟨fields_from_cost value (by scalar_tac), ?_, ?_⟩ <;> scalar_tac

@[step] theorem projection_encoder_bounded (value : auths_model.PortableVerificationResult) (include : Bool)
    (fits : (ResultObjects.result include value).length ≤ 8388608) :
    encode.encode_verification_result_projection value include ⦃ result => Encodes (ResultObjects.result include value) result ⦄ := by
  obtain ⟨fields, space, native⟩ := resources include value fits
  exact ResultWriters.projection_encoder value include fields space native

@[step] theorem canonical_encoder_bounded
    (carrier : canonical_value.Canonical auths_model.PortableVerificationResult)
    (value : auths_model.PortableVerificationResult) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (fits : (ResultObjects.result true value).length ≤ 8388608) :
    encode.encode_verification_result carrier ⦃ result => Encodes (ResultObjects.result true value) result ⦄ := by
  obtain ⟨fields, space, native⟩ := resources true value fits
  exact ResultWriters.canonical_encoder carrier value projection fields space native

theorem digest_bounded_exact [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256)
    (value : auths_model.PortableVerificationResult)
    (fits : (ResultObjects.result false value).length ≤ 8388608) :
    hash.verification_result_digest value = ok (.Ok (sha256 (ResultObjects.result false value))) := by
  obtain ⟨fields, space, native⟩ := resources false value fits
  exact ResultCommitments.digest_exact sha256 contract value fields space native

end Auths.Crypto.ResultCost
