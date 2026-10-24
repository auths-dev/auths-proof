import Auths.Crypto.BundleArrays
import Auths.Crypto.BundleNormalization
import Auths.Crypto.BorrowedFields

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BundleWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Crypto.SigningObjectWriters

/- Concrete input conditions, not a successful decoder/encoder/normalizer or
trusted flag. Constructor/public-decoder closure must earn these conditions
at byte-to-authority callers. Source normalization and all eleven encoded
fields are composed below; signature authenticity remains separate. -/
structure Fields (value : auths_model.ProofBundle) : Prop where
  grants : ∀ record ∈ value.grants.val, SignedObjectWriters.GrantStrings record
  actions : ∀ record ∈ value.actions.val, SignedObjectWriters.ActionStrings record
  evidence : ∀ record ∈ value.evidence.val, EvidenceWriters.Strings record
  principal : ∀ record ∈ value.principal_status.val, SignedObjectWriters.PrincipalStatusStrings record
  grantStatus : ∀ record ∈ value.grant_status.val, SignedObjectWriters.GrantStatusStrings record
  attachments : ∀ record ∈ value.attachments.val, ProtocolArrayWriters.AttachmentStrings record
  approvals : ∀ record ∈ value.approvals.val, SignedObjectWriters.ApprovalStrings record

structure Dimensions (value : auths_model.ProofBundle) : Prop where
  grants : BorrowedKeys.ReferenceCapacity value.grants.val.length
  actions : BorrowedKeys.ReferenceCapacity value.actions.val.length
  evidence : BorrowedKeys.ReferenceCapacity value.evidence.val.length
  bindings : BorrowedKeys.ReferenceCapacity value.bindings.val.length
  principal : BorrowedKeys.ReferenceCapacity value.principal_status.val.length
  grantStatus : BorrowedKeys.ReferenceCapacity value.grant_status.val.length
  attachments : BorrowedKeys.ReferenceCapacity value.attachments.val.length

structure IdentifierDomains (value : auths_model.ProofBundle) : Prop where
  grants : ∀ record ∈ value.grants.val, BorrowedKeys.GrantDomain record
  principal : ∀ record ∈ value.principal_status.val, BorrowedKeys.PrincipalStatusDomain record
  grantStatus : ∀ record ∈ value.grant_status.val, BorrowedKeys.GrantStatusDomain record

theorem fields_sorted {Value Key : Type} [LinearOrder Key] (key : Value → Key)
    (predicate : Value → Prop) (values : List Value) (fields : ∀ value ∈ values, predicate value) :
    ∀ value ∈ StableNormalization.sort key values, predicate value := by
  intro value member
  exact fields value ((StableNormalization.permutation key values).mem_iff.mp member)

theorem records_success {Value : Type} {expected : List Value}
    {effect : Result (core.result.Result (alloc.vec.Vec Value) error.CodecError)}
    (specified : effect ⦃ result => match result with
      | .Err _ => False | .Ok output => output.val = expected ⦄) :
    ∃ output, effect = ok (.Ok output) ∧ output.val = expected := by
  obtain ⟨result, runs, meaning⟩ := spec_imp_exists specified
  cases result with
  | Err reason => exact False.elim meaning
  | Ok output => exact ⟨output, runs, meaning⟩

variable [primitive : Sha256Primitives]

@[step] theorem bundle_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (self : cbor.Encoder) (value : auths_model.ProofBundle)
    (fields : Fields value) (dimensions : Dimensions value) (domains : IdentifierDomains value)
    (space : self.output.val.length + BundleObjects.cost value ≤ Usize.max)
    (native : (2 * (self.output.val.length + BundleObjects.cost value) : Int) ≤ Isize.max) :
    encode.encode_bundle_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ BundleObjects.bundle sha256 value ⦄ := by
  obtain ⟨grants, grantsRun, grantsOrder⟩ := records_success
    (BundleNormalization.grant_exact sha256 contract value domains.grants dimensions.grants)
  obtain ⟨principal, principalRun, principalOrder⟩ := records_success
    (BundleNormalization.principal_status_exact sha256 contract (alloc.vec.Vec.deref value.principal_status)
      (by simpa only [alloc.vec.deref_exact] using domains.principal)
      (by simpa only [alloc.vec.deref_exact] using dimensions.principal))
  obtain ⟨grantStatus, grantStatusRun, grantStatusOrder⟩ := records_success
    (BundleNormalization.grant_status_exact sha256 contract (alloc.vec.Vec.deref value.grant_status)
      (by simpa only [alloc.vec.deref_exact] using domains.grantStatus)
      (by simpa only [alloc.vec.deref_exact] using dimensions.grantStatus))
  obtain ⟨actions, actionsRun, actionsOrder⟩ := spec_imp_exists
    (BorrowedFields.action_exact (alloc.vec.Vec.deref value.actions)
      (by simpa only [alloc.vec.deref_exact] using dimensions.actions))
  obtain ⟨evidence, evidenceRun, evidenceOrder⟩ := spec_imp_exists
    (BorrowedFields.evidence_exact (alloc.vec.Vec.deref value.evidence)
      (by simpa only [alloc.vec.deref_exact] using dimensions.evidence))
  obtain ⟨bindings, bindingsRun, bindingsOrder⟩ := spec_imp_exists
    (BorrowedFields.binding_exact (alloc.vec.Vec.deref value.bindings)
      (by simpa only [alloc.vec.deref_exact] using dimensions.bindings))
  obtain ⟨attachments, attachmentsRun, attachmentsOrder⟩ := spec_imp_exists
    (BorrowedFields.attachment_exact (alloc.vec.Vec.deref value.attachments)
      (by simpa only [alloc.vec.deref_exact] using dimensions.attachments))
  have principalModel : principal.val = BundleObjects.principalStatus sha256 value := by
    simpa only [BundleObjects.principalStatus, alloc.vec.deref_exact] using principalOrder
  have grantStatusModel : grantStatus.val = BundleObjects.grantStatus sha256 value := by
    simpa only [BundleObjects.grantStatus, alloc.vec.deref_exact] using grantStatusOrder
  have actionsModel : actions.val = BundleObjects.actions value := by
    simpa only [BundleObjects.actions, alloc.vec.deref_exact] using actionsOrder
  have evidenceModel : evidence.val = BundleObjects.evidence value := by
    simpa only [BundleObjects.evidence, alloc.vec.deref_exact] using evidenceOrder
  have bindingsModel : bindings.val = BundleObjects.bindings value := by
    simpa only [BundleObjects.bindings, alloc.vec.deref_exact] using bindingsOrder
  have attachmentsModel : attachments.val = BundleObjects.attachments value := by
    simpa only [BundleObjects.attachments, alloc.vec.deref_exact] using attachmentsOrder
  have grantsAllocation : allocation SignedObjectWriters.grantCost grants.val =
      allocation SignedObjectWriters.grantCost value.grants.val := by
    rw [grantsOrder]
    exact BundleObjects.allocation_normalized (BundleObjects.grantKey sha256) SignedObjectWriters.grantCost value.grants.val
  have grantsFields : ∀ record ∈ grants.val, SignedObjectWriters.GrantStrings record := by
    rw [grantsOrder]
    exact fields_sorted (BundleObjects.grantKey sha256) SignedObjectWriters.GrantStrings value.grants.val fields.grants
  have actionsAllocation : allocation SignedObjectWriters.actionCost actions.val =
      allocation SignedObjectWriters.actionCost value.actions.val := by
    rw [actionsModel]
    exact BundleObjects.allocation_normalized (BundleObjects.actionKey) SignedObjectWriters.actionCost value.actions.val
  have actionsFields : ∀ record ∈ actions.val, SignedObjectWriters.ActionStrings record := by
    rw [actionsModel]
    exact fields_sorted (BundleObjects.actionKey) SignedObjectWriters.ActionStrings value.actions.val fields.actions
  have evidenceAllocation : allocation EvidenceWriters.recordCost evidence.val =
      allocation EvidenceWriters.recordCost value.evidence.val := by
    rw [evidenceModel]
    exact BundleObjects.allocation_normalized (BundleObjects.evidenceKey) EvidenceWriters.recordCost value.evidence.val
  have evidenceFields : ∀ record ∈ evidence.val, EvidenceWriters.Strings record := by
    rw [evidenceModel]
    exact fields_sorted (BundleObjects.evidenceKey) EvidenceWriters.Strings value.evidence.val fields.evidence
  have bindingsAllocation : allocation BundleObjects.bindingCost bindings.val =
      allocation BundleObjects.bindingCost value.bindings.val := by
    rw [bindingsModel]
    exact BundleObjects.allocation_normalized (BundleObjects.bindingKey) BundleObjects.bindingCost value.bindings.val
  have principalAllocation : allocation SignedObjectWriters.principal_statusCost principal.val =
      allocation SignedObjectWriters.principal_statusCost value.principal_status.val := by
    rw [principalModel]
    exact BundleObjects.allocation_normalized (BundleObjects.principalStatusKey sha256) SignedObjectWriters.principal_statusCost value.principal_status.val
  have principalFields : ∀ record ∈ principal.val, SignedObjectWriters.PrincipalStatusStrings record := by
    rw [principalModel]
    exact fields_sorted (BundleObjects.principalStatusKey sha256) SignedObjectWriters.PrincipalStatusStrings value.principal_status.val fields.principal
  have grantStatusAllocation : allocation SignedObjectWriters.grant_statusCost grantStatus.val =
      allocation SignedObjectWriters.grant_statusCost value.grant_status.val := by
    rw [grantStatusModel]
    exact BundleObjects.allocation_normalized (BundleObjects.grantStatusKey sha256) SignedObjectWriters.grant_statusCost value.grant_status.val
  have grantStatusFields : ∀ record ∈ grantStatus.val, SignedObjectWriters.GrantStatusStrings record := by
    rw [grantStatusModel]
    exact fields_sorted (BundleObjects.grantStatusKey sha256) SignedObjectWriters.GrantStatusStrings value.grant_status.val fields.grantStatus
  have attachmentsAllocation : allocation UnsignedLeaves.attachmentCost attachments.val =
      allocation UnsignedLeaves.attachmentCost value.attachments.val := by
    rw [attachmentsModel]
    exact BundleObjects.allocation_normalized (BundleObjects.attachmentKey) UnsignedLeaves.attachmentCost value.attachments.val
  have attachmentsFields : ∀ record ∈ attachments.val, ProtocolArrayWriters.AttachmentStrings record := by
    rw [attachmentsModel]
    exact fields_sorted (BundleObjects.attachmentKey) ProtocolArrayWriters.AttachmentStrings value.attachments.val fields.attachments
  unfold encode.encode_bundle_to
  simp only [BundleObjects.cost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 11#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 11⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.header, bind_tc_ok]
  step with BundleLeaves.header_exact e1 value.header (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := BundleLeaves.header_length value.header
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [grantsRun, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.grant_exact e3 grants grantsFields (by rw [grantsAllocation]; omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := array_model_length UnsignedObjects.signedGrant SignedObjectWriters.grantCost SignedObjectWriters.grant_length grants.val
  rw [grantsAllocation] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.actions, core.ops.deref.DerefVec, actionsRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.action_exact e5 actions actionsFields (by rw [actionsAllocation]; omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := array_model_length UnsignedObjects.signedAction SignedObjectWriters.actionCost SignedObjectWriters.action_length actions.val
  rw [actionsAllocation] at bound6
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.plan, bind_tc_ok]
  step with PlanWriters.plan_exact e7 value.plan (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := PlanWire.encode_length (PlanWriters.viewPlan value.plan)
  change (PlanWire.encode (PlanWriters.viewPlan value.plan)).length ≤ PlanWriters.cost value.plan at bound8
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.evidence, core.ops.deref.DerefVec, evidenceRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.evidence_exact e9 evidence evidenceFields (by rw [evidenceAllocation]; omega) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := array_model_length UnsignedObjects.evidence EvidenceWriters.recordCost EvidenceWriters.record_length evidence.val
  rw [evidenceAllocation] at bound10
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.bindings, core.ops.deref.DerefVec, bindingsRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.binding_exact e11 bindings (by simp) (by rw [bindingsAllocation]; omega) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := array_model_length BundleObjects.binding BundleObjects.bindingCost BundleLeaves.binding_length bindings.val
  rw [bindingsAllocation] at bound12
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.principal_status, core.ops.deref.DerefVec, principalRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.principal_status_exact e13 principal principalFields (by rw [principalAllocation]; omega) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := array_model_length UnsignedObjects.signedPrincipalStatus SignedObjectWriters.principal_statusCost SignedObjectWriters.principal_status_length principal.val
  rw [principalAllocation] at bound14
  simp only [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega) as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.grant_status, core.ops.deref.DerefVec, grantStatusRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.grant_status_exact e15 grantStatus grantStatusFields (by rw [grantStatusAllocation]; omega) as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := array_model_length UnsignedObjects.signedGrantStatus SignedObjectWriters.grant_statusCost SignedObjectWriters.grant_status_length grantStatus.val
  rw [grantStatusAllocation] at bound16
  simp only [ok16, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega) as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.attachments, core.ops.deref.DerefVec, attachmentsRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.attachment_exact e17 attachments attachmentsFields (by rw [attachmentsAllocation]; omega) as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := array_model_length UnsignedObjects.attachment UnsignedLeaves.attachmentCost UnsignedLeaves.attachment_length_bound attachments.val
  rw [attachmentsAllocation] at bound18
  simp only [ok18, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega) as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [BundleLeaves.body_projection, bind_tc_ok]
  step with BundleLeaves.optional_body_exact e19 (BundleObjects.bodySlices value.canonical_body) (by rw [BundleObjects.body_slice_cost]; omega) as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := BundleLeaves.optional_bytes_length value.canonical_body
  rw [BundleObjects.body_slice_bytes] at bytes20 len20
  simp only [ok20, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega) as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofBundle.impl.approvals, core.ops.deref.DerefVec, bind_tc_ok]
  step with BundleArrays.approval_exact e21 (alloc.vec.Vec.deref value.approvals) fields.approvals (by simpa only [alloc.vec.deref_exact] using (show e21.output.val.length + 9 + allocation SignedObjectWriters.approvalCost value.approvals.val ≤ Usize.max by omega)) as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := array_model_length UnsignedObjects.signedApproval SignedObjectWriters.approvalCost SignedObjectWriters.approval_length value.approvals.val
  simp [ok22, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, BundleObjects.bundle, grantsOrder, actionsModel, evidenceModel, bindingsModel, principalModel, grantStatusModel, attachmentsModel,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem bundle_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.ProofBundle)
    (fields : Fields value) (dimensions : Dimensions value) (domains : IdentifierDomains value)
    (space : BundleObjects.cost value ≤ Usize.max)
    (native : (2 * BundleObjects.cost value : Int) ≤ Isize.max) :
    encode.encode_bundle_value value ⦃ result => Encodes (BundleObjects.bundle sha256 value) result ⦄ := by
  unfold encode.encode_bundle_value
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with bundle_exact sha256 contract (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value fields dimensions domains
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using native)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem canonical_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.ProofBundle)
    (value : auths_model.ProofBundle) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (fields : Fields value) (dimensions : Dimensions value) (domains : IdentifierDomains value)
    (space : BundleObjects.cost value ≤ Usize.max)
    (native : (2 * BundleObjects.cost value : Int) ≤ Isize.max) :
    encode.encode_bundle carrier ⦃ result => Encodes (BundleObjects.bundle sha256 value) result ⦄ := by
  unfold encode.encode_bundle
  rw [projection]
  simpa only [bind_tc_ok] using bundle_encoder sha256 contract value fields dimensions domains space native

theorem canonical_projection (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.ProofBundle) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (fields : Fields value) (dimensions : Dimensions value) (domains : IdentifierDomains value)
        (space : BundleObjects.cost value ≤ Usize.max)
        (native : (2 * BundleObjects.cost value : Int) ≤ Isize.max),
        encode.encode_bundle carrier ⦃ result => Encodes (BundleObjects.bundle sha256 value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun fields dimensions domains space native =>
    canonical_encoder sha256 contract carrier value projection fields dimensions domains space native⟩

end Auths.Crypto.BundleWriters
