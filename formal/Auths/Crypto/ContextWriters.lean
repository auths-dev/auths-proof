import Auths.Crypto.ContextLimits
import Auths.Crypto.ContextAnchorArrays
import Auths.Crypto.ContextAssurance
import Auths.Crypto.ContextApproval
import Auths.Crypto.SnapshotWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Crypto.SigningObjectWriters

/- Complete actual context encoding, including real snapshot and requirement
normalization. All fields are independent input projections; no successful
writer/normalizer, accepted context flag or expected bytes is supplied. This
wire statement alone grants no authority to configuration data or a carrier. -/
structure Fields (value : auths_model.TrustedContext) : Prop where
  anchors : ∀ anchor ∈ value.trust_anchors.val, ContextAnchors.AnchorStrings anchor
  registries : ContextAnchors.RegistriesStrings value.accepted_registries
  audience : value.expected_audience.toByteArray.size ≤ U32.max
  assurance : ContextAssurance.PolicyStrings value.assurance_policy
  principal : SnapshotWriters.PrincipalFields value.principal_status_snapshot
  grant : SnapshotWriters.GrantFields value.grant_status_snapshot
  matcher : value.resource_matcher.toByteArray.size ≤ U32.max
  profile : value.profile_policy.toByteArray.size ≤ U32.max
  channel : value.channel_policy.toByteArray.size ≤ U32.max
  observers : ∀ anchor ∈ value.observer_anchors.val, ContextAnchors.ObserverStrings anchor
  approvers : ∀ anchor ∈ value.approver_anchors.val, ContextAnchors.ApproverStrings anchor

structure Domains (value : auths_model.TrustedContext) : Prop where
  principal : ∀ record ∈ value.principal_status_snapshot.statements.val, BorrowedKeys.PrincipalStatusDomain record
  grant : ∀ record ∈ value.grant_status_snapshot.statements.val, BorrowedKeys.GrantStatusDomain record
  approvals : ∀ requirement ∈ value.approval_requirements.val, ContextApproval.Domain requirement

structure Dimensions (value : auths_model.TrustedContext) : Prop where
  principal : BorrowedKeys.ReferenceCapacity value.principal_status_snapshot.statements.val.length
  grant : BorrowedKeys.ReferenceCapacity value.grant_status_snapshot.statements.val.length
  approvals : value.approval_requirements.val.length ≤ 64

variable [primitive : Sha256Primitives]

theorem context_length (sha256 : List Nat → auths_model.Digest) (value : auths_model.TrustedContext) :
    (ContextObjects.context sha256 value).length ≤ ContextObjects.contextCost value := by
  have outer := UnsignedWire.map_length [(0, ContextObjects.limits value.limits),
    (1, UnsignedObjects.digest value.configuration), (2, ContextObjects.composition value.composition),
    (3, UnsignedWire.array (value.trust_anchors.val.map ContextObjects.anchor)),
    (4, ContextObjects.registries value.accepted_registries), (5, UnsignedObjects.identifier value.expected_audience),
    (6, UnsignedObjects.digest value.expected_challenge), (7, UnsignedWire.uint value.evaluation_time.val),
    (8, ContextObjects.assurancePolicy value.assurance_policy),
    (9, SnapshotObjects.principalSnapshot sha256 value.principal_status_snapshot),
    (10, SnapshotObjects.grantSnapshot sha256 value.grant_status_snapshot),
    (11, UnsignedObjects.identifier value.resource_matcher), (12, UnsignedObjects.identifier value.profile_policy),
    (13, UnsignedObjects.identifier value.channel_policy),
    (14, UnsignedWire.array (value.observer_anchors.val.map ContextObjects.observer)),
    (15, UnsignedWire.array (value.approver_anchors.val.map ContextObjects.approver)),
    (16, ContextObjects.approvalRequirements sha256 value.approval_requirements.val)]
  have limits := ContextLimits.limits_length value.limits
  have configuration := UnsignedLeaves.digest_length value.configuration
  have composition := ContextLimits.composition_length value.composition
  have anchors := array_model_length ContextObjects.anchor ContextObjects.anchorCost ContextAnchors.anchor_length value.trust_anchors.val
  have registries := ContextAnchors.registries_length value.accepted_registries
  have audience := UnsignedLeaves.identifier_length value.expected_audience
  have challenge := UnsignedLeaves.digest_length value.expected_challenge
  have time := UnsignedWire.uint_length value.evaluation_time.val
  have assurance := ContextAssurance.policy_length value.assurance_policy
  have principal := SnapshotWriters.principal_length sha256 value.principal_status_snapshot
  have grant := SnapshotWriters.grant_length sha256 value.grant_status_snapshot
  have matcher := UnsignedLeaves.identifier_length value.resource_matcher
  have profile := UnsignedLeaves.identifier_length value.profile_policy
  have channel := UnsignedLeaves.identifier_length value.channel_policy
  have observers := array_model_length ContextObjects.observer ContextObjects.observerCost ContextAnchors.observer_length value.observer_anchors.val
  have approvers := array_model_length ContextObjects.approver ContextObjects.approverCost ContextAnchors.approver_length value.approver_anchors.val
  have requirements := array_model_length UnsignedObjects.approvalRequirement RequirementWriters.approvalCost
    RequirementWriters.approval_length (StableNormalization.sort (ContextObjects.approvalKey sha256) value.approval_requirements.val)
  simp only [BundleObjects.allocation_normalized] at requirements
  simp only [ContextObjects.approvalRequirements] at outer
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.contextCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem context_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (self : cbor.Encoder) (value : auths_model.TrustedContext)
    (fields : Fields value) (domains : Domains value) (dimensions : Dimensions value)
    (space : self.output.val.length + ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * (self.output.val.length + ContextObjects.contextCost value) : Int) ≤ Isize.max) :
    encode.encode_verifier_context_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.context sha256 value ⦄ := by
  unfold encode.encode_verifier_context_to
  simp only [ContextObjects.contextCost, List.sum_cons, List.sum_nil] at space native
  step with ProtocolWriter.map_exact self 17#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 17⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.limits, bind_tc_ok]
  step with ContextLimits.limits_exact e1 value.limits (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := ContextLimits.limits_length value.limits
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.configuration, auths_model.VerifierConfigurationId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e3 value.configuration (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := UnsignedLeaves.digest_length value.configuration
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.composition, bind_tc_ok]
  step with ContextLimits.composition_exact e5 value.composition (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := ContextLimits.composition_length value.composition
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.trust_anchors, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextAnchorArrays.anchors_exact e7 (alloc.vec.Vec.deref value.trust_anchors) fields.anchors (by simpa only [alloc.vec.deref_exact] using (show e7.output.val.length + 9 + allocation ContextObjects.anchorCost value.trust_anchors.val ≤ Usize.max by omega)) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := array_model_length ContextObjects.anchor ContextObjects.anchorCost ContextAnchors.anchor_length value.trust_anchors.val
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.accepted_registries, bind_tc_ok]
  step with ContextAnchors.registries_exact e9 value.accepted_registries fields.registries (by omega) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := ContextAnchors.registries_length value.accepted_registries
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.expected_audience, auths_model.Audience.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.expected_audience fields.audience]
  simp only [bind_tc_ok]
  have borrowLength12 : (toStr value.expected_audience fields.audience).val.length = value.expected_audience.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e11 (toStr value.expected_audience fields.audience) (by omega) as ⟨r12, e12, ok12, bytes12⟩
  rw [borrowed_bytes] at bytes12
  have len12 := output_length bytes12
  have bound12 := payload_length_bound 3 (stringBytes value.expected_audience)
  rw [stringBytes_length] at bound12
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.expected_challenge, auths_model.Challenge.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e13 value.expected_challenge (by omega) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := UnsignedLeaves.digest_length value.expected_challenge
  simp only [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega) as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.evaluation_time, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e15 value.evaluation_time (by omega) as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := encodeHead_length_le_nine ⟨0, (value.evaluation_time).val⟩
  simp only [ok16, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega) as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.assurance_policy, bind_tc_ok]
  step with ContextAssurance.policy_exact e17 value.assurance_policy fields.assurance (by omega) as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := ContextAssurance.policy_length value.assurance_policy
  simp only [ok18, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega) as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.principal_status_snapshot, bind_tc_ok]
  step with SnapshotWriters.principal_exact sha256 contract e19 value.principal_status_snapshot fields.principal domains.principal dimensions.principal (by omega) (by omega) as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := SnapshotWriters.principal_length sha256 value.principal_status_snapshot
  simp only [ok20, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega) as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.grant_status_snapshot, bind_tc_ok]
  step with SnapshotWriters.grant_exact sha256 contract e21 value.grant_status_snapshot fields.grant domains.grant dimensions.grant (by omega) (by omega) as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := SnapshotWriters.grant_length sha256 value.grant_status_snapshot
  simp only [ok22, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e22 11#u8 (by omega) as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := encodeHead_length_le_nine ⟨0, 11⟩
  simp only [ok23, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.resource_matcher, auths_model.ResourceMatcherId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.resource_matcher fields.matcher]
  simp only [bind_tc_ok]
  have borrowLength24 : (toStr value.resource_matcher fields.matcher).val.length = value.resource_matcher.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e23 (toStr value.resource_matcher fields.matcher) (by omega) as ⟨r24, e24, ok24, bytes24⟩
  rw [borrowed_bytes] at bytes24
  have len24 := output_length bytes24
  have bound24 := payload_length_bound 3 (stringBytes value.resource_matcher)
  rw [stringBytes_length] at bound24
  simp only [ok24, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e24 12#u8 (by omega) as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := encodeHead_length_le_nine ⟨0, 12⟩
  simp only [ok25, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.profile_policy, auths_model.ProfilePolicyId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.profile_policy fields.profile]
  simp only [bind_tc_ok]
  have borrowLength26 : (toStr value.profile_policy fields.profile).val.length = value.profile_policy.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e25 (toStr value.profile_policy fields.profile) (by omega) as ⟨r26, e26, ok26, bytes26⟩
  rw [borrowed_bytes] at bytes26
  have len26 := output_length bytes26
  have bound26 := payload_length_bound 3 (stringBytes value.profile_policy)
  rw [stringBytes_length] at bound26
  simp only [ok26, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e26 13#u8 (by omega) as ⟨r27, e27, ok27, bytes27⟩
  have len27 := output_length bytes27
  have bound27 := encodeHead_length_le_nine ⟨0, 13⟩
  simp only [ok27, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.channel_policy, auths_model.ChannelBindingId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.channel_policy fields.channel]
  simp only [bind_tc_ok]
  have borrowLength28 : (toStr value.channel_policy fields.channel).val.length = value.channel_policy.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e27 (toStr value.channel_policy fields.channel) (by omega) as ⟨r28, e28, ok28, bytes28⟩
  rw [borrowed_bytes] at bytes28
  have len28 := output_length bytes28
  have bound28 := payload_length_bound 3 (stringBytes value.channel_policy)
  rw [stringBytes_length] at bound28
  simp only [ok28, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e28 14#u8 (by omega) as ⟨r29, e29, ok29, bytes29⟩
  have len29 := output_length bytes29
  have bound29 := encodeHead_length_le_nine ⟨0, 14⟩
  simp only [ok29, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.observer_anchors, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextAnchorArrays.observers_exact e29 (alloc.vec.Vec.deref value.observer_anchors) fields.observers (by simpa only [alloc.vec.deref_exact] using (show e29.output.val.length + 9 + allocation ContextObjects.observerCost value.observer_anchors.val ≤ Usize.max by omega)) as ⟨r30, e30, ok30, bytes30⟩
  have len30 := output_length bytes30
  have bound30 := array_model_length ContextObjects.observer ContextObjects.observerCost ContextAnchors.observer_length value.observer_anchors.val
  simp only [ok30, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e30 15#u8 (by omega) as ⟨r31, e31, ok31, bytes31⟩
  have len31 := output_length bytes31
  have bound31 := encodeHead_length_le_nine ⟨0, 15⟩
  simp only [ok31, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.approver_anchors, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextAnchorArrays.approvers_exact e31 (alloc.vec.Vec.deref value.approver_anchors) fields.approvers (by simpa only [alloc.vec.deref_exact] using (show e31.output.val.length + 9 + allocation ContextObjects.approverCost value.approver_anchors.val ≤ Usize.max by omega)) as ⟨r32, e32, ok32, bytes32⟩
  have len32 := output_length bytes32
  have bound32 := array_model_length ContextObjects.approver ContextObjects.approverCost ContextAnchors.approver_length value.approver_anchors.val
  simp only [ok32, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e32 16#u8 (by omega) as ⟨r33, e33, ok33, bytes33⟩
  have len33 := output_length bytes33
  have bound33 := encodeHead_length_le_nine ⟨0, 16⟩
  simp only [ok33, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustedContext.impl.approval_requirements, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextApproval.context_exact sha256 contract e33 (alloc.vec.Vec.deref value.approval_requirements) domains.approvals dimensions.approvals (by simpa only [alloc.vec.deref_exact] using (show e33.output.val.length + 9 + allocation RequirementWriters.approvalCost value.approval_requirements.val ≤ Usize.max by omega)) as ⟨r34, e34, ok34, bytes34⟩
  have len34 := output_length bytes34
  have bound34 := array_model_length UnsignedObjects.approvalRequirement RequirementWriters.approvalCost RequirementWriters.approval_length (StableNormalization.sort (ContextObjects.approvalKey sha256) value.approval_requirements.val)
  simp only [BundleObjects.allocation_normalized] at bound34
  simp [ok34, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes34, bytes33, bytes32, bytes31, bytes30, bytes29, bytes28, bytes27, bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.context,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem context_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.TrustedContext)
    (fields : Fields value) (domains : Domains value) (dimensions : Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max) :
    encode.encode_verifier_context_value value ⦃ result => Encodes (ContextObjects.context sha256 value) result ⦄ := by
  unfold encode.encode_verifier_context_value
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with context_exact sha256 contract (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value fields domains dimensions
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using native)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem canonical_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.TrustedContext)
    (value : auths_model.TrustedContext) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (fields : Fields value) (domains : Domains value) (dimensions : Dimensions value)
    (space : ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max) :
    encode.encode_verifier_context carrier ⦃ result => Encodes (ContextObjects.context sha256 value) result ⦄ := by
  unfold encode.encode_verifier_context
  rw [projection]
  simpa only [bind_tc_ok] using context_encoder sha256 contract value fields domains dimensions space native

theorem canonical_projection (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.TrustedContext) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (fields : Fields value) (domains : Domains value) (dimensions : Dimensions value)
        (space : ContextObjects.contextCost value ≤ Usize.max)
        (native : (2 * ContextObjects.contextCost value : Int) ≤ Isize.max),
        encode.encode_verifier_context carrier ⦃ result => Encodes (ContextObjects.context sha256 value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun fields domains dimensions space native =>
    canonical_encoder sha256 contract carrier value projection fields domains dimensions space native⟩

end Auths.Crypto.ContextWriters
