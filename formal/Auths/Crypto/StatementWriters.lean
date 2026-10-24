import Auths.Crypto.UnsignedCollections

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.StatementWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolEncoderState Auths.Codec.ProtocolArrayWriters
open Auths.Crypto.UnsignedLeaves Auths.Crypto.UnsignedCollections

/- Complete unsigned source writers against independent byte schemas. These
conditions describe field borrowing and intermediate capacity, not expected
encodings, successful source calls, signature validity or trusted inputs.
Actual generated accessor and backward-borrow interfaces remain subject to
fresh extraction/elaboration in the deferred final validation pass. -/

structure GrantStrings (value : auths_model.GrantStatement) : Prop where
  issuer : value.issuer.toByteArray.size ≤ U32.max
  subject : value.subject.toByteArray.size ≤ U32.max
  profile : value.profile.id.toByteArray.size ≤ U32.max
  permissions : ∀ item ∈ value.permissions.val, PermissionStrings item
  audiences : ∀ item ∈ value.audiences.val, item.toByteArray.size ≤ U32.max
  budget : ∀ item ∈ value.budget_ceiling, item.algebra.toByteArray.size ≤ U32.max
  policy : PolicyStrings value.status_policy
  assurance : value.assurance_floor.toByteArray.size ≤ U32.max
  extensions : ∀ item ∈ value.extensions.val, ExtensionStrings item

def grantCost (value : auths_model.GrantStatement) : Nat :=
  9 + 9 * 16 + ([9,
    (9 + value.issuer.toByteArray.size),
    (9 + value.subject.toByteArray.size),
    (9 + value.profile.id.toByteArray.size),
    9,
    (permissionsCost value.permissions),
    9,
    9,
    (audiencesCost value.audiences),
    (constraintCost value.action_constraint),
    (budgetOptionCost value.budget_ceiling),
    9,
    41,
    (statusPolicyCost value.status_policy),
    (9 + value.assurance_floor.toByteArray.size),
    (extensionsCost value.extensions)] : List Nat).sum

theorem grant_length (value : auths_model.GrantStatement) :
    (UnsignedObjects.grant value).length ≤ grantCost value := by
  have outer := UnsignedWire.map_length [
    (0, UnsignedWire.uint value.version.val),
    (1, UnsignedObjects.identifier value.issuer),
    (2, UnsignedObjects.identifier value.subject),
    (3, UnsignedObjects.identifier value.profile.id),
    (4, UnsignedWire.uint value.profile.version.val),
    (5, UnsignedWire.array (value.permissions.val.map UnsignedObjects.permission)),
    (6, UnsignedWire.uint value.validity.not_before.val),
    (7, UnsignedWire.uint value.validity.expires_at.val),
    (8, UnsignedWire.array (value.audiences.val.map UnsignedObjects.identifier)),
    (9, UnsignedObjects.constraint value.action_constraint),
    (10, UnsignedObjects.optionalBudget value.budget_ceiling),
    (11, UnsignedWire.uint value.remaining_depth.val),
    (12, UnsignedObjects.optionalDigest value.parent),
    (13, UnsignedObjects.statusPolicy value.status_policy),
    (14, UnsignedObjects.identifier value.assurance_floor),
    (15, UnsignedObjects.extensions value.extensions)]
  have bound0 := UnsignedWire.uint_length value.version.val
  have bound1 := identifier_length value.issuer
  have bound2 := identifier_length value.subject
  have bound3 := identifier_length value.profile.id
  have bound4 := UnsignedWire.uint_length value.profile.version.val
  have bound5 := permissions_length value.permissions
  have bound6 := UnsignedWire.uint_length value.validity.not_before.val
  have bound7 := UnsignedWire.uint_length value.validity.expires_at.val
  have bound8 := audiences_length value.audiences
  have bound9 := constraint_length value.action_constraint
  have bound10 := optional_budget_length value.budget_ceiling
  have bound11 := UnsignedWire.uint_length value.remaining_depth.val
  have bound12 := optional_digest_length value.parent
  have bound13 := status_policy_length value.status_policy
  have bound14 := identifier_length value.assurance_floor
  have bound15 := extensions_length value.extensions
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [grantCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem grant_exact (self : cbor.Encoder) (value : auths_model.GrantStatement)
    (strings : GrantStrings value) (space : self.output.val.length + grantCost value ≤ Usize.max) :
    encode.encode_grant_statement_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.grant value ⦄ := by
  unfold encode.encode_grant_statement_to
  simp only [grantCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 16#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 16⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.version, auths_model.ProtocolVersion.get, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.version (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, value.version.val⟩
  simp only [ok2, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.issuer, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.issuer strings.issuer]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.issuer strings.issuer).val.length = value.issuer.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.issuer strings.issuer) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.issuer)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.subject, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.subject strings.subject]
  simp only [bind_tc_ok]
  have borrowLength6 : (toStr value.subject strings.subject).val.length = value.subject.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e5 (toStr value.subject strings.subject) (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  rw [borrowed_bytes] at bytes6
  have len6 := output_length bytes6
  have bound6 := payload_length_bound 3 (stringBytes value.subject)
  rw [stringBytes_length] at bound6
  simp only [ok6, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.profile, auths_model.ProfileRef.impl.id, auths_model.ProfileId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.profile.id strings.profile]
  simp only [bind_tc_ok]
  have borrowLength8 : (toStr value.profile.id strings.profile).val.length = value.profile.id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e7 (toStr value.profile.id strings.profile) (by omega)
    as ⟨r8, e8, ok8, bytes8⟩
  rw [borrowed_bytes] at bytes8
  have len8 := output_length bytes8
  have bound8 := payload_length_bound 3 (stringBytes value.profile.id)
  rw [stringBytes_length] at bound8
  simp only [ok8, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.profile, auths_model.ProfileRef.impl.version, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e9 value.profile.version (by omega)
    as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := encodeHead_length_le_nine ⟨0, value.profile.version.val⟩
  simp only [ok10, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.permissions, bind_tc_ok]
  step with UnsignedCollections.permissions_exact e11 value.permissions strings.permissions (by omega)
    as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := permissions_length value.permissions
  simp only [ok12, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega)
    as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.validity, auths_model.ValidityWindow.impl.not_before, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e13 value.validity.not_before (by omega)
    as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := encodeHead_length_le_nine ⟨0, value.validity.not_before.val⟩
  simp only [ok14, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega)
    as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.validity, auths_model.ValidityWindow.impl.expires_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e15 value.validity.expires_at (by omega)
    as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := encodeHead_length_le_nine ⟨0, value.validity.expires_at.val⟩
  simp only [ok16, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega)
    as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.audiences, auths_model.AudienceSet.impl.as_slice, auths_model.bounded.BoundedSet.impl.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
  step with UnsignedCollections.audiences_exact e17 value.audiences strings.audiences (by omega)
    as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := audiences_length value.audiences
  simp only [ok18, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega)
    as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.action_constraint, bind_tc_ok]
  step with UnsignedCollections.constraint_exact e19 value.action_constraint (by omega)
    as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := constraint_length value.action_constraint
  simp only [ok20, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega)
    as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.budget_ceiling, core.option.Option.as_ref, bind_tc_ok]
  step with UnsignedLeaves.optional_budget_exact e21 value.budget_ceiling strings.budget (by omega)
    as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := optional_budget_length value.budget_ceiling
  simp only [ok22, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e22 11#u8 (by omega)
    as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := encodeHead_length_le_nine ⟨0, 11⟩
  simp only [ok23, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.remaining_depth, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e23 value.remaining_depth (by omega)
    as ⟨r24, e24, ok24, bytes24⟩
  have len24 := output_length bytes24
  have bound24 := encodeHead_length_le_nine ⟨0, value.remaining_depth.val⟩
  simp only [ok24, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e24 12#u8 (by omega)
    as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := encodeHead_length_le_nine ⟨0, 12⟩
  simp only [ok25, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.parent, core.option.Option.as_ref, bind_tc_ok]
  rw [UnsignedLeaves.optional_grant_borrow]
  simp only [bind_tc_ok]
  step with UnsignedLeaves.optional_digest_exact e25 value.parent (by omega)
    as ⟨r26, e26, ok26, bytes26⟩
  have len26 := output_length bytes26
  have bound26 := optional_digest_length value.parent
  simp only [ok26, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e26 13#u8 (by omega)
    as ⟨r27, e27, ok27, bytes27⟩
  have len27 := output_length bytes27
  have bound27 := encodeHead_length_le_nine ⟨0, 13⟩
  simp only [ok27, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.status_policy, bind_tc_ok]
  step with UnsignedLeaves.status_policy_exact e27 value.status_policy strings.policy (by omega)
    as ⟨r28, e28, ok28, bytes28⟩
  have len28 := output_length bytes28
  have bound28 := status_policy_length value.status_policy
  simp only [ok28, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e28 14#u8 (by omega)
    as ⟨r29, e29, ok29, bytes29⟩
  have len29 := output_length bytes29
  have bound29 := encodeHead_length_le_nine ⟨0, 14⟩
  simp only [ok29, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.assurance_floor, auths_model.AssurancePolicyId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.assurance_floor strings.assurance]
  simp only [bind_tc_ok]
  have borrowLength30 : (toStr value.assurance_floor strings.assurance).val.length = value.assurance_floor.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e29 (toStr value.assurance_floor strings.assurance) (by omega)
    as ⟨r30, e30, ok30, bytes30⟩
  rw [borrowed_bytes] at bytes30
  have len30 := output_length bytes30
  have bound30 := payload_length_bound 3 (stringBytes value.assurance_floor)
  rw [stringBytes_length] at bound30
  simp only [ok30, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e30 15#u8 (by omega)
    as ⟨r31, e31, ok31, bytes31⟩
  have len31 := output_length bytes31
  have bound31 := encodeHead_length_le_nine ⟨0, 15⟩
  simp only [ok31, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatement.impl.extensions, bind_tc_ok]
  step with UnsignedCollections.extensions_exact e31 value.extensions strings.extensions (by omega)
    as ⟨r32, e32, ok32, bytes32⟩
  have len32 := output_length bytes32
  have bound32 := extensions_length value.extensions
  simp only [ok32, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes32, bytes31, bytes30, bytes29, bytes28, bytes27, bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.grant, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, stringBytes, payloadEncoding, alloc.vec.deref_exact, List.append_assoc]

structure ActionStrings (value : auths_model.ActionEnvelope) : Prop where
  profile : value.profile.id.toByteArray.size ≤ U32.max
  media : value.body_media_type.toByteArray.size ≤ U32.max
  capability : value.permission.capability.toByteArray.size ≤ U32.max
  resource : value.permission.resource.toByteArray.size ≤ U32.max
  budget : ∀ item ∈ value.requested_budget, item.algebra.toByteArray.size ≤ U32.max
  audience : value.audience.toByteArray.size ≤ U32.max
  actor : value.actor.toByteArray.size ≤ U32.max
  channel : value.channel_binding.toByteArray.size ≤ U32.max
  attachments : ∀ item ∈ value.attachments.val, AttachmentStrings item
  extensions : ∀ item ∈ value.extensions.val, ExtensionStrings item

def actionCost (value : auths_model.ActionEnvelope) : Nat :=
  9 + 9 * 19 + ([9,
    (9 + value.profile.id.toByteArray.size),
    9,
    (9 + value.body_media_type.toByteArray.size),
    41,
    (9 + value.permission.capability.toByteArray.size),
    (9 + value.permission.resource.toByteArray.size),
    (budgetOptionCost value.requested_budget),
    (9 + value.audience.toByteArray.size),
    41,
    9,
    9,
    (9 + value.actor.toByteArray.size),
    41,
    41,
    (9 + value.channel_binding.toByteArray.size),
    41,
    (attachmentsCost value.attachments),
    (extensionsCost value.extensions)] : List Nat).sum

theorem action_length (value : auths_model.ActionEnvelope) :
    (UnsignedObjects.action value).length ≤ actionCost value := by
  have outer := UnsignedWire.map_length [
    (0, UnsignedWire.uint value.version.val),
    (1, UnsignedObjects.identifier value.profile.id),
    (2, UnsignedWire.uint value.profile.version.val),
    (3, UnsignedObjects.identifier value.body_media_type),
    (4, UnsignedObjects.digest value.canonical_body_digest),
    (5, UnsignedObjects.identifier value.permission.capability),
    (6, UnsignedObjects.identifier value.permission.resource),
    (7, UnsignedObjects.optionalBudget value.requested_budget),
    (8, UnsignedObjects.identifier value.audience),
    (9, UnsignedObjects.digest value.challenge),
    (10, UnsignedWire.uint value.validity.not_before.val),
    (11, UnsignedWire.uint value.validity.expires_at.val),
    (12, UnsignedObjects.identifier value.actor),
    (13, UnsignedObjects.optionalDigest value.terminal_grant),
    (14, UnsignedObjects.digest value.authorization_plan),
    (15, UnsignedObjects.identifier value.channel_binding),
    (16, UnsignedObjects.digest value.proof_ref),
    (17, UnsignedWire.array (value.attachments.val.map UnsignedObjects.attachment)),
    (18, UnsignedObjects.extensions value.extensions)]
  have bound0 := UnsignedWire.uint_length value.version.val
  have bound1 := identifier_length value.profile.id
  have bound2 := UnsignedWire.uint_length value.profile.version.val
  have bound3 := identifier_length value.body_media_type
  have bound4 := digest_length value.canonical_body_digest
  have bound5 := identifier_length value.permission.capability
  have bound6 := identifier_length value.permission.resource
  have bound7 := optional_budget_length value.requested_budget
  have bound8 := identifier_length value.audience
  have bound9 := digest_length value.challenge
  have bound10 := UnsignedWire.uint_length value.validity.not_before.val
  have bound11 := UnsignedWire.uint_length value.validity.expires_at.val
  have bound12 := identifier_length value.actor
  have bound13 := optional_digest_length value.terminal_grant
  have bound14 := digest_length value.authorization_plan
  have bound15 := identifier_length value.channel_binding
  have bound16 := digest_length value.proof_ref
  have bound17 := attachments_length value.attachments
  have bound18 := extensions_length value.extensions
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [actionCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem action_exact (self : cbor.Encoder) (value : auths_model.ActionEnvelope)
    (strings : ActionStrings value) (space : self.output.val.length + actionCost value ≤ Usize.max) :
    encode.encode_action_envelope_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.action value ⦄ := by
  unfold encode.encode_action_envelope_to
  simp only [actionCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 19#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 19⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.version, auths_model.ProtocolVersion.get, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.version (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, value.version.val⟩
  simp only [ok2, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.profile, auths_model.ProfileRef.impl.id, auths_model.ProfileId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.profile.id strings.profile]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.profile.id strings.profile).val.length = value.profile.id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.profile.id strings.profile) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.profile.id)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.profile, auths_model.ProfileRef.impl.version, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e5 value.profile.version (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := encodeHead_length_le_nine ⟨0, value.profile.version.val⟩
  simp only [ok6, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.body_media_type, auths_model.MediaType.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.body_media_type strings.media]
  simp only [bind_tc_ok]
  have borrowLength8 : (toStr value.body_media_type strings.media).val.length = value.body_media_type.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e7 (toStr value.body_media_type strings.media) (by omega)
    as ⟨r8, e8, ok8, bytes8⟩
  rw [borrowed_bytes] at bytes8
  have len8 := output_length bytes8
  have bound8 := payload_length_bound 3 (stringBytes value.body_media_type)
  rw [stringBytes_length] at bound8
  simp only [ok8, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.canonical_body_digest, auths_model.Digest.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e9 value.canonical_body_digest (by omega)
    as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := digest_length value.canonical_body_digest
  simp only [ok10, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.permission, auths_model.Permission.impl.capability, auths_model.CapabilityId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.permission.capability strings.capability]
  simp only [bind_tc_ok]
  have borrowLength12 : (toStr value.permission.capability strings.capability).val.length = value.permission.capability.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e11 (toStr value.permission.capability strings.capability) (by omega)
    as ⟨r12, e12, ok12, bytes12⟩
  rw [borrowed_bytes] at bytes12
  have len12 := output_length bytes12
  have bound12 := payload_length_bound 3 (stringBytes value.permission.capability)
  rw [stringBytes_length] at bound12
  simp only [ok12, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega)
    as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.permission, auths_model.Permission.impl.resource, auths_model.ResourceId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.permission.resource strings.resource]
  simp only [bind_tc_ok]
  have borrowLength14 : (toStr value.permission.resource strings.resource).val.length = value.permission.resource.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e13 (toStr value.permission.resource strings.resource) (by omega)
    as ⟨r14, e14, ok14, bytes14⟩
  rw [borrowed_bytes] at bytes14
  have len14 := output_length bytes14
  have bound14 := payload_length_bound 3 (stringBytes value.permission.resource)
  rw [stringBytes_length] at bound14
  simp only [ok14, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega)
    as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.requested_budget, core.option.Option.as_ref, bind_tc_ok]
  step with UnsignedLeaves.optional_budget_exact e15 value.requested_budget strings.budget (by omega)
    as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := optional_budget_length value.requested_budget
  simp only [ok16, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega)
    as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.audience, auths_model.Audience.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.audience strings.audience]
  simp only [bind_tc_ok]
  have borrowLength18 : (toStr value.audience strings.audience).val.length = value.audience.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e17 (toStr value.audience strings.audience) (by omega)
    as ⟨r18, e18, ok18, bytes18⟩
  rw [borrowed_bytes] at bytes18
  have len18 := output_length bytes18
  have bound18 := payload_length_bound 3 (stringBytes value.audience)
  rw [stringBytes_length] at bound18
  simp only [ok18, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega)
    as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.challenge, auths_model.Challenge.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e19 value.challenge (by omega)
    as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := digest_length value.challenge
  simp only [ok20, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega)
    as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.validity, auths_model.ValidityWindow.impl.not_before, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e21 value.validity.not_before (by omega)
    as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := encodeHead_length_le_nine ⟨0, value.validity.not_before.val⟩
  simp only [ok22, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e22 11#u8 (by omega)
    as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := encodeHead_length_le_nine ⟨0, 11⟩
  simp only [ok23, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.validity, auths_model.ValidityWindow.impl.expires_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e23 value.validity.expires_at (by omega)
    as ⟨r24, e24, ok24, bytes24⟩
  have len24 := output_length bytes24
  have bound24 := encodeHead_length_le_nine ⟨0, value.validity.expires_at.val⟩
  simp only [ok24, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e24 12#u8 (by omega)
    as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := encodeHead_length_le_nine ⟨0, 12⟩
  simp only [ok25, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.actor, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.actor strings.actor]
  simp only [bind_tc_ok]
  have borrowLength26 : (toStr value.actor strings.actor).val.length = value.actor.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e25 (toStr value.actor strings.actor) (by omega)
    as ⟨r26, e26, ok26, bytes26⟩
  rw [borrowed_bytes] at bytes26
  have len26 := output_length bytes26
  have bound26 := payload_length_bound 3 (stringBytes value.actor)
  rw [stringBytes_length] at bound26
  simp only [ok26, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e26 13#u8 (by omega)
    as ⟨r27, e27, ok27, bytes27⟩
  have len27 := output_length bytes27
  have bound27 := encodeHead_length_le_nine ⟨0, 13⟩
  simp only [ok27, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.terminal_grant, core.option.Option.as_ref, bind_tc_ok]
  rw [UnsignedLeaves.optional_grant_borrow]
  simp only [bind_tc_ok]
  step with UnsignedLeaves.optional_digest_exact e27 value.terminal_grant (by omega)
    as ⟨r28, e28, ok28, bytes28⟩
  have len28 := output_length bytes28
  have bound28 := optional_digest_length value.terminal_grant
  simp only [ok28, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e28 14#u8 (by omega)
    as ⟨r29, e29, ok29, bytes29⟩
  have len29 := output_length bytes29
  have bound29 := encodeHead_length_le_nine ⟨0, 14⟩
  simp only [ok29, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.authorization_plan, auths_model.AuthorizationPlanRef.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e29 value.authorization_plan (by omega)
    as ⟨r30, e30, ok30, bytes30⟩
  have len30 := output_length bytes30
  have bound30 := digest_length value.authorization_plan
  simp only [ok30, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e30 15#u8 (by omega)
    as ⟨r31, e31, ok31, bytes31⟩
  have len31 := output_length bytes31
  have bound31 := encodeHead_length_le_nine ⟨0, 15⟩
  simp only [ok31, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.channel_binding, auths_model.ChannelBindingId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.channel_binding strings.channel]
  simp only [bind_tc_ok]
  have borrowLength32 : (toStr value.channel_binding strings.channel).val.length = value.channel_binding.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e31 (toStr value.channel_binding strings.channel) (by omega)
    as ⟨r32, e32, ok32, bytes32⟩
  rw [borrowed_bytes] at bytes32
  have len32 := output_length bytes32
  have bound32 := payload_length_bound 3 (stringBytes value.channel_binding)
  rw [stringBytes_length] at bound32
  simp only [ok32, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e32 16#u8 (by omega)
    as ⟨r33, e33, ok33, bytes33⟩
  have len33 := output_length bytes33
  have bound33 := encodeHead_length_le_nine ⟨0, 16⟩
  simp only [ok33, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.proof_ref, auths_model.ProofRef.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e33 value.proof_ref (by omega)
    as ⟨r34, e34, ok34, bytes34⟩
  have len34 := output_length bytes34
  have bound34 := digest_length value.proof_ref
  simp only [ok34, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e34 17#u8 (by omega)
    as ⟨r35, e35, ok35, bytes35⟩
  have len35 := output_length bytes35
  have bound35 := encodeHead_length_le_nine ⟨0, 17⟩
  simp only [ok35, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.attachments, core.ops.deref.DerefVec, bind_tc_ok]
  step with UnsignedCollections.attachments_exact e35 value.attachments strings.attachments (by omega)
    as ⟨r36, e36, ok36, bytes36⟩
  have len36 := output_length bytes36
  have bound36 := attachments_length value.attachments
  simp only [ok36, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e36 18#u8 (by omega)
    as ⟨r37, e37, ok37, bytes37⟩
  have len37 := output_length bytes37
  have bound37 := encodeHead_length_le_nine ⟨0, 18⟩
  simp only [ok37, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ActionEnvelope.impl.extensions, bind_tc_ok]
  step with UnsignedCollections.extensions_exact e37 value.extensions strings.extensions (by omega)
    as ⟨r38, e38, ok38, bytes38⟩
  have len38 := output_length bytes38
  have bound38 := extensions_length value.extensions
  simp only [ok38, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes38, bytes37, bytes36, bytes35, bytes34, bytes33, bytes32, bytes31, bytes30, bytes29, bytes28, bytes27, bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.action, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, stringBytes, payloadEncoding, alloc.vec.deref_exact, List.append_assoc]

structure PrincipalStatusStrings (value : auths_model.PrincipalStatusStatement) : Prop where
  method : value.method.toByteArray.size ≤ U32.max
  principal : value.principal.toByteArray.size ≤ U32.max
  issuer : value.issuer.toByteArray.size ≤ U32.max
  extensions : ∀ item ∈ value.extensions.val, ExtensionStrings item

def principal_statusCost (value : auths_model.PrincipalStatusStatement) : Nat :=
  9 + 9 * 9 + ([9,
    (9 + value.method.toByteArray.size),
    (9 + value.principal.toByteArray.size),
    9,
    9,
    9,
    9,
    (9 + value.issuer.toByteArray.size),
    (extensionsCost value.extensions)] : List Nat).sum

theorem principal_status_length (value : auths_model.PrincipalStatusStatement) :
    (UnsignedObjects.principalStatus value).length ≤ principal_statusCost value := by
  have outer := UnsignedWire.map_length [
    (0, UnsignedWire.uint value.version.val),
    (1, UnsignedObjects.identifier value.method),
    (2, UnsignedObjects.identifier value.principal),
    (3, UnsignedWire.uint (UnsignedObjects.principalState value.state)),
    (4, UnsignedWire.uint value.sequence.val),
    (5, UnsignedWire.uint value.observed_at.val),
    (6, UnsignedWire.uint value.valid_until.val),
    (7, UnsignedObjects.identifier value.issuer),
    (8, UnsignedObjects.extensions value.extensions)]
  have bound0 := UnsignedWire.uint_length value.version.val
  have bound1 := identifier_length value.method
  have bound2 := identifier_length value.principal
  have bound3 := UnsignedWire.uint_length (UnsignedObjects.principalState value.state)
  have bound4 := UnsignedWire.uint_length value.sequence.val
  have bound5 := UnsignedWire.uint_length value.observed_at.val
  have bound6 := UnsignedWire.uint_length value.valid_until.val
  have bound7 := identifier_length value.issuer
  have bound8 := extensions_length value.extensions
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [principal_statusCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem principal_status_exact (self : cbor.Encoder) (value : auths_model.PrincipalStatusStatement)
    (strings : PrincipalStatusStrings value) (space : self.output.val.length + principal_statusCost value ≤ Usize.max) :
    encode.encode_principal_status_statement_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.principalStatus value ⦄ := by
  unfold encode.encode_principal_status_statement_to
  simp only [principal_statusCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 9#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 9⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.version, auths_model.ProtocolVersion.get, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.version (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, value.version.val⟩
  simp only [ok2, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.method, auths_model.StatusMethodId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.method strings.method]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.method strings.method).val.length = value.method.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.method strings.method) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.method)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.principal, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.principal strings.principal]
  simp only [bind_tc_ok]
  have borrowLength6 : (toStr value.principal strings.principal).val.length = value.principal.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e5 (toStr value.principal strings.principal) (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  rw [borrowed_bytes] at bytes6
  have len6 := output_length bytes6
  have bound6 := payload_length_bound 3 (stringBytes value.principal)
  rw [stringBytes_length] at bound6
  simp only [ok6, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.state, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e7 (match value.state with | .Active => 0#u8 | .Revoked => 1#u8 | .Superseded => 2#u8) (by omega)
    as ⟨r8, e8, ok8, bytes8⟩
  have stateValue8 : (match value.state with | .Active => 0#u8 | .Revoked => 1#u8 | .Superseded => 2#u8).val = UnsignedObjects.principalState value.state := by
    cases value.state <;> rfl
  rw [stateValue8] at bytes8
  have len8 := output_length bytes8
  have bound8 := encodeHead_length_le_nine ⟨0, UnsignedObjects.principalState value.state⟩
  simp only [ok8, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.sequence, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e9 value.sequence (by omega)
    as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := encodeHead_length_le_nine ⟨0, value.sequence.val⟩
  simp only [ok10, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.observed_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e11 value.observed_at (by omega)
    as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := encodeHead_length_le_nine ⟨0, value.observed_at.val⟩
  simp only [ok12, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega)
    as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.valid_until, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e13 value.valid_until (by omega)
    as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := encodeHead_length_le_nine ⟨0, value.valid_until.val⟩
  simp only [ok14, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega)
    as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.issuer, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.issuer strings.issuer]
  simp only [bind_tc_ok]
  have borrowLength16 : (toStr value.issuer strings.issuer).val.length = value.issuer.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e15 (toStr value.issuer strings.issuer) (by omega)
    as ⟨r16, e16, ok16, bytes16⟩
  rw [borrowed_bytes] at bytes16
  have len16 := output_length bytes16
  have bound16 := payload_length_bound 3 (stringBytes value.issuer)
  rw [stringBytes_length] at bound16
  simp only [ok16, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega)
    as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusStatement.impl.extensions, bind_tc_ok]
  step with UnsignedCollections.extensions_exact e17 value.extensions strings.extensions (by omega)
    as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := extensions_length value.extensions
  simp only [ok18, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.principalStatus, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, stringBytes, payloadEncoding, alloc.vec.deref_exact, List.append_assoc]

structure GrantStatusStrings (value : auths_model.GrantStatusStatement) : Prop where
  method : value.method.toByteArray.size ≤ U32.max
  issuer : value.issuer.toByteArray.size ≤ U32.max
  extensions : ∀ item ∈ value.extensions.val, ExtensionStrings item

def grant_statusCost (value : auths_model.GrantStatusStatement) : Nat :=
  9 + 9 * 9 + ([9,
    (9 + value.method.toByteArray.size),
    41,
    9,
    9,
    9,
    9,
    (9 + value.issuer.toByteArray.size),
    (extensionsCost value.extensions)] : List Nat).sum

theorem grant_status_length (value : auths_model.GrantStatusStatement) :
    (UnsignedObjects.grantStatus value).length ≤ grant_statusCost value := by
  have outer := UnsignedWire.map_length [
    (0, UnsignedWire.uint value.version.val),
    (1, UnsignedObjects.identifier value.method),
    (2, UnsignedObjects.digest value.grant_id),
    (3, UnsignedWire.uint (UnsignedObjects.grantState value.state)),
    (4, UnsignedWire.uint value.sequence.val),
    (5, UnsignedWire.uint value.observed_at.val),
    (6, UnsignedWire.uint value.valid_until.val),
    (7, UnsignedObjects.identifier value.issuer),
    (8, UnsignedObjects.extensions value.extensions)]
  have bound0 := UnsignedWire.uint_length value.version.val
  have bound1 := identifier_length value.method
  have bound2 := digest_length value.grant_id
  have bound3 := UnsignedWire.uint_length (UnsignedObjects.grantState value.state)
  have bound4 := UnsignedWire.uint_length value.sequence.val
  have bound5 := UnsignedWire.uint_length value.observed_at.val
  have bound6 := UnsignedWire.uint_length value.valid_until.val
  have bound7 := identifier_length value.issuer
  have bound8 := extensions_length value.extensions
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [grant_statusCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem grant_status_exact (self : cbor.Encoder) (value : auths_model.GrantStatusStatement)
    (strings : GrantStatusStrings value) (space : self.output.val.length + grant_statusCost value ≤ Usize.max) :
    encode.encode_grant_status_statement_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.grantStatus value ⦄ := by
  unfold encode.encode_grant_status_statement_to
  simp only [grant_statusCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 9#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 9⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.version, auths_model.ProtocolVersion.get, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.version (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, value.version.val⟩
  simp only [ok2, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.method, auths_model.StatusMethodId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.method strings.method]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.method strings.method).val.length = value.method.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.method strings.method) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.method)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.grant_id, auths_model.GrantId.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e5 value.grant_id (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := digest_length value.grant_id
  simp only [ok6, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.state, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e7 (match value.state with | .Active => 0#u8 | .Revoked => 1#u8 | .Superseded => 2#u8) (by omega)
    as ⟨r8, e8, ok8, bytes8⟩
  have stateValue8 : (match value.state with | .Active => 0#u8 | .Revoked => 1#u8 | .Superseded => 2#u8).val = UnsignedObjects.grantState value.state := by
    cases value.state <;> rfl
  rw [stateValue8] at bytes8
  have len8 := output_length bytes8
  have bound8 := encodeHead_length_le_nine ⟨0, UnsignedObjects.grantState value.state⟩
  simp only [ok8, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.sequence, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e9 value.sequence (by omega)
    as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := encodeHead_length_le_nine ⟨0, value.sequence.val⟩
  simp only [ok10, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.observed_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e11 value.observed_at (by omega)
    as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := encodeHead_length_le_nine ⟨0, value.observed_at.val⟩
  simp only [ok12, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega)
    as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.valid_until, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e13 value.valid_until (by omega)
    as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := encodeHead_length_le_nine ⟨0, value.valid_until.val⟩
  simp only [ok14, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega)
    as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.issuer, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.issuer strings.issuer]
  simp only [bind_tc_ok]
  have borrowLength16 : (toStr value.issuer strings.issuer).val.length = value.issuer.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e15 (toStr value.issuer strings.issuer) (by omega)
    as ⟨r16, e16, ok16, bytes16⟩
  rw [borrowed_bytes] at bytes16
  have len16 := output_length bytes16
  have bound16 := payload_length_bound 3 (stringBytes value.issuer)
  rw [stringBytes_length] at bound16
  simp only [ok16, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega)
    as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusStatement.impl.extensions, bind_tc_ok]
  step with UnsignedCollections.extensions_exact e17 value.extensions strings.extensions (by omega)
    as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := extensions_length value.extensions
  simp only [ok18, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.grantStatus, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, stringBytes, payloadEncoding, alloc.vec.deref_exact, List.append_assoc]

structure ApprovalStrings (value : auths_model.approval.ApprovalStatement) : Prop where
  approver : value.approver.toByteArray.size ≤ U32.max
  media : value.media_type.toByteArray.size ≤ U32.max
  capability : value.permission.capability.toByteArray.size ≤ U32.max
  resource : value.permission.resource.toByteArray.size ≤ U32.max
  budget : ∀ item ∈ value.requested_budget, item.algebra.toByteArray.size ≤ U32.max
  audience : value.audience.toByteArray.size ≤ U32.max

def approvalCost (value : auths_model.approval.ApprovalStatement) : Nat :=
  9 + 9 * 13 + ([9,
    (9 + value.approver.toByteArray.size),
    41,
    (9 + value.media_type.toByteArray.size),
    41,
    (9 + value.permission.capability.toByteArray.size),
    (9 + value.permission.resource.toByteArray.size),
    (budgetOptionCost value.requested_budget),
    41,
    (9 + value.audience.toByteArray.size),
    41,
    9,
    9] : List Nat).sum

theorem approval_length (value : auths_model.approval.ApprovalStatement) :
    (UnsignedObjects.approval value).length ≤ approvalCost value := by
  have outer := UnsignedWire.map_length [
    (0, UnsignedWire.uint value.version.val),
    (1, UnsignedObjects.identifier value.approver),
    (2, UnsignedObjects.digest value.requirement),
    (3, UnsignedObjects.identifier value.media_type),
    (4, UnsignedObjects.digest value.body_digest),
    (5, UnsignedObjects.identifier value.permission.capability),
    (6, UnsignedObjects.identifier value.permission.resource),
    (7, UnsignedObjects.optionalBudget value.requested_budget),
    (8, UnsignedObjects.optionalDigest value.attributes),
    (9, UnsignedObjects.identifier value.audience),
    (10, UnsignedObjects.digest value.challenge),
    (11, UnsignedWire.uint value.validity.not_before.val),
    (12, UnsignedWire.uint value.validity.expires_at.val)]
  have bound0 := UnsignedWire.uint_length value.version.val
  have bound1 := identifier_length value.approver
  have bound2 := digest_length value.requirement
  have bound3 := identifier_length value.media_type
  have bound4 := digest_length value.body_digest
  have bound5 := identifier_length value.permission.capability
  have bound6 := identifier_length value.permission.resource
  have bound7 := optional_budget_length value.requested_budget
  have bound8 := optional_digest_length value.attributes
  have bound9 := identifier_length value.audience
  have bound10 := digest_length value.challenge
  have bound11 := UnsignedWire.uint_length value.validity.not_before.val
  have bound12 := UnsignedWire.uint_length value.validity.expires_at.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [approvalCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem approval_exact (self : cbor.Encoder) (value : auths_model.approval.ApprovalStatement)
    (strings : ApprovalStrings value) (space : self.output.val.length + approvalCost value ≤ Usize.max) :
    approval.encode_approval_statement_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.approval value ⦄ := by
  unfold approval.encode_approval_statement_to
  simp only [approvalCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 13#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 13⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.version, auths_model.ProtocolVersion.get, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.version (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, value.version.val⟩
  simp only [ok2, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.approver, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.approver strings.approver]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.approver strings.approver).val.length = value.approver.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.approver strings.approver) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.approver)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.requirement, auths_model.ApprovalRequirementId.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e5 value.requirement (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := digest_length value.requirement
  simp only [ok6, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.media_type, auths_model.MediaType.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.media_type strings.media]
  simp only [bind_tc_ok]
  have borrowLength8 : (toStr value.media_type strings.media).val.length = value.media_type.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e7 (toStr value.media_type strings.media) (by omega)
    as ⟨r8, e8, ok8, bytes8⟩
  rw [borrowed_bytes] at bytes8
  have len8 := output_length bytes8
  have bound8 := payload_length_bound 3 (stringBytes value.media_type)
  rw [stringBytes_length] at bound8
  simp only [ok8, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.body_digest, auths_model.Digest.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e9 value.body_digest (by omega)
    as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := digest_length value.body_digest
  simp only [ok10, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.permission, auths_model.Permission.impl.capability, auths_model.CapabilityId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.permission.capability strings.capability]
  simp only [bind_tc_ok]
  have borrowLength12 : (toStr value.permission.capability strings.capability).val.length = value.permission.capability.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e11 (toStr value.permission.capability strings.capability) (by omega)
    as ⟨r12, e12, ok12, bytes12⟩
  rw [borrowed_bytes] at bytes12
  have len12 := output_length bytes12
  have bound12 := payload_length_bound 3 (stringBytes value.permission.capability)
  rw [stringBytes_length] at bound12
  simp only [ok12, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega)
    as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.permission, auths_model.Permission.impl.resource, auths_model.ResourceId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.permission.resource strings.resource]
  simp only [bind_tc_ok]
  have borrowLength14 : (toStr value.permission.resource strings.resource).val.length = value.permission.resource.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e13 (toStr value.permission.resource strings.resource) (by omega)
    as ⟨r14, e14, ok14, bytes14⟩
  rw [borrowed_bytes] at bytes14
  have len14 := output_length bytes14
  have bound14 := payload_length_bound 3 (stringBytes value.permission.resource)
  rw [stringBytes_length] at bound14
  simp only [ok14, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega)
    as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.requested_budget, core.option.Option.as_ref, bind_tc_ok]
  step with UnsignedLeaves.optional_budget_exact e15 value.requested_budget strings.budget (by omega)
    as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := optional_budget_length value.requested_budget
  simp only [ok16, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega)
    as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.attributes, core.option.Option.as_ref, bind_tc_ok]
  rw [UnsignedLeaves.optional_digest_borrow]
  simp only [bind_tc_ok]
  step with UnsignedLeaves.optional_digest_exact e17 value.attributes (by omega)
    as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := optional_digest_length value.attributes
  simp only [ok18, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega)
    as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.audience, auths_model.Audience.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.audience strings.audience]
  simp only [bind_tc_ok]
  have borrowLength20 : (toStr value.audience strings.audience).val.length = value.audience.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e19 (toStr value.audience strings.audience) (by omega)
    as ⟨r20, e20, ok20, bytes20⟩
  rw [borrowed_bytes] at bytes20
  have len20 := output_length bytes20
  have bound20 := payload_length_bound 3 (stringBytes value.audience)
  rw [stringBytes_length] at bound20
  simp only [ok20, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega)
    as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.challenge, auths_model.Challenge.as_bytes, bind_tc_ok]
  simp only [lift, Array.to_slice, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e21 value.challenge (by omega)
    as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := digest_length value.challenge
  simp only [ok22, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e22 11#u8 (by omega)
    as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := encodeHead_length_le_nine ⟨0, 11⟩
  simp only [ok23, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.validity, auths_model.ValidityWindow.impl.not_before, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e23 value.validity.not_before (by omega)
    as ⟨r24, e24, ok24, bytes24⟩
  have len24 := output_length bytes24
  have bound24 := encodeHead_length_le_nine ⟨0, value.validity.not_before.val⟩
  simp only [ok24, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e24 12#u8 (by omega)
    as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := encodeHead_length_le_nine ⟨0, 12⟩
  simp only [ok25, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApprovalStatement.impl.validity, auths_model.ValidityWindow.impl.expires_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e25 value.validity.expires_at (by omega)
    as ⟨r26, e26, ok26, bytes26⟩
  have len26 := output_length bytes26
  have bound26 := encodeHead_length_le_nine ⟨0, value.validity.expires_at.val⟩
  simp only [ok26, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.approval, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, stringBytes, payloadEncoding, alloc.vec.deref_exact, List.append_assoc]

structure ObservationStrings (value : auths_model.observation.ObservationStatement) : Prop where
  observer : value.observer.toByteArray.size ≤ U32.max
  schema : value.schema.toByteArray.size ≤ U32.max
  subject : value.subject.toByteArray.size ≤ U32.max
  facts : ∀ item ∈ value.facts.val, FactStrings item

def observationCost (value : auths_model.observation.ObservationStatement) : Nat :=
  9 + 9 * 6 + ([9,
    (9 + value.observer.toByteArray.size),
    (9 + value.schema.toByteArray.size),
    (9 + value.subject.toByteArray.size),
    9,
    (factsCost value.facts)] : List Nat).sum

theorem observation_length (value : auths_model.observation.ObservationStatement) :
    (UnsignedObjects.observation value).length ≤ observationCost value := by
  have outer := UnsignedWire.map_length [
    (0, UnsignedWire.uint value.version.val),
    (1, UnsignedObjects.identifier value.observer),
    (2, UnsignedObjects.identifier value.schema),
    (3, UnsignedObjects.identifier value.subject),
    (4, UnsignedWire.uint value.observed_at.val),
    (5, UnsignedWire.array (value.facts.val.map UnsignedObjects.fact))]
  have bound0 := UnsignedWire.uint_length value.version.val
  have bound1 := identifier_length value.observer
  have bound2 := identifier_length value.schema
  have bound3 := identifier_length value.subject
  have bound4 := UnsignedWire.uint_length value.observed_at.val
  have bound5 := facts_length value.facts
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [observationCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem observation_exact (self : cbor.Encoder) (value : auths_model.observation.ObservationStatement)
    (strings : ObservationStrings value) (space : self.output.val.length + observationCost value ≤ Usize.max) :
    observation.encode_observation_statement_to self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.observation value ⦄ := by
  unfold observation.encode_observation_statement_to
  simp only [observationCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 6#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 6⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationStatement.impl.version, auths_model.ProtocolVersion.get, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e1 value.version (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, value.version.val⟩
  simp only [ok2, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationStatement.impl.observer, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.observer strings.observer]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.observer strings.observer).val.length = value.observer.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.observer strings.observer) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.observer)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationStatement.impl.schema, auths_model.observation.ObservationSchemaId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.schema strings.schema]
  simp only [bind_tc_ok]
  have borrowLength6 : (toStr value.schema strings.schema).val.length = value.schema.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e5 (toStr value.schema strings.schema) (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  rw [borrowed_bytes] at bytes6
  have len6 := output_length bytes6
  have bound6 := payload_length_bound 3 (stringBytes value.schema)
  rw [stringBytes_length] at bound6
  simp only [ok6, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationStatement.impl.subject, auths_model.ResourceId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.subject strings.subject]
  simp only [bind_tc_ok]
  have borrowLength8 : (toStr value.subject strings.subject).val.length = value.subject.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e7 (toStr value.subject strings.subject) (by omega)
    as ⟨r8, e8, ok8, bytes8⟩
  rw [borrowed_bytes] at bytes8
  have len8 := output_length bytes8
  have bound8 := payload_length_bound 3 (stringBytes value.subject)
  rw [stringBytes_length] at bound8
  simp only [ok8, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationStatement.impl.observed_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e9 value.observed_at (by omega)
    as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := encodeHead_length_le_nine ⟨0, value.observed_at.val⟩
  simp only [ok10, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationStatement.impl.facts, auths_model.observation.ObservationFacts.impl.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
  step with UnsignedCollections.facts_exact e11 value.facts strings.facts (by omega)
    as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := facts_length value.facts
  simp only [ok12, core.result.Result.map_err,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.observation, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, stringBytes, payloadEncoding, alloc.vec.deref_exact, List.append_assoc]

end Auths.Crypto.StatementWriters
