import Auths.Crypto.ContextProfiles

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextAnchors
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Codec.ProtocolTextWriters

/- Exact configuration bytes do not imply that a principal, registry entry,
profile, status issuer or evidence source is trusted by a verifier. Every
actual record writer is composed below using concrete input field conditions;
no encoder success, expected intermediate bytes or authority flag is assumed. -/

structure AnchorStrings (value : auths_model.TrustAnchor) : Prop where
  id : value.id.toByteArray.size ≤ U32.max
  principal : value.principal.toByteArray.size ≤ U32.max
  accepted_methods : ∀ item ∈ value.accepted_methods.val, item.toByteArray.size ≤ U32.max
  profiles : ∀ item ∈ value.profiles.val, ContextProfiles.Strings item
  permissions : ∀ item ∈ value.permissions.val, UnsignedLeaves.PermissionStrings item
  resource_namespaces : ∀ item ∈ value.resource_namespaces.val, item.toByteArray.size ≤ U32.max
  audiences : ∀ item ∈ value.audiences.val, item.toByteArray.size ≤ U32.max
  assurance_policy : value.assurance_policy.toByteArray.size ≤ U32.max
  status_policy : UnsignedLeaves.PolicyStrings value.status_policy

theorem anchor_length (value : auths_model.TrustAnchor) :
    (ContextObjects.anchor value).length ≤ ContextObjects.anchorCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.id),
    (1, UnsignedObjects.identifier value.principal),
    (2, UnsignedWire.array (value.accepted_methods.val.map UnsignedObjects.identifier)),
    (3, ContextObjects.profiles value.profiles.val),
    (4, UnsignedWire.array (value.permissions.val.map UnsignedObjects.permission)),
    (5, UnsignedWire.array (value.resource_namespaces.val.map UnsignedObjects.identifier)),
    (6, UnsignedWire.array (value.audiences.val.map UnsignedObjects.identifier)),
    (7, UnsignedWire.uint value.validity.not_before.val),
    (8, UnsignedWire.uint value.validity.expires_at.val),
    (9, UnsignedObjects.optionalBudget value.budget_ceiling),
    (10, UnsignedWire.uint value.max_delegation_depth.val),
    (11, UnsignedObjects.identifier value.assurance_policy),
    (12, UnsignedObjects.statusPolicy value.status_policy)]
  have field0 := UnsignedLeaves.identifier_length value.id
  have field1 := UnsignedLeaves.identifier_length value.principal
  have field2 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.accepted_methods.val
  have field3 := array_model_length UnsignedObjects.profile ContextObjects.profileCost ContextProfiles.profile_length value.profiles.val
  have field4 := UnsignedCollections.permissions_length value.permissions
  have field5 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.resource_namespaces.val
  have field6 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.audiences.val
  have field7 := UnsignedWire.uint_length value.validity.not_before.val
  have field8 := UnsignedWire.uint_length value.validity.expires_at.val
  have field9 := UnsignedLeaves.optional_budget_length value.budget_ceiling
  have field10 := UnsignedWire.uint_length value.max_delegation_depth.val
  have field11 := UnsignedLeaves.identifier_length value.assurance_policy
  have field12 := UnsignedLeaves.status_policy_length value.status_policy
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.anchorCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, ContextObjects.profileCost,
    List.sum_cons, List.sum_nil] at *
  omega

@[step] theorem anchor_exact (self : cbor.Encoder) (value : auths_model.TrustAnchor)
    (strings : AnchorStrings value)
    (space : self.output.val.length + ContextObjects.anchorCost value ≤ Usize.max) :
    encode.encode_anchor self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.anchor value ⦄ := by
  unfold encode.encode_anchor
  simp only [ContextObjects.anchorCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 13#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 13⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.id, auths_model.TrustAnchorId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.id strings.id]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.id strings.id).val.length = value.id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.id strings.id) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.id)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.principal, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.principal strings.principal]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.principal strings.principal).val.length = value.principal.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.principal strings.principal) (by omega) as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.principal)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.accepted_methods, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.principal_methods_exact e5 (alloc.vec.Vec.deref value.accepted_methods) strings.accepted_methods (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation textCost value.accepted_methods.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.accepted_methods.val
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.profiles, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextProfiles.profiles_exact e7 (alloc.vec.Vec.deref value.profiles) strings.profiles (by simpa only [alloc.vec.deref_exact] using (show e7.output.val.length + 9 + allocation ContextObjects.profileCost value.profiles.val ≤ Usize.max by omega)) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := array_model_length UnsignedObjects.profile ContextObjects.profileCost ContextProfiles.profile_length value.profiles.val
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.permissions, bind_tc_ok]
  step with UnsignedCollections.permissions_exact e9 value.permissions strings.permissions (by omega) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := UnsignedCollections.permissions_length value.permissions
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.resource_namespaces, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.resource_ids_exact e11 (alloc.vec.Vec.deref value.resource_namespaces) strings.resource_namespaces (by simpa only [alloc.vec.deref_exact] using (show e11.output.val.length + 9 + allocation textCost value.resource_namespaces.val ≤ Usize.max by omega)) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.resource_namespaces.val
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.audiences, auths_model.AudienceSet.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.audiences_exact e13 (alloc.vec.Vec.deref value.audiences) strings.audiences (by simpa only [alloc.vec.deref_exact] using (show e13.output.val.length + 9 + allocation textCost value.audiences.val ≤ Usize.max by omega)) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.audiences.val
  simp only [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega) as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.validity, auths_model.ValidityWindow.impl.not_before, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e15 value.validity.not_before (by omega) as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := encodeHead_length_le_nine ⟨0, (value.validity.not_before).val⟩
  simp only [ok16, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega) as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.validity, auths_model.ValidityWindow.impl.expires_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e17 value.validity.expires_at (by omega) as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := encodeHead_length_le_nine ⟨0, (value.validity.expires_at).val⟩
  simp only [ok18, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega) as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.budget_ceiling, core.option.Option.as_ref, bind_tc_ok]
  step with UnsignedLeaves.optional_budget_exact e19 value.budget_ceiling (by omega) as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := UnsignedLeaves.optional_budget_length value.budget_ceiling
  simp only [ok20, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega) as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.max_delegation_depth, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e21 value.max_delegation_depth (by omega) as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := encodeHead_length_le_nine ⟨0, (value.max_delegation_depth).val⟩
  simp only [ok22, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e22 11#u8 (by omega) as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := encodeHead_length_le_nine ⟨0, 11⟩
  simp only [ok23, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.assurance_policy, auths_model.AssurancePolicyId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.assurance_policy strings.assurance_policy]
  simp only [bind_tc_ok]
  have borrowLength24 : (toStr value.assurance_policy strings.assurance_policy).val.length = value.assurance_policy.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e23 (toStr value.assurance_policy strings.assurance_policy) (by omega) as ⟨r24, e24, ok24, bytes24⟩
  rw [borrowed_bytes] at bytes24
  have len24 := output_length bytes24
  have bound24 := payload_length_bound 3 (stringBytes value.assurance_policy)
  rw [stringBytes_length] at bound24
  simp only [ok24, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e24 12#u8 (by omega) as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := encodeHead_length_le_nine ⟨0, 12⟩
  simp only [ok25, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.TrustAnchor.impl.status_policy, bind_tc_ok]
  step with UnsignedLeaves.status_policy_exact e25 value.status_policy strings.status_policy (by omega) as ⟨r26, e26, ok26, bytes26⟩
  have len26 := output_length bytes26
  have bound26 := UnsignedLeaves.status_policy_length value.status_policy
  simp [ok26, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.anchor, ContextObjects.profiles,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

structure RegistriesStrings (value : auths_model.AcceptedRegistries) : Prop where
  principal_methods : ∀ item ∈ value.principal_methods.val, item.toByteArray.size ≤ U32.max
  signature_suites : ∀ item ∈ value.signature_suites.val, item.toByteArray.size ≤ U32.max
  evidence_types : ∀ item ∈ value.evidence_types.val, item.toByteArray.size ≤ U32.max
  principal_status_methods : ∀ item ∈ value.principal_status_methods.val, item.toByteArray.size ≤ U32.max
  grant_status_methods : ∀ item ∈ value.grant_status_methods.val, item.toByteArray.size ≤ U32.max
  assurance_claims : ∀ item ∈ value.assurance_claims.val, item.toByteArray.size ≤ U32.max
  assurance_implications : ∀ item ∈ value.assurance_implications.val, item.toByteArray.size ≤ U32.max
  resource_matchers : ∀ item ∈ value.resource_matchers.val, item.toByteArray.size ≤ U32.max
  budget_algebras : ∀ item ∈ value.budget_algebras.val, item.toByteArray.size ≤ U32.max
  critical_extensions : ∀ item ∈ value.critical_extensions.val, item.toByteArray.size ≤ U32.max
  profiles : ∀ item ∈ value.profiles.val, ContextProfiles.Strings item
  profile_policies : ∀ item ∈ value.profile_policies.val, item.toByteArray.size ≤ U32.max
  budget_free_profiles : ∀ item ∈ value.budget_free_profiles.val, ContextProfiles.Strings item

theorem registries_length (value : auths_model.AcceptedRegistries) :
    (ContextObjects.registries value).length ≤ ContextObjects.registriesCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.digest value.manifest_id),
    (1, UnsignedWire.array (value.principal_methods.val.map UnsignedObjects.identifier)),
    (2, UnsignedWire.array (value.signature_suites.val.map UnsignedObjects.identifier)),
    (3, UnsignedWire.array (value.evidence_types.val.map UnsignedObjects.identifier)),
    (4, UnsignedWire.array (value.principal_status_methods.val.map UnsignedObjects.identifier)),
    (5, UnsignedWire.array (value.grant_status_methods.val.map UnsignedObjects.identifier)),
    (6, UnsignedWire.array (value.assurance_claims.val.map UnsignedObjects.identifier)),
    (7, UnsignedWire.array (value.assurance_implications.val.map UnsignedObjects.identifier)),
    (8, UnsignedWire.array (value.resource_matchers.val.map UnsignedObjects.identifier)),
    (9, UnsignedWire.array (value.budget_algebras.val.map UnsignedObjects.identifier)),
    (10, UnsignedWire.array (value.critical_extensions.val.map UnsignedObjects.identifier)),
    (11, ContextObjects.profiles value.profiles.val),
    (12, UnsignedWire.array (value.profile_policies.val.map UnsignedObjects.identifier)),
    (13, ContextObjects.profiles value.budget_free_profiles.val)]
  have field0 := UnsignedLeaves.digest_length value.manifest_id
  have field1 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.principal_methods.val
  have field2 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.signature_suites.val
  have field3 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.evidence_types.val
  have field4 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.principal_status_methods.val
  have field5 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.grant_status_methods.val
  have field6 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.assurance_claims.val
  have field7 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.assurance_implications.val
  have field8 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.resource_matchers.val
  have field9 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.budget_algebras.val
  have field10 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.critical_extensions.val
  have field11 := array_model_length UnsignedObjects.profile ContextObjects.profileCost ContextProfiles.profile_length value.profiles.val
  have field12 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.profile_policies.val
  have field13 := array_model_length UnsignedObjects.profile ContextObjects.profileCost ContextProfiles.profile_length value.budget_free_profiles.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.registriesCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, ContextObjects.profileCost,
    List.sum_cons, List.sum_nil] at *
  omega

@[step] theorem registries_exact (self : cbor.Encoder) (value : auths_model.AcceptedRegistries)
    (strings : RegistriesStrings value)
    (space : self.output.val.length + ContextObjects.registriesCost value ≤ Usize.max) :
    encode.encode_registries self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.registries value ⦄ := by
  unfold encode.encode_registries
  simp only [ContextObjects.registriesCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 14#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 14⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.manifest_id, auths_model.RegistryManifestId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e1 value.manifest_id (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := UnsignedLeaves.digest_length value.manifest_id
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.principal_methods, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.principal_methods_exact e3 (alloc.vec.Vec.deref value.principal_methods) strings.principal_methods (by simpa only [alloc.vec.deref_exact] using (show e3.output.val.length + 9 + allocation textCost value.principal_methods.val ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.principal_methods.val
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.signature_suites, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.signature_suites_exact e5 (alloc.vec.Vec.deref value.signature_suites) strings.signature_suites (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation textCost value.signature_suites.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.signature_suites.val
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.evidence_types, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.evidence_types_exact e7 (alloc.vec.Vec.deref value.evidence_types) strings.evidence_types (by simpa only [alloc.vec.deref_exact] using (show e7.output.val.length + 9 + allocation textCost value.evidence_types.val ≤ Usize.max by omega)) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.evidence_types.val
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.principal_status_methods, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.status_methods_exact e9 (alloc.vec.Vec.deref value.principal_status_methods) strings.principal_status_methods (by simpa only [alloc.vec.deref_exact] using (show e9.output.val.length + 9 + allocation textCost value.principal_status_methods.val ≤ Usize.max by omega)) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.principal_status_methods.val
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.grant_status_methods, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.status_methods_exact e11 (alloc.vec.Vec.deref value.grant_status_methods) strings.grant_status_methods (by simpa only [alloc.vec.deref_exact] using (show e11.output.val.length + 9 + allocation textCost value.grant_status_methods.val ≤ Usize.max by omega)) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.grant_status_methods.val
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.assurance_claims, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.assurance_claims_exact e13 (alloc.vec.Vec.deref value.assurance_claims) strings.assurance_claims (by simpa only [alloc.vec.deref_exact] using (show e13.output.val.length + 9 + allocation textCost value.assurance_claims.val ≤ Usize.max by omega)) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.assurance_claims.val
  simp only [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega) as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.assurance_implications, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.assurance_implications_exact e15 (alloc.vec.Vec.deref value.assurance_implications) strings.assurance_implications (by simpa only [alloc.vec.deref_exact] using (show e15.output.val.length + 9 + allocation textCost value.assurance_implications.val ≤ Usize.max by omega)) as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.assurance_implications.val
  simp only [ok16, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega) as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.resource_matchers, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.resource_matchers_exact e17 (alloc.vec.Vec.deref value.resource_matchers) strings.resource_matchers (by simpa only [alloc.vec.deref_exact] using (show e17.output.val.length + 9 + allocation textCost value.resource_matchers.val ≤ Usize.max by omega)) as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.resource_matchers.val
  simp only [ok18, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega) as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.budget_algebras, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.budget_algebras_exact e19 (alloc.vec.Vec.deref value.budget_algebras) strings.budget_algebras (by simpa only [alloc.vec.deref_exact] using (show e19.output.val.length + 9 + allocation textCost value.budget_algebras.val ≤ Usize.max by omega)) as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.budget_algebras.val
  simp only [ok20, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega) as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.critical_extensions, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.extension_ids_exact e21 (alloc.vec.Vec.deref value.critical_extensions) strings.critical_extensions (by simpa only [alloc.vec.deref_exact] using (show e21.output.val.length + 9 + allocation textCost value.critical_extensions.val ≤ Usize.max by omega)) as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.critical_extensions.val
  simp only [ok22, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e22 11#u8 (by omega) as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := encodeHead_length_le_nine ⟨0, 11⟩
  simp only [ok23, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.profiles, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextProfiles.profiles_exact e23 (alloc.vec.Vec.deref value.profiles) strings.profiles (by simpa only [alloc.vec.deref_exact] using (show e23.output.val.length + 9 + allocation ContextObjects.profileCost value.profiles.val ≤ Usize.max by omega)) as ⟨r24, e24, ok24, bytes24⟩
  have len24 := output_length bytes24
  have bound24 := array_model_length UnsignedObjects.profile ContextObjects.profileCost ContextProfiles.profile_length value.profiles.val
  simp only [ok24, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e24 12#u8 (by omega) as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := encodeHead_length_le_nine ⟨0, 12⟩
  simp only [ok25, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.profile_policies, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.profile_policies_exact e25 (alloc.vec.Vec.deref value.profile_policies) strings.profile_policies (by simpa only [alloc.vec.deref_exact] using (show e25.output.val.length + 9 + allocation textCost value.profile_policies.val ≤ Usize.max by omega)) as ⟨r26, e26, ok26, bytes26⟩
  have len26 := output_length bytes26
  have bound26 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.profile_policies.val
  simp only [ok26, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e26 13#u8 (by omega) as ⟨r27, e27, ok27, bytes27⟩
  have len27 := output_length bytes27
  have bound27 := encodeHead_length_le_nine ⟨0, 13⟩
  simp only [ok27, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AcceptedRegistries.impl.budget_free_profiles, core.ops.deref.DerefVec, bind_tc_ok]
  step with ContextProfiles.profiles_exact e27 (alloc.vec.Vec.deref value.budget_free_profiles) strings.budget_free_profiles (by simpa only [alloc.vec.deref_exact] using (show e27.output.val.length + 9 + allocation ContextObjects.profileCost value.budget_free_profiles.val ≤ Usize.max by omega)) as ⟨r28, e28, ok28, bytes28⟩
  have len28 := output_length bytes28
  have bound28 := array_model_length UnsignedObjects.profile ContextObjects.profileCost ContextProfiles.profile_length value.budget_free_profiles.val
  simp [ok28, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes28, bytes27, bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.registries, ContextObjects.profiles,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

structure ObserverStrings (value : auths_model.observation.ObserverAnchor) : Prop where
  id : value.id.toByteArray.size ≤ U32.max
  principal : value.principal.toByteArray.size ≤ U32.max
  accepted_methods : ∀ item ∈ value.accepted_methods.val, item.toByteArray.size ≤ U32.max
  schemas : ∀ item ∈ value.schemas.val, item.toByteArray.size ≤ U32.max
  subject_namespaces : ∀ item ∈ value.subject_namespaces.val, item.toByteArray.size ≤ U32.max

theorem observer_length (value : auths_model.observation.ObserverAnchor) :
    (ContextObjects.observer value).length ≤ ContextObjects.observerCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.id),
    (1, UnsignedObjects.identifier value.principal),
    (2, UnsignedWire.array (value.accepted_methods.val.map UnsignedObjects.identifier)),
    (3, UnsignedWire.array (value.schemas.val.map UnsignedObjects.identifier)),
    (4, UnsignedWire.array (value.subject_namespaces.val.map UnsignedObjects.identifier)),
    (5, UnsignedWire.uint value.validity.not_before.val),
    (6, UnsignedWire.uint value.validity.expires_at.val)]
  have field0 := UnsignedLeaves.identifier_length value.id
  have field1 := UnsignedLeaves.identifier_length value.principal
  have field2 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.accepted_methods.val
  have field3 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.schemas.val
  have field4 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.subject_namespaces.val
  have field5 := UnsignedWire.uint_length value.validity.not_before.val
  have field6 := UnsignedWire.uint_length value.validity.expires_at.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.observerCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, ContextObjects.profileCost,
    List.sum_cons, List.sum_nil] at *
  omega

@[step] theorem observer_exact (self : cbor.Encoder) (value : auths_model.observation.ObserverAnchor)
    (strings : ObserverStrings value)
    (space : self.output.val.length + ContextObjects.observerCost value ≤ Usize.max) :
    observation.encode_observer_anchor self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.observer value ⦄ := by
  unfold observation.encode_observer_anchor
  simp only [ContextObjects.observerCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 7#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 7⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObserverAnchor.impl.id, auths_model.observation.ObserverAnchorId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.id strings.id]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.id strings.id).val.length = value.id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.id strings.id) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.id)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObserverAnchor.impl.principal, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.principal strings.principal]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.principal strings.principal).val.length = value.principal.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.principal strings.principal) (by omega) as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.principal)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObserverAnchor.impl.accepted_methods, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.principal_methods_exact e5 (alloc.vec.Vec.deref value.accepted_methods) strings.accepted_methods (by simpa only [alloc.vec.deref_exact] using (show e5.output.val.length + 9 + allocation textCost value.accepted_methods.val ≤ Usize.max by omega)) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.accepted_methods.val
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObserverAnchor.impl.schemas, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.observation_schemas_exact e7 (alloc.vec.Vec.deref value.schemas) strings.schemas (by simpa only [alloc.vec.deref_exact] using (show e7.output.val.length + 9 + allocation textCost value.schemas.val ≤ Usize.max by omega)) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.schemas.val
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObserverAnchor.impl.subject_namespaces, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.resource_ids_exact e9 (alloc.vec.Vec.deref value.subject_namespaces) strings.subject_namespaces (by simpa only [alloc.vec.deref_exact] using (show e9.output.val.length + 9 + allocation textCost value.subject_namespaces.val ≤ Usize.max by omega)) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.subject_namespaces.val
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObserverAnchor.impl.validity, auths_model.ValidityWindow.impl.not_before, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e11 value.validity.not_before (by omega) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := encodeHead_length_le_nine ⟨0, (value.validity.not_before).val⟩
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObserverAnchor.impl.validity, auths_model.ValidityWindow.impl.expires_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e13 value.validity.expires_at (by omega) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := encodeHead_length_le_nine ⟨0, (value.validity.expires_at).val⟩
  simp [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.observer, ContextObjects.profiles,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

structure ApproverStrings (value : auths_model.approval.ApproverAnchor) : Prop where
  principal : value.principal.toByteArray.size ≤ U32.max
  accepted_methods : ∀ item ∈ value.accepted_methods.val, item.toByteArray.size ≤ U32.max
  status_policy : UnsignedLeaves.PolicyStrings value.status_policy

theorem approver_length (value : auths_model.approval.ApproverAnchor) :
    (ContextObjects.approver value).length ≤ ContextObjects.approverCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.principal),
    (1, UnsignedWire.array (value.accepted_methods.val.map UnsignedObjects.identifier)),
    (2, UnsignedWire.uint value.validity.not_before.val),
    (3, UnsignedWire.uint value.validity.expires_at.val),
    (4, UnsignedObjects.statusPolicy value.status_policy)]
  have field0 := UnsignedLeaves.identifier_length value.principal
  have field1 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.accepted_methods.val
  have field2 := UnsignedWire.uint_length value.validity.not_before.val
  have field3 := UnsignedWire.uint_length value.validity.expires_at.val
  have field4 := UnsignedLeaves.status_policy_length value.status_policy
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ContextObjects.approverCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, ContextObjects.profileCost,
    List.sum_cons, List.sum_nil] at *
  omega

@[step] theorem approver_exact (self : cbor.Encoder) (value : auths_model.approval.ApproverAnchor)
    (strings : ApproverStrings value)
    (space : self.output.val.length + ContextObjects.approverCost value ≤ Usize.max) :
    approval.encode_approver_anchor self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.approver value ⦄ := by
  unfold approval.encode_approver_anchor
  simp only [ContextObjects.approverCost, ContextObjects.textArrayCost, ContextObjects.profilesCost,
    UnsignedCollections.permissionsCost, List.sum_cons, List.sum_nil] at space
  step with ProtocolWriter.map_exact self 5#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 5⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApproverAnchor.impl.principal, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.principal strings.principal]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.principal strings.principal).val.length = value.principal.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.principal strings.principal) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.principal)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApproverAnchor.impl.accepted_methods, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolTextWriters.principal_methods_exact e3 (alloc.vec.Vec.deref value.accepted_methods) strings.accepted_methods (by simpa only [alloc.vec.deref_exact] using (show e3.output.val.length + 9 + allocation textCost value.accepted_methods.val ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length value.accepted_methods.val
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApproverAnchor.impl.validity, auths_model.ValidityWindow.impl.not_before, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e5 value.validity.not_before (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := encodeHead_length_le_nine ⟨0, (value.validity.not_before).val⟩
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApproverAnchor.impl.validity, auths_model.ValidityWindow.impl.expires_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e7 value.validity.expires_at (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := encodeHead_length_le_nine ⟨0, (value.validity.expires_at).val⟩
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.approval.ApproverAnchor.impl.status_policy, bind_tc_ok]
  step with UnsignedLeaves.status_policy_exact e9 value.status_policy strings.status_policy (by omega) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := UnsignedLeaves.status_policy_length value.status_policy
  simp [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.approver, ContextObjects.profiles,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

end Auths.Crypto.ContextAnchors
