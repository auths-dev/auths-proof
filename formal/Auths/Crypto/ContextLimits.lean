import Auths.Crypto.ContextObjects
import Auths.Crypto.SnapshotLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextLimits
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter

/- The independent values are direct named configuration fields. Actual
source get/widen/key/word operations are composed, with no trusted limit flag,
source success or desired intermediate byte vector supplied. Encoding these
values does not prove that deployment limits are valid. -/

def entry (index value : Nat) : List Nat := UnsignedWire.uint index ++ UnsignedWire.uint value

theorem entry_length (index value : Nat) : (entry index value).length ≤ 18 := by
  have key := UnsignedWire.uint_length index
  have value := UnsignedWire.uint_length value
  simp only [entry, List.length_append]
  omega

@[step] theorem get_exact (value : auths_model.VerifierLimits) (kind : auths_model.LimitKind) :
    auths_model.VerifierLimits.get value kind ⦃ result => result.val = ContextObjects.limitValue value kind ⦄ := by
  cases kind <;> simp [auths_model.VerifierLimits.get, ContextObjects.limitValue, spec_ok]

@[step] theorem entry_exact (self : cbor.Encoder) (index : Std.U8)
    (kind : auths_model.LimitKind) (value : auths_model.VerifierLimits)
    (space : self.output.val.length + 18 ≤ Usize.max) :
    encode.encode_limit_entry self index kind value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ entry index.val (ContextObjects.limitValue value kind) ⦄ := by
  unfold encode.encode_limit_entry
  step with ProtocolWriter.key_exact self index (by omega) as ⟨verdict, afterKey, success, keyBytes⟩
  have keyLength := output_length keyBytes
  have keyBound := encodeHead_length_le_nine ⟨0, index.val⟩
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with get_exact value kind as ⟨configured, configuredMeaning⟩
  step with ProtocolWriter.length_exact configured as ⟨converted, convertedMeaning⟩
  cases converted with
  | Err reason => exact False.elim convertedMeaning
  | Ok word =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u64_exact afterKey word (by omega)
      as ⟨verdict, afterValue, valueSuccess, valueBytes⟩
    simp [valueSuccess, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      valueBytes, keyBytes, convertedMeaning, configuredMeaning, entry, UnsignedWire.uint, List.append_assoc]

theorem numbered_budget (index : Nat) (values : List Nat) :
    ((ContextObjects.numbered index values).map (fun field => 9 + field.2.length)).sum ≤ 18 * values.length := by
  induction values generalizing index with
  | nil => simp [ContextObjects.numbered]
  | cons first rest ih =>
    have head := UnsignedWire.uint_length first
    have tail := ih (index + 1)
    simp only [ContextObjects.numbered, List.map_cons, List.sum_cons, List.length_cons]
    omega

theorem limits_length (value : auths_model.VerifierLimits) : (ContextObjects.limits value).length ≤ 549 := by
  have outer := UnsignedWire.map_length (ContextObjects.numbered 0 (ContextObjects.limitValues value))
  have budget := numbered_budget 0 (ContextObjects.limitValues value)
  simp only [ContextObjects.limitValues, List.length_cons, List.length_nil] at budget
  change (UnsignedWire.map _).length ≤ _
  omega

@[step] theorem limits_exact (self : cbor.Encoder) (value : auths_model.VerifierLimits)
    (space : self.output.val.length + 549 ≤ Usize.max) :
    encode.encode_limits self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.limits value ⦄ := by
  unfold encode.encode_limits
  step with ProtocolWriter.map_exact self 30#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 30⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e0 0#u8 .BundleBytes value (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := entry_length 0 (ContextObjects.limitValue value .BundleBytes)
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e1 1#u8 .ActionBytes value (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := entry_length 1 (ContextObjects.limitValue value .ActionBytes)
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e2 2#u8 .ContextBytes value (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := entry_length 2 (ContextObjects.limitValue value .ContextBytes)
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e3 3#u8 .Grants value (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := entry_length 3 (ContextObjects.limitValue value .Grants)
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e4 4#u8 .Actions value (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := entry_length 4 (ContextObjects.limitValue value .Actions)
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e5 5#u8 .PlanLeaves value (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := entry_length 5 (ContextObjects.limitValue value .PlanLeaves)
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e6 6#u8 .PlanDepth value (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := entry_length 6 (ContextObjects.limitValue value .PlanDepth)
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e7 7#u8 .PlanBranching value (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := entry_length 7 (ContextObjects.limitValue value .PlanBranching)
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e8 8#u8 .EvidenceObjects value (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := entry_length 8 (ContextObjects.limitValue value .EvidenceObjects)
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e9 9#u8 .EvidenceBytes value (by omega) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := entry_length 9 (ContextObjects.limitValue value .EvidenceBytes)
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e10 10#u8 .ControlBindings value (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := entry_length 10 (ContextObjects.limitValue value .ControlBindings)
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e11 11#u8 .PrincipalStatusStatements value (by omega) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := entry_length 11 (ContextObjects.limitValue value .PrincipalStatusStatements)
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e12 12#u8 .GrantStatusStatements value (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := entry_length 12 (ContextObjects.limitValue value .GrantStatusStatements)
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e13 13#u8 .Attachments value (by omega) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := entry_length 13 (ContextObjects.limitValue value .Attachments)
  simp only [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e14 14#u8 .AttachmentBytes value (by omega) as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := entry_length 14 (ContextObjects.limitValue value .AttachmentBytes)
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e15 15#u8 .Signatures value (by omega) as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := entry_length 15 (ContextObjects.limitValue value .Signatures)
  simp only [ok16, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e16 16#u8 .SignatureBytes value (by omega) as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := entry_length 16 (ContextObjects.limitValue value .SignatureBytes)
  simp only [ok17, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e17 17#u8 .Permissions value (by omega) as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := entry_length 17 (ContextObjects.limitValue value .Permissions)
  simp only [ok18, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e18 18#u8 .Audiences value (by omega) as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := entry_length 18 (ContextObjects.limitValue value .Audiences)
  simp only [ok19, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e19 19#u8 .CriticalExtensions value (by omega) as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := entry_length 19 (ContextObjects.limitValue value .CriticalExtensions)
  simp only [ok20, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e20 20#u8 .CriticalExtensionBytes value (by omega) as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := entry_length 20 (ContextObjects.limitValue value .CriticalExtensionBytes)
  simp only [ok21, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e21 21#u8 .AllowedBodyDigests value (by omega) as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := entry_length 21 (ContextObjects.limitValue value .AllowedBodyDigests)
  simp only [ok22, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e22 22#u8 .BindingEvidence value (by omega) as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := entry_length 22 (ContextObjects.limitValue value .BindingEvidence)
  simp only [ok23, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e23 23#u8 .CanonicalBodyBytes value (by omega) as ⟨r24, e24, ok24, bytes24⟩
  have len24 := output_length bytes24
  have bound24 := entry_length 23 (ContextObjects.limitValue value .CanonicalBodyBytes)
  simp only [ok24, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e24 24#u8 .RegistryEntries value (by omega) as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := entry_length 24 (ContextObjects.limitValue value .RegistryEntries)
  simp only [ok25, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e25 25#u8 .TrustAnchors value (by omega) as ⟨r26, e26, ok26, bytes26⟩
  have len26 := output_length bytes26
  have bound26 := entry_length 25 (ContextObjects.limitValue value .TrustAnchors)
  simp only [ok26, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e26 26#u8 (by omega) as ⟨r27, e27, ok27, bytes27⟩
  have len27 := output_length bytes27
  have bound27 := encodeHead_length_le_nine ⟨0, 26⟩
  simp only [ok27, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.VerifierLimits.max_work_units, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e27 value.work_units (by omega) as ⟨r28, e28, ok28, bytes28⟩
  have len28 := output_length bytes28
  have bound28 := encodeHead_length_le_nine ⟨0, (value.work_units).val⟩
  simp only [ok28, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e28 27#u8 .Approvals value (by omega) as ⟨r29, e29, ok29, bytes29⟩
  have len29 := output_length bytes29
  have bound29 := entry_length 27 (ContextObjects.limitValue value .Approvals)
  simp only [ok29, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e29 28#u8 .ApproverAnchors value (by omega) as ⟨r30, e30, ok30, bytes30⟩
  have len30 := output_length bytes30
  have bound30 := entry_length 28 (ContextObjects.limitValue value .ApproverAnchors)
  simp only [ok30, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with entry_exact e30 29#u8 .ApprovalRequirements value (by omega) as ⟨r31, e31, ok31, bytes31⟩
  have len31 := output_length bytes31
  have bound31 := entry_length 29 (ContextObjects.limitValue value .ApprovalRequirements)
  simp [ok31, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes31, bytes30, bytes29, bytes28, bytes27, bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.limits, ContextObjects.numbered, ContextObjects.limitValues, ContextObjects.limitValue, entry,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem composition_length (value : auths_model.CompositionRequirement) :
    (ContextObjects.composition value).length ≤ 113 := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.optionalDigest value.expected_plan),
    (1, UnsignedWire.uint value.minimum_authorized_branches.val),
    (2, UnsignedWire.uint value.minimum_distinct_actors.val),
    (3, UnsignedWire.uint value.minimum_distinct_roots.val)]
  have plan := UnsignedLeaves.optional_digest_length value.expected_plan
  have branches := UnsignedWire.uint_length value.minimum_authorized_branches.val
  have actors := UnsignedWire.uint_length value.minimum_distinct_actors.val
  have roots := UnsignedWire.uint_length value.minimum_distinct_roots.val
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  omega

theorem optional_plan_borrow (value : Option auths_model.PlanId) :
    (match value with
      | none => ok none
      | some identifier => do
          let bytes ← auths_model.PlanId.as_bytes identifier
          ok (some bytes)) = ok value := by cases value <;> rfl

@[step] theorem composition_exact (self : cbor.Encoder) (value : auths_model.CompositionRequirement)
    (space : self.output.val.length + 113 ≤ Usize.max) :
    encode.encode_composition_requirement self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.composition value ⦄ := by
  unfold encode.encode_composition_requirement
  step with ProtocolWriter.map_exact self 4#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 4⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CompositionRequirement.impl.expected_plan, core.option.Option.as_ref, optional_plan_borrow, bind_tc_ok]
  step with UnsignedLeaves.optional_digest_exact e1 value.expected_plan (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := UnsignedLeaves.optional_digest_length value.expected_plan
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CompositionRequirement.impl.minimum_authorized_branches, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e3 value.minimum_authorized_branches (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, (value.minimum_authorized_branches).val⟩
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CompositionRequirement.impl.minimum_distinct_actors, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e5 value.minimum_distinct_actors (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := encodeHead_length_le_nine ⟨0, (value.minimum_distinct_actors).val⟩
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CompositionRequirement.impl.minimum_distinct_roots, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e7 value.minimum_distinct_roots (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := encodeHead_length_le_nine ⟨0, (value.minimum_distinct_roots).val⟩
  simp [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ContextObjects.composition,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

end Auths.Crypto.ContextLimits
