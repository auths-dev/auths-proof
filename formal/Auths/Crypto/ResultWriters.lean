import Auths.Crypto.ResultAssurance
import Auths.Crypto.ResultSatisfactions
import Auths.Codec.CanonicalValues

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ResultWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Crypto.SigningObjectWriters

/- Complete actual portable-result output and zero-self-digest projection.
All fields are retained under explicit field/native space conditions, without
assuming any successful encoder, expected byte string, trusted result flag,
decision consistency, digest opening or execution authority. -/
structure Fields (value : auths_model.PortableVerificationResult) : Prop where
  reports : ∀ report ∈ value.assurance.val, ResultAssurance.ReportFields report
  satisfactions : ∀ satisfaction ∈ value.assurance_satisfactions.val, ResultAssurance.SatisfactionFields satisfaction

theorem result_length (include : Bool) (value : auths_model.PortableVerificationResult) :
    (ResultObjects.result include value).length ≤ ResultObjects.resultCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedWire.uint (ResultObjects.decision value.decision)),
    (1, UnsignedWire.uint (ResultObjects.stage value.stage)), (2, ResultObjects.code value.code),
    (3, UnsignedObjects.digest value.proof_digest), (4, UnsignedObjects.digest value.action_digest),
    (5, UnsignedObjects.digest value.context_digest), (6, UnsignedObjects.optionalDigest value.plan_id),
    (7, ResultObjects.selfDigest include value.result_digest),
    (8, UnsignedWire.array (value.authorized_branches.val.map UnsignedObjects.digest)),
    (9, UnsignedWire.array (value.assurance.val.map ResultObjects.report)),
    (10, UnsignedWire.array (value.assurance_satisfactions.val.map ResultObjects.assuranceSatisfaction)),
    (11, ResultObjects.resources value.resources), (12, UnsignedObjects.digest value.registry_manifest),
    (13, UnsignedObjects.optionalDigest value.required_configuration),
    (14, UnsignedObjects.digest value.local_configuration), (15, UnsignedWire.uint 4),
    (16, UnsignedWire.array (value.observation_satisfactions.val.map ResultObjects.observationSatisfaction)),
    (17, UnsignedWire.array (value.approval_satisfactions.val.map ResultObjects.approvalSatisfaction))]
  have decision := UnsignedWire.uint_length (ResultObjects.decision value.decision)
  have stage := UnsignedWire.uint_length (ResultObjects.stage value.stage)
  have code := ResultLeaves.code_length value.code
  have proof := UnsignedLeaves.digest_length value.proof_digest
  have action := UnsignedLeaves.digest_length value.action_digest
  have context := UnsignedLeaves.digest_length value.context_digest
  have plan := UnsignedLeaves.optional_digest_length value.plan_id
  have selfDigest := ResultLeaves.self_digest_length include value.result_digest
  have branches := BundleLeaves.evidence_ids_length value.authorized_branches.val
  have reports := array_model_length ResultObjects.report ResultObjects.reportCost ResultAssurance.report_length value.assurance.val
  have satisfactions := array_model_length ResultObjects.assuranceSatisfaction ResultObjects.assuranceSatisfactionCost
    ResultAssurance.satisfaction_length value.assurance_satisfactions.val
  have resources := ResultLeaves.resources_length value.resources
  have registry := UnsignedLeaves.digest_length value.registry_manifest
  have required := UnsignedLeaves.optional_digest_length value.required_configuration
  have localConfiguration := UnsignedLeaves.digest_length value.local_configuration
  have version := UnsignedWire.uint_length 4
  have observations := array_model_length ResultObjects.observationSatisfaction (fun _ => 109)
    ResultSatisfactions.observation_length value.observation_satisfactions.val
  have approvals := array_model_length ResultObjects.approvalSatisfaction ResultObjects.approvalSatisfactionCost
    ResultSatisfactions.approval_length value.approval_satisfactions.val
  simp only [ResultSatisfactions.constant_allocation] at observations
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [ResultObjects.resultCost, List.sum_cons, List.sum_nil]
  omega

@[step] theorem result_exact (self : cbor.Encoder) (value : auths_model.PortableVerificationResult)
    (include : Bool) (fields : Fields value)
    (space : self.output.val.length + ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * (self.output.val.length + ResultObjects.resultCost value) : Int) ≤ Isize.max) :
    encode.encode_verification_result_to self value include ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ResultObjects.result include value ⦄ := by
  unfold encode.encode_verification_result_to
  simp only [ResultObjects.resultCost, List.sum_cons, List.sum_nil] at space native
  step with ProtocolWriter.map_exact self 18#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 18⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.decision, bind_tc_ok]
  step with ResultLeaves.decision_tag_exact value.decision as ⟨decision, decisionMeaning⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e1 decision (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (decision).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.stage, bind_tc_ok]
  step with ResultLeaves.stage_tag_exact value.stage as ⟨stage, stageMeaning⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e3 stage (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, (stage).val⟩
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.code, bind_tc_ok]
  step with ResultLeaves.code_exact e5 value.code (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := ResultLeaves.code_length value.code
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.proof_digest, auths_model.Digest.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e7 value.proof_digest (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := UnsignedLeaves.digest_length value.proof_digest
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.action_digest, auths_model.Digest.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e9 value.action_digest (by omega) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := UnsignedLeaves.digest_length value.action_digest
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.context_digest, auths_model.ContextDigest.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e11 value.context_digest (by omega) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := UnsignedLeaves.digest_length value.context_digest
  simp only [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e12 6#u8 (by omega) as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.plan_id, core.option.Option.as_ref, ContextLimits.optional_plan_borrow, bind_tc_ok]
  step with UnsignedLeaves.optional_digest_exact e13 value.plan_id (by omega) as ⟨r14, e14, ok14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 := UnsignedLeaves.optional_digest_length value.plan_id
  simp only [ok14, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e14 7#u8 (by omega) as ⟨r15, e15, ok15, bytes15⟩
  have len15 := output_length bytes15
  have bound15 := encodeHead_length_le_nine ⟨0, 7⟩
  simp only [ok15, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.result_digest, bind_tc_ok]
  step with ResultLeaves.self_digest_exact e15 value.result_digest include (by omega) as ⟨r16, e16, ok16, bytes16⟩
  have len16 := output_length bytes16
  have bound16 := ResultLeaves.self_digest_length include value.result_digest
  simp only [ok16, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e16 8#u8 (by omega) as ⟨r17, e17, ok17, bytes17⟩
  have len17 := output_length bytes17
  have bound17 := encodeHead_length_le_nine ⟨0, 8⟩
  simp only [ok17, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.authorized_branches, core.ops.deref.DerefVec, bind_tc_ok]
  step with ResultLeaves.proof_refs_exact e17 (alloc.vec.Vec.deref value.authorized_branches) (by simpa only [alloc.vec.deref_exact, BundleLeaves.id_allocation] using (show e17.output.val.length + 9 + 41 * value.authorized_branches.val.length ≤ Usize.max by omega)) as ⟨r18, e18, ok18, bytes18⟩
  have len18 := output_length bytes18
  have bound18 := BundleLeaves.evidence_ids_length value.authorized_branches.val
  simp only [ok18, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e18 9#u8 (by omega) as ⟨r19, e19, ok19, bytes19⟩
  have len19 := output_length bytes19
  have bound19 := encodeHead_length_le_nine ⟨0, 9⟩
  simp only [ok19, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.assurance, core.ops.deref.DerefVec, bind_tc_ok]
  step with ResultAssurance.reports_exact e19 (alloc.vec.Vec.deref value.assurance) fields.reports (by simpa only [alloc.vec.deref_exact] using (show e19.output.val.length + 9 + allocation ResultObjects.reportCost value.assurance.val ≤ Usize.max by omega)) as ⟨r20, e20, ok20, bytes20⟩
  have len20 := output_length bytes20
  have bound20 := array_model_length ResultObjects.report ResultObjects.reportCost ResultAssurance.report_length value.assurance.val
  simp only [ok20, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e20 10#u8 (by omega) as ⟨r21, e21, ok21, bytes21⟩
  have len21 := output_length bytes21
  have bound21 := encodeHead_length_le_nine ⟨0, 10⟩
  simp only [ok21, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.assurance_satisfactions, core.ops.deref.DerefVec, bind_tc_ok]
  step with ResultAssurance.satisfactions_exact e21 (alloc.vec.Vec.deref value.assurance_satisfactions) fields.satisfactions (by simpa only [alloc.vec.deref_exact] using (show e21.output.val.length + 9 + allocation ResultObjects.assuranceSatisfactionCost value.assurance_satisfactions.val ≤ Usize.max by omega)) as ⟨r22, e22, ok22, bytes22⟩
  have len22 := output_length bytes22
  have bound22 := array_model_length ResultObjects.assuranceSatisfaction ResultObjects.assuranceSatisfactionCost ResultAssurance.satisfaction_length value.assurance_satisfactions.val
  simp only [ok22, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e22 11#u8 (by omega) as ⟨r23, e23, ok23, bytes23⟩
  have len23 := output_length bytes23
  have bound23 := encodeHead_length_le_nine ⟨0, 11⟩
  simp only [ok23, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.resources, bind_tc_ok]
  step with ResultLeaves.resources_exact e23 value.resources (by omega) as ⟨r24, e24, ok24, bytes24⟩
  have len24 := output_length bytes24
  have bound24 := ResultLeaves.resources_length value.resources
  simp only [ok24, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e24 12#u8 (by omega) as ⟨r25, e25, ok25, bytes25⟩
  have len25 := output_length bytes25
  have bound25 := encodeHead_length_le_nine ⟨0, 12⟩
  simp only [ok25, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.registry_manifest, auths_model.RegistryManifestId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e25 value.registry_manifest (by omega) as ⟨r26, e26, ok26, bytes26⟩
  have len26 := output_length bytes26
  have bound26 := UnsignedLeaves.digest_length value.registry_manifest
  simp only [ok26, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e26 13#u8 (by omega) as ⟨r27, e27, ok27, bytes27⟩
  have len27 := output_length bytes27
  have bound27 := encodeHead_length_le_nine ⟨0, 13⟩
  simp only [ok27, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.required_configuration, core.option.Option.as_ref, ResultLeaves.optional_configuration_borrow, bind_tc_ok]
  step with UnsignedLeaves.optional_digest_exact e27 value.required_configuration (by omega) as ⟨r28, e28, ok28, bytes28⟩
  have len28 := output_length bytes28
  have bound28 := UnsignedLeaves.optional_digest_length value.required_configuration
  simp only [ok28, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e28 14#u8 (by omega) as ⟨r29, e29, ok29, bytes29⟩
  have len29 := output_length bytes29
  have bound29 := encodeHead_length_le_nine ⟨0, 14⟩
  simp only [ok29, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.local_configuration, auths_model.VerifierConfigurationId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e29 value.local_configuration (by omega) as ⟨r30, e30, ok30, bytes30⟩
  have len30 := output_length bytes30
  have bound30 := UnsignedLeaves.digest_length value.local_configuration
  simp only [ok30, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e30 15#u8 (by omega) as ⟨r31, e31, ok31, bytes31⟩
  have len31 := output_length bytes31
  have bound31 := encodeHead_length_le_nine ⟨0, 15⟩
  simp only [ok31, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [encode.PORTABLE_RESULT_ABI_VERSION, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e31 4#u16 (by omega) as ⟨r32, e32, ok32, bytes32⟩
  have len32 := output_length bytes32
  have bound32 := encodeHead_length_le_nine ⟨0, (4#u16).val⟩
  simp only [ok32, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e32 16#u8 (by omega) as ⟨r33, e33, ok33, bytes33⟩
  have len33 := output_length bytes33
  have bound33 := encodeHead_length_le_nine ⟨0, 16⟩
  simp only [ok33, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.observation_satisfactions, core.ops.deref.DerefVec, bind_tc_ok]
  step with ResultSatisfactions.observations_exact e33 (alloc.vec.Vec.deref value.observation_satisfactions) (by simp) (by simpa only [alloc.vec.deref_exact, ResultSatisfactions.constant_allocation] using (show e33.output.val.length + 9 + 109 * value.observation_satisfactions.val.length ≤ Usize.max by omega)) as ⟨r34, e34, ok34, bytes34⟩
  have len34 := output_length bytes34
  have bound34 := array_model_length ResultObjects.observationSatisfaction (fun _ => 109) ResultSatisfactions.observation_length value.observation_satisfactions.val
  simp only [ResultSatisfactions.constant_allocation] at bound34
  simp only [ok34, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e34 17#u8 (by omega) as ⟨r35, e35, ok35, bytes35⟩
  have len35 := output_length bytes35
  have bound35 := encodeHead_length_le_nine ⟨0, 17⟩
  simp only [ok35, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PortableVerificationResult.impl.approval_satisfactions, core.ops.deref.DerefVec, bind_tc_ok]
  step with ResultSatisfactions.approvals_exact e35 (alloc.vec.Vec.deref value.approval_satisfactions) (by simp) (by simpa only [alloc.vec.deref_exact] using (show e35.output.val.length + 9 + allocation ResultObjects.approvalSatisfactionCost value.approval_satisfactions.val ≤ Usize.max by omega)) as ⟨r36, e36, ok36, bytes36⟩
  have len36 := output_length bytes36
  have bound36 := array_model_length ResultObjects.approvalSatisfaction ResultObjects.approvalSatisfactionCost ResultSatisfactions.approval_length value.approval_satisfactions.val
  simp [ok36, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes36, bytes35, bytes34, bytes33, bytes32, bytes31, bytes30, bytes29, bytes28, bytes27, bytes26, bytes25, bytes24, bytes23, bytes22, bytes21, bytes20, bytes19, bytes18, bytes17, bytes16, bytes15, bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, ResultObjects.result, decisionMeaning, stageMeaning,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem projection_encoder (value : auths_model.PortableVerificationResult) (include : Bool)
    (fields : Fields value) (space : ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * ResultObjects.resultCost value : Int) ≤ Isize.max) :
    encode.encode_verification_result_projection value include ⦃ result => Encodes (ResultObjects.result include value) result ⦄ := by
  unfold encode.encode_verification_result_projection
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with result_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value include fields
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using native)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem result_encoder (value : auths_model.PortableVerificationResult)
    (fields : Fields value) (space : ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * ResultObjects.resultCost value : Int) ≤ Isize.max) :
    encode.encode_verification_result_value value ⦃ result => Encodes (ResultObjects.result true value) result ⦄ := by
  unfold encode.encode_verification_result_value
  exact projection_encoder value true fields space native

@[step] theorem digest_input_encoder (value : auths_model.PortableVerificationResult)
    (fields : Fields value) (space : ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * ResultObjects.resultCost value : Int) ≤ Isize.max) :
    encode.encode_verification_result_digest_input value ⦃ result => Encodes (ResultObjects.result false value) result ⦄ := by
  unfold encode.encode_verification_result_digest_input
  exact projection_encoder value false fields space native

@[step] theorem canonical_encoder
    (carrier : canonical_value.Canonical auths_model.PortableVerificationResult)
    (value : auths_model.PortableVerificationResult) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (fields : Fields value) (space : ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * ResultObjects.resultCost value : Int) ≤ Isize.max) :
    encode.encode_verification_result carrier ⦃ result => Encodes (ResultObjects.result true value) result ⦄ := by
  unfold encode.encode_verification_result
  rw [projection]
  simpa only [bind_tc_ok] using result_encoder value fields space native

theorem canonical_projection (carrier : canonical_value.Canonical auths_model.PortableVerificationResult) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (fields : Fields value) (space : ResultObjects.resultCost value ≤ Usize.max)
        (native : (2 * ResultObjects.resultCost value : Int) ≤ Isize.max),
        encode.encode_verification_result carrier ⦃ result => Encodes (ResultObjects.result true value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun fields space native => canonical_encoder carrier value projection fields space native⟩

end Auths.Crypto.ResultWriters
