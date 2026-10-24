import Auths.Crypto.SnapshotObjects
import Auths.Codec.ProtocolTextWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SnapshotLeaves
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Codec.ProtocolTextWriters

def ScopeStrings : auths_model.StatusScope → Prop
  | .OwnAnchor => True
  | .Anchors anchors => ∀ identifier ∈ anchors.val, identifier.toByteArray.size ≤ U32.max
  | .AnyAnchor => True

structure TrustStrings (value : auths_model.StatusTrustRule) : Prop where
  method : value.method.toByteArray.size ≤ U32.max
  issuer : value.issuer.toByteArray.size ≤ U32.max
  scope : ScopeStrings value.scope

theorem scope_length (value : auths_model.StatusScope) :
    (SnapshotObjects.scope value).length ≤ SnapshotObjects.scopeCost value := by
  cases value with
  | OwnAnchor =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 0)]
    have tag := UnsignedWire.uint_length 0
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ _
    simp only [SnapshotObjects.scopeCost]
    omega
  | Anchors anchors =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 1),
      (1, UnsignedWire.array (anchors.val.map UnsignedObjects.identifier))]
    have tag := UnsignedWire.uint_length 1
    have values := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length anchors.val
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ _
    simp only [SnapshotObjects.scopeCost]
    omega
  | AnyAnchor =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 2)]
    have tag := UnsignedWire.uint_length 2
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ _
    simp only [SnapshotObjects.scopeCost]
    omega

theorem trust_rule_length (value : auths_model.StatusTrustRule) :
    (SnapshotObjects.trustRule value).length ≤ SnapshotObjects.trustRuleCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.identifier value.method),
    (1, UnsignedObjects.identifier value.issuer), (2, UnsignedWire.uint value.sequence_floor.val),
    (3, SnapshotObjects.scope value.scope)]
  have method := UnsignedLeaves.identifier_length value.method
  have issuer := UnsignedLeaves.identifier_length value.issuer
  have floor := UnsignedWire.uint_length value.sequence_floor.val
  have scope := scope_length value.scope
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [SnapshotObjects.trustRuleCost]
  omega

theorem trust_length (values : List auths_model.StatusTrustRule) :
    (SnapshotObjects.trust values).length ≤ SnapshotObjects.trustCost values :=
  array_model_length SnapshotObjects.trustRule SnapshotObjects.trustRuleCost trust_rule_length values

@[step] theorem scope_exact (self : cbor.Encoder) (value : auths_model.StatusScope)
    (strings : ScopeStrings value)
    (space : self.output.val.length + SnapshotObjects.scopeCost value ≤ Usize.max) :
    encode.encode_status_scope self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ SnapshotObjects.scope value ⦄ := by
  cases value with
  | OwnAnchor =>
    unfold encode.encode_status_scope
    simp only [SnapshotObjects.scopeCost] at space
    step with ProtocolWriter.map_exact self 1#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 1⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 0#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, (0#u8).val⟩
    simp [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes2, bytes1, bytes0, SnapshotObjects.scope,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | Anchors anchors =>
    unfold encode.encode_status_scope
    simp only [SnapshotObjects.scopeCost] at space
    step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 1#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, (1#u8).val⟩
    simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.StatusScopeAnchors.impl.ids, core.ops.deref.DerefVec, bind_tc_ok]
    step with ProtocolTextWriters.trust_anchor_ids_exact e3 (alloc.vec.Vec.deref anchors) strings (by simpa only [alloc.vec.deref_exact] using (show e3.output.val.length + 9 + allocation textCost anchors.val ≤ Usize.max by omega)) as ⟨r4, e4, ok4, bytes4⟩
    have len4 := output_length bytes4
    have bound4 := array_model_length UnsignedObjects.identifier textCost UnsignedLeaves.identifier_length anchors.val
    simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes4, bytes3, bytes2, bytes1, bytes0, SnapshotObjects.scope,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]
  | AnyAnchor =>
    unfold encode.encode_status_scope
    simp only [SnapshotObjects.scopeCost] at space
    step with ProtocolWriter.map_exact self 1#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 1⟩
    simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 2#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, (2#u8).val⟩
    simp [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
      bytes2, bytes1, bytes0, SnapshotObjects.scope,
      UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
      alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem trust_rule_exact (self : cbor.Encoder) (value : auths_model.StatusTrustRule)
    (strings : TrustStrings value)
    (space : self.output.val.length + SnapshotObjects.trustRuleCost value ≤ Usize.max) :
    encode.encode_status_trust_rule self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ SnapshotObjects.trustRule value ⦄ := by
  unfold encode.encode_status_trust_rule
  simp only [SnapshotObjects.trustRuleCost] at space
  step with ProtocolWriter.map_exact self 4#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 4⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.StatusTrustRule.impl.method, auths_model.StatusMethodId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.method strings.method]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.method strings.method).val.length = value.method.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.method strings.method) (by omega) as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.method)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.StatusTrustRule.impl.issuer, auths_model.PrincipalId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.issuer strings.issuer]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.issuer strings.issuer).val.length = value.issuer.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.issuer strings.issuer) (by omega) as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.issuer)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.StatusTrustRule.impl.sequence_floor, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e5 value.sequence_floor (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := encodeHead_length_le_nine ⟨0, (value.sequence_floor).val⟩
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.StatusTrustRule.impl.scope, bind_tc_ok]
  step with scope_exact e7 value.scope strings.scope (by omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := scope_length value.scope
  simp [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, SnapshotObjects.trustRule,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

end Auths.Crypto.SnapshotLeaves
