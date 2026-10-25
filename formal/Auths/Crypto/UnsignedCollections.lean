import Auths.Codec.ProtocolTextWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.UnsignedCollections
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolEncoderState Auths.Codec.ProtocolArrayWriters
open Auths.Crypto.UnsignedLeaves

def permissionsCost (value : auths_model.PermissionSet) : Nat :=
  9 + allocation permissionCost value.val

def extensionsCost (value : auths_model.CriticalExtensions) : Nat :=
  9 + allocation extensionCost value.val

def attachmentsCost (values : alloc.vec.Vec auths_model.AttachmentDescriptor) : Nat :=
  9 + allocation attachmentCost values.val

def factsCost (value : auths_model.observation.ObservationFacts) : Nat :=
  9 + allocation factCost value.val

def audiencesCost (value : auths_model.AudienceSet) : Nat :=
  9 + allocation ProtocolTextWriters.textCost value.val

def constraintCost : auths_model.ActionConstraint → Nat
  | .AnyBody => 27
  | .ExactBodyDigest _ => 77
  | .AllowedBodyDigests values => 45 + allocation (fun _ => 41) values.val

theorem permissions_length (value : auths_model.PermissionSet) :
    (UnsignedWire.array (value.val.map UnsignedObjects.permission)).length ≤ permissionsCost value :=
  array_model_length _ _ permission_length _

theorem extensions_length (value : auths_model.CriticalExtensions) :
    (UnsignedObjects.extensions value).length ≤ extensionsCost value :=
  array_model_length _ _ extension_length_bound _

theorem attachments_length (value : alloc.vec.Vec auths_model.AttachmentDescriptor) :
    (UnsignedWire.array (value.val.map UnsignedObjects.attachment)).length ≤ attachmentsCost value :=
  array_model_length _ _ attachment_length_bound _

theorem facts_length (value : auths_model.observation.ObservationFacts) :
    (UnsignedWire.array (value.val.map UnsignedObjects.fact)).length ≤ factsCost value :=
  array_model_length _ _ fact_length_bound _

theorem audiences_length (value : auths_model.AudienceSet) :
    (UnsignedWire.array (value.val.map UnsignedObjects.identifier)).length ≤ audiencesCost value :=
  array_model_length _ _ ProtocolTextWriters.text_length_bound _

theorem constraint_length (value : auths_model.ActionConstraint) :
    (UnsignedObjects.constraint value).length ≤ constraintCost value := by
  cases value with
  | AnyBody =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 0)]
    have tag := UnsignedWire.uint_length 0
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ 27
    omega
  | ExactBodyDigest value =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 1), (1, UnsignedObjects.digest value)]
    have tag := UnsignedWire.uint_length 1
    have digest := digest_length value
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ 77
    omega
  | AllowedBodyDigests values =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 2),
      (1, UnsignedWire.array (values.val.map UnsignedObjects.digest))]
    have tag := UnsignedWire.uint_length 2
    have valuesBound := array_model_length _ (fun _ => 41) digest_length values.val
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
    change (UnsignedWire.map _).length ≤ 45 + allocation (fun _ => 41) values.val
    omega

@[step] theorem constraint_exact (self : cbor.Encoder) (value : auths_model.ActionConstraint)
    (space : self.output.val.length + constraintCost value ≤ Usize.max) :
    encode.encode_constraint self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.constraint value ⦄ := by
  cases value with
  | AnyBody =>
    unfold encode.encode_constraint
    simp only [constraintCost] at space
    step with ProtocolWriter.map_exact self 1#u64 (by omega)
      as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 1⟩
    simp only [ok0, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega)
      as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 0#u8 (by omega)
      as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok2, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp [bytes2, bytes1, bytes0, UnsignedObjects.constraint, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, alloc.vec.deref_exact, List.append_assoc]
  | ExactBodyDigest digest =>
    unfold encode.encode_constraint
    simp only [constraintCost] at space
    step with ProtocolWriter.map_exact self 2#u64 (by omega)
      as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega)
      as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 1#u8 (by omega)
      as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok2, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega)
      as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.Digest.as_bytes, lift, Array.to_slice, bind_tc_ok]
    step with UnsignedLeaves.digest_exact e3 digest (by omega)
      as ⟨r4, e4, ok4, bytes4⟩
    have len4 := output_length bytes4
    have bound4 := digest_length digest
    simp only [ok4, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp [bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.constraint, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, alloc.vec.deref_exact, List.append_assoc]
  | AllowedBodyDigests values =>
    unfold encode.encode_constraint
    simp only [constraintCost] at space
    step with ProtocolWriter.map_exact self 2#u64 (by omega)
      as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega)
      as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 2#u8 (by omega)
      as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 2⟩
    simp only [ok2, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e2 1#u8 (by omega)
      as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.BodyDigestSet.impl.as_slice,
      auths_model.bounded.BoundedSet.impl.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
    step with ProtocolArrayWriters.body_digests_exact e3 (alloc.vec.Vec.deref values)
      (by intro value member; trivial) (by
        simpa only [alloc.vec.deref_exact] using
          (show e3.output.val.length + 9 + allocation (fun _ => 41) values.val ≤ Usize.max by omega))
      as ⟨r4, e4, ok4, bytes4⟩
    have len4 := output_length bytes4
    have bound4 := array_model_length _ (fun _ => 41) digest_length values.val
    simp only [alloc.vec.deref_exact] at len4
    simp only [ok4, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp [bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.constraint, UnsignedWire.map, UnsignedWire.entries,
      UnsignedWire.uint, alloc.vec.deref_exact, List.append_assoc]

@[step] theorem permissions_exact (self : cbor.Encoder) (value : auths_model.PermissionSet)
    (fields : ∀ item ∈ value.val, PermissionStrings item) (space : self.output.val.length + permissionsCost value ≤ Usize.max) :
    encode.encode_permission_set self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedWire.array (value.val.map UnsignedObjects.permission) ⦄ := by
  apply spec_mono (ProtocolArrayWriters.permissions_exact self value (by simpa only [alloc.vec.deref_exact] using fields) (by
    simpa only [permissionsCost, alloc.vec.deref_exact, Nat.add_assoc] using space))
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [alloc.vec.deref_exact, UnsignedObjects.extensions] using written⟩

@[step] theorem extensions_exact (self : cbor.Encoder) (value : auths_model.CriticalExtensions)
    (fields : ∀ item ∈ value.val, ExtensionStrings item) (space : self.output.val.length + extensionsCost value ≤ Usize.max) :
    encode.encode_extensions self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.extensions value ⦄ := by
  apply spec_mono (ProtocolArrayWriters.extensions_exact self value (by simpa only [alloc.vec.deref_exact] using fields) (by
    simpa only [extensionsCost, alloc.vec.deref_exact, Nat.add_assoc] using space))
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [alloc.vec.deref_exact, UnsignedObjects.extensions] using written⟩

@[step] theorem attachments_exact (self : cbor.Encoder) (value : alloc.vec.Vec auths_model.AttachmentDescriptor)
    (fields : ∀ item ∈ value.val, AttachmentStrings item) (space : self.output.val.length + attachmentsCost value ≤ Usize.max) :
    encode.encode_attachments self (alloc.vec.Vec.deref value) ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedWire.array (value.val.map UnsignedObjects.attachment) ⦄ := by
  apply spec_mono (ProtocolArrayWriters.attachments_exact self (alloc.vec.Vec.deref value) (by simpa only [alloc.vec.deref_exact] using fields) (by
    simpa only [attachmentsCost, alloc.vec.deref_exact, Nat.add_assoc] using space))
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [alloc.vec.deref_exact, UnsignedObjects.extensions] using written⟩

@[step] theorem facts_exact (self : cbor.Encoder) (value : auths_model.observation.ObservationFacts)
    (fields : ∀ item ∈ value.val, FactStrings item) (space : self.output.val.length + factsCost value ≤ Usize.max) :
    observation.encode_observation_facts self (alloc.vec.Vec.deref value) ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedWire.array (value.val.map UnsignedObjects.fact) ⦄ := by
  apply spec_mono (ProtocolArrayWriters.facts_exact self (alloc.vec.Vec.deref value) (by simpa only [alloc.vec.deref_exact] using fields) (by
    simpa only [factsCost, alloc.vec.deref_exact, Nat.add_assoc] using space))
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [alloc.vec.deref_exact, UnsignedObjects.extensions] using written⟩

@[step] theorem audiences_exact (self : cbor.Encoder) (value : auths_model.AudienceSet)
    (fields : ∀ item ∈ value.val, item.toByteArray.size ≤ U32.max) (space : self.output.val.length + audiencesCost value ≤ Usize.max) :
    text_list.encode_audiences self (alloc.vec.Vec.deref value) ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedWire.array (value.val.map UnsignedObjects.identifier) ⦄ := by
  apply spec_mono (ProtocolTextWriters.audiences_exact self (alloc.vec.Vec.deref value) (by simpa only [alloc.vec.deref_exact] using fields) (by
    simpa only [audiencesCost, alloc.vec.deref_exact, Nat.add_assoc] using space))
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [alloc.vec.deref_exact, UnsignedObjects.extensions] using written⟩

end Auths.Crypto.UnsignedCollections
