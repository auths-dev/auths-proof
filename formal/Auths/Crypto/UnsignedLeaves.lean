import Auths.Crypto.DescriptorWriter

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.UnsignedLeaves
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolEncoderState
open Auths.Codec.ProtocolWriter Auths.Codec.ProtocolObjectWriter

/- Concrete source leaves for the independent unsigned/signed schemas. Space
budgets cover every intermediate append; no caller supplies a successful
source writer, expected intermediate bytes or cryptographic assumption. -/

@[simp] theorem utf8_length (value : String) :
    (UnsignedObjects.utf8 value).length = value.toByteArray.size :=
  ProtocolWriter.stringBytes_length value

theorem identifier_length (value : String) :
    (UnsignedObjects.identifier value).length ≤ 9 + value.toByteArray.size := by
  simpa [UnsignedObjects.identifier, utf8_length] using
    UnsignedWire.text_length (UnsignedObjects.utf8 value)

def PermissionStrings (value : auths_model.Permission) : Prop :=
  value.capability.toByteArray.size ≤ U32.max ∧ value.resource.toByteArray.size ≤ U32.max

def permissionCost (value : auths_model.Permission) : Nat :=
  45 + value.capability.toByteArray.size + value.resource.toByteArray.size

def budgetCost (value : auths_model.BudgetCeiling) : Nat :=
  45 + value.algebra.toByteArray.size

def budgetOptionCost (value : Option auths_model.BudgetCeiling) : Nat :=
  match value with | none => 1 | some value => budgetCost value

def PolicyStrings : auths_model.StatusPolicy → Prop
  | .ExpiryOnly => True
  | .SnapshotRequired method _ => method.toByteArray.size ≤ U32.max

def statusPolicyCost : auths_model.StatusPolicy → Nat
  | .ExpiryOnly => 27
  | .SnapshotRequired method _ => 63 + method.toByteArray.size

theorem permission_schema (value : auths_model.Permission) :
    UnsignedObjects.permission value = permissionEncoding
      (stringBytes value.capability) (stringBytes value.resource) := by
  simp [UnsignedObjects.permission, UnsignedObjects.identifier, UnsignedObjects.utf8,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, UnsignedWire.text,
    permissionEncoding, payloadEncoding, stringBytes, encodeHead, argumentWidth,
    additionalTag, bigEndian, List.append_assoc]

theorem budget_schema (value : auths_model.BudgetCeiling) :
    UnsignedObjects.budget value = budgetEncoding (stringBytes value.algebra) value.value.val := by
  simp [UnsignedObjects.budget, UnsignedObjects.identifier, UnsignedObjects.utf8,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, UnsignedWire.text,
    budgetEncoding, payloadEncoding, stringBytes, encodeHead, argumentWidth,
    additionalTag, bigEndian, List.append_assoc]

theorem profile_schema (value : auths_model.ProfileRef) :
    UnsignedObjects.profile value = profileEncoding (stringBytes value.id) value.version.val := by
  simp [UnsignedObjects.profile, UnsignedObjects.identifier, UnsignedObjects.utf8,
    UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint, UnsignedWire.text,
    profileEncoding, payloadEncoding, stringBytes, encodeHead, argumentWidth,
    additionalTag, bigEndian, List.append_assoc]

theorem optional_budget_schema (value : Option auths_model.BudgetCeiling) :
    UnsignedObjects.optionalBudget value = optionalBudgetEncoding (value.map budgetView) := by
  cases value with
  | none => rfl
  | some value => simpa only [UnsignedObjects.optionalBudget, Option.map_some,
      optionalBudgetEncoding, budgetView] using budget_schema value

theorem optional_budget_length (value : Option auths_model.BudgetCeiling) :
    (UnsignedObjects.optionalBudget value).length ≤ budgetOptionCost value := by
  cases value with
  | none => simp [UnsignedObjects.optionalBudget, UnsignedWire.null, budgetOptionCost]
  | some value =>
    rw [UnsignedObjects.optionalBudget, budget_schema]
    have bound := budget_length_bound (stringBytes value.algebra) value.value.val
    simp only [stringBytes_length] at bound
    simp only [budgetOptionCost, budgetCost]
    omega

@[step] theorem optional_budget_exact (self : cbor.Encoder)
    (value : Option auths_model.BudgetCeiling)
    (strings : ∀ budget ∈ value, budget.algebra.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + budgetOptionCost value ≤ Usize.max) :
    encode.encode_optional_budget self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.optionalBudget value ⦄ := by
  have sameCost : budgetOptionCost value = optionalBudgetCost value := by cases value <;> rfl
  rw [sameCost] at space
  apply spec_mono (ProtocolObjectWriter.optional_budget_exact self value strings space)
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [optional_budget_schema] using written⟩

theorem permission_length (value : auths_model.Permission) :
    (UnsignedObjects.permission value).length ≤ permissionCost value := by
  rw [permission_schema]
  have bound := permission_length_bound (stringBytes value.capability) (stringBytes value.resource)
  simp only [stringBytes_length] at bound
  simp only [permissionCost]
  omega

@[step] theorem permission_exact (self : cbor.Encoder) (value : auths_model.Permission)
    (strings : PermissionStrings value)
    (space : self.output.val.length + permissionCost value ≤ Usize.max) :
    encode.encode_permission self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.permission value ⦄ := by
  apply spec_mono (ProtocolObjectWriter.permission_exact self value strings.1 strings.2 space)
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [permission_schema] using written⟩

@[step] theorem budget_exact (self : cbor.Encoder) (value : auths_model.BudgetCeiling)
    (strings : value.algebra.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + budgetCost value ≤ Usize.max) :
    encode.encode_budget self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.budget value ⦄ := by
  apply spec_mono (ProtocolObjectWriter.budget_exact self value strings space)
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa only [budget_schema] using written⟩

theorem digest_length (value : auths_model.Digest) : (UnsignedObjects.digest value).length ≤ 41 := by
  have length : value.val.length = 32 := by simpa using value.property
  simpa [UnsignedObjects.digest, length] using UnsignedWire.bytes_length (value.val.map UScalar.val)

@[step] theorem digest_exact (self : cbor.Encoder) (value : auths_model.Digest)
    (space : self.output.val.length + 41 ≤ Usize.max) :
    encode.bytes self (Array.to_slice value) ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.digest value ⦄ := by
  have length : value.val.length = 32 := by simpa using value.property
  apply spec_mono (ProtocolWriter.bytes_exact self (Array.to_slice value) (by
    change self.output.val.length + (9 + value.val.length) ≤ Usize.max
    omega))
  rintro actual ⟨success, written⟩
  exact ⟨success, by simpa [UnsignedObjects.digest, Array.to_slice, payloadEncoding, byteList] using written⟩

theorem optional_digest_length (value : Option auths_model.Digest) :
    (UnsignedObjects.optionalDigest value).length ≤ 41 := by
  cases value with
  | none => simp [UnsignedObjects.optionalDigest, UnsignedWire.null]
  | some value => exact digest_length value

theorem optional_grant_borrow (value : Option auths_model.GrantId) :
    (match value with
      | none => ok none
      | some id => do
          let bytes ← auths_model.GrantId.as_bytes id
          ok (some bytes)) = ok value := by
  cases value <;> rfl

theorem optional_digest_borrow (value : Option auths_model.Digest) :
    (match value with
      | none => ok none
      | some id => do
          let bytes ← auths_model.Digest.as_bytes id
          ok (some bytes)) = ok value := by
  cases value <;> rfl

@[step] theorem optional_digest_exact (self : cbor.Encoder) (value : Option auths_model.Digest)
    (space : self.output.val.length + 41 ≤ Usize.max) :
    encode.encode_optional_digest self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.optionalDigest value ⦄ := by
  unfold encode.encode_optional_digest
  cases value with
  | none =>
    step with ProtocolEncoderState.null_exact self (by omega) as ⟨next, written⟩
    simpa [UnsignedObjects.optionalDigest, UnsignedWire.null] using written
  | some value =>
    simpa [UnsignedObjects.optionalDigest] using digest_exact self value space

def extensionCost (value : auths_model.CriticalExtension) : Nat :=
  45 + value.id.toByteArray.size + value.bytes.val.length

def signatureCost (value : auths_model.SignatureEnvelope) : Nat :=
  36 + DescriptorWriter.cost value.descriptor + value.signature.val.length

def factValueCost : auths_model.observation.FactValue → Nat
  | .Uint _ => 9
  | .Bytes value => 9 + value.val.length
  | .Text value => 9 + value.toByteArray.size

def FactValueStrings : auths_model.observation.FactValue → Prop
  | .Text value => value.toByteArray.size ≤ U32.max
  | _ => True

def factCost (value : auths_model.observation.ObservationFact) : Nat :=
  36 + value.name.toByteArray.size + factValueCost value.value

def attachmentCost (value : auths_model.AttachmentDescriptor) : Nat :=
  143 + value.media_type.toByteArray.size + value.disposition.toByteArray.size

theorem extension_length_bound (value : auths_model.CriticalExtension) :
    (UnsignedObjects.extension value).length ≤ extensionCost value := by
  have outer := UnsignedWire.map_length
    [(0, UnsignedWire.text (UnsignedObjects.utf8 value.id)),
     (1, UnsignedWire.bytes (value.bytes.val.map UScalar.val))]
  have textBound := UnsignedWire.text_length (UnsignedObjects.utf8 value.id)
  have bytesBound := UnsignedWire.bytes_length (value.bytes.val.map UScalar.val)
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    List.length_map, utf8_length] at outer textBound bytesBound
  change (UnsignedWire.map _).length ≤ _
  simp only [extensionCost]
  omega

theorem signature_length_bound (value : auths_model.SignatureEnvelope) :
    (UnsignedObjects.signature value).length ≤ signatureCost value := by
  have outer := UnsignedWire.map_length
    [(0, UnsignedObjects.signatureDescriptor value.descriptor),
     (1, UnsignedWire.bytes (value.signature.val.map UScalar.val))]
  have descriptorBound := DescriptorWriter.length_bound value.descriptor
  have bytesBound := UnsignedWire.bytes_length (value.signature.val.map UScalar.val)
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, List.length_map]
    at outer bytesBound
  change (UnsignedWire.map _).length ≤ _
  simp only [signatureCost]
  omega

theorem fact_value_length_bound (value : auths_model.observation.FactValue) :
    (UnsignedObjects.factValue value).length ≤ factValueCost value := by
  cases value with
  | Uint value => exact UnsignedWire.uint_length value.val
  | Bytes value =>
    simpa [UnsignedObjects.factValue, factValueCost] using
      UnsignedWire.bytes_length (value.val.map UScalar.val)
  | Text value =>
    simpa [UnsignedObjects.factValue, UnsignedObjects.identifier, factValueCost] using
      UnsignedWire.text_length (UnsignedObjects.utf8 value)

theorem fact_length_bound (value : auths_model.observation.ObservationFact) :
    (UnsignedObjects.fact value).length ≤ factCost value := by
  have outer := UnsignedWire.map_length
    [(0, UnsignedWire.text (UnsignedObjects.utf8 value.name)),
     (1, UnsignedObjects.factValue value.value)]
  have nameBound := UnsignedWire.text_length (UnsignedObjects.utf8 value.name)
  have valueBound := fact_value_length_bound value.value
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, utf8_length]
    at outer nameBound
  change (UnsignedWire.map _).length ≤ _
  simp only [factCost]
  omega

@[step] theorem extension_exact (self : cbor.Encoder) (value : auths_model.CriticalExtension)
    (idBound : value.id.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + extensionCost value ≤ Usize.max) :
    encode.encode_extension self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.extension value ⦄ := by
  unfold encode.encode_extension
  simp only [extensionCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CriticalExtension.impl.id, auths_model.ExtensionId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.id idBound]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.id idBound).val.length = value.id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.id idBound) (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.id)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CriticalExtension.impl.bytes, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolWriter.bytes_exact e3 (alloc.vec.Vec.deref value.bytes) (by
    simpa only [alloc.vec.deref_exact] using
      (show e3.output.val.length + (9 + value.bytes.val.length) ≤ Usize.max by omega))
    as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 2 (byteList value.bytes.val)
  simp only [byteList, List.length_map] at bound4
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.extension, UnsignedObjects.signatureDescriptor,
    UnsignedObjects.descriptorFields, UnsignedObjects.utf8, UnsignedObjects.identifier,
    UnsignedWire.descriptor, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, UnsignedWire.bytes, stringBytes, payloadEncoding,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, List.append_assoc]

@[step] theorem signature_exact (self : cbor.Encoder) (value : auths_model.SignatureEnvelope)
    (principalBound : value.descriptor.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : value.descriptor.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : value.descriptor.suite.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + signatureCost value ≤ Usize.max) :
    encode.encode_signature self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.signature value ⦄ := by
  unfold encode.encode_signature
  simp only [signatureCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignatureEnvelope.impl.descriptor, bind_tc_ok]
  step with DescriptorWriter.descriptor_exact e1 value.descriptor
    principalBound verificationBound suiteBound (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := DescriptorWriter.length_bound value.descriptor
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.SignatureEnvelope.impl.signature, auths_model.SignatureBytes.impl.as_slice, core.ops.deref.DerefVec, bind_tc_ok]
  step with ProtocolWriter.bytes_exact e3 (alloc.vec.Vec.deref value.signature) (by
    simpa only [alloc.vec.deref_exact] using
      (show e3.output.val.length + (9 + value.signature.val.length) ≤ Usize.max by omega))
    as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 2 (byteList value.signature.val)
  simp only [byteList, List.length_map] at bound4
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.signature, UnsignedObjects.signatureDescriptor,
    UnsignedObjects.descriptorFields, UnsignedObjects.utf8, UnsignedObjects.identifier,
    UnsignedWire.descriptor, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, UnsignedWire.bytes, stringBytes, payloadEncoding,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, List.append_assoc]

@[step] theorem fact_value_exact (self : cbor.Encoder)
    (value : auths_model.observation.FactValue) (strings : FactValueStrings value)
    (space : self.output.val.length + factValueCost value ≤ Usize.max) :
    observation.encode_fact_value self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.factValue value ⦄ := by
  cases value with
  | Uint value =>
    unfold observation.encode_fact_value
    step with ProtocolEncoderState.u64_exact self value (by simpa [factValueCost] using space)
      as ⟨verdict, next, success, written⟩
    simpa [UnsignedObjects.factValue, UnsignedWire.uint, success,
      core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch] using written
  | Bytes value =>
    unfold observation.encode_fact_value
    simp only [auths_model.observation.FactBytes.impl.as_slice,
      core.ops.deref.DerefVec, bind_tc_ok]
    apply spec_mono (ProtocolWriter.bytes_exact self (alloc.vec.Vec.deref value) (by
      simpa [factValueCost, alloc.vec.deref_exact] using space))
    rintro actual ⟨success, written⟩
    exact ⟨success, by simpa [UnsignedObjects.factValue, UnsignedWire.bytes,
      payloadEncoding, byteList, alloc.vec.deref_exact] using written⟩
  | Text value =>
    unfold observation.encode_fact_value
    simp only [auths_model.observation.FactText.impl.as_str]
    have bounded : value.toByteArray.size ≤ U32.max := strings
    rw [StringRefinement.string_borrow_exact value bounded]
    simp only [bind_tc_ok]
    have size : (toStr value bounded).val.length = value.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    apply spec_mono (ProtocolWriter.text_exact self (toStr value bounded) (by
      simpa [factValueCost, size] using space))
    rintro actual ⟨success, written⟩
    exact ⟨success, by simpa [UnsignedObjects.factValue, UnsignedObjects.identifier,
      UnsignedObjects.utf8, UnsignedWire.text, payloadEncoding, borrowed_bytes,
      stringBytes] using written⟩

@[step] theorem fact_exact (self : cbor.Encoder) (value : auths_model.observation.ObservationFact)
    (nameBound : value.name.toByteArray.size ≤ U32.max)
    (valueBound : FactValueStrings value.value)
    (space : self.output.val.length + factCost value ≤ Usize.max) :
    observation.encode_observation_fact self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.fact value ⦄ := by
  unfold observation.encode_observation_fact
  simp only [factCost] at space
  step with ProtocolWriter.map_exact self 2#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationFact.impl.name, auths_model.observation.FactName.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.name nameBound]
  simp only [bind_tc_ok]
  have borrowLength2 : (toStr value.name nameBound).val.length = value.name.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.name nameBound) (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.name)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.observation.ObservationFact.impl.value, bind_tc_ok]
  step with fact_value_exact e3 value.value valueBound (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := fact_value_length_bound value.value
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp [bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.fact, UnsignedObjects.signatureDescriptor,
    UnsignedObjects.descriptorFields, UnsignedObjects.utf8, UnsignedObjects.identifier,
    UnsignedWire.descriptor, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, UnsignedWire.bytes, stringBytes, payloadEncoding,
    alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref, List.append_assoc]


theorem attachment_length_bound (value : auths_model.AttachmentDescriptor) :
    (UnsignedObjects.attachment value).length ≤ attachmentCost value := by
  have digestLength : value.digest.val.length = 32 := by simpa using value.digest.property
  have digestBound : (UnsignedObjects.digest value.digest).length ≤ 41 := by
    simpa [UnsignedObjects.digest, digestLength] using
      UnsignedWire.bytes_length (value.digest.val.map UScalar.val)
  have mediaBound := UnsignedWire.text_length (UnsignedObjects.utf8 value.media_type)
  have dispositionBound := UnsignedWire.text_length (UnsignedObjects.utf8 value.disposition)
  have wordBound := UnsignedWire.uint_length value.byte_length.val
  have outer := UnsignedWire.map_length [
    (0, UnsignedObjects.digest value.digest),
    (1, UnsignedObjects.identifier value.media_type),
    (2, UnsignedWire.uint value.byte_length.val),
    (3, UnsignedObjects.identifier value.disposition),
    (4, UnsignedWire.boolean (match value.confidentiality with | .Encrypted => true | .Plain => false)),
    (5, UnsignedWire.boolean (match value.presence with | .Required => true | .Optional => false)),
    (6, UnsignedWire.boolean (match value.opacity with | .OpaqueAllowed => true | .MustBeInspectable => false))]
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    UnsignedWire.boolean_length, utf8_length] at outer mediaBound dispositionBound
  change (UnsignedWire.map _).length ≤ _
  simp only [attachmentCost]
  omega

@[step] theorem attachment_exact (self : cbor.Encoder) (value : auths_model.AttachmentDescriptor)
    (mediaBound : value.media_type.toByteArray.size ≤ U32.max)
    (dispositionBound : value.disposition.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + attachmentCost value ≤ Usize.max) :
    encode.encode_attachment self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.attachment value ⦄ := by
  unfold encode.encode_attachment
  simp only [attachmentCost] at space
  have digestLength : value.digest.val.length = 32 := by simpa using value.digest.property
  step with ProtocolWriter.map_exact self 7#u64 (by omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 7⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AttachmentDescriptor.impl.digest, auths_model.AttachmentDigest.as_bytes,
    lift, Array.to_slice, bind_tc_ok]
  step with ProtocolWriter.bytes_exact e1 (Array.to_slice value.digest) (by
    change e1.output.val.length + (9 + value.digest.val.length) ≤ Usize.max
    omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 2 (byteList value.digest.val)
  simp only [byteList, List.length_map, digestLength] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AttachmentDescriptor.impl.media_type, auths_model.MediaType.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.media_type mediaBound]
  simp only [bind_tc_ok]
  have borrowLength4 : (toStr value.media_type mediaBound).val.length = value.media_type.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.media_type mediaBound) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.media_type)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AttachmentDescriptor.impl.byte_length, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e5 value.byte_length (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := encodeHead_length_le_nine ⟨0, value.byte_length.val⟩
  simp only [ok6, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AttachmentDescriptor.impl.disposition, auths_model.DispositionId.as_str, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact value.disposition dispositionBound]
  simp only [bind_tc_ok]
  have borrowLength8 : (toStr value.disposition dispositionBound).val.length = value.disposition.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e7 (toStr value.disposition dispositionBound) (by omega)
    as ⟨r8, e8, ok8, bytes8⟩
  rw [borrowed_bytes] at bytes8
  have len8 := output_length bytes8
  have bound8 := payload_length_bound 3 (stringBytes value.disposition)
  rw [stringBytes_length] at bound8
  simp only [ok8, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AttachmentDescriptor.impl.confidentiality, bind_tc_ok]
  step with ProtocolEncoderState.bool_exact e9 (match value.confidentiality with | .Encrypted => true | .Plain => false) (by omega)
    as ⟨e10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 : (if (match value.confidentiality with | .Encrypted => true | .Plain => false) then [245] else [244] : List Nat).length ≤ 1 := by
    split <;> simp
  step with ProtocolWriter.key_exact e10 5#u8 (by omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AttachmentDescriptor.impl.presence, bind_tc_ok]
  step with ProtocolEncoderState.bool_exact e11 (match value.presence with | .Required => true | .Optional => false) (by omega)
    as ⟨e12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 : (if (match value.presence with | .Required => true | .Optional => false) then [245] else [244] : List Nat).length ≤ 1 := by
    split <;> simp
  step with ProtocolWriter.key_exact e12 6#u8 (by omega)
    as ⟨r13, e13, ok13, bytes13⟩
  have len13 := output_length bytes13
  have bound13 := encodeHead_length_le_nine ⟨0, 6⟩
  simp only [ok13, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.AttachmentDescriptor.impl.opacity, bind_tc_ok]
  step with ProtocolEncoderState.bool_exact e13 (match value.opacity with | .OpaqueAllowed => true | .MustBeInspectable => false) (by omega)
    as ⟨e14, bytes14⟩
  have len14 := output_length bytes14
  have bound14 : (if (match value.opacity with | .OpaqueAllowed => true | .MustBeInspectable => false) then [245] else [244] : List Nat).length ≤ 1 := by
    split <;> simp
  simp [bytes14, bytes13, bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0,
    UnsignedObjects.attachment, UnsignedObjects.digest, UnsignedObjects.identifier,
    UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
    UnsignedWire.text, UnsignedWire.bytes, UnsignedWire.boolean, stringBytes, payloadEncoding,
    Array.to_slice, byteList, List.append_assoc]

theorem status_policy_length (value : auths_model.StatusPolicy) :
    (UnsignedObjects.statusPolicy value).length ≤ statusPolicyCost value := by
  cases value with
  | ExpiryOnly =>
    have outer := UnsignedWire.map_length [(0, UnsignedWire.uint 0)]
    have tag := UnsignedWire.uint_length 0
    simpa [UnsignedObjects.statusPolicy, statusPolicyCost, UnsignedWire.map,
      UnsignedWire.entries, UnsignedWire.uint, encodeHead, argumentWidth, additionalTag, bigEndian] using
      (show (UnsignedWire.map [(0, UnsignedWire.uint 0)]).length ≤ 27 from by
        simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
        omega)
  | SnapshotRequired method maximum =>
    have outer := UnsignedWire.map_length
      [(0, UnsignedWire.uint 1), (1, UnsignedObjects.identifier method),
       (2, UnsignedWire.uint maximum.val)]
    have tag := UnsignedWire.uint_length 1
    have age := UnsignedWire.uint_length maximum.val
    have textBound := UnsignedWire.text_length (UnsignedObjects.utf8 method)
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      utf8_length] at outer textBound
    change (UnsignedWire.map _).length ≤ _
    simp only [statusPolicyCost]
    omega

@[step] theorem status_policy_exact (self : cbor.Encoder) (value : auths_model.StatusPolicy)
    (strings : PolicyStrings value)
    (space : self.output.val.length + statusPolicyCost value ≤ Usize.max) :
    encode.encode_status_policy self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ UnsignedObjects.statusPolicy value ⦄ := by
  cases value with
  | ExpiryOnly =>
    unfold encode.encode_status_policy
    simp only [statusPolicyCost] at space
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
    step with ProtocolEncoderState.u8_exact e1 (0#u8) (by omega)
      as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok2, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp [bytes2, bytes1, bytes0, UnsignedObjects.statusPolicy, UnsignedObjects.identifier,
      UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
      UnsignedWire.text, stringBytes, payloadEncoding, List.append_assoc]
  | SnapshotRequired method maximum =>
    unfold encode.encode_status_policy
    simp only [statusPolicyCost] at space
    step with ProtocolWriter.map_exact self 3#u64 (by omega)
      as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
    simp only [ok0, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e0 0#u8 (by omega)
      as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncoderState.u8_exact e1 (1#u8) (by omega)
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
    simp only [auths_model.StatusMethodId.as_str]
    have bounded : method.toByteArray.size ≤ U32.max := strings
    rw [StringRefinement.string_borrow_exact method bounded]
    simp only [bind_tc_ok]
    have textLength : (toStr method bounded).val.length = method.toByteArray.size := by
      simp [toStr, ByteArray.length_toList]
    step with ProtocolWriter.text_exact e3 (toStr method bounded) (by omega)
      as ⟨r4, e4, ok4, bytes4⟩
    rw [borrowed_bytes] at bytes4
    have len4 := output_length bytes4
    have bound4 := payload_length_bound 3 (stringBytes method)
    rw [stringBytes_length] at bound4
    simp only [ok4, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolWriter.key_exact e4 2#u8 (by omega)
      as ⟨r5, e5, ok5, bytes5⟩
    have len5 := output_length bytes5
    have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
    simp only [ok5, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [auths_model.FreshnessLimit.get, bind_tc_ok]
    step with ProtocolEncoderState.u64_exact e5 maximum (by omega)
      as ⟨r6, e6, ok6, bytes6⟩
    have len6 := output_length bytes6
    have bound6 := encodeHead_length_le_nine ⟨0, maximum.val⟩
    simp only [ok6, core.result.Result.map_err,
      core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp [bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, UnsignedObjects.statusPolicy, UnsignedObjects.identifier,
      UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries, UnsignedWire.uint,
      UnsignedWire.text, stringBytes, payloadEncoding, List.append_assoc]

end Auths.Crypto.UnsignedLeaves
