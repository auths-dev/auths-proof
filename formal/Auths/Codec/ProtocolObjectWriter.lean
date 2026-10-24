import Auths.Codec.ProtocolWriter
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec
namespace Auths.Codec.ProtocolObjectWriter
open Refinement ProtocolEncoderState ProtocolWriter

/-- These are field encodings. Standalone canonical acceptance additionally
requires exact outer shape, complete consumption and canonical re-encoding. -/
def profileEncoding (id : List Nat) (version : Nat) : List Nat :=
  [162, 0] ++ payloadEncoding 3 id ++ [1] ++ encodeHead ⟨0, version⟩

def permissionEncoding (capability resource : List Nat) : List Nat :=
  [162, 0] ++ payloadEncoding 3 capability ++ [1] ++ payloadEncoding 3 resource

def budgetEncoding (algebra : List Nat) (value : Nat) : List Nat :=
  [162, 0] ++ payloadEncoding 3 algebra ++ [1] ++ encodeHead ⟨0, value⟩

def optionalBudgetEncoding (value : Option (List Nat × Nat)) : List Nat :=
  match value with | none => [246] | some (algebra, amount) => budgetEncoding algebra amount

theorem payload_length_bound (major : Nat) (bytes : List Nat) :
    (payloadEncoding major bytes).length ≤ 9 + bytes.length := by
  have headBound := encodeHead_length_le_nine ⟨major, bytes.length⟩
  simpa only [payloadEncoding, List.length_append] using Nat.add_le_add_right headBound bytes.length

theorem profile_length_bound (id : List Nat) (version : Nat) :
    (profileEncoding id version).length ≤ 21 + id.length := by
  have textBound := payload_length_bound 3 id
  have wordBound := encodeHead_length_le_nine ⟨0, version⟩
  simp only [profileEncoding, List.length_append, List.length_cons, List.length_nil]
  omega

theorem permission_length_bound (capability resource : List Nat) :
    (permissionEncoding capability resource).length ≤ 21 + capability.length + resource.length := by
  have capBound := payload_length_bound 3 capability
  have resourceBound := payload_length_bound 3 resource
  simp only [permissionEncoding, List.length_append, List.length_cons, List.length_nil]
  omega

theorem budget_length_bound (algebra : List Nat) (value : Nat) :
    (budgetEncoding algebra value).length ≤ 21 + algebra.length := by
  exact profile_length_bound algebra value

@[step] theorem profile_exact (self : cbor.Encoder) (value : AuthsProtocolCodec.auths_model.ProfileRef)
    (firstBound : value.id.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + (45 + value.id.toByteArray.size) ≤ Usize.max) :
    encode.encode_profile_ref self value ⦃ actual =>
      actual.1 = .Ok () ∧ byteList actual.2.output.val = byteList self.output.val ++
        profileEncoding (stringBytes value.id) value.version.val ⦄ := by
  unfold encode.encode_profile_ref
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.ProfileRef.impl.id, auths_model.ProfileId.as_str]
  rw [StringRefinement.string_borrow_exact value.id firstBound]
  simp only [bind_tc_ok]
  have firstLength : (toStr value.id firstBound).val.length = value.id.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.id firstBound) (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.id)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.ProfileRef.impl.version]
  step with ProtocolEncoderState.u16_exact e3 value.version (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, profileEncoding, List.append_assoc,
    encodeHead, additionalTag, argumentWidth, bigEndian]

@[step] theorem budget_exact (self : cbor.Encoder) (value : AuthsProtocolCodec.auths_model.BudgetCeiling)
    (firstBound : value.algebra.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + (45 + value.algebra.toByteArray.size) ≤ Usize.max) :
    encode.encode_budget self value ⦃ actual =>
      actual.1 = .Ok () ∧ byteList actual.2.output.val = byteList self.output.val ++
        budgetEncoding (stringBytes value.algebra) value.value.val ⦄ := by
  unfold encode.encode_budget
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.BudgetCeiling.impl.algebra, auths_model.BudgetAlgebraId.as_str]
  rw [StringRefinement.string_borrow_exact value.algebra firstBound]
  simp only [bind_tc_ok]
  have firstLength : (toStr value.algebra firstBound).val.length = value.algebra.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.algebra firstBound) (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.algebra)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.BudgetCeiling.impl.value]
  step with ProtocolEncoderState.u64_exact e3 value.value (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, budgetEncoding, List.append_assoc,
    encodeHead, additionalTag, argumentWidth, bigEndian]

@[step] theorem permission_exact (self : cbor.Encoder) (value : AuthsProtocolCodec.auths_model.Permission)
    (firstBound : value.capability.toByteArray.size ≤ U32.max)
    (secondBound : value.resource.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + (45 + value.capability.toByteArray.size + value.resource.toByteArray.size) ≤ Usize.max) :
    encode.encode_permission self value ⦃ actual =>
      actual.1 = .Ok () ∧ byteList actual.2.output.val = byteList self.output.val ++
        permissionEncoding (stringBytes value.capability) (stringBytes value.resource) ⦄ := by
  unfold encode.encode_permission
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.Permission.impl.capability, auths_model.CapabilityId.as_str]
  rw [StringRefinement.string_borrow_exact value.capability firstBound]
  simp only [bind_tc_ok]
  have firstLength : (toStr value.capability firstBound).val.length = value.capability.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.capability firstBound) (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.capability)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.Permission.impl.resource, auths_model.ResourceId.as_str]
  rw [StringRefinement.string_borrow_exact value.resource secondBound]
  simp only [bind_tc_ok]
  have secondLength : (toStr value.resource secondBound).val.length = value.resource.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.resource secondBound) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, permissionEncoding, List.append_assoc,
    encodeHead, additionalTag, argumentWidth, bigEndian]

def budgetView (value : AuthsProtocolCodec.auths_model.BudgetCeiling) : List Nat × Nat :=
  (stringBytes value.algebra, value.value.val)

def optionalBudgetCost (value : Option AuthsProtocolCodec.auths_model.BudgetCeiling) : Nat :=
  match value with | none => 1 | some value => 45 + value.algebra.toByteArray.size

def optionalBudgetStringsBounded (value : Option AuthsProtocolCodec.auths_model.BudgetCeiling) : Prop :=
  ∀ budget ∈ value, budget.algebra.toByteArray.size ≤ U32.max

@[step] theorem optional_budget_exact (self : cbor.Encoder)
    (value : Option AuthsProtocolCodec.auths_model.BudgetCeiling)
    (stringsBounded : optionalBudgetStringsBounded value)
    (space : self.output.val.length + optionalBudgetCost value ≤ Usize.max) :
    encode.encode_optional_budget self value ⦃ actual =>
      actual.1 = .Ok () ∧ byteList actual.2.output.val = byteList self.output.val ++
        optionalBudgetEncoding (value.map budgetView) ⦄ := by
  unfold encode.encode_optional_budget
  cases value with
  | none =>
    step with ProtocolEncoderState.null_exact self (by simpa [optionalBudgetCost] using space)
      as ⟨next, written⟩
    simp [written, optionalBudgetEncoding]
  | some budget =>
    have bounded : budget.algebra.toByteArray.size ≤ U32.max := stringsBounded budget (by simp)
    simpa [optionalBudgetEncoding, optionalBudgetCost, budgetView] using
      budget_exact self budget bounded space

end Auths.Codec.ProtocolObjectWriter
