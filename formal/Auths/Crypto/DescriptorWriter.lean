import Auths.Codec.ProtocolObjectWriter
import Auths.Crypto.UnsignedObjects

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.DescriptorWriter
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolEncoderState
open Auths.Codec.ProtocolWriter Auths.Codec.ProtocolObjectWriter

def cost (value : auths_model.SignatureDescriptor) : Nat :=
  63 + value.principal_method.toByteArray.size + value.verification_method.toByteArray.size +
    value.suite.toByteArray.size

theorem length_bound (value : auths_model.SignatureDescriptor) :
    (UnsignedObjects.signatureDescriptor value).length ≤ cost value := by
  have outer := UnsignedWire.map_length
    [(0, UnsignedWire.text (UnsignedObjects.utf8 value.principal_method)),
     (1, UnsignedWire.text (UnsignedObjects.utf8 value.verification_method)),
     (2, UnsignedWire.text (UnsignedObjects.utf8 value.suite))]
  have principal := UnsignedWire.text_length (UnsignedObjects.utf8 value.principal_method)
  have verification := UnsignedWire.text_length (UnsignedObjects.utf8 value.verification_method)
  have suite := UnsignedWire.text_length (UnsignedObjects.utf8 value.suite)
  have utf8Length (text : String) : (UnsignedObjects.utf8 text).length = text.toByteArray.size :=
    ProtocolWriter.stringBytes_length text
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  simp only [utf8Length] at principal verification suite
  change (UnsignedWire.map _).length ≤ _
  simp only [cost]
  omega

/-- The actual source writer emits all three independent descriptor fields
in the specified map positions. The space envelope bounds every intermediate
append; string bounds describe the standard borrow representation, not a
successful encoding or expected-byte premise. -/
@[step] theorem descriptor_exact (self : cbor.Encoder) (value : auths_model.SignatureDescriptor)
    (principalBound : value.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : value.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : value.suite.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + cost value ≤ Usize.max) :
    encode.encode_signature_descriptor self value ⦃ actual =>
      actual.1 = .Ok () ∧ byteList actual.2.output.val = byteList self.output.val ++
        UnsignedObjects.signatureDescriptor value ⦄ := by
  unfold encode.encode_signature_descriptor
  simp only [cost] at space
  step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.SignatureDescriptor.impl.principal_method, auths_model.PrincipalMethodId.as_str]
  rw [StringRefinement.string_borrow_exact value.principal_method principalBound]
  simp only [bind_tc_ok]
  have principalLength : (toStr value.principal_method principalBound).val.length =
      value.principal_method.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e1 (toStr value.principal_method principalBound) (by omega)
    as ⟨r2, e2, ok2, bytes2⟩
  rw [borrowed_bytes] at bytes2
  have len2 := output_length bytes2
  have bound2 := payload_length_bound 3 (stringBytes value.principal_method)
  rw [stringBytes_length] at bound2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.SignatureDescriptor.impl.verification_method, auths_model.VerificationMethod.as_str]
  rw [StringRefinement.string_borrow_exact value.verification_method verificationBound]
  simp only [bind_tc_ok]
  have verificationLength : (toStr value.verification_method verificationBound).val.length =
      value.verification_method.toByteArray.size := by simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e3 (toStr value.verification_method verificationBound) (by omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes value.verification_method)
  rw [stringBytes_length] at bound4
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
    auths_model.SignatureDescriptor.impl.suite, auths_model.SignatureSuiteId.as_str]
  rw [StringRefinement.string_borrow_exact value.suite suiteBound]
  simp only [bind_tc_ok]
  have suiteLength : (toStr value.suite suiteBound).val.length = value.suite.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolWriter.text_exact e5 (toStr value.suite suiteBound) (by omega)
    as ⟨r6, e6, ok6, bytes6⟩
  rw [borrowed_bytes] at bytes6
  simp [ok6, core.result.Result.Insts.CoreOpsTry.branch,
    bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0,
    UnsignedObjects.signatureDescriptor, UnsignedObjects.descriptorFields,
    UnsignedObjects.utf8, UnsignedWire.descriptor, UnsignedWire.map,
    UnsignedWire.entries, UnsignedWire.uint, UnsignedWire.text,
    stringBytes, payloadEncoding, List.append_assoc]

theorem fields_valid (value : auths_model.SignatureDescriptor)
    (principalBound : value.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : value.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : value.suite.toByteArray.size ≤ U32.max) :
    (UnsignedObjects.descriptorFields value).Valid := by
  have utf8Length (text : String) : (UnsignedObjects.utf8 text).length = text.toByteArray.size :=
    ProtocolWriter.stringBytes_length text
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · change (UnsignedObjects.utf8 value.principal_method).length < 2 ^ 64
    rw [utf8Length]
    scalar_tac
  · change (UnsignedObjects.utf8 value.verification_method).length < 2 ^ 64
    rw [utf8Length]
    scalar_tac
  · change (UnsignedObjects.utf8 value.suite).length < 2 ^ 64
    rw [utf8Length]
    scalar_tac
  · change BytesValid (stringBytes value.principal_method)
    rw [← borrowed_bytes value.principal_method principalBound]
    exact ProtocolFraming.byte_values_valid _
  · change BytesValid (stringBytes value.verification_method)
    rw [← borrowed_bytes value.verification_method verificationBound]
    exact ProtocolFraming.byte_values_valid _
  · change BytesValid (stringBytes value.suite)
    rw [← borrowed_bytes value.suite suiteBound]
    exact ProtocolFraming.byte_values_valid _

/-- Equal successful output from a common prefix binds every descriptor's
exact UTF-8 field bytes. This composes actual writer execution with the
independent descriptor inverse and uses no hash or signature premise. -/
theorem source_binds_fields (self : cbor.Encoder) (left right : auths_model.SignatureDescriptor)
    (leftPrincipal : left.principal_method.toByteArray.size ≤ U32.max)
    (leftVerification : left.verification_method.toByteArray.size ≤ U32.max)
    (leftSuite : left.suite.toByteArray.size ≤ U32.max)
    (rightPrincipal : right.principal_method.toByteArray.size ≤ U32.max)
    (rightVerification : right.verification_method.toByteArray.size ≤ U32.max)
    (rightSuite : right.suite.toByteArray.size ≤ U32.max)
    (leftSpace : self.output.val.length + cost left ≤ Usize.max)
    (rightSpace : self.output.val.length + cost right ≤ Usize.max)
    (leftOutput rightOutput : cbor.Encoder)
    (leftAccepted : encode.encode_signature_descriptor self left = ok (.Ok (), leftOutput))
    (rightAccepted : encode.encode_signature_descriptor self right = ok (.Ok (), rightOutput))
    (same : leftOutput.output.val = rightOutput.output.val) :
    UnsignedObjects.utf8 left.principal_method = UnsignedObjects.utf8 right.principal_method ∧
      UnsignedObjects.utf8 left.verification_method = UnsignedObjects.utf8 right.verification_method ∧
      UnsignedObjects.utf8 left.suite = UnsignedObjects.utf8 right.suite := by
  obtain ⟨leftActual, leftRuns, _, leftBytes⟩ := spec_imp_exists
    (descriptor_exact self left leftPrincipal leftVerification leftSuite leftSpace)
  obtain ⟨rightActual, rightRuns, _, rightBytes⟩ := spec_imp_exists
    (descriptor_exact self right rightPrincipal rightVerification rightSuite rightSpace)
  have leftSame : leftActual = (.Ok (), leftOutput) := Result.ok.inj (leftRuns.symm.trans leftAccepted)
  have rightSame : rightActual = (.Ok (), rightOutput) := Result.ok.inj (rightRuns.symm.trans rightAccepted)
  simp only [leftSame] at leftBytes
  simp only [rightSame] at rightBytes
  have outputBytes := congrArg byteList same
  rw [leftBytes, rightBytes] at outputBytes
  have descriptorSame : UnsignedObjects.signatureDescriptor left = UnsignedObjects.signatureDescriptor right :=
    List.append_left_cancel outputBytes
  exact UnsignedWire.descriptor_binds_fields _ _
    (fields_valid left leftPrincipal leftVerification leftSuite)
    (fields_valid right rightPrincipal rightVerification rightSuite) descriptorSame

end Auths.Crypto.DescriptorWriter
