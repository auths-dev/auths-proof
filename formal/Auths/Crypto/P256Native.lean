import Auths.Crypto.P256LowContract
import Auths.Crypto.P256Encoding
import Auths.Crypto.Strict.SourceAcceptance
open Aeneas Aeneas.Std Result
open AuthsNativeP256
open Auths.Crypto.Strict.SuiteModel
namespace Auths.Crypto.P256Native

/-- Projections of ordinary foreign Result values, independent of Auths policy. -/
def resultOption {T E : Type} : Aeneas.Std.core.result.Result T E → Option T
  | .Ok value => some value | .Err _ => none

def resultIsOk {T E : Type} : Aeneas.Std.core.result.Result T E → Bool
  | .Ok _ => true | .Err _ => false

/-- Functional contracts of the three foreign P-256/SHA-256 operations.
No encoding guard, low-S check, Auths wrapper or desired suite result is a premise. -/
structure Contract [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool) : Prop where
  decode_exact : ∀ bytes, (do let value ← P.decode bytes; ok (resultOption value)) = ok (decode bytes.val)
  parse_exact : ∀ bytes, (do let value ← P.parse bytes; ok (resultOption value)) = ok (parse bytes.val)
  verify_exact : ∀ key message signature,
    (do let value ← P.verify key message signature; ok (resultIsOk value)) =
      ok (equation key message.val signature)

def keyOption [P : P256Primitives] : Option P.Key → core.qualified_p256_type_decls_13
  | none => .None | some key => .Some key

def signatureOption [P : P256Primitives] : Option P.Signature → core.qualified_p256_type_decls_12
  | none => .None | some signature => .Some signature

def failure : Failure → P256Error
  | .key => .InvalidKey | .shape => .InvalidSignatureEncoding | .equation => .VerificationFailed

def keyResult [P : P256Primitives] : Except Failure P.Key → core.qualified_p256_type_decls_3
  | .ok key => .Ok key | .error reason => .Err (failure reason)

def verifyResult : Except Failure Unit → core.qualified_p256_type_decls_0
  | .ok unitValue => .Ok unitValue | .error reason => .Err (failure reason)

def fixedResult : Option (Array Std.U8 64#usize) → core.qualified_p256_type_decls_9
  | none => .Err () | some bytes => .Ok bytes

theorem decode_leaf_refines [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : Contract decode parse equation) (bytes : Slice Std.U8) :
    AuthsNativeP256.decode_p256_point bytes = ok (keyOption (decode bytes.val)) := by
  have meaning := contract.decode_exact bytes
  unfold AuthsNativeP256.decode_p256_point ecdsa.qualified_p256_fun_decls_29
    core.qualified_p256_fun_decls_30
  cases evaluated : P.decode bytes with
  | fail reason => simp [evaluated] at meaning
  | div => simp [evaluated] at meaning
  | ok value =>
    cases value <;> simp_all [resultOption, keyOption] <;> rw [← meaning]

theorem parse_leaf_refines [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : Contract decode parse equation) (bytes : Array Std.U8 64#usize) :
    AuthsNativeP256.parse_p256_signature bytes = ok (signatureOption (parse bytes.val)) := by
  have meaning := contract.parse_exact bytes.to_slice
  unfold AuthsNativeP256.parse_p256_signature ecdsa.qualified_p256_fun_decls_23
    core.qualified_p256_fun_decls_24
  simp only [lift, bind_tc_ok]
  cases evaluated : P.parse bytes.to_slice with
  | fail reason => simp [evaluated] at meaning
  | div => simp [evaluated] at meaning
  | ok value =>
    cases value <;> simp_all [resultOption, signatureOption] <;> rw [← meaning]

theorem equation_leaf_refines [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : Contract decode parse equation)
    (key : P.Key) (message : Slice Std.U8) (signature : P.Signature) :
    AuthsNativeP256.verify_p256_equation key message signature = ok (equation key message.val signature) := by
  have meaning := contract.verify_exact key message signature
  unfold AuthsNativeP256.verify_p256_equation
    ecdsa.qualified_p256_type_decls_4.Insts.SignatureVerifierVerifierqualified_p256_type_decls_11.verify
    core.qualified_p256_fun_decls_27
  cases evaluated : P.verify key message signature with
  | fail reason => simp [evaluated] at meaning
  | div => simp [evaluated] at meaning
  | ok value => cases value <;> simp_all [resultIsOk]

theorem fixed_refines (bytes : Slice Std.U8) :
    SharedSliceU8.Insts.CoreConvertTryIntoArrayU864.try_into bytes =
      ok (fixedResult (fixed 64#usize bytes.val)) := by
  unfold SharedSliceU8.Insts.CoreConvertTryIntoArrayU864.try_into fixed fixedResult
  by_cases sized : bytes.val.length = 64 <;> simp [sized]

theorem decode_refines [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : Contract decode parse equation) (bytes : Slice Std.U8) :
    AuthsNativeP256.decode_p256_key_with bytes = ok (keyResult (p256Key decode bytes.val)) := by
  unfold AuthsNativeP256.decode_p256_key_with
  rw [P256Encoding.guard_refines]
  simp only [bind_tc_ok, AuthsNativeP256.NativeP256.Insts.Auths_signature_coreP256Primitive.decode]
  rw [decode_leaf_refines decode parse equation contract]
  by_cases canonical : Auths.Crypto.Encoding.P256.Encoding (bytes.val.map UScalar.val)
  · cases decoded : decode bytes.val <;>
      simp [canonical, decoded, keyOption, keyResult, failure, p256Key, P256Encoding.Encoding]
  · simp [canonical, keyResult, failure, p256Key, P256Encoding.Encoding]

theorem public_verify_refines [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : Contract decode parse equation) (bytes message signature : Slice Std.U8) :
    AuthsNativeP256.verify_p256_sha256 bytes message signature =
      ok (verifyResult (p256Verify decode parse equation bytes.val message.val signature.val)) := by
  unfold AuthsNativeP256.verify_p256_sha256 AuthsNativeP256.verify_p256_sha256_with
  rw [decode_refines decode parse equation contract]
  cases decoded : p256Key decode bytes.val with
  | error reason =>
    simp [keyResult, verifyResult, decoded, p256Verify, Except.bind, Bind.bind, Except.instMonad,
      core.qualified_p256_type_decls_3.Insts.CoreOpsTry_traitTry.branch,
      core.qualified_p256_type_decls_0.Insts.CoreOpsTry_traitFromResidualqualified_p256_type_decls_7.from_residual]
  | ok point =>
    simp only [keyResult, bind_tc_ok,
      core.qualified_p256_type_decls_3.Insts.CoreOpsTry_traitTry.branch]
    rw [fixed_refines]
    cases sized : fixed 64#usize signature.val with
    | none =>
      simp [fixedResult, p256Verify, decoded, fixedSignature, sized, verifyResult, failure, Except.bind, Bind.bind, Except.instMonad]
    | some array =>
      simp only [fixedResult, bind_tc_ok,
        AuthsNativeP256.NativeP256.Insts.Auths_signature_coreP256Primitive.parse]
      rw [parse_leaf_refines decode parse equation contract]
      cases parsed : parse array.val with
      | none =>
        simp [signatureOption, parsed, p256Verify, decoded, fixedSignature, sized, verifyResult, failure, Except.bind, Bind.bind, Except.instMonad]
      | some scalar =>
        simp only [signatureOption, bind_tc_ok,
          AuthsNativeP256.NativeP256.Insts.Auths_signature_coreP256Primitive.verify]
        rw [P256LowContract.guard_refines, equation_leaf_refines decode parse equation contract]
        by_cases low : ByteLex.value (array.val.drop 32) ≤ LowContract.order / 2 <;>
          cases checked : equation point message.val scalar <;>
          simp [low, checked, parsed, p256Verify, decoded, fixedSignature, sized,
            P256LowContract.order, verifyResult, failure, Except.bind, Bind.bind, Except.instMonad]

theorem verify_result_ok (result : Except Failure Unit) :
    verifyResult result = .Ok () ↔ result = .ok () := by
  cases result with
  | error reason => simp [verifyResult]
  | ok unitValue => cases unitValue; simp [verifyResult]

theorem public_accepts_iff [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : Contract decode parse equation) (bytes message signature : Slice Std.U8) :
    AuthsNativeP256.verify_p256_sha256 bytes message signature = ok (.Ok ()) ↔
      Auths.Crypto.Strict.Acceptance.P256Accepts decode parse equation bytes.val message.val signature.val := by
  rw [public_verify_refines decode parse equation contract]
  simp only [Result.ok.injEq, verify_result_ok, Auths.Crypto.Strict.Acceptance.p256_accepts_iff]

theorem public_validate_refines [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : Contract decode parse equation) (bytes : Slice Std.U8) :
    AuthsNativeP256.validate_p256_key bytes =
      ok (verifyResult (do let _ ← p256Key decode bytes.val; pure ())) := by
  unfold AuthsNativeP256.validate_p256_key AuthsNativeP256.decode_p256_key
  rw [decode_refines decode parse equation contract]
  cases decoded : p256Key decode bytes.val <;>
    simp [keyResult, verifyResult, Except.bind, Bind.bind, Except.instMonad] <;> rfl

end Auths.Crypto.P256Native
