import qualification.aeneas.generated.suite_adapter.Funs
import Auths.Crypto.NativeContract
import Auths.Crypto.P256Native
open Aeneas Aeneas.Std Result
open AuthsSuiteAdapters
open Auths.Crypto.Strict.SuiteModel
namespace Auths.Crypto.SuiteAdapters

def portFailure : Failure → auths_ports.SignatureError
  | .key => .InvalidKey | .shape => .InvalidSignatureEncoding | .equation => .InvalidSignature

def portResult : Except Failure Unit → Aeneas.Std.core.result.Result Unit auths_ports.SignatureError
  | .ok value => .Ok value | .error reason => .Err (portFailure reason)

theorem ed_public_refines [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key) (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool)
    (contract : Native.Ed25519Contract decode signatureValue equation)
    (suite : Ed25519Suite) (input : auths_ports.SignatureInput) :
    Ed25519Suite.Insts.Auths_portsSignatureSuite.verify (edPrimitive := P) suite input =
      ok (portResult (edVerify decode equation input.verification_key.val
        input.signing_preimage.val input.signature.val)) := by
  unfold Ed25519Suite.Insts.Auths_portsSignatureSuite.verify
    AuthsSuiteAdapters.auths_signature_core.verify_ed25519
  rw [Native.public_verify_refines decode signatureValue equation contract]
  cases result : edVerify decode equation input.verification_key.val input.signing_preimage.val input.signature.val with
  | error reason =>
    cases reason <;> simp [edResult, fromEdError, sourceEd, sourceEdFailure, portResult, portFailure,
      AuthsSuiteAdapters.core.result.Result.map_err, _root_.core.result.Result.map_err,
      SignatureSuiteEd25519Suite.verify.closure.Insts.CoreOpsFunctionFnOnceTupleEd25519ErrorSignatureError.call_once]
  | ok value =>
    cases value
    simp [edResult, sourceEd, portResult, AuthsSuiteAdapters.core.result.Result.map_err,
      _root_.core.result.Result.map_err]

theorem p256_public_refines [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : P256Native.Contract decode parse equation)
    (suite : P256Sha256Suite) (input : auths_ports.SignatureInput) :
    P256Sha256Suite.Insts.Auths_portsSignatureSuite.verify (p256Primitive := P) suite input =
      ok (portResult (p256Verify decode parse equation input.verification_key.val
        input.signing_preimage.val input.signature.val)) := by
  unfold P256Sha256Suite.Insts.Auths_portsSignatureSuite.verify
    AuthsSuiteAdapters.auths_signature_core.verify_p256_sha256
  rw [P256Native.public_verify_refines decode parse equation contract]
  cases result : p256Verify decode parse equation input.verification_key.val input.signing_preimage.val input.signature.val with
  | error reason =>
    cases reason <;> simp [p256Result, fromP256Error, P256Native.verifyResult, P256Native.failure,
      portResult, portFailure, AuthsSuiteAdapters.core.result.Result.map_err,
      _root_.core.result.Result.map_err,
      SignatureSuiteP256Sha256Suite.verify.closure.Insts.CoreOpsFunctionFnOnceTupleP256ErrorSignatureError.call_once]
  | ok value =>
    cases value
    simp [p256Result, P256Native.verifyResult, portResult,
      AuthsSuiteAdapters.core.result.Result.map_err, _root_.core.result.Result.map_err]

theorem port_result_ok (result : Except Failure Unit) :
    portResult result = .Ok () ↔ result = .ok () := by
  cases result with
  | error reason => simp [portResult]
  | ok value => cases value; simp [portResult]

theorem ed_accepts_iff [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key) (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool)
    (contract : Native.Ed25519Contract decode signatureValue equation)
    (suite : Ed25519Suite) (input : auths_ports.SignatureInput) :
    Ed25519Suite.Insts.Auths_portsSignatureSuite.verify (edPrimitive := P) suite input = ok (.Ok ()) ↔
      Strict.Acceptance.EdAccepts decode equation input.verification_key.val
        input.signing_preimage.val input.signature.val := by
  rw [ed_public_refines decode signatureValue equation contract]
  simp only [Result.ok.injEq, port_result_ok, Strict.Acceptance.ed_accepts_iff]

theorem p256_accepts_iff [P : P256Primitives]
    (decode : List Std.U8 → Option P.Key) (parse : List Std.U8 → Option P.Signature)
    (equation : P.Key → List Std.U8 → P.Signature → Bool)
    (contract : P256Native.Contract decode parse equation)
    (suite : P256Sha256Suite) (input : auths_ports.SignatureInput) :
    P256Sha256Suite.Insts.Auths_portsSignatureSuite.verify (p256Primitive := P) suite input = ok (.Ok ()) ↔
      Strict.Acceptance.P256Accepts decode parse equation input.verification_key.val
        input.signing_preimage.val input.signature.val := by
  rw [p256_public_refines decode parse equation contract]
  simp only [Result.ok.injEq, port_result_ok, Strict.Acceptance.p256_accepts_iff]

end Auths.Crypto.SuiteAdapters
