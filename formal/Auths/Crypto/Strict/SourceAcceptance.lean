import Auths.Crypto.Strict.Acceptance
open Aeneas Aeneas.Std Result
open auths_signature_core Auths.Crypto.Strict.SuiteModel Auths.Crypto.Strict.Acceptance
namespace Auths.Crypto.Strict.SourceAcceptance

theorem ed_result_ok (outcome : Except Failure Unit) :
    sourceEd outcome = .Ok () ↔ outcome = .ok () := by
  cases outcome with
  | error reason => simp [sourceEd]
  | ok empty => cases empty; simp [sourceEd]

theorem p256_result_ok (outcome : Except Failure Unit) :
    sourceP256 outcome = .Ok () ↔ outcome = .ok () := by
  cases outcome with
  | error reason => simp [sourceP256]
  | ok empty => cases empty; simp [sourceP256]

theorem ed_source_accepts_iff {K D V : Type}
    (decoderPrimitive : core.ops.function.FnOnce D (Array Std.U8 32#usize) (Option K))
    (verifierPrimitive : core.ops.function.FnOnce V (K × Slice Std.U8 × Array Std.U8 64#usize) Bool)
    (decoder : D) (verifier : V) (decode : List Std.U8 → Option K)
    (equation : K → List Std.U8 → List Std.U8 → Bool)
    (decodeContract : ∀ array, decoderPrimitive.call_once decoder array = ok (decode array.val))
    (verifyContract : ∀ key message signature, verifierPrimitive.call_once verifier (key, message, signature) =
      ok (equation key message.val signature.val))
    (bytes message signature : Slice Std.U8) :
    verify_ed25519_with decoderPrimitive verifierPrimitive bytes message signature decoder verifier = ok (.Ok ()) ↔
      EdAccepts decode equation bytes.val message.val signature.val := by
  rw [Auths.Crypto.Strict.SuiteRefinement.verify_ed25519_refines decoderPrimitive verifierPrimitive decoder verifier
    decode equation decodeContract verifyContract bytes message signature]
  simp only [Result.ok.injEq, ed_result_ok, ed_accepts_iff]

theorem p256_source_accepts_iff {T K S : Type}
    (primitive : P256Primitive T K S)
    (decode : List Std.U8 → Option K) (parse : List Std.U8 → Option S)
    (equation : K → List Std.U8 → S → Bool)
    (decodeContract : ∀ bytes, primitive.decode bytes = ok (decode bytes.val))
    (parseContract : ∀ array, primitive.parse array = ok (parse array.val))
    (verifyContract : ∀ key message signature, primitive.verify key message signature =
      ok (equation key message.val signature))
    (bytes message signature : Slice Std.U8) :
    verify_p256_sha256_with primitive bytes message signature = ok (.Ok ()) ↔
      P256Accepts decode parse equation bytes.val message.val signature.val := by
  rw [Auths.Crypto.Strict.SuiteRefinement.verify_p256_refines primitive
    decode parse equation decodeContract parseContract verifyContract bytes message signature]
  simp only [Result.ok.injEq, p256_result_ok, p256_accepts_iff]

end Auths.Crypto.Strict.SourceAcceptance
