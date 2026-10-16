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

theorem p256_source_accepts_iff {K S D P V : Type}
    (decoderPrimitive : core.ops.function.FnOnce D (Slice Std.U8) (Option K))
    (parserPrimitive : core.ops.function.FnOnce P (Array Std.U8 64#usize) (Option S))
    (verifierPrimitive : core.ops.function.FnOnce V (K × Slice Std.U8 × S) Bool)
    (decoder : D) (parser : P) (verifier : V)
    (decode : List Std.U8 → Option K) (parse : List Std.U8 → Option S)
    (equation : K → List Std.U8 → S → Bool)
    (decodeContract : ∀ bytes, decoderPrimitive.call_once decoder bytes = ok (decode bytes.val))
    (parseContract : ∀ array, parserPrimitive.call_once parser array = ok (parse array.val))
    (verifyContract : ∀ key message signature, verifierPrimitive.call_once verifier (key, message, signature) =
      ok (equation key message.val signature))
    (bytes message signature : Slice Std.U8) :
    verify_p256_sha256_with decoderPrimitive parserPrimitive verifierPrimitive bytes message signature decoder parser verifier = ok (.Ok ()) ↔
      P256Accepts decode parse equation bytes.val message.val signature.val := by
  rw [Auths.Crypto.Strict.SuiteRefinement.verify_p256_refines decoderPrimitive parserPrimitive verifierPrimitive
    decoder parser verifier decode parse equation decodeContract parseContract verifyContract bytes message signature]
  simp only [Result.ok.injEq, p256_result_ok, p256_accepts_iff]

end Auths.Crypto.Strict.SourceAcceptance
