import Auths.Crypto.Strict.SuiteModel
open Aeneas Aeneas.Std Result
open auths_signature_core Auths.Crypto.Strict.SuiteModel
namespace Auths.Crypto.Strict.SuiteRefinement

theorem fixed_refines (N : Std.Usize) (bytes : Slice Std.U8) :
    core.array.TryFromSharedArraySlice.try_from N bytes =
      ok (match fixed N bytes.val with | some array => .Ok array | none => .Err ()) := by
  unfold core.array.TryFromSharedArraySlice.try_from fixed
  have sizes : bytes.len = N ↔ bytes.val.length = N.val := by scalar_tac
  by_cases sized : bytes.val.length = N.val
  · have words : bytes.len = N := sizes.mpr sized
    simp only [words, sized, _root_.dite_true]
  · have words : bytes.len ≠ N := fun h => sized (sizes.mp h)
    simp only [words, sized, _root_.dite_false]

theorem fixed_value (N : Std.Usize) (bytes : List Std.U8) (array : Array Std.U8 N)
    (accepted : fixed N bytes = some array) : array.val = bytes := by
  unfold fixed at accepted
  split at accepted
  · simp only [Option.some.injEq] at accepted
    subst array
    rfl
  · contradiction

theorem key_encoding_refines (bytes : Slice Std.U8) :
    ed25519_key_encoding bytes = ok (sourceEd (keyEncoding bytes.val)) := by
  unfold ed25519_key_encoding
  rw [fixed_refines]
  cases sized : fixed 32#usize bytes.val with
  | none => simp [sized, keyEncoding, fixedKey, sourceEd, sourceEdFailure]
  | some array =>
    simp only [bind_tc_ok]
    rw [Auths.Crypto.Encoding.Ed25519.guard_refines]
    by_cases canonical : Auths.Crypto.Encoding.Encoded.Encoding array <;>
      simp [canonical, keyEncoding, fixedKey, sized, sourceEd, sourceEdFailure]

theorem key_encoding_value (bytes : List Std.U8) (array : Auths.Crypto.Encoding.Encoded.Input)
    (accepted : keyEncoding bytes = .ok array) : array.val = bytes := by
  unfold keyEncoding at accepted
  cases sized : fixedKey bytes with
  | none => simp [sized] at accepted
  | some raw =>
    simp only [sized] at accepted
    split at accepted
    · simp only [Except.ok.injEq] at accepted
      subst array
      exact fixed_value 32#usize bytes raw sized
    · contradiction

theorem decode_ed25519_refines {K D : Type}
    (primitive : core.ops.function.FnOnce D (Array Std.U8 32#usize) (Option K))
    (decoder : D) (decode : List Std.U8 → Option K)
    (contract : ∀ array, primitive.call_once decoder array = ok (decode array.val))
    (bytes : Slice Std.U8) :
    decode_ed25519_key_with primitive bytes decoder = ok (sourceEd (edKey decode bytes.val)) := by
  unfold decode_ed25519_key_with
  rw [key_encoding_refines]
  cases encoded : keyEncoding bytes.val with
  | error reason =>
    simp [encoded, sourceEd, edKey, Except.bind, Bind.bind, Except.instMonad,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from]
  | ok raw =>
    have exactBytes := key_encoding_value bytes.val raw encoded
    simp only [encoded, sourceEd, bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
    rw [contract]
    cases decoded : decode bytes.val <;>
      simp [exactBytes, decoded, encoded, edKey, sourceEd, sourceEdFailure, Except.bind, Bind.bind, Except.instMonad]

theorem decode_p256_refines {K D : Type}
    (primitive : core.ops.function.FnOnce D (Slice Std.U8) (Option K))
    (decoder : D) (decode : List Std.U8 → Option K)
    (contract : ∀ bytes, primitive.call_once decoder bytes = ok (decode bytes.val))
    (bytes : Slice Std.U8) :
    decode_p256_key_with primitive bytes decoder = ok (sourceP256 (p256Key decode bytes.val)) := by
  unfold decode_p256_key_with
  rw [Auths.Crypto.Encoding.P256.guard_refines]
  simp only [bind_tc_ok]
  rw [contract]
  by_cases canonical : Auths.Crypto.Encoding.P256.Encoding (bytes.val.map UScalar.val)
  · cases decoded : decode bytes.val <;> simp [canonical, decoded, p256Key, sourceP256, sourceP256Failure]
  · simp [canonical, p256Key, sourceP256, sourceP256Failure]

theorem verify_ed25519_refines {K D V : Type}
    (decoderPrimitive : core.ops.function.FnOnce D (Array Std.U8 32#usize) (Option K))
    (verifierPrimitive : core.ops.function.FnOnce V (K × Slice Std.U8 × Array Std.U8 64#usize) Bool)
    (decoder : D) (verifier : V) (decode : List Std.U8 → Option K)
    (equation : K → List Std.U8 → List Std.U8 → Bool)
    (decodeContract : ∀ array, decoderPrimitive.call_once decoder array = ok (decode array.val))
    (verifyContract : ∀ key message signature, verifierPrimitive.call_once verifier (key, message, signature) =
      ok (equation key message.val signature.val))
    (bytes message signature : Slice Std.U8) :
    verify_ed25519_with decoderPrimitive verifierPrimitive bytes message signature decoder verifier =
      ok (sourceEd (edVerify decode equation bytes.val message.val signature.val)) := by
  unfold verify_ed25519_with
  rw [key_encoding_refines]
  cases encoded : keyEncoding bytes.val with
  | error reason =>
    simp [encoded, sourceEd, edVerify, Except.bind, Bind.bind, Except.instMonad,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from]
  | ok raw =>
    have exactBytes := key_encoding_value bytes.val raw encoded
    simp only [sourceEd, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    rw [decodeContract]
    simp only [exactBytes]
    cases decoded : decode bytes.val with
    | none => simp [edVerify, encoded, decoded, sourceEd, sourceEdFailure, Except.bind, Bind.bind, Except.instMonad]
    | some point =>
      simp only [bind_tc_ok]
      rw [fixed_refines]
      cases sized : fixed 64#usize signature.val with
      | none => simp [edVerify, encoded, decoded, fixedSignature, sized, sourceEd, sourceEdFailure, Except.bind, Bind.bind, Except.instMonad]
      | some array =>
        simp only [bind_tc_ok]
        rw [WeakContract.guard_refines, RContract.guard_refines, verifyContract]
        by_cases weak : WeakContract.WeakCoordinate (Encoding.Encoded.ordinate raw) <;>
          by_cases allowed : RContract.Allowed array <;>
          cases checked : equation point message.val array.val <;>
          simp [weak, allowed, checked, edVerify, encoded, decoded, fixedSignature, sized,
            sourceEd, sourceEdFailure, Except.bind, Bind.bind, Except.instMonad]

theorem verify_p256_refines {K S D P V : Type}
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
    verify_p256_sha256_with decoderPrimitive parserPrimitive verifierPrimitive bytes message signature decoder parser verifier =
      ok (sourceP256 (p256Verify decode parse equation bytes.val message.val signature.val)) := by
  unfold verify_p256_sha256_with
  rw [decode_p256_refines decoderPrimitive decoder decode decodeContract]
  cases decoded : p256Key decode bytes.val with
  | error reason =>
    simp [sourceP256, decoded, p256Verify, Except.bind, Bind.bind, Except.instMonad,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from]
  | ok point =>
    simp only [sourceP256, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    rw [fixed_refines]
    cases sized : fixed 64#usize signature.val with
    | none => simp [p256Verify, decoded, fixedSignature, sized, sourceP256, sourceP256Failure, Except.bind, Bind.bind, Except.instMonad]
    | some array =>
      simp only [bind_tc_ok]
      rw [parseContract]
      cases parsed : parse array.val with
      | none => simp [p256Verify, decoded, fixedSignature, sized, parsed, sourceP256, sourceP256Failure, Except.bind, Bind.bind, Except.instMonad]
      | some scalar =>
        simp only [bind_tc_ok]
        rw [LowContract.guard_refines, verifyContract]
        by_cases low : ByteLex.value (array.val.drop 32) ≤ LowContract.order / 2 <;>
          cases verified : equation point message.val scalar <;>
          simp [low, verified, parsed, p256Verify, decoded, fixedSignature, sized,
            sourceP256, sourceP256Failure, Except.bind, Bind.bind, Except.instMonad]

end Auths.Crypto.Strict.SuiteRefinement
