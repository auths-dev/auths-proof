-- EXACT DELEGATION TO QUALIFIED OWNING RUST UNITS, WITH EXHAUSTIVE ERROR REBOXING.
-- No Auths algorithm or crypto operation is assumed as an opaque function.
import qualification.aeneas.generated.suite_adapter.Types
import qualification.aeneas.generated.signature.Funs
import qualification.aeneas.generated.p256.Funs
import qualification.aeneas.generated.codec.FunsExternal
open Aeneas Aeneas.Std Result
namespace AuthsSuiteAdapters

abbrev core.result.Result.map_err := @_root_.core.result.Result.map_err

def fromEdError : _root_.auths_signature_core.Ed25519Error → auths_signature_core.Ed25519Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def toEdError : auths_signature_core.Ed25519Error → _root_.auths_signature_core.Ed25519Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def fromP256Error : AuthsNativeP256.P256Error → auths_signature_core.P256Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def toP256Error : auths_signature_core.P256Error → AuthsNativeP256.P256Error
  | .InvalidKey => .InvalidKey
  | .InvalidSignatureEncoding => .InvalidSignatureEncoding
  | .VerificationFailed => .VerificationFailed

def edResult : Aeneas.Std.core.result.Result Unit _root_.auths_signature_core.Ed25519Error →
    Aeneas.Std.core.result.Result Unit auths_signature_core.Ed25519Error
  | .Ok value => .Ok value | .Err reason => .Err (fromEdError reason)

def p256Result : AuthsNativeP256.core.qualified_p256_type_decls_0 →
    Aeneas.Std.core.result.Result Unit auths_signature_core.P256Error
  | .Ok value => .Ok value | .Err reason => .Err (fromP256Error reason)

def auths_signature_core.verify_ed25519 [P : Auths.Crypto.Ed25519Primitives]
    (key message signature : Slice Std.U8) :
    Result (Aeneas.Std.core.result.Result Unit auths_signature_core.Ed25519Error) := do
  let result ← _root_.auths_signature_core.verify_ed25519 (primitives := P) key message signature
  ok (edResult result)

def auths_signature_core.verify_p256_sha256 [P : Auths.Crypto.P256Primitives]
    (key message signature : Slice Std.U8) :
    Result (Aeneas.Std.core.result.Result Unit auths_signature_core.P256Error) := do
  let result ← AuthsNativeP256.verify_p256_sha256 (primitive := P) key message signature
  ok (p256Result result)

-- Both conversions are isomorphisms on the complete error domains.
theorem ed_error_to_from (reason : _root_.auths_signature_core.Ed25519Error) :
    toEdError (fromEdError reason) = reason := by cases reason <;> rfl

theorem ed_error_from_to (reason : auths_signature_core.Ed25519Error) :
    fromEdError (toEdError reason) = reason := by cases reason <;> rfl

theorem p256_error_to_from (reason : AuthsNativeP256.P256Error) :
    toP256Error (fromP256Error reason) = reason := by cases reason <;> rfl

theorem p256_error_from_to (reason : auths_signature_core.P256Error) :
    fromP256Error (toP256Error reason) = reason := by cases reason <;> rfl

theorem ed25519_delegates [P : Auths.Crypto.Ed25519Primitives]
    (key message signature : Slice Std.U8) :
    auths_signature_core.verify_ed25519 (P := P) key message signature =
      (do let result ← _root_.auths_signature_core.verify_ed25519 (primitives := P) key message signature
          ok (edResult result)) := rfl

theorem p256_delegates [P : Auths.Crypto.P256Primitives]
    (key message signature : Slice Std.U8) :
    auths_signature_core.verify_p256_sha256 (P := P) key message signature =
      (do let result ← AuthsNativeP256.verify_p256_sha256 (primitive := P) key message signature
          ok (p256Result result)) := rfl

end AuthsSuiteAdapters
