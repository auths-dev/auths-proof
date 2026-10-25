-- REVIEWED TRANSPARENT STANDARD RESULT MODEL AND EXPLICIT FOREIGN INTERFACE.
import qualification.aeneas.generated.signature.Types
import qualification.aeneas.generated.codec.FunsExternal

open Aeneas Aeneas.Std Result

def core.result.Result.ok {T E : Type} (value : core.result.Result T E) : Result (Option T) :=
  Aeneas.Std.Result.ok (match value with | .Ok value => some value | .Err _ => none)

def ed25519.Signature.from_bytes [P : Auths.Crypto.Ed25519Primitives]
    (bytes : Array Std.U8 64#usize) : Result ed25519.Signature := P.signatureFromBytes bytes

def ed25519_dalek.verifying.VerifyingKey.from_bytes [P : Auths.Crypto.Ed25519Primitives]
    (bytes : Array Std.U8 32#usize) :
    Result (core.result.Result ed25519_dalek.verifying.VerifyingKey signature.error.Error) :=
  P.decode bytes

def ed25519_dalek.verifying.VerifyingKey.verify_strict [P : Auths.Crypto.Ed25519Primitives]
    (key : ed25519_dalek.verifying.VerifyingKey) (message : Slice Std.U8)
    (encodedSignature : ed25519.Signature) : Result (core.result.Result Unit signature.error.Error) :=
  P.verifyStrict key message encodedSignature
