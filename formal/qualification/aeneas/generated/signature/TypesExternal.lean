-- REVIEWED FOREIGN TYPE INTERFACE. NO GLOBAL INSTANCE OR AXIOM.
import Auths.Crypto.NativePrimitives

abbrev ed25519.Signature [P : Auths.Crypto.Ed25519Primitives] := P.Signature
abbrev ed25519_dalek.verifying.VerifyingKey [P : Auths.Crypto.Ed25519Primitives] := P.Key
abbrev signature.error.Error [P : Auths.Crypto.Ed25519Primitives] := P.Error
