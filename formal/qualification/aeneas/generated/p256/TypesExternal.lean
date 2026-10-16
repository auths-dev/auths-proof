-- REVIEWED EXPLICIT FOREIGN TYPES. NO GLOBAL INSTANCE OR AXIOM.
import Auths.Crypto.P256Primitives
namespace AuthsNativeP256
abbrev ecdsa.qualified_p256_type_decls_4 [P : Auths.Crypto.P256Primitives] := P.Key
abbrev ecdsa.qualified_p256_type_decls_11 [P : Auths.Crypto.P256Primitives] := P.Signature
abbrev signature.error.Error [P : Auths.Crypto.P256Primitives] := P.Error
end AuthsNativeP256
