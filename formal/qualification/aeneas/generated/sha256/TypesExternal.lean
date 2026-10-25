-- Explicit foreign output type, without a global instance or axiom.
import Auths.Crypto.Sha256Primitives
abbrev generic_array.qualified_sha256_type_decls_1 [P : Auths.Crypto.Sha256Primitives] := P.Output
