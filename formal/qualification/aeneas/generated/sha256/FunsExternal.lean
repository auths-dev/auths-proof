-- Exact selected foreign calls are explicit implementation projections.
import qualification.aeneas.generated.sha256.Types
open Aeneas Aeneas.Std Result

def generic_array.qualified_sha256_type_decls_1.Insts.CoreConvertIntoArrayU832.into
    [P : Auths.Crypto.Sha256Primitives] (value : generic_array.qualified_sha256_type_decls_1) :
    Result (Array Std.U8 32#usize) := P.intoBytes value

def digest.qualified_sha256_type_decls_11.Insts.DigestDigestDigest.digest
    [P : Auths.Crypto.Sha256Primitives] (value : Slice Std.U8) :
    Result generic_array.qualified_sha256_type_decls_1 := P.digest value
