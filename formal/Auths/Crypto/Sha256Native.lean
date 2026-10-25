import qualification.aeneas.generated.sha256.Funs
open Aeneas Aeneas.Std Result
namespace Auths.Crypto.Sha256Native

/-- Functional SHA-256/output representation premise. This does not assert
collision freedom, preimage resistance or any signature authenticity. -/
structure Contract [P : Sha256Primitives] (sha256 : List Std.U8 → Array Std.U8 32#usize) : Prop where
  exact_calls : ∀ bytes, ∃ output,
    P.digest bytes = ok output ∧ P.intoBytes output = ok (sha256 bytes.val)

theorem raw_hash_refines [P : Sha256Primitives]
    (sha256 : List Std.U8 → Array Std.U8 32#usize) (contract : Contract sha256)
    (bytes : Slice Std.U8) :
    AuthsNativeSha256.hash.raw_sha256 bytes = ok (sha256 bytes.val) := by
  obtain ⟨output, digestExact, representationExact⟩ := contract.exact_calls bytes
  simp only [AuthsNativeSha256.hash.raw_sha256,
    digest.qualified_sha256_type_decls_11.Insts.DigestDigestDigest.digest,
    generic_array.qualified_sha256_type_decls_1.Insts.CoreConvertIntoArrayU832.into,
    digestExact, representationExact, bind_tc_ok, AuthsNativeSha256.auths_model.Digest.new]

end Auths.Crypto.Sha256Native
