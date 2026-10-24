import qualification.aeneas.generated.protocol_codec.Types
import qualification.aeneas.generated.sha256.Funs
import Auths.Crypto.Sha256Native

open Aeneas Aeneas.Std Result

namespace AuthsProtocolCodec

/-- Exact source-unit linkage, rather than an assumed hash algorithm. The
owner contains the actual Rust `raw_sha256` body and exposes the pinned
foreign digest/output-conversion contract as an explicit parameter. Both
units must refer to the same source path/span and release source closure. -/
def hash.raw_sha256 [primitive : Auths.Crypto.Sha256Primitives]
    (input : Slice Std.U8) : Result auths_model.Digest :=
  AuthsNativeSha256.hash.raw_sha256 (primitive := primitive) input

/-- All arguments and the complete Result value are delegated intact. This
does not assert hash injectivity, collision resistance, or primitive correctness. -/
theorem raw_sha256_delegates [primitive : Auths.Crypto.Sha256Primitives]
    (input : Slice Std.U8) :
    hash.raw_sha256 (primitive := primitive) input =
      AuthsNativeSha256.hash.raw_sha256 (primitive := primitive) input := rfl

/-- The protocol route inherits the owner's explicit functional primitive
contract. It receives the complete input and exact fixed-size output; no hash
injectivity, collision resistance or signature authenticity follows. -/
theorem raw_sha256_refines [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Std.U8 → Array Std.U8 32#usize)
    (contract : Auths.Crypto.Sha256Native.Contract sha256) (input : Slice Std.U8) :
    hash.raw_sha256 (primitive := primitive) input = ok (sha256 input.val) := by
  rw [raw_sha256_delegates]
  exact Auths.Crypto.Sha256Native.raw_hash_refines sha256 contract input

end AuthsProtocolCodec
